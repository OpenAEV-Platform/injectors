import json
import os
import tempfile
import time
from importlib.resources import files
from typing import Dict, List, Optional, Tuple

from pyoaev.credential import (
    AwsAssumeRoleSecret,
    AwsSourceIdentityType,
    CredentialCleanupError,
    CredentialErrorCode,
    CredentialResolutionError,
    ResolvedSecret,
    get_credential_attachment,
    materialize,
    resolve_credential_attachment,
)
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from injector_common.stratus_executor import (
    AUTH_FAILED,
    AUTH_PASSED,
    StratusExecutor,
    StratusResult,
)
from stratus.configuration.config_loader import ConfigLoader
from stratus.contracts import (
    CONTRACT_REGISTRY,
    CREDENTIAL_SOURCE_KEY,
    CREDENTIAL_SOURCE_VALUES,
    CUSTOM_TECHNIQUE_FIELD_KEY,
    MANUAL_CREDENTIALS,
    PLATFORMS,
    PlatformSpec,
    ResolvedContract,
)

ICON_PATH = "img/icon-stratus.png"

# Provider whose credential type a platform expects from a credential reference,
# looked up in the pyoaev mapping shared with the contract field (see
# ``PlatformSpec.credential_provider``).
CREDENTIAL_PROVIDER_BY_PLATFORM = {
    platform.key: platform.credential_provider
    for platform in PLATFORMS
    if platform.credential_provider is not None
}

# Platform names as printed by the Stratus authentication check.
AUTH_PLATFORM_LABELS = {
    "AWS": "AWS",
    "EKS": "Amazon EKS",
    "azure": "Azure",
    "entra-id": "Entra ID",
    "GCP": "Google Cloud",
    "kubernetes": "Kubernetes",
}
# Stratus only builds a client for these platforms, without contacting them: a
# passed check proves the credentials were loaded, not that they are valid.
UNVERIFIED_AUTH_PLATFORMS = frozenset({"azure", "GCP"})

# Stratus runs without the host cloud credentials. An AWS assume-role credential
# whose source is the host's own identity (INSTANCE_DEFAULT) only works if the
# variables that describe that identity are handed over: the ambient keys, and
# the settings of the EC2 instance metadata service the profile falls back on.
AWS_INSTANCE_IDENTITY_VARIABLES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_EC2_METADATA_V1_DISABLED",
    "AWS_METADATA_SERVICE_TIMEOUT",
    "AWS_METADATA_SERVICE_NUM_ATTEMPTS",
)

LEGACY_CREDENTIAL_SOURCE = "the inject credential fields"

CREDENTIAL_MISSING_MESSAGE = (
    "No credential is selected on this inject, which uses the credential manager. "
    "Select a credential on the inject, or choose manual credentials, then run it "
    "again."
)
CREDENTIAL_SOURCE_INVALID_MESSAGE = (
    "Choose the credential manager or manual credentials in the 'Credentials' "
    "field of the inject, then run it again."
)


class OpenAEVStratus:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(self.config, self._load_icon())
        self.stratus = StratusExecutor(logger=self.helper.injector_logger)

    def _load_icon(self) -> bytes:
        icon_path = files("stratus").joinpath(ICON_PATH)
        with icon_path.open("rb") as icon_file:
            return icon_file.read()

    @staticmethod
    def _resolve_contract(data: Dict) -> ResolvedContract:
        contract_id = DataHelpers.get_injector_contract_id(data)
        resolved = CONTRACT_REGISTRY.get(contract_id)
        if resolved is None:
            raise ValueError(
                f"Unsupported contract '{contract_id}' for the Stratus injector"
            )
        return resolved

    @staticmethod
    def _resolve_technique(resolved: ResolvedContract, content: Dict) -> Optional[str]:
        # Per-technique contracts carry a fixed technique; custom contracts read
        # the free-form technique id from the inject content.
        if resolved.technique_id is not None:
            return resolved.technique_id
        supplied = content.get(CUSTOM_TECHNIQUE_FIELD_KEY)
        if isinstance(supplied, list):
            supplied = supplied[0] if supplied else None
        if isinstance(supplied, str):
            supplied = supplied.strip()
        return supplied or None

    @staticmethod
    def _build_env(
        platform: PlatformSpec, content: Dict
    ) -> Tuple[Dict[str, str], List[str]]:
        """Build the Stratus process environment for the target platform.

        Returns the environment mapping and the list of temp files created for
        materialized secrets so the caller can remove them after detonation.
        """
        env: Dict[str, str] = {}
        temp_files: List[str] = []
        try:
            for cred in platform.cred_fields:
                raw = content.get(cred.key)
                value = raw.strip() if isinstance(raw, str) else raw
                if not value:
                    if cred.mandatory:
                        raise ValueError(f"'{cred.label}' is required")
                    if cred.default is not None:
                        value = cred.default
                    else:
                        continue

                if cred.as_file_env:
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=cred.file_suffix, delete=False
                    ) as handle:
                        handle.write(value)
                        path = handle.name
                    temp_files.append(path)
                    if cred.file_mode is not None:
                        os.chmod(path, cred.file_mode)
                    env[cred.as_file_env] = path
                else:
                    for env_var in cred.env_vars:
                        env[env_var] = value
        except Exception:
            # Never leave a secret temp file behind if wiring fails partway
            # (e.g. a later mandatory field is missing after an earlier secret
            # was already materialized to disk).
            for path in temp_files:
                if os.path.exists(path):
                    os.remove(path)
            raise
        return env, temp_files

    @staticmethod
    def _uses_manual_credentials(
        platform: PlatformSpec, content: Dict
    ) -> Optional[bool]:
        """Return whether the inject selects manual credentials.

        ``None`` for a platform without a credential type, which has no
        credential source select: its credentials are the inject fields.
        """
        if platform.credential_provider is None:
            return None
        submitted = content.get(CREDENTIAL_SOURCE_KEY)
        if isinstance(submitted, list) and len(submitted) == 1:
            submitted = submitted[0]
        if submitted not in CREDENTIAL_SOURCE_VALUES:
            raise ValueError(CREDENTIAL_SOURCE_INVALID_MESSAGE)
        return submitted == MANUAL_CREDENTIALS

    def _resolve_credential(
        self, inject_id: str, data: Dict, platform: PlatformSpec
    ) -> Optional[Tuple[str, ResolvedSecret]]:
        """Resolve the credential referenced by the job, if any.

        Returns ``None`` when the job carries no credential reference: the
        legacy credential fields of the inject are then used. Otherwise returns
        the reference id with its resolved secret.
        """
        attachment = get_credential_attachment(data)
        if attachment is None:
            return None
        provider = CREDENTIAL_PROVIDER_BY_PLATFORM.get(platform.key)
        if provider is None:
            # Fail before resolving: the secret is never fetched for nothing.
            raise CredentialResolutionError(
                CredentialErrorCode.CREDENTIAL_INCOMPATIBLE, attachment.reference
            )
        credential = resolve_credential_attachment(
            self.helper.api, inject_id, attachment, provider
        )
        self.helper.injector_logger.info(
            f"Credential reference {attachment.reference} resolved "
            f"({credential.secret_type.value}) for inject {inject_id}"
        )
        return attachment.reference, credential

    @staticmethod
    def _host_identity_env(credential: ResolvedSecret) -> Dict[str, str]:
        """Host variables of a credential whose identity is the host's own.

        Only the listed variables that are set are handed over; a value the
        credential materializes itself always wins over the host one.
        """
        if not (
            isinstance(credential, AwsAssumeRoleSecret)
            and credential.aws_source_identity_type
            == AwsSourceIdentityType.INSTANCE_DEFAULT
        ):
            return {}
        return {
            name: os.environ[name]
            for name in AWS_INSTANCE_IDENTITY_VARIABLES
            if name in os.environ
        }

    @staticmethod
    def _reference_default_env(
        platform: PlatformSpec, reference: str, credential: ResolvedSecret
    ) -> Dict[str, str]:
        """Defaults of the scope values the resolved credential omits.

        With the credential manager, the region, subscription, and project come
        from the credential only: the inject fields are hidden. A required one
        the credential lacks, with no default, ends the execution.
        """
        env: Dict[str, str] = {}
        for cred in platform.cred_fields:
            if cred.reference_attribute is None or getattr(
                credential, cred.reference_attribute, None
            ):
                continue
            if cred.default is not None:
                for env_var in cred.env_vars:
                    env[env_var] = cred.default
            elif cred.mandatory:
                raise ValueError(
                    f"The credential {reference} has no {cred.label}. Set it on the "
                    "credential, then run it again."
                )
        return env

    def _detonate_with_credential(
        self,
        technique_id: str,
        platform: PlatformSpec,
        reference: str,
        credential: ResolvedSecret,
    ) -> Tuple[StratusResult, bool]:
        """Detonate with the resolved credential only.

        Returns the result and whether the temporary credential files could not
        be removed afterwards. A cleanup failure after the detonation ran does
        not hide its result; it is still raised when the detonation did not run.
        """
        result: Optional[StratusResult] = None
        default_env = self._reference_default_env(platform, reference, credential)
        try:
            # The legacy credential fields are not read at all, and the host
            # credentials are not inherited: the resolved credential is the only
            # one Stratus can use, apart from the host identity it names as its
            # source.
            with materialize(credential, reference=reference) as materialized:
                env = {
                    **self._host_identity_env(credential),
                    **default_env,
                    **materialized.env,
                }
                result = self.stratus.detonate(
                    technique_id, env=env, cleanup=True, isolate_host_credentials=True
                )
        except CredentialCleanupError:
            if result is None:
                raise
            return result, True
        return result, False

    def _send_trace(
        self, inject_id: str, action: str, status: str, message: str, start: float
    ) -> None:
        """Send an intermediate execution trace, never failing the execution."""
        try:
            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": message,
                    "execution_status": status,
                    "execution_duration": int(time.time() - start),
                    "execution_action": action,
                },
            )
        except Exception as exc:  # noqa: BLE001
            self.helper.injector_logger.error(
                f"Failed to send the {action} trace for inject {inject_id}: {exc}"
            )

    def _report_authentication(
        self, inject_id: str, result: StratusResult, source: str, start: float
    ) -> None:
        """Log and trace the outcome of the Stratus authentication check."""
        if result.auth_status == AUTH_FAILED:
            self.helper.injector_logger.error(
                f"Stratus authentication check failed for inject {inject_id} "
                f"with {source}: {result.message}"
            )
            return
        if result.auth_status != AUTH_PASSED:
            return
        label = AUTH_PLATFORM_LABELS.get(result.auth_platform, result.auth_platform)
        if result.auth_platform in UNVERIFIED_AUTH_PLATFORMS:
            message = (
                f"Stratus authentication check passed for {label} with {source}: "
                f"the credentials were loaded, but Stratus does not contact {label} "
                "during this check, the detonation confirms them"
            )
        else:
            message = f"Authenticated against {label} with {source}"
        self.helper.injector_logger.info(f"{message} (inject {inject_id})")
        self._send_trace(inject_id, "prerequisite_check", "INFO", message, start)

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        temp_files: List[str] = []
        try:
            resolved = self._resolve_contract(data)
            content = DataHelpers.get_content(data)
            technique_id = self._resolve_technique(resolved, content)
            if not technique_id:
                raise ValueError("No Stratus technique id provided")

            # Resolved just in time, after the reception and before the callback,
            # while the inject is in progress. With manual credentials, a
            # credential still attached to the inject is ignored.
            manual = self._uses_manual_credentials(resolved.platform, content)
            referenced = (
                None
                if manual
                else self._resolve_credential(inject_id, data, resolved.platform)
            )
            if referenced is None and manual is False:
                raise ValueError(CREDENTIAL_MISSING_MESSAGE)
            cleanup_failed = False
            if referenced is None:
                source = LEGACY_CREDENTIAL_SOURCE
                env, temp_files = self._build_env(resolved.platform, content)
                result = self.stratus.detonate(technique_id, env=env, cleanup=True)
            else:
                reference, credential = referenced
                source = (
                    f"credential reference {reference} "
                    f"({credential.secret_type.value})"
                )
                result, cleanup_failed = self._detonate_with_credential(
                    technique_id, resolved.platform, reference, credential
                )

            self._report_authentication(inject_id, result, source, start)
            if cleanup_failed:
                self.helper.injector_logger.error(
                    f"Temporary credential files of inject {inject_id} could not "
                    "be removed after the detonation"
                )
                self._send_trace(
                    inject_id,
                    "cleanup_execution",
                    "WARNING",
                    "The temporary credential files could not be removed after the "
                    "detonation",
                    start,
                )

            callback_data = {
                "execution_message": result.message,
                "execution_status": "SUCCESS" if result.success else "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            if result.success:
                callback_data["execution_output_structured"] = json.dumps(
                    result.outputs
                )
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            if isinstance(e, CredentialResolutionError):
                # The code and its fixed message only: never a secret value.
                self.helper.injector_logger.error(
                    f"Credential reference resolution failed for inject "
                    f"{inject_id}: {e}"
                )
            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": str(e),
                    "execution_status": "ERROR",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                },
            )
        finally:
            for path in temp_files:
                if os.path.exists(path):
                    os.remove(path)

    def start(self):
        self.helper.injector_logger.info("Starting Stratus Red Team injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVStratus().start()
