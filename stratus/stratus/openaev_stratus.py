import json
import os
import tempfile
import time
from importlib.resources import files
from typing import Dict, List, Optional, Tuple

from pyoaev.credential import (
    CredentialErrorCode,
    CredentialResolutionError,
    ResolvedSecret,
    get_credential_attachment,
    materialize,
    resolve_inject_credential,
)
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from injector_common.stratus_executor import StratusExecutor, StratusResult
from stratus.configuration.config_loader import ConfigLoader
from stratus.contracts import (
    CONTRACT_REGISTRY,
    CUSTOM_TECHNIQUE_FIELD_KEY,
    PlatformSpec,
    ResolvedContract,
)

ICON_PATH = "img/icon-stratus.png"

# Provider whose credential type a platform expects from a credential reference,
# looked up in the pyoaev mapping shared with the contract field. Entra ID
# declares no type on its contract but authenticates with an Azure credential;
# Kubernetes needs a kubeconfig, which no referenced credential provides.
CREDENTIAL_PROVIDER_BY_PLATFORM = {
    "aws": "aws",
    "eks": "eks",
    "azure": "azure",
    "entra-id": "azure",
    "gcp": "gcp",
}


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

    def _resolve_credential(
        self, inject_id: str, data: Dict, platform: PlatformSpec
    ) -> Optional[ResolvedSecret]:
        """Resolve the credential referenced by the job, if any.

        Returns ``None`` when the job carries no credential reference: the
        legacy credential fields of the inject are then used.
        """
        provider = CREDENTIAL_PROVIDER_BY_PLATFORM.get(platform.key)
        if provider is None:
            attachment = get_credential_attachment(data)
            if attachment is None:
                return None
            # Fail before resolving: the secret is never fetched for nothing.
            raise CredentialResolutionError(
                CredentialErrorCode.CREDENTIAL_INCOMPATIBLE, attachment.reference
            )
        return resolve_inject_credential(self.helper.api, inject_id, data, provider)

    @staticmethod
    def _reference_fallback_env(
        platform: PlatformSpec, content: Dict, credential: ResolvedSecret
    ) -> Dict[str, str]:
        """Non-secret values of the inject that the resolved credential omits."""
        env: Dict[str, str] = {}
        for cred in platform.cred_fields:
            if cred.reference_attribute is None or getattr(
                credential, cred.reference_attribute, None
            ):
                continue
            raw = content.get(cred.key)
            value = (raw.strip() if isinstance(raw, str) else raw) or cred.default
            if value:
                for env_var in cred.env_vars:
                    env[env_var] = value
        return env

    def _detonate_with_credential(
        self,
        technique_id: str,
        platform: PlatformSpec,
        content: Dict,
        credential: ResolvedSecret,
    ) -> StratusResult:
        # The legacy credential fields are not read at all, and the host
        # credentials are not inherited: the resolved credential is the only
        # one Stratus can use.
        with materialize(credential) as materialized:
            env = {
                **self._reference_fallback_env(platform, content, credential),
                **materialized.env,
            }
            return self.stratus.detonate(
                technique_id, env=env, cleanup=True, isolate_host_credentials=True
            )

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
            # while the inject is in progress.
            credential = self._resolve_credential(inject_id, data, resolved.platform)
            if credential is None:
                env, temp_files = self._build_env(resolved.platform, content)
                result = self.stratus.detonate(technique_id, env=env, cleanup=True)
            else:
                result = self._detonate_with_credential(
                    technique_id, resolved.platform, content, credential
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
