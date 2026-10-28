import base64
import json
import os
import subprocess
import tempfile
from unittest import TestCase
from unittest.mock import MagicMock, patch

from pyoaev.credential import (
    CredentialCleanupError,
    CredentialErrorCode,
    CredentialResolutionError,
)

import stratus.openaev_stratus as mod
from injector_common.stratus_executor import (
    AUTH_FAILED,
    AUTH_PASSED,
    StratusExecutor,
    StratusResult,
    parse_authentication,
)
from stratus.contracts import CONTRACT_REGISTRY, technique_contract_id
from stratus.contracts.platforms import (
    AWS_CUSTOM_CONTRACT,
    AZURE_CUSTOM_CONTRACT,
    ENTRA_CUSTOM_CONTRACT,
    K8S_CUSTOM_CONTRACT,
    PLATFORMS,
    PLATFORMS_BY_KEY,
    CredField,
    PlatformSpec,
)

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "stratus--test",
}

AWS_TECH = "aws.persistence.iam-backdoor-user"
AWS_TECH_CONTRACT = technique_contract_id(AWS_TECH)
GCP_TECH = "gcp.exfiltration.share-compute-disk"
GCP_TECH_CONTRACT = technique_contract_id(GCP_TECH)


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod.OpenAEVStratus, "_load_icon", return_value=b"icon"
    ):
        injector = mod.OpenAEVStratus()
    injector.helper = MagicMock()
    injector.stratus = MagicMock()
    return injector


def _data(content, contract_id, attachments=None):
    # The credential source the form sends, unless the test sets its own: the
    # credential manager with a credential reference, manual credentials
    # otherwise. Platforms without a credential type ignore it.
    content = {
        "credential_source": "credential_manager" if attachments else "manual",
        **content,
    }
    data = {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content,
        }
    }
    if attachments is not None:
        data["attachments"] = attachments
    return data


AWS_CREDS = {"aws_access_key_id": "AKIA", "aws_secret_access_key": "secret"}

REFERENCE = "ref-1"
AUTHORISATION_CODE = "code-1"
ATTACHMENTS = {
    "credential_references": [REFERENCE],
    "authorisation_code": AUTHORISATION_CODE,
}

AWS_ACCESS_KEY_PAYLOAD = {
    "type": "AWS_ACCESS_KEY",
    "value": {
        "aws_access_key_id": "AKIA-REF",
        "aws_secret_access_key": "ref-aws-secret",
        "aws_default_region": "us-west-2",
    },
}
AZURE_SERVICE_PRINCIPAL_PAYLOAD = {
    "type": "AZURE_SERVICE_PRINCIPAL",
    "value": {
        "azure_environment": "AzureCloud",
        "azure_client_id": "ref-client",
        "azure_client_secret": "ref-azure-secret",
        "azure_tenant_id": "ref-tenant",
        "azure_subscription_id": "ref-subscription",
    },
}
GCP_SERVICE_ACCOUNT_KEY = b'{"type": "service_account", "private_key": "ref-gcp-key"}'
GCP_SERVICE_ACCOUNT_PAYLOAD = {
    "type": "GCP_SERVICE_ACCOUNT",
    "value": {
        "gcp_scope": "googleapis.com",
        "gcp_project_id": "ref-project",
        "gcp_private_key_json": base64.b64encode(GCP_SERVICE_ACCOUNT_KEY).decode(),
    },
}
GCP_OAUTH2_PAYLOAD = {
    "type": "GCP_OAUTH2",
    "value": {
        "gcp_scope": "googleapis.com",
        "gcp_project_id": "ref-project",
        "gcp_oauth_client_id": "ref-oauth-client",
        "gcp_oauth_client_secret": "ref-oauth-secret",
        "gcp_oauth_refresh_token": "ref-oauth-refresh",
    },
}
AZURE_CONTENT = {"technique_id": "azure.x"}
SOVEREIGN_CA_CERTIFICATE = (
    b"-----BEGIN CERTIFICATE-----\nref-ca-pem\n-----END CERTIFICATE-----\n"
)
SECRET_VALUES = (
    "AKIA-REF",
    "ref-aws-secret",
    "ref-azure-secret",
    "ref-gcp-key",
    "ref-oauth-token",
    "ref-ca-pem",
    AUTHORISATION_CODE,
)


def _with_values(payload, **values):
    """Copy of a resolved secret payload with extra (sovereign cloud) values."""
    return {"type": payload["type"], "value": {**payload["value"], **values}}


class ResolveContractTest(TestCase):
    def test_resolves_every_registered_contract(self):
        for contract_id, expected in CONTRACT_REGISTRY.items():
            resolved = mod.OpenAEVStratus._resolve_contract(_data({}, contract_id))
            self.assertIs(resolved, expected)

    def test_unknown_contract_raises(self):
        with self.assertRaises(ValueError):
            mod.OpenAEVStratus._resolve_contract(_data({}, "not-a-contract"))


class ResolveTechniqueTest(TestCase):
    def test_fixed_technique_ignores_content(self):
        resolved = CONTRACT_REGISTRY[AWS_TECH_CONTRACT]
        technique = mod.OpenAEVStratus._resolve_technique(
            resolved, {"technique_id": "something.else"}
        )
        self.assertEqual(technique, AWS_TECH)

    def test_custom_technique_reads_from_content(self):
        resolved = CONTRACT_REGISTRY[AWS_CUSTOM_CONTRACT]
        technique = mod.OpenAEVStratus._resolve_technique(
            resolved, {"technique_id": "aws.discovery.ses-enumerate"}
        )
        self.assertEqual(technique, "aws.discovery.ses-enumerate")

    def test_custom_technique_missing_returns_none(self):
        resolved = CONTRACT_REGISTRY[AWS_CUSTOM_CONTRACT]
        self.assertIsNone(mod.OpenAEVStratus._resolve_technique(resolved, {}))
        self.assertIsNone(
            mod.OpenAEVStratus._resolve_technique(resolved, {"technique_id": "  "})
        )


class BuildEnvTest(TestCase):
    def test_aws_direct_env_and_region_default(self):
        env, temp_files = mod.OpenAEVStratus._build_env(
            PLATFORMS_BY_KEY["aws"], AWS_CREDS
        )
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIA")
        self.assertEqual(env["AWS_REGION"], "us-east-1")
        self.assertEqual(env["AWS_DEFAULT_REGION"], "us-east-1")
        self.assertNotIn("AWS_SESSION_TOKEN", env)
        self.assertEqual(temp_files, [])

    def test_missing_mandatory_field_raises(self):
        with self.assertRaises(ValueError):
            mod.OpenAEVStratus._build_env(
                PLATFORMS_BY_KEY["aws"], {"aws_access_key_id": "AKIA"}
            )

    def test_gcp_key_materialized_to_temp_file_with_mode(self):
        env, temp_files = mod.OpenAEVStratus._build_env(
            PLATFORMS_BY_KEY["gcp"],
            {"gcp_project_id": "proj", "gcp_service_account_key": '{"type":"x"}'},
        )
        path = env["GOOGLE_APPLICATION_CREDENTIALS"]
        try:
            self.assertEqual(env["GOOGLE_PROJECT"], "proj")
            self.assertTrue(path.endswith(".json"))
            self.assertEqual(temp_files, [path])
        finally:
            os.remove(path)

    def test_eks_reuses_aws_credentials(self):
        env, _ = mod.OpenAEVStratus._build_env(PLATFORMS_BY_KEY["eks"], AWS_CREDS)
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIA")

    def test_secret_temp_file_removed_when_later_field_raises(self):
        # A secret materialized to disk must not leak if a subsequent mandatory
        # field is missing and _build_env raises before returning.
        captured = {}
        real_named_tmp = tempfile.NamedTemporaryFile

        def _spy(*args, **kwargs):
            handle = real_named_tmp(*args, **kwargs)
            captured["path"] = handle.name
            return handle

        platform = PlatformSpec(
            key="probe",
            custom_contract_id="probe",
            label="Probe",
            cred_fields=[
                CredField(
                    key="secret_file",
                    label="Secret file",
                    textarea=True,
                    as_file_env="SECRET_FILE",
                    file_suffix=".txt",
                    file_mode=0o600,
                ),
                CredField(key="required_after", label="Required after"),
            ],
        )
        with patch.object(mod.tempfile, "NamedTemporaryFile", _spy):
            with self.assertRaises(ValueError):
                mod.OpenAEVStratus._build_env(platform, {"secret_file": "topsecret"})
        self.assertIn("path", captured)
        self.assertFalse(os.path.exists(captured["path"]))


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_fixed_technique_success(self):
        injector = make_injector()
        injector.stratus.detonate.return_value = StratusResult(
            success=True,
            technique_id=AWS_TECH,
            status="DETONATED",
            message="done",
            outputs={"technique": AWS_TECH},
        )
        injector.process_message(_data(AWS_CREDS, AWS_TECH_CONTRACT))
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "SUCCESS")
        self.assertEqual(injector.stratus.detonate.call_args.args[0], AWS_TECH)
        self.assertEqual(
            json.loads(callback["execution_output_structured"]),
            {"technique": AWS_TECH},
        )

    def test_custom_contract_uses_supplied_technique(self):
        injector = make_injector()
        injector.stratus.detonate.return_value = StratusResult(
            success=True, technique_id="aws.x", status="DETONATED", message="ok"
        )
        content = dict(AWS_CREDS, technique_id="aws.discovery.ses-enumerate")
        injector.process_message(_data(content, AWS_CUSTOM_CONTRACT))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        self.assertEqual(
            injector.stratus.detonate.call_args.args[0], "aws.discovery.ses-enumerate"
        )

    def test_custom_contract_missing_technique_reports_error(self):
        injector = make_injector()
        injector.process_message(_data(AWS_CREDS, AWS_CUSTOM_CONTRACT))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        injector.stratus.detonate.assert_not_called()

    def test_gcp_key_removed_after_success(self):
        injector = make_injector()
        injector.stratus.detonate.return_value = StratusResult(
            success=True, technique_id=GCP_TECH, status="DETONATED", message="ok"
        )
        content = {"gcp_project_id": "proj", "gcp_service_account_key": '{"type":"x"}'}
        injector.process_message(_data(content, GCP_TECH_CONTRACT))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        env = injector.stratus.detonate.call_args.kwargs["env"]
        self.assertFalse(os.path.exists(env["GOOGLE_APPLICATION_CREDENTIALS"]))

    def test_temp_file_removed_when_detonate_raises(self):
        injector = make_injector()
        injector.stratus.detonate.side_effect = RuntimeError("boom")
        content = {"gcp_project_id": "proj", "gcp_service_account_key": '{"type":"x"}'}
        injector.process_message(_data(content, GCP_TECH_CONTRACT))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        env = injector.stratus.detonate.call_args.kwargs["env"]
        self.assertFalse(os.path.exists(env["GOOGLE_APPLICATION_CREDENTIALS"]))

    def test_missing_credential_reports_error(self):
        injector = make_injector()
        injector.process_message(
            _data({"aws_access_key_id": "AKIA"}, AWS_TECH_CONTRACT)
        )
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        injector.stratus.detonate.assert_not_called()

    def test_unknown_contract_reports_error(self):
        injector = make_injector()
        injector.process_message(_data({}, "nope"))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        injector.stratus.detonate.assert_not_called()

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class ProcessMessageCredentialReferenceTest(TestCase):
    def _injector(self, payload=None, resolution_error=None, detonate=None):
        injector = make_injector()
        resolve = injector.helper.api.inject.resolve_attachment_secret
        resolve.return_value = payload
        resolve.side_effect = resolution_error
        if detonate is None:
            injector.stratus.detonate.return_value = StratusResult(
                success=True, technique_id="t", status="DETONATED", message="ok"
            )
        else:
            injector.stratus.detonate.side_effect = detonate
        return injector

    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def _detonate_env(self, injector):
        return injector.stratus.detonate.call_args.kwargs["env"]

    def _assert_no_secret_reported(self, injector):
        for call in injector.helper.api.inject.execution_callback.call_args_list:
            reported = json.dumps(call.kwargs["data"])
            for secret in SECRET_VALUES:
                self.assertNotIn(secret, reported)

    def test_reference_is_resolved_with_the_job_authorisation(self):
        injector = self._injector(AWS_ACCESS_KEY_PAYLOAD)
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        injector.helper.api.inject.resolve_attachment_secret.assert_called_once_with(
            "i1", REFERENCE, AUTHORISATION_CODE
        )
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "SUCCESS")
        env = self._detonate_env(injector)
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIA-REF")
        self.assertEqual(env["AWS_SECRET_ACCESS_KEY"], "ref-aws-secret")
        self.assertEqual(env["AWS_REGION"], "us-west-2")
        self._assert_no_secret_reported(injector)

    def test_resolution_happens_after_reception_and_before_callback(self):
        injector = self._injector(AWS_ACCESS_KEY_PAYLOAD)
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        calls = [name for name, _, _ in injector.helper.api.inject.mock_calls]
        self.assertEqual(
            calls,
            ["execution_reception", "resolve_attachment_secret", "execution_callback"],
        )

    def test_reference_wins_over_filled_legacy_fields(self):
        injector = self._injector(AWS_ACCESS_KEY_PAYLOAD)
        content = dict(AWS_CREDS, aws_session_token="legacy-token")
        injector.process_message(_data(content, AWS_TECH_CONTRACT, ATTACHMENTS))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        env = self._detonate_env(injector)
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIA-REF")
        self.assertEqual(env["AWS_SECRET_ACCESS_KEY"], "ref-aws-secret")
        # No merge: a legacy value the credential does not carry is not used.
        self.assertNotIn("AWS_SESSION_TOKEN", env)
        self.assertNotIn("legacy-token", env.values())
        self.assertNotIn("secret", env.values())

    def test_reference_path_does_not_inherit_host_credentials(self):
        injector = self._injector(AWS_ACCESS_KEY_PAYLOAD)
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        self.assertTrue(
            injector.stratus.detonate.call_args.kwargs["isolate_host_credentials"]
        )

    def test_no_attachments_keeps_the_legacy_path(self):
        for attachments in (
            None,
            {"credential_references": [], "authorisation_code": "x"},
            {"credential_references": None},
        ):
            with self.subTest(attachments=attachments):
                injector = self._injector()
                data = _data(AWS_CREDS, AWS_TECH_CONTRACT)
                data["attachments"] = attachments
                injector.process_message(data)
                resolve = injector.helper.api.inject.resolve_attachment_secret
                resolve.assert_not_called()
                self.assertEqual(
                    self._callback(injector)["execution_status"], "SUCCESS"
                )
                env = self._detonate_env(injector)
                self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIA")
                self.assertEqual(env["AWS_REGION"], "us-east-1")
                self.assertNotIn(
                    "isolate_host_credentials",
                    injector.stratus.detonate.call_args.kwargs,
                )

    def test_platform_resolution_codes_reported_in_the_trace(self):
        for code in (
            CredentialErrorCode.CREDENTIAL_NOT_FOUND,
            CredentialErrorCode.CREDENTIAL_INACTIVE,
            CredentialErrorCode.CREDENTIAL_ACCESS_DENIED,
        ):
            with self.subTest(code=code):
                error = CredentialResolutionError(code, reference=REFERENCE)
                injector = self._injector(resolution_error=error)
                injector.process_message(
                    _data(AWS_CREDS, AWS_TECH_CONTRACT, ATTACHMENTS)
                )
                callback = self._callback(injector)
                self.assertEqual(callback["execution_status"], "ERROR")
                self.assertEqual(callback["execution_message"], str(error))
                self.assertTrue(callback["execution_message"].startswith(code.value))
                self.assertIn(error.message, callback["execution_message"])
                # The legacy fields are not a fallback for a failed resolution.
                injector.stratus.detonate.assert_not_called()
                self._assert_no_secret_reported(injector)

    def test_not_found_and_inactive_identify_the_reference(self):
        for code in (
            CredentialErrorCode.CREDENTIAL_NOT_FOUND,
            CredentialErrorCode.CREDENTIAL_INACTIVE,
        ):
            with self.subTest(code=code):
                error = CredentialResolutionError(code, reference=REFERENCE)
                injector = self._injector(resolution_error=error)
                injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
                self.assertIn(REFERENCE, self._callback(injector)["execution_message"])

    def test_missing_authorisation_code_is_access_denied(self):
        injector = self._injector(AWS_ACCESS_KEY_PAYLOAD)
        attachments = {"credential_references": [REFERENCE]}
        injector.process_message(_data(AWS_CREDS, AWS_TECH_CONTRACT, attachments))
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertTrue(
            callback["execution_message"].startswith(
                CredentialErrorCode.CREDENTIAL_ACCESS_DENIED.value
            )
        )
        injector.helper.api.inject.resolve_attachment_secret.assert_not_called()
        injector.stratus.detonate.assert_not_called()

    def test_incompatible_credential_type_is_reported(self):
        injector = self._injector(GCP_SERVICE_ACCOUNT_PAYLOAD)
        injector.process_message(_data(AWS_CREDS, AWS_TECH_CONTRACT, ATTACHMENTS))
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertTrue(
            callback["execution_message"].startswith(
                CredentialErrorCode.CREDENTIAL_INCOMPATIBLE.value
            )
        )
        self.assertIn(REFERENCE, callback["execution_message"])
        injector.stratus.detonate.assert_not_called()
        self._assert_no_secret_reported(injector)

    def test_kubernetes_reference_is_incompatible_without_resolution(self):
        injector = self._injector(AWS_ACCESS_KEY_PAYLOAD)
        content = {"kubeconfig": "apiVersion: v1", "technique_id": "k8s.x"}
        injector.process_message(_data(content, K8S_CUSTOM_CONTRACT, ATTACHMENTS))
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertTrue(
            callback["execution_message"].startswith(
                CredentialErrorCode.CREDENTIAL_INCOMPATIBLE.value
            )
        )
        injector.helper.api.inject.resolve_attachment_secret.assert_not_called()
        injector.stratus.detonate.assert_not_called()

    def test_kubernetes_without_reference_keeps_the_legacy_path(self):
        injector = self._injector()
        content = {"kubeconfig": "apiVersion: v1", "technique_id": "k8s.x"}
        injector.process_message(_data(content, K8S_CUSTOM_CONTRACT))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        self.assertIn("KUBECONFIG", self._detonate_env(injector))

    def test_entra_id_uses_an_azure_credential(self):
        injector = self._injector(AZURE_SERVICE_PRINCIPAL_PAYLOAD)
        content = {"technique_id": "entra-id.persistence.guest-user"}
        injector.process_message(_data(content, ENTRA_CUSTOM_CONTRACT, ATTACHMENTS))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        env = self._detonate_env(injector)
        self.assertEqual(env["AZURE_CLIENT_ID"], "ref-client")
        self.assertEqual(env["AZURE_TENANT_ID"], "ref-tenant")

    def test_every_credential_platform_maps_to_a_provider(self):
        self.assertEqual(
            {p.key for p in PLATFORMS} - set(mod.CREDENTIAL_PROVIDER_BY_PLATFORM),
            {"k8s"},
        )

    def test_resolved_region_wins_over_the_inject_region(self):
        injector = self._injector(AWS_ACCESS_KEY_PAYLOAD)
        content = {"aws_region": "eu-west-3"}
        injector.process_message(_data(content, AWS_TECH_CONTRACT, ATTACHMENTS))
        env = self._detonate_env(injector)
        self.assertEqual(env["AWS_REGION"], "us-west-2")
        self.assertEqual(env["AWS_DEFAULT_REGION"], "us-west-2")

    def test_default_region_used_when_the_credential_omits_it(self):
        # The inject region field is hidden with the credential manager: a
        # stale form value is ignored, the Stratus default applies.
        payload = {
            "type": "AWS_ACCESS_KEY",
            "value": {
                "aws_access_key_id": "AKIA-REF",
                "aws_secret_access_key": "ref-aws-secret",
            },
        }
        for content in ({"aws_region": " eu-west-3 "}, {}):
            with self.subTest(content=content):
                injector = self._injector(payload)
                injector.process_message(_data(content, AWS_TECH_CONTRACT, ATTACHMENTS))
                env = self._detonate_env(injector)
                self.assertEqual(env["AWS_REGION"], "us-east-1")
                self.assertEqual(env["AWS_DEFAULT_REGION"], "us-east-1")

    def test_assume_role_region_is_not_overridden(self):
        payload = {
            "type": "AWS_ASSUME_ROLE",
            "value": {
                "aws_role_arn": "arn:aws:iam::123456789012:role/r",
                "aws_source_identity_type": "INSTANCE_DEFAULT",
                "aws_default_region": "us-west-2",
            },
        }
        injector = self._injector(payload)
        injector.process_message(
            _data({"aws_region": "eu-west-3"}, AWS_TECH_CONTRACT, ATTACHMENTS)
        )
        env = self._detonate_env(injector)
        # The credential region wins over the stale inject form value, and
        # matches the one written in the materialized profile.
        self.assertEqual(env["AWS_REGION"], "us-west-2")
        self.assertEqual(env["AWS_DEFAULT_REGION"], "us-west-2")
        self.assertEqual(env["AWS_PROFILE"], "srt-target")

    def test_resolved_subscription_wins_over_the_inject_fields(self):
        injector = self._injector(AZURE_SERVICE_PRINCIPAL_PAYLOAD)
        content = {
            "azure_subscription_id": "form-subscription",
            "azure_client_secret": "legacy-secret",
            "technique_id": "azure.x",
        }
        injector.process_message(_data(content, AZURE_CUSTOM_CONTRACT, ATTACHMENTS))
        env = self._detonate_env(injector)
        self.assertEqual(env["AZURE_SUBSCRIPTION_ID"], "ref-subscription")
        self.assertEqual(env["AZURE_CLIENT_SECRET"], "ref-azure-secret")

    def test_credential_without_subscription_is_reported_on_the_credential(self):
        payload = json.loads(json.dumps(AZURE_SERVICE_PRINCIPAL_PAYLOAD))
        del payload["value"]["azure_subscription_id"]
        injector = self._injector(payload)
        content = {"azure_subscription_id": "form-subscription", "technique_id": "x"}
        injector.process_message(_data(content, AZURE_CUSTOM_CONTRACT, ATTACHMENTS))
        injector.stratus.detonate.assert_not_called()
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertEqual(
            callback["execution_message"],
            f"The credential {REFERENCE} has no Azure Subscription ID. Set it on "
            "the credential, then run it again.",
        )

    def test_credential_manager_without_credential_is_reported(self):
        injector = self._injector()
        injector.process_message(
            _data({"credential_source": "credential_manager"}, AWS_TECH_CONTRACT)
        )
        injector.stratus.detonate.assert_not_called()
        injector.helper.api.inject.resolve_attachment_secret.assert_not_called()
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertEqual(callback["execution_message"], mod.CREDENTIAL_MISSING_MESSAGE)

    def test_manual_credentials_ignore_an_attached_credential(self):
        injector = self._injector()
        content = {"credential_source": "manual", **AWS_CREDS}
        injector.process_message(_data(content, AWS_TECH_CONTRACT, ATTACHMENTS))
        injector.helper.api.inject.resolve_attachment_secret.assert_not_called()
        env = injector.stratus.detonate.call_args.kwargs["env"]
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIA")

    def test_unknown_credential_source_is_reported(self):
        for source in (None, "", "other", ["manual", "credential_manager"]):
            with self.subTest(source=source):
                injector = self._injector()
                content = {"credential_source": source, **AWS_CREDS}
                injector.process_message(_data(content, AWS_TECH_CONTRACT))
                injector.stratus.detonate.assert_not_called()
                callback = self._callback(injector)
                self.assertEqual(
                    callback["execution_message"],
                    mod.CREDENTIAL_SOURCE_INVALID_MESSAGE,
                )

    def test_resolved_project_wins_and_key_file_is_removed_after_success(self):
        seen = {}

        def _detonate(technique_id, env, **kwargs):
            path = env["GOOGLE_APPLICATION_CREDENTIALS"]
            with open(path, "rb") as handle:
                seen["key"] = handle.read()
            seen["path"] = path
            return StratusResult(
                success=True, technique_id=technique_id, status="DETONATED", message=""
            )

        injector = self._injector(GCP_SERVICE_ACCOUNT_PAYLOAD, detonate=_detonate)
        content = {
            "gcp_project_id": "form-project",
            "gcp_service_account_key": '{"type": "legacy"}',
        }
        injector.process_message(_data(content, GCP_TECH_CONTRACT, ATTACHMENTS))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        env = self._detonate_env(injector)
        self.assertEqual(env["GOOGLE_PROJECT"], "ref-project")
        self.assertEqual(seen["key"], GCP_SERVICE_ACCOUNT_KEY)
        self.assertFalse(os.path.exists(seen["path"]))
        self.assertFalse(os.path.exists(os.path.dirname(seen["path"])))

    def test_key_file_is_removed_when_detonate_raises(self):
        injector = self._injector(
            GCP_SERVICE_ACCOUNT_PAYLOAD, detonate=RuntimeError("boom")
        )
        injector.process_message(_data({}, GCP_TECH_CONTRACT, ATTACHMENTS))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        path = self._detonate_env(injector)["GOOGLE_APPLICATION_CREDENTIALS"]
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(os.path.dirname(path)))

    def test_aws_endpoint_url_is_applied_to_the_api_and_sts_calls(self):
        payloads = (
            _with_values(AWS_ACCESS_KEY_PAYLOAD, aws_endpoint_url="http://mock:4566"),
            {
                "type": "AWS_ASSUME_ROLE",
                "value": {
                    "aws_role_arn": "arn:aws:iam::123456789012:role/r",
                    "aws_source_identity_type": "INSTANCE_DEFAULT",
                    "aws_default_region": "us-west-2",
                    "aws_account_id": "123456789012",
                    "aws_endpoint_url": "http://mock:4566",
                },
            },
        )
        for payload in payloads:
            with self.subTest(secret_type=payload["type"]):
                injector = self._injector(payload)
                injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
                self.assertEqual(
                    self._callback(injector)["execution_status"], "SUCCESS"
                )
                env = self._detonate_env(injector)
                self.assertEqual(env["AWS_ENDPOINT_URL"], "http://mock:4566")
                self.assertEqual(env["AWS_ENDPOINT_URL_STS"], "http://mock:4566")

    def test_aws_endpoint_url_is_absent_from_a_credential_without_it(self):
        injector = self._injector(AWS_ACCESS_KEY_PAYLOAD)
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        env = self._detonate_env(injector)
        self.assertNotIn("AWS_ENDPOINT_URL", env)
        self.assertNotIn("AWS_ENDPOINT_URL_STS", env)

    def test_gcp_oauth2_sovereign_values_are_applied(self):
        payload = _with_values(
            GCP_OAUTH2_PAYLOAD,
            gcp_custom_token_uri="http://mock/token",
            gcp_custom_iam_uri="http://mock/iam",
            gcp_custom_oauth_access_token="ref-oauth-token",
        )
        injector = self._injector(payload)
        injector.process_message(_data({}, GCP_TECH_CONTRACT, ATTACHMENTS))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        env = self._detonate_env(injector)
        self.assertEqual(env["GOOGLE_OAUTH2_TOKEN_URI_OVERRIDE"], "http://mock/token")
        self.assertEqual(env["GOOGLE_IAM_CUSTOM_ENDPOINT"], "http://mock/iam")
        self.assertEqual(env["GOOGLE_OAUTH_ACCESS_TOKEN"], "ref-oauth-token")
        self.assertNotIn("GOOGLE_RESOURCE_MANAGER_CUSTOM_ENDPOINT", env)
        self._assert_no_secret_reported(injector)

    def test_gcp_service_account_resource_manager_uri_is_applied(self):
        payload = _with_values(
            GCP_SERVICE_ACCOUNT_PAYLOAD,
            gcp_custom_resource_manager_uri="http://mock/resource-manager",
        )
        injector = self._injector(payload)
        injector.process_message(_data({}, GCP_TECH_CONTRACT, ATTACHMENTS))
        env = self._detonate_env(injector)
        self.assertEqual(
            env["GOOGLE_RESOURCE_MANAGER_CUSTOM_ENDPOINT"],
            "http://mock/resource-manager",
        )
        self.assertNotIn("GOOGLE_OAUTH2_TOKEN_URI_OVERRIDE", env)

    def test_gcp_credentials_without_sovereign_values_keep_the_official_endpoints(self):
        for payload in (GCP_OAUTH2_PAYLOAD, GCP_SERVICE_ACCOUNT_PAYLOAD):
            with self.subTest(secret_type=payload["type"]):
                injector = self._injector(payload)
                injector.process_message(_data({}, GCP_TECH_CONTRACT, ATTACHMENTS))
                env = self._detonate_env(injector)
                self.assertFalse(
                    {
                        "GOOGLE_OAUTH2_TOKEN_URI_OVERRIDE",
                        "GOOGLE_IAM_CUSTOM_ENDPOINT",
                        "GOOGLE_OAUTH_ACCESS_TOKEN",
                        "GOOGLE_RESOURCE_MANAGER_CUSTOM_ENDPOINT",
                    }
                    & set(env)
                )

    def test_azure_authority_host_is_normalized_and_applied(self):
        managed_identity = {
            "type": "AZURE_MANAGED_IDENTITY",
            "value": {
                "azure_environment": "AzureCloud",
                "azure_subscription_id": "ref-subscription",
            },
        }
        for payload in (AZURE_SERVICE_PRINCIPAL_PAYLOAD, managed_identity):
            for uri in ("http://mock:8080", "http://mock:8080/"):
                with self.subTest(secret_type=payload["type"], uri=uri):
                    injector = self._injector(
                        _with_values(payload, azure_authority_host_uri=uri)
                    )
                    injector.process_message(
                        _data(AZURE_CONTENT, AZURE_CUSTOM_CONTRACT, ATTACHMENTS)
                    )
                    self.assertEqual(
                        self._callback(injector)["execution_status"], "SUCCESS"
                    )
                    env = self._detonate_env(injector)
                    self.assertEqual(env["AZURE_AUTHORITY_HOST"], "http://mock:8080/")
                    self.assertEqual(
                        env["AZURE_POD_IDENTITY_AUTHORITY_HOST"], "http://mock:8080/"
                    )
                    self.assertNotIn("REQUESTS_CA_BUNDLE", env)
                    self.assertNotIn("SSL_CERT_FILE", env)

    def test_azure_without_sovereign_values_uses_the_official_authority(self):
        injector = self._injector(AZURE_SERVICE_PRINCIPAL_PAYLOAD)
        injector.process_message(
            _data(AZURE_CONTENT, AZURE_CUSTOM_CONTRACT, ATTACHMENTS)
        )
        env = self._detonate_env(injector)
        self.assertEqual(
            env["AZURE_AUTHORITY_HOST"], "https://login.microsoftonline.com/"
        )
        self.assertNotIn("AZURE_POD_IDENTITY_AUTHORITY_HOST", env)

    def test_azure_certificate_is_trusted_by_python_and_go_then_removed(self):
        seen = {}

        def _detonate(technique_id, env, **kwargs):
            seen["env"] = dict(env)
            with open(env["REQUESTS_CA_BUNDLE"], "rb") as handle:
                seen["content"] = handle.read()
            return StratusResult(
                success=True, technique_id=technique_id, status="DETONATED", message=""
            )

        payload = _with_values(
            AZURE_SERVICE_PRINCIPAL_PAYLOAD,
            azure_requests_certificate=base64.b64encode(
                SOVEREIGN_CA_CERTIFICATE
            ).decode(),
        )
        injector = self._injector(payload, detonate=_detonate)
        injector.process_message(
            _data(AZURE_CONTENT, AZURE_CUSTOM_CONTRACT, ATTACHMENTS)
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        env = seen["env"]
        self.assertEqual(env["REQUESTS_CA_BUNDLE"], env["SSL_CERT_FILE"])
        self.assertEqual(seen["content"], SOVEREIGN_CA_CERTIFICATE)
        self.assertFalse(os.path.exists(env["REQUESTS_CA_BUNDLE"]))
        self.assertFalse(os.path.exists(os.path.dirname(env["REQUESTS_CA_BUNDLE"])))
        self._assert_no_secret_reported(injector)

    def test_azure_certificate_is_removed_when_detonate_raises(self):
        payload = _with_values(
            AZURE_SERVICE_PRINCIPAL_PAYLOAD,
            azure_requests_certificate=base64.b64encode(
                SOVEREIGN_CA_CERTIFICATE
            ).decode(),
        )
        injector = self._injector(payload, detonate=RuntimeError("boom"))
        injector.process_message(
            _data(AZURE_CONTENT, AZURE_CUSTOM_CONTRACT, ATTACHMENTS)
        )
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        path = self._detonate_env(injector)["REQUESTS_CA_BUNDLE"]
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(os.path.dirname(path)))

    def test_invalid_certificate_is_reported_without_its_value(self):
        payload = _with_values(
            AZURE_SERVICE_PRINCIPAL_PAYLOAD, azure_requests_certificate="not base64 !"
        )
        injector = self._injector(payload)
        injector.process_message(
            _data(AZURE_CONTENT, AZURE_CUSTOM_CONTRACT, ATTACHMENTS)
        )
        injector.stratus.detonate.assert_not_called()
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertNotIn("not base64", json.dumps(callback))


class StratusExecutorTest(TestCase):
    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        result = StratusExecutor().detonate("aws.foo", env={"A": "B"})
        self.assertTrue(result.success)
        self.assertEqual(result.outputs, {"technique": "aws.foo"})

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_inherits_the_host_environment_by_default(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with patch.dict(os.environ, {"AWS_PROFILE": "host"}):
            StratusExecutor().detonate("aws.foo", env={"A": "B"})
        run_env = run.call_args.kwargs["env"]
        self.assertEqual(run_env["AWS_PROFILE"], "host")
        self.assertEqual(run_env["A"], "B")

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_can_isolate_host_credentials(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        host = {
            "AWS_PROFILE": "host",
            "AWS_ACCESS_KEY_ID": "host",
            "AZURE_CLIENT_SECRET": "host",
            "ARM_CLIENT_SECRET": "host",
            "GOOGLE_APPLICATION_CREDENTIALS": "host",
            "GCLOUD_PROJECT": "host",
            "CLOUDSDK_CORE_PROJECT": "host",
            "KUBECONFIG": "host",
            "STRATUS_KEEP_ME": "kept",
        }
        with patch.dict(os.environ, host):
            StratusExecutor().detonate(
                "aws.foo",
                env={"AWS_ACCESS_KEY_ID": "resolved"},
                isolate_host_credentials=True,
            )
        run_env = run.call_args.kwargs["env"]
        self.assertEqual(run_env["AWS_ACCESS_KEY_ID"], "resolved")
        self.assertEqual(run_env["STRATUS_KEEP_ME"], "kept")
        self.assertNotIn("host", run_env.values())

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_isolation_drops_host_sovereign_cloud_variables(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        host = {
            "AWS_ENDPOINT_URL": "host",
            "AWS_ENDPOINT_URL_STS": "host",
            "AZURE_AUTHORITY_HOST": "host",
            "AZURE_POD_IDENTITY_AUTHORITY_HOST": "host",
            "GOOGLE_OAUTH2_TOKEN_URI_OVERRIDE": "host",
            "GOOGLE_IAM_CUSTOM_ENDPOINT": "host",
            "GOOGLE_OAUTH_ACCESS_TOKEN": "host",
            "GOOGLE_RESOURCE_MANAGER_CUSTOM_ENDPOINT": "host",
            "REQUESTS_CA_BUNDLE": "/host/ca.pem",
        }
        with patch.dict(os.environ, host):
            StratusExecutor().detonate(
                "aws.foo",
                env={"AWS_ENDPOINT_URL": "resolved"},
                isolate_host_credentials=True,
            )
        run_env = run.call_args.kwargs["env"]
        self.assertEqual(run_env["AWS_ENDPOINT_URL"], "resolved")
        for name in host:
            if name not in ("AWS_ENDPOINT_URL", "REQUESTS_CA_BUNDLE"):
                self.assertNotIn(name, run_env)
        # Not a cloud credential: a trust store of the host (proxy) is kept.
        self.assertEqual(run_env["REQUESTS_CA_BUNDLE"], "/host/ca.pem")

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_appends_cleanup_flag(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        StratusExecutor().detonate("aws.foo", cleanup=True)
        self.assertIn("--cleanup", run.call_args.args[0])

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_failure_truncates_error(self, run):
        run.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
        result = StratusExecutor().detonate("aws.foo", cleanup=False)
        self.assertFalse(result.success)
        self.assertEqual(result.message, "boom")

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_detonate_missing_binary(self, _run):
        self.assertFalse(StratusExecutor().detonate("aws.foo").success)

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="stratus", timeout=900),
    )
    def test_detonate_timeout(self, _run):
        self.assertEqual(StratusExecutor().detonate("aws.foo").status, "TIMEOUT")

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=PermissionError("not executable"),
    )
    def test_detonate_os_error(self, _run):
        self.assertEqual(StratusExecutor().detonate("aws.foo").status, "ERROR")

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_cleanup_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = StratusExecutor().cleanup("aws.foo")
        self.assertTrue(result.success)
        self.assertEqual(result.status, "CLEAN")
        # A successful cleanup always has an actionable message, even when the
        # tool prints nothing.
        self.assertTrue(result.message)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_cleanup_failure_falls_back_to_message(self, run):
        run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = StratusExecutor().cleanup("aws.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "ERROR")
        self.assertTrue(result.message)

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="stratus", timeout=900),
    )
    def test_cleanup_timeout(self, _run):
        self.assertEqual(StratusExecutor().cleanup("aws.foo").status, "TIMEOUT")

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_cleanup_missing_binary(self, _run):
        result = StratusExecutor().cleanup("aws.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "ERROR")

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=PermissionError("not executable"),
    )
    def test_cleanup_os_error(self, _run):
        result = StratusExecutor().cleanup("aws.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "ERROR")


def _stratus_output(*lines):
    return "".join(f"2026/10/13 12:00:00 {line}\n" for line in lines)


class ParseAuthenticationTest(TestCase):
    def test_passed_when_stratus_exits_successfully(self):
        output = _stratus_output("Checking your authentication against AWS")
        self.assertEqual(parse_authentication(output, 0), ("AWS", AUTH_PASSED, None))

    def test_passed_when_stratus_goes_on_then_fails_later(self):
        output = _stratus_output(
            "Checking your authentication against AWS",
            "Warming up aws.persistence.iam-backdoor-user",
            "Error: terraform apply failed",
        )
        self.assertEqual(parse_authentication(output, 1), ("AWS", AUTH_PASSED, None))

    def test_failed_with_the_stratus_failure_message(self):
        for platform, failure in (
            ("AWS", "you are not authenticated against AWS, *or* you have not set "),
            ("azure", "AZURE_SUBSCRIPTION_ID is not set."),
            ("GCP", "you are not authenticated against GCP, or you have not set "),
            ("kubernetes", "You do not have a kubeconfig set up, or you do not"),
            ("EKS", "unable to load AWS configuration, boom"),
        ):
            with self.subTest(platform=platform):
                output = _stratus_output(
                    f"Checking your authentication against {platform}", failure
                )
                self.assertEqual(
                    parse_authentication(output, 1),
                    (platform, AUTH_FAILED, failure.strip()),
                )

    def test_failed_when_stratus_stops_right_after_the_check(self):
        output = _stratus_output("Checking your authentication against GCP")
        self.assertEqual(parse_authentication(output, 1), ("GCP", AUTH_FAILED, None))

    def test_no_check_reached(self):
        for output, returncode in (("", 0), ("", 1), ("unknown technique\n", 1)):
            with self.subTest(output=output):
                self.assertEqual(
                    parse_authentication(output, returncode), (None, None, None)
                )

    def test_line_without_go_log_prefix_is_accepted(self):
        output = "Checking your authentication against entra-id\nok\n"
        self.assertEqual(
            parse_authentication(output, 0), ("entra-id", AUTH_PASSED, None)
        )


class StratusExecutorAuthenticationTest(TestCase):
    @patch("injector_common.stratus_executor.subprocess.run")
    def test_success_reports_the_passed_check(self, run):
        run.return_value = MagicMock(
            returncode=0,
            stdout=_stratus_output("Checking your authentication against AWS"),
            stderr="",
        )
        result = StratusExecutor().detonate("aws.foo")
        self.assertEqual(result.auth_platform, "AWS")
        self.assertEqual(result.auth_status, AUTH_PASSED)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_authentication_failure_has_a_clean_message(self, run):
        run.return_value = MagicMock(
            returncode=1,
            stdout=_stratus_output(
                "Checking your authentication against AWS",
                "you are not authenticated against AWS, *or* you have not set your "
                "region.",
                "",
                "Troubleshooting:",
            ),
            stderr="",
        )
        result = StratusExecutor().detonate("aws.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.auth_status, AUTH_FAILED)
        self.assertEqual(
            result.message,
            "Authentication against AWS failed: you are not authenticated against "
            "AWS, *or* you have not set your region.",
        )

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_other_failure_reports_the_tail_of_the_output(self, run):
        run.return_value = MagicMock(
            returncode=1,
            stdout=_stratus_output(
                "Checking your authentication against AWS", "x" * 600, "real error"
            ),
            stderr="",
        )
        result = StratusExecutor().detonate("aws.foo")
        self.assertEqual(result.auth_status, AUTH_PASSED)
        self.assertTrue(result.message.endswith("real error"))
        self.assertLessEqual(len(result.message), 500)


class ProcessMessageAuthenticationTest(TestCase):
    def _injector(self, result, payload=AWS_ACCESS_KEY_PAYLOAD):
        injector = make_injector()
        injector.helper.api.inject.resolve_attachment_secret.return_value = payload
        injector.stratus.detonate.return_value = result
        return injector

    @staticmethod
    def _result(platform, status=AUTH_PASSED, success=True, message="Detonated t"):
        return StratusResult(
            success=success,
            technique_id="t",
            status="DETONATED" if success else "ERROR",
            message=message,
            auth_platform=platform,
            auth_status=status,
        )

    def _callbacks(self, injector):
        return [
            call.kwargs["data"]
            for call in injector.helper.api.inject.execution_callback.call_args_list
        ]

    def _info_logs(self, injector):
        return [
            call.args[0] for call in injector.helper.injector_logger.info.call_args_list
        ]

    def test_passed_check_is_traced_before_completion(self):
        injector = self._injector(self._result("AWS"))
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        auth, complete = self._callbacks(injector)
        self.assertEqual(auth["execution_action"], "prerequisite_check")
        self.assertEqual(auth["execution_status"], "INFO")
        self.assertEqual(
            auth["execution_message"],
            f"Authenticated against AWS with credential reference {REFERENCE} "
            "(AWS_ACCESS_KEY)",
        )
        self.assertEqual(complete["execution_action"], "complete")
        self.assertEqual(complete["execution_status"], "SUCCESS")
        self.assertTrue(
            any(
                log.startswith("Authenticated against AWS")
                for log in self._info_logs(injector)
            )
        )
        for data in self._callbacks(injector):
            for secret in SECRET_VALUES:
                self.assertNotIn(secret, json.dumps(data))

    def test_legacy_path_names_the_inject_fields(self):
        injector = self._injector(self._result("AWS"))
        injector.process_message(_data(AWS_CREDS, AWS_TECH_CONTRACT))
        auth = self._callbacks(injector)[0]
        self.assertEqual(
            auth["execution_message"],
            "Authenticated against AWS with the inject credential fields",
        )
        injector.helper.api.inject.resolve_attachment_secret.assert_not_called()

    def test_azure_and_gcp_checks_do_not_claim_a_verified_credential(self):
        for platform, label, contract, payload in (
            ("azure", "Azure", AZURE_CUSTOM_CONTRACT, AZURE_SERVICE_PRINCIPAL_PAYLOAD),
            ("GCP", "Google Cloud", GCP_TECH_CONTRACT, GCP_SERVICE_ACCOUNT_PAYLOAD),
        ):
            with self.subTest(platform=platform):
                injector = self._injector(self._result(platform), payload)
                content = {"technique_id": "x"}
                injector.process_message(_data(content, contract, ATTACHMENTS))
                message = self._callbacks(injector)[0]["execution_message"]
                self.assertNotIn("Authenticated against", message)
                self.assertIn(f"Stratus does not contact {label}", message)

    def test_failed_check_sends_no_auth_trace_and_logs_an_error(self):
        result = self._result(
            "AWS",
            status=AUTH_FAILED,
            success=False,
            message="Authentication against AWS failed: you are not authenticated",
        )
        injector = self._injector(result)
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        (complete,) = self._callbacks(injector)
        self.assertEqual(complete["execution_status"], "ERROR")
        self.assertEqual(complete["execution_message"], result.message)
        injector.helper.injector_logger.error.assert_called_once()

    def test_no_check_reached_sends_no_auth_trace(self):
        injector = self._injector(self._result(None, status=None))
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        self.assertEqual(len(self._callbacks(injector)), 1)

    def test_credential_resolution_is_logged_without_secret(self):
        injector = self._injector(self._result("AWS"))
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        resolved = [log for log in self._info_logs(injector) if "resolved" in log]
        self.assertEqual(
            resolved,
            [
                f"Credential reference {REFERENCE} resolved (AWS_ACCESS_KEY) for inject i1"
            ],
        )

    def test_resolution_failure_is_logged(self):
        injector = make_injector()
        injector.helper.api.inject.resolve_attachment_secret.side_effect = (
            CredentialResolutionError(
                CredentialErrorCode.CREDENTIAL_INACTIVE, reference=REFERENCE
            )
        )
        injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        logged = injector.helper.injector_logger.error.call_args.args[0]
        self.assertIn("CREDENTIAL_INACTIVE", logged)
        self.assertIn(REFERENCE, logged)

    def test_cleanup_failure_after_detonation_keeps_the_result(self):
        injector = self._injector(self._result("AWS"))
        with patch.object(
            mod.OpenAEVStratus,
            "_detonate_with_credential",
            return_value=(self._result("AWS"), True),
        ):
            injector.process_message(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS))
        auth, cleanup, complete = self._callbacks(injector)
        self.assertEqual(cleanup["execution_action"], "cleanup_execution")
        self.assertEqual(cleanup["execution_status"], "WARNING")
        self.assertEqual(complete["execution_status"], "SUCCESS")

    def test_detonate_with_credential_reports_a_cleanup_failure(self):
        injector = self._injector(self._result("AWS"))
        credential = mod.resolve_credential_attachment(
            injector.helper.api,
            "i1",
            mod.get_credential_attachment(_data({}, AWS_TECH_CONTRACT, ATTACHMENTS)),
            "aws",
        )
        with patch(
            "pyoaev.credential.materializer._Workspace.cleanup",
            side_effect=CredentialCleanupError(),
        ):
            result, cleanup_failed = injector._detonate_with_credential(
                "t", PLATFORMS_BY_KEY["aws"], REFERENCE, credential
            )
        self.assertTrue(result.success)
        self.assertTrue(cleanup_failed)
