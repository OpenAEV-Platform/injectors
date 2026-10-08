import base64
import json
import os
import subprocess
import tempfile
from unittest import TestCase
from unittest.mock import MagicMock, patch

from pyoaev.credential import CredentialErrorCode, CredentialResolutionError

import stratus.openaev_stratus as mod
from injector_common.stratus_executor import StratusExecutor, StratusResult
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
SECRET_VALUES = (
    "AKIA-REF",
    "ref-aws-secret",
    "ref-azure-secret",
    "ref-gcp-key",
    AUTHORISATION_CODE,
)


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

    def test_inject_region_used_when_the_credential_omits_it(self):
        payload = {
            "type": "AWS_ACCESS_KEY",
            "value": {
                "aws_access_key_id": "AKIA-REF",
                "aws_secret_access_key": "ref-aws-secret",
            },
        }
        for content, expected in (
            ({"aws_region": " eu-west-3 "}, "eu-west-3"),
            ({}, "us-east-1"),
        ):
            with self.subTest(content=content):
                injector = self._injector(payload)
                injector.process_message(_data(content, AWS_TECH_CONTRACT, ATTACHMENTS))
                env = self._detonate_env(injector)
                self.assertEqual(env["AWS_REGION"], expected)
                self.assertEqual(env["AWS_DEFAULT_REGION"], expected)

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
        # The region lives in the materialized profile: an AWS_REGION variable
        # would take precedence over it.
        self.assertNotIn("AWS_REGION", env)
        self.assertEqual(env["AWS_PROFILE"], "srt-target")

    def test_inject_subscription_used_when_the_credential_omits_it(self):
        injector = self._injector(AZURE_SERVICE_PRINCIPAL_PAYLOAD)
        content = {
            "azure_subscription_id": "form-subscription",
            "azure_client_secret": "legacy-secret",
            "technique_id": "azure.x",
        }
        injector.process_message(_data(content, AZURE_CUSTOM_CONTRACT, ATTACHMENTS))
        env = self._detonate_env(injector)
        self.assertEqual(env["AZURE_SUBSCRIPTION_ID"], "form-subscription")
        self.assertEqual(env["AZURE_CLIENT_SECRET"], "ref-azure-secret")

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
