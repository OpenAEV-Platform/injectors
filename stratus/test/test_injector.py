import json
import os
import subprocess
import tempfile
from unittest import TestCase
from unittest.mock import MagicMock, patch

from injector_common.stratus_executor import StratusExecutor, StratusResult

import stratus.openaev_stratus as mod
from stratus.contracts import CONTRACT_REGISTRY, technique_contract_id
from stratus.contracts.platforms import (
    AWS_CUSTOM_CONTRACT,
    GCP_CUSTOM_CONTRACT,
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


def _data(content, contract_id):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content,
        }
    }


AWS_CREDS = {"aws_access_key_id": "AKIA", "aws_secret_access_key": "secret"}


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


class StratusExecutorTest(TestCase):
    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        result = StratusExecutor().detonate("aws.foo", env={"A": "B"})
        self.assertTrue(result.success)
        self.assertEqual(result.outputs, {"technique": "aws.foo"})

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
