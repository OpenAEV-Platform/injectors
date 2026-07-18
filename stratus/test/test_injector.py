import json
import os
import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch

from injector_common.stratus_executor import StratusExecutor, StratusResult

import stratus.openaev_stratus as mod
from stratus.contracts.platforms import (
    AWS_CONTRACT,
    EKS_CONTRACT,
    GCP_CONTRACT,
    K8S_CONTRACT,
    PLATFORMS_BY_CONTRACT,
)

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "stratus--test",
}


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


def _data(content, contract_id=AWS_CONTRACT):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content,
        }
    }


class ResolvePlatformTest(TestCase):
    def test_resolves_each_known_contract(self):
        for contract_id, platform in PLATFORMS_BY_CONTRACT.items():
            resolved = mod.OpenAEVStratus._resolve_platform(_data({}, contract_id))
            self.assertIs(resolved, platform)

    def test_unknown_contract_raises(self):
        with self.assertRaises(ValueError):
            mod.OpenAEVStratus._resolve_platform(_data({}, "not-a-contract"))


class ResolveTechniqueTest(TestCase):
    def test_custom_override_wins(self):
        technique = mod.OpenAEVStratus._resolve_technique(
            {
                "technique_id": ["aws.persistence.iam-backdoor-user"],
                "custom_technique_id": "aws.x",
            }
        )
        self.assertEqual(technique, "aws.x")

    def test_whitespace_custom_falls_back_to_selection(self):
        technique = mod.OpenAEVStratus._resolve_technique(
            {
                "technique_id": ["aws.persistence.iam-backdoor-user"],
                "custom_technique_id": "   ",
            }
        )
        self.assertEqual(technique, "aws.persistence.iam-backdoor-user")

    def test_selection_list_is_unwrapped(self):
        technique = mod.OpenAEVStratus._resolve_technique(
            {"technique_id": ["aws.discovery.ses-enumerate"]}
        )
        self.assertEqual(technique, "aws.discovery.ses-enumerate")

    def test_empty_selection_returns_none(self):
        self.assertIsNone(mod.OpenAEVStratus._resolve_technique({"technique_id": []}))
        self.assertIsNone(mod.OpenAEVStratus._resolve_technique({}))


class BuildEnvTest(TestCase):
    def _platform(self, contract_id):
        return PLATFORMS_BY_CONTRACT[contract_id]

    def test_aws_direct_env_and_region_default(self):
        env, temp_files = mod.OpenAEVStratus._build_env(
            self._platform(AWS_CONTRACT),
            {"aws_access_key_id": "AKIA", "aws_secret_access_key": "secret"},
        )
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIA")
        self.assertEqual(env["AWS_SECRET_ACCESS_KEY"], "secret")
        # Region falls back to the default and is mirrored onto both env vars.
        self.assertEqual(env["AWS_REGION"], "us-east-1")
        self.assertEqual(env["AWS_DEFAULT_REGION"], "us-east-1")
        # Optional session token is omitted when not supplied.
        self.assertNotIn("AWS_SESSION_TOKEN", env)
        self.assertEqual(temp_files, [])

    def test_aws_optional_fields_are_used_when_present(self):
        env, _ = mod.OpenAEVStratus._build_env(
            self._platform(AWS_CONTRACT),
            {
                "aws_access_key_id": "AKIA",
                "aws_secret_access_key": "secret",
                "aws_session_token": "tok",
                "aws_region": "eu-west-1",
            },
        )
        self.assertEqual(env["AWS_SESSION_TOKEN"], "tok")
        self.assertEqual(env["AWS_REGION"], "eu-west-1")

    def test_missing_mandatory_field_raises(self):
        with self.assertRaises(ValueError):
            mod.OpenAEVStratus._build_env(
                self._platform(AWS_CONTRACT), {"aws_access_key_id": "AKIA"}
            )

    def test_whitespace_mandatory_field_raises(self):
        with self.assertRaises(ValueError):
            mod.OpenAEVStratus._build_env(
                self._platform(AWS_CONTRACT),
                {"aws_access_key_id": "AKIA", "aws_secret_access_key": "  \n"},
            )

    def test_gcp_key_materialized_to_temp_file_with_mode(self):
        env, temp_files = mod.OpenAEVStratus._build_env(
            self._platform(GCP_CONTRACT),
            {"gcp_project_id": "proj", "gcp_service_account_key": '{"type":"x"}'},
        )
        self.assertEqual(env["GOOGLE_PROJECT"], "proj")
        self.assertEqual(env["CLOUDSDK_CORE_PROJECT"], "proj")
        path = env["GOOGLE_APPLICATION_CREDENTIALS"]
        try:
            self.assertTrue(os.path.exists(path))
            self.assertTrue(path.endswith(".json"))
            with open(path) as handle:
                self.assertEqual(handle.read(), '{"type":"x"}')
            self.assertEqual(temp_files, [path])
        finally:
            os.remove(path)

    def test_kubeconfig_materialized_to_temp_file(self):
        env, temp_files = mod.OpenAEVStratus._build_env(
            self._platform(K8S_CONTRACT), {"kubeconfig": "apiVersion: v1"}
        )
        path = env["KUBECONFIG"]
        try:
            self.assertTrue(path.endswith(".yaml"))
            self.assertEqual(temp_files, [path])
        finally:
            os.remove(path)

    def test_eks_reuses_aws_credentials(self):
        env, _ = mod.OpenAEVStratus._build_env(
            self._platform(EKS_CONTRACT),
            {"aws_access_key_id": "AKIA", "aws_secret_access_key": "secret"},
        )
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIA")


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_success_reports_structured_output(self):
        injector = make_injector()
        injector.stratus.detonate.return_value = StratusResult(
            success=True,
            technique_id="aws.discovery.ses-enumerate",
            status="DETONATED",
            message="done",
            outputs={"technique": "aws.discovery.ses-enumerate"},
        )
        injector.process_message(
            _data(
                {
                    "technique_id": ["aws.discovery.ses-enumerate"],
                    "aws_access_key_id": "AKIA",
                    "aws_secret_access_key": "secret",
                }
            )
        )
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "SUCCESS")
        self.assertEqual(
            json.loads(callback["execution_output_structured"]),
            {"technique": "aws.discovery.ses-enumerate"},
        )

    def test_gcp_key_removed_after_success(self):
        injector = make_injector()
        injector.stratus.detonate.return_value = StratusResult(
            success=True, technique_id="t", status="DETONATED", message="ok"
        )
        injector.process_message(
            _data(
                {
                    "technique_id": ["gcp.exfiltration.share-compute-disk"],
                    "gcp_project_id": "proj",
                    "gcp_service_account_key": '{"type":"service_account"}',
                },
                contract_id=GCP_CONTRACT,
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        env = injector.stratus.detonate.call_args.kwargs["env"]
        self.assertFalse(os.path.exists(env["GOOGLE_APPLICATION_CREDENTIALS"]))

    def test_temp_file_removed_when_detonate_raises(self):
        injector = make_injector()
        injector.stratus.detonate.side_effect = RuntimeError("boom")
        injector.process_message(
            _data(
                {
                    "technique_id": ["gcp.exfiltration.share-compute-disk"],
                    "gcp_project_id": "proj",
                    "gcp_service_account_key": '{"type":"service_account"}',
                },
                contract_id=GCP_CONTRACT,
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        env = injector.stratus.detonate.call_args.kwargs["env"]
        self.assertFalse(os.path.exists(env["GOOGLE_APPLICATION_CREDENTIALS"]))

    def test_missing_technique_reports_error(self):
        injector = make_injector()
        injector.process_message(
            _data({"aws_access_key_id": "AKIA", "aws_secret_access_key": "secret"})
        )
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        injector.stratus.detonate.assert_not_called()

    def test_missing_credential_reports_error(self):
        injector = make_injector()
        injector.process_message(
            _data(
                {
                    "technique_id": ["aws.discovery.ses-enumerate"],
                    "aws_access_key_id": "AKIA",
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        injector.stratus.detonate.assert_not_called()

    def test_unknown_contract_reports_error(self):
        injector = make_injector()
        injector.process_message(_data({}, contract_id="nope"))
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
        # Output is a single value to match the contract (isMultiple=False).
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
        result = StratusExecutor().detonate("aws.foo")
        self.assertEqual(result.status, "TIMEOUT")

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=PermissionError("not executable"),
    )
    def test_detonate_os_error(self, _run):
        result = StratusExecutor().detonate("aws.foo")
        self.assertEqual(result.status, "ERROR")

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_cleanup_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        self.assertTrue(StratusExecutor().cleanup("aws.foo").success)

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=PermissionError("not executable"),
    )
    def test_cleanup_os_error(self, _run):
        result = StratusExecutor().cleanup("aws.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "ERROR")
