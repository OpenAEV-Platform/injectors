"""Tests for the Netexec signature lifecycle integration.

Gherkin: test/signatures/netexec_signature_lifecycle.feature

These tests verify that OpenAEVNetExecInjector correctly integrates
SignatureManager to compile and send expectation signatures per target.
pyoaev is mocked by test/conftest.py — SignatureManager and build_network_configs
are both MagicMocks in this context, which lets us assert on their call signatures.
"""

from unittest import TestCase
from unittest.mock import MagicMock, patch

# Import the production module to register it in sys.modules BEFORE any patch() call,
# so that patch("netexec.openaev_netexec.SignatureManager") can resolve successfully.
import netexec.openaev_netexec  # noqa: F401
from netexec.helpers.signature_helper import NETEXEC_SIGNATURE_TYPES


def _build_data(
    targets: list[str],
    inject_id: str = "inject-001",
    contract_id: str = "netexec_smb",
    ip_to_asset_id_map: dict | None = None,
) -> tuple[dict, dict]:
    """Build a minimal inject data dict + ip_to_asset_id_map for tests."""
    asset_map = ip_to_asset_id_map or {t: f"asset-{i}" for i, t in enumerate(targets)}
    data = {
        "injection": {
            "inject_id": inject_id,
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": {
                "target_selector": "manual",
                "target_property_selector": "automatic",
                "targets": ", ".join(targets),
            },
        },
        "assetGroups": [],
        "assets": [],
    }
    return data, asset_map


class SignatureLifecycleTest(TestCase):
    """
    Feature: Netexec signature lifecycle

    Verifies that OpenAEVNetExecInjector compiles pre/post-execution signatures
    and sends them via SignatureManager for every inject execution.
    """

    def setUp(self):
        self.sm_patcher = patch(
            "netexec.openaev_netexec.SignatureManager", autospec=False
        )
        self.MockSignatureManager = self.sm_patcher.start()
        self.mock_sm = self.MockSignatureManager.return_value

        # compile_pre returns a list matching the target count
        self.mock_sm.compile_pre_execution_signatures.side_effect = lambda **kw: (
            kw["config"] if isinstance(kw["config"], list) else [kw["config"]]
        )
        # compile_post returns whatever pre returned (simple passthrough)
        self.mock_sm.compile_post_execution_signatures.side_effect = lambda pre, _: pre
        self.mock_sm.build_payload.return_value = {"phase": "execution_complete"}

    def tearDown(self):
        self.sm_patcher.stop()

    def _make_injector(self):
        """Build an OpenAEVNetExecInjector with fully mocked infrastructure."""
        with patch("netexec.openaev_netexec.ConfigLoader"), patch(
            "netexec.openaev_netexec.OpenAEVConfigHelper"
        ), patch("netexec.openaev_netexec.OpenAEVInjectorHelper"), patch(
            "netexec.openaev_netexec.execute_netexec",
            return_value=("output", "", 0),
        ), patch(
            "netexec.openaev_netexec.intercept_dump_argument"
        ):
            from netexec.openaev_netexec import OpenAEVNetExecInjector

            injector = OpenAEVNetExecInjector.__new__(OpenAEVNetExecInjector)
            injector.helper = MagicMock()
            injector.parser = MagicMock()
            injector.parser.parse.return_value = {"outputs": {}}
            injector.config = MagicMock()
            return injector

    def _run_process_message(self, injector, data: dict, returncode: int = 0):
        """Patch execute_netexec and run process_message."""
        with patch(
            "netexec.openaev_netexec.execute_netexec",
            return_value=("stdout", "stderr", returncode),
        ):
            injector.process_message(data)

    # -- Scenario: Pre-execution signatures are compiled before running NetExec --

    def test_compile_pre_called_with_network_config_for_single_target(self):
        """
        Given an inject with a single IPv4 target "10.0.0.1"
        When process_message is called
        Then compile_pre_execution_signatures is called with a NetworkInjectorConfig for "10.0.0.1"
        """
        injector = self._make_injector()
        data, _ = _build_data(["10.0.0.1"])

        with patch("netexec.openaev_netexec.build_network_configs") as mock_build:
            mock_build.return_value = ["cfg-10.0.0.1"]
            self._run_process_message(injector, data)

        mock_build.assert_called_once_with(["10.0.0.1"])
        self.mock_sm.compile_pre_execution_signatures.assert_called_once_with(
            config=["cfg-10.0.0.1"]
        )

    # -- Scenario: Post-execution signatures reflect a successful run --

    def test_compile_post_called_with_success_tool_output(self):
        """
        Given an inject with a single IPv4 target "10.0.0.1"
        And NetExec exits with return code 0
        When process_message is called
        Then compile_post_execution_signatures is called with a success tool_output
        """
        injector = self._make_injector()
        data, _ = _build_data(["10.0.0.1"])
        self._run_process_message(injector, data, returncode=0)

        self.mock_sm.compile_post_execution_signatures.assert_called_once()
        _, tool_output = self.mock_sm.compile_post_execution_signatures.call_args[0]
        # A successful run has no error_info with non-zero exit code
        error_info = tool_output.get("error_info") or {}
        exit_code = error_info.get("exit_code", 0)
        self.assertEqual(exit_code, 0)

    # -- Scenario: Post-execution signatures reflect a failed run --

    def test_compile_post_called_with_failure_tool_output(self):
        """
        Given an inject with a single IPv4 target "10.0.0.1"
        And NetExec exits with return code 1
        When process_message is called
        Then compile_post_execution_signatures is called with a non-zero exit code
        """
        injector = self._make_injector()
        data, _ = _build_data(["10.0.0.1"])
        self._run_process_message(injector, data, returncode=1)

        self.mock_sm.compile_post_execution_signatures.assert_called_once()
        _, tool_output = self.mock_sm.compile_post_execution_signatures.call_args[0]
        error_info = tool_output.get("error_info") or {}
        exit_code = error_info.get("exit_code", 0)
        self.assertNotEqual(exit_code, 0)

    # -- Scenario: Signatures are sent after execution (success or failure) --

    def test_send_signatures_called_with_inject_id_and_phase(self):
        """
        Given an inject with a single IPv4 target "10.0.0.1"
        And NetExec exits with return code 0
        When process_message is called
        Then send_signatures is called with the inject id and phase "execution_complete"
        """
        injector = self._make_injector()
        data, _ = _build_data(["10.0.0.1"], inject_id="inject-xyz")
        self._run_process_message(injector, data, returncode=0)

        self.mock_sm.send_signatures.assert_called_once()
        kwargs = self.mock_sm.send_signatures.call_args[1]
        self.assertEqual(kwargs["inject_id"], "inject-xyz")
        self.assertEqual(kwargs["phase"], "execution_complete")

    def test_send_signatures_called_on_failed_execution(self):
        """
        Given an inject with a single IPv4 target "10.0.0.1"
        And NetExec exits with return code 1
        When process_message is called
        Then send_signatures is still called with the inject id and phase "execution_complete"
        """
        injector = self._make_injector()
        data, _ = _build_data(["10.0.0.1"], inject_id="inject-fail")
        self._run_process_message(injector, data, returncode=1)

        self.mock_sm.send_signatures.assert_called_once()
        kwargs = self.mock_sm.send_signatures.call_args[1]
        self.assertEqual(kwargs["inject_id"], "inject-fail")
        self.assertEqual(kwargs["phase"], "execution_complete")

    # -- Scenario: Each target gets its own signature config --

    def test_compile_pre_called_with_two_configs_for_two_targets(self):
        """
        Given an inject with targets "10.0.0.1" and "192.168.1.1"
        When process_message is called
        Then compile_pre_execution_signatures is called with 2 NetworkInjectorConfig entries
        """
        injector = self._make_injector()
        data, _ = _build_data(["10.0.0.1", "192.168.1.1"])

        with patch("netexec.openaev_netexec.build_network_configs") as mock_build:
            mock_build.return_value = ["cfg-1", "cfg-2"]
            self._run_process_message(injector, data)

        mock_build.assert_called_once_with(["10.0.0.1", "192.168.1.1"])
        self.mock_sm.compile_pre_execution_signatures.assert_called_once_with(
            config=["cfg-1", "cfg-2"]
        )

    # -- Scenario: Asset metadata is mapped to signature target --

    def test_build_payload_includes_asset_id_from_map(self):
        """
        Given an inject with target "10.0.0.1" mapped to asset id "asset-abc-123"
        When process_message is called
        Then build_payload is called with target meta containing asset "asset-abc-123"
        """
        injector = self._make_injector()
        data, asset_map = _build_data(
            ["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "asset-abc-123"}
        )
        # Patch Targets.extract_targets to use our asset map
        from injector_common.targets import TargetExtractionResult

        with patch(
            "netexec.openaev_netexec.Targets.extract_targets",
            return_value=TargetExtractionResult(
                targets=["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "asset-abc-123"}
            ),
        ), patch(
            "netexec.openaev_netexec.execute_netexec",
            return_value=("stdout", "", 0),
        ):
            injector.process_message(data)

        self.mock_sm.build_payload.assert_called_once()
        kwargs = self.mock_sm.build_payload.call_args[1]
        targets_meta = kwargs["targets_meta"]
        self.assertIsInstance(targets_meta, list)
        self.assertEqual(targets_meta[0].get("asset"), "asset-abc-123")


class NetexecSignatureTypesTest(TestCase):
    """
    Scenario Outline: Netexec signature types are always network-category types
    """

    def test_netexec_signature_types_contains_source_ipv4_address(self):
        self.assertIn("source_ipv4_address", NETEXEC_SIGNATURE_TYPES)

    def test_netexec_signature_types_contains_target_ipv4_address(self):
        self.assertIn("target_ipv4_address", NETEXEC_SIGNATURE_TYPES)

    def test_netexec_signature_types_contains_target_ipv6_address(self):
        self.assertIn("target_ipv6_address", NETEXEC_SIGNATURE_TYPES)

    def test_netexec_signature_types_contains_target_hostname_address(self):
        self.assertIn("target_hostname_address", NETEXEC_SIGNATURE_TYPES)

    def test_netexec_signature_types_contains_start_date(self):
        self.assertIn("start_date", NETEXEC_SIGNATURE_TYPES)

    def test_netexec_signature_types_contains_end_date(self):
        self.assertIn("end_date", NETEXEC_SIGNATURE_TYPES)
