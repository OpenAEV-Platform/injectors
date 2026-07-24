"""Unit tests for EmailSignatureService."""

from unittest.mock import Mock

from email_smtp.services.signature_service import EmailSignatureService
from pyoaev.signatures import ExtraSignatureData
from pyoaev.signatures.models import ExecutionDetails, ExecutionSignature

from injector_common.targets import TargetMeta


class TestBuildExecutionDetails:
    def test_returns_execution_details(self):
        details = EmailSignatureService.build_execution_details()
        assert isinstance(details, ExecutionDetails)
        assert details.start_time is not None
        assert details.end_time is None

    def test_returns_fresh_instance_each_call(self):
        d1 = EmailSignatureService.build_execution_details()
        d2 = EmailSignatureService.build_execution_details()
        assert d1 is not d2


class TestBuildExecutionSignature:
    def test_returns_execution_signature_with_start_time(self):
        sig = EmailSignatureService.build_execution_signature()
        assert isinstance(sig, ExecutionSignature)
        assert sig.start_time is not None
        assert sig.end_time is None

    def test_has_no_network_or_cloud_fields(self):
        sig = EmailSignatureService.build_execution_signature()
        assert sig.source_ipv4 is None
        assert sig.target_ipv4 is None
        assert sig.cloud_provider is None


class TestPostExecutionUpdates:
    def test_success_passes_no_error_info(self):
        mock_sm = Mock()
        service = EmailSignatureService(mock_sm)
        details = Mock()
        sig = Mock()

        service.post_execution_updates(details, sig, success=True)

        mock_sm.post_execution_updates.assert_called_once()
        tool_output = mock_sm.post_execution_updates.call_args[0][2]
        assert tool_output["error_info"] is None

    def test_failure_passes_exit_code_1(self):
        mock_sm = Mock()
        service = EmailSignatureService(mock_sm)
        details = Mock()
        sig = Mock()

        service.post_execution_updates(details, sig, success=False)

        tool_output = mock_sm.post_execution_updates.call_args[0][2]
        assert tool_output["error_info"]["exit_code"] == 1


class TestSendSignatures:
    def test_builds_and_sends_payload(self):
        mock_sm = Mock()
        mock_sm.build_payload.return_value = {"targets": []}
        service = EmailSignatureService(mock_sm)
        details = Mock()
        sig = Mock()

        service.send_signatures("inject-1", details, sig)

        mock_sm.build_payload.assert_called_once()
        build_kwargs = mock_sm.build_payload.call_args.kwargs
        assert build_kwargs["expectation_types"] == ["DETECTION"]
        assert isinstance(build_kwargs["extra_signatures"], ExtraSignatureData)
        assert build_kwargs["extra_signatures"].detection == {}

        mock_sm.send_signatures.assert_called_once_with(
            "inject-1", details, signatures={"targets": []}
        )

    def test_uses_empty_target_meta(self):
        mock_sm = Mock()
        mock_sm.build_payload.return_value = {"targets": []}
        service = EmailSignatureService(mock_sm)

        service.send_signatures("inject-1", Mock(), Mock())

        targets_meta = mock_sm.build_payload.call_args.kwargs["targets_meta"]
        assert isinstance(targets_meta, list)
        assert len(targets_meta) == 1
        assert isinstance(targets_meta[0], TargetMeta)
        assert targets_meta[0].agent_id is None
        assert targets_meta[0].asset_id is None
        assert targets_meta[0].asset_group_id is None
