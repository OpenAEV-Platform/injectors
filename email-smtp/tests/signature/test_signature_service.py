"""Unit tests for EmailSignatureService."""

import hashlib
from unittest.mock import Mock

from email_smtp.services.signature_service import (
    RECIPIENT_EMAIL,
    REPLY_TO_EMAIL,
    SENDER_EMAIL,
    URL_HASH,
    EmailSignatureService,
)
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


class TestBuildEmailSignatures:
    def test_from_field_generates_sender_email(self):
        payload = {"from": "sender@example.test", "to": ""}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[SENDER_EMAIL] == ["sender@example.test"]

    def test_mail_from_generates_sender_email(self):
        payload = {"from": "", "mail_from": "bounce@example.test", "to": ""}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[SENDER_EMAIL] == ["bounce@example.test"]

    def test_mail_from_different_from_both_included(self):
        payload = {
            "from": "sender@example.test",
            "mail_from": "bounce@example.test",
            "to": "",
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[SENDER_EMAIL] == [
            "sender@example.test",
            "bounce@example.test",
        ]

    def test_mail_from_same_as_from_not_duplicated(self):
        payload = {
            "from": "sender@example.test",
            "mail_from": "sender@example.test",
            "to": "",
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[SENDER_EMAIL] == ["sender@example.test"]

    def test_to_field_generates_recipient_email(self):
        payload = {"from": "", "to": "victim@example.test"}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[RECIPIENT_EMAIL] == ["victim@example.test"]

    def test_cc_generates_recipient_email(self):
        payload = {"from": "", "to": "", "cc": ["copy@example.test"]}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[RECIPIENT_EMAIL] == ["copy@example.test"]

    def test_bcc_generates_recipient_email(self):
        payload = {"from": "", "to": "", "bcc": ["hidden@example.test"]}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[RECIPIENT_EMAIL] == ["hidden@example.test"]

    def test_to_cc_bcc_all_combined(self):
        payload = {
            "from": "",
            "to": "victim@example.test",
            "cc": ["copy@example.test"],
            "bcc": ["hidden@example.test"],
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[RECIPIENT_EMAIL] == [
            "victim@example.test",
            "copy@example.test",
            "hidden@example.test",
        ]

    def test_reply_to_generates_reply_to_email(self):
        payload = {"from": "", "to": "", "reply_to": "reply@example.test"}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[REPLY_TO_EMAIL] == ["reply@example.test"]

    def test_no_reply_to_when_absent(self):
        payload = {"from": "sender@example.test", "to": "victim@example.test"}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert REPLY_TO_EMAIL not in signatures

    def test_no_reply_to_when_none(self):
        payload = {
            "from": "sender@example.test",
            "to": "victim@example.test",
            "reply_to": None,
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert REPLY_TO_EMAIL not in signatures

    def test_empty_payload_returns_empty_signatures(self):
        payload = {"from": "", "to": "", "cc": [], "bcc": []}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures == {}

    def test_all_fields_combined(self):
        payload = {
            "from": "sender@example.test",
            "mail_from": "bounce@example.test",
            "to": "victim@example.test",
            "cc": ["copy@example.test"],
            "bcc": ["hidden@example.test"],
            "reply_to": "reply@example.test",
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[SENDER_EMAIL] == [
            "sender@example.test",
            "bounce@example.test",
        ]
        assert signatures[RECIPIENT_EMAIL] == [
            "victim@example.test",
            "copy@example.test",
            "hidden@example.test",
        ]
        assert signatures[REPLY_TO_EMAIL] == ["reply@example.test"]


def _sha256(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


class TestUrlHashSignatures:
    def test_text_body_with_url(self):
        payload = {"from": "", "to": "", "body": "Visit https://example.com/path"}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[URL_HASH] == [_sha256("https://example.com/path")]

    def test_html_body_with_url(self):
        payload = {
            "from": "",
            "to": "",
            "body": '<a href="https://evil.com/phish">Click here</a>',
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[URL_HASH] == [_sha256("https://evil.com/phish")]

    def test_multiple_urls_in_body(self):
        payload = {
            "from": "",
            "to": "",
            "body": "Links: https://first.com and http://second.org/page",
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert len(signatures[URL_HASH]) == 2
        assert _sha256("https://first.com") in signatures[URL_HASH]
        assert _sha256("http://second.org/page") in signatures[URL_HASH]

    def test_no_url_in_body(self):
        payload = {"from": "", "to": "", "body": "No links here, just plain text."}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert URL_HASH not in signatures

    def test_empty_body(self):
        payload = {"from": "", "to": "", "body": ""}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert URL_HASH not in signatures

    def test_no_body_key(self):
        payload = {"from": "", "to": ""}
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert URL_HASH not in signatures

    def test_duplicate_urls_deduplicated(self):
        payload = {
            "from": "",
            "to": "",
            "body": "https://dup.com https://dup.com",
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[URL_HASH] == [_sha256("https://dup.com")]

    def test_url_hashes_combined_with_email_signatures(self):
        payload = {
            "from": "sender@test.com",
            "to": "victim@test.com",
            "body": "Click https://evil.com",
        }
        signatures = EmailSignatureService.build_email_signatures(payload)
        assert signatures[SENDER_EMAIL] == ["sender@test.com"]
        assert signatures[RECIPIENT_EMAIL] == ["victim@test.com"]
        assert signatures[URL_HASH] == [_sha256("https://evil.com")]


class TestSendSignatures:
    def test_builds_and_sends_with_empty_extra_signatures(self):
        mock_sm = Mock()
        mock_sm.build_payload.return_value = {"targets": []}
        service = EmailSignatureService(mock_sm)
        details = Mock()
        sig = Mock()

        service.send_signatures("inject-1", details, sig)

        mock_sm.build_payload.assert_called_once()
        build_kwargs = mock_sm.build_payload.call_args.kwargs
        assert build_kwargs["expectation_types"] == ["DETECTION"]
        extra = build_kwargs["extra_signatures"]
        assert isinstance(extra, ExtraSignatureData)
        assert extra.detection == {}

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
