from unittest.mock import patch

import pytest
from email_smtp.contracts import EmailContractId
from email_smtp.models.exceptions import (
    CustomHeaderValidationError,
    InvalidContractError,
    MissingRequiredFieldError,
)
from email_smtp.services.email_client import ExecutionResult

CONTRACT_ID = EmailContractId.CRAFT_EMAIL


def _data(contract_id=CONTRACT_ID, content=None, documents=None):
    return {
        "injection": {
            "inject_id": "inject-1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content
            or {
                "smtp_hostname": "smtp.example.com",
                "smtp_port": "25",
                "from": "sender@example.com",
                "to": "recipient@example.com",
                "subject": "Subject",
                "body": "Body",
            },
            "inject_documents": documents or [],
        }
    }


def test_execute_rejects_unknown_contract(email_smtp_injector):
    with pytest.raises(InvalidContractError, match="Unsupported contract"):
        email_smtp_injector.execute(_data(contract_id="other"))


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_execute_sends_email_with_downloaded_attachments(
    mock_send_email, email_smtp_injector
):
    email_smtp_injector.helper.api.document.download.return_value = {
        "status_code": 200,
        "content": b"attachment",
    }
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")

    result = email_smtp_injector.execute(
        _data(
            documents=[
                {
                    "document_attached": True,
                    "document_id": "document-1",
                    "document_name": "report.txt",
                }
            ]
        )
    )

    assert result.success
    email_smtp_injector.helper.api.document.download.assert_called_once_with(
        "document-1"
    )
    assert mock_send_email.call_args.kwargs["attachments"] == [
        ("report.txt", b"attachment")
    ]


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_execute_parses_and_forwards_custom_headers(
    mock_send_email, email_smtp_injector
):
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Subject",
        "body": "Body",
        "custom_headers": "X-OpenAEV-Test: true\nX-Trace-ID: abc-123",
    }

    result = email_smtp_injector.execute(_data(content=content))

    assert result.success
    assert mock_send_email.call_args.kwargs["custom_headers"] == [
        ("X-OpenAEV-Test", "true"),
        ("X-Trace-ID", "abc-123"),
    ]


def test_extract_attachments_requires_document_id(email_smtp_injector):
    with pytest.raises(MissingRequiredFieldError, match="missing a document_id"):
        email_smtp_injector._extract_attachments(
            _data(
                documents=[
                    {
                        "document_attached": True,
                        "document_name": "report.txt",
                    }
                ]
            )
        )


@pytest.mark.parametrize(
    "custom_headers,expected_message",
    [
        ("bad header: true", "unsafe header name"),
        ("X-OpenAEV-Test:", "header value is required"),
    ],
)
@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_execute_rejects_unsafe_custom_headers(
    mock_send_email, email_smtp_injector, custom_headers, expected_message
):
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Subject",
        "body": "Body",
        "custom_headers": custom_headers,
    }

    with pytest.raises(CustomHeaderValidationError, match=expected_message):
        email_smtp_injector.execute(_data(content=content))

    mock_send_email.assert_not_called()


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_reports_execution_status(mock_send_email, email_smtp_injector):
    mock_send_email.return_value = ExecutionResult(success=False, message="failed")

    email_smtp_injector.process_message(_data())

    email_smtp_injector.helper.api.inject.execution_reception.assert_called_once_with(
        inject_id="inject-1", data={"tracking_total_count": 1}
    )
    callback_data = (
        email_smtp_injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
    )
    assert callback_data["execution_status"] == "ERROR"
    assert callback_data["execution_message"] == "failed"


# ---------------------------------------------------------------------------
# SignatureExpectation integration tests
# ---------------------------------------------------------------------------


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_sends_signatures_on_success(
    mock_send_email, email_smtp_injector
):
    """Successful execution sends SignatureExpectation data to the platform."""
    mock_send_email.return_value = ExecutionResult(
        success=True, message="Email crafted successfully for recipient@example.com"
    )

    email_smtp_injector.process_message(_data())

    sig_service = email_smtp_injector.signature_service
    sig_service._sm.post_execution_updates.assert_called_once()
    sig_service._sm.build_payload.assert_called_once()
    sig_service._sm.send_signatures.assert_called_once()

    # Verify build_payload was called with DETECTION expectation type
    build_call = sig_service._sm.build_payload.call_args
    assert build_call.kwargs["expectation_types"] == ["DETECTION"]


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_sends_signatures_on_email_failure(
    mock_send_email, email_smtp_injector
):
    """Failed email send still reports signatures (with error info)."""
    mock_send_email.return_value = ExecutionResult(
        success=False, message="Connection refused"
    )

    email_smtp_injector.process_message(_data())

    sig_service = email_smtp_injector.signature_service
    sig_service._sm.send_signatures.assert_called_once()

    # post_execution_updates should have been called with error tool_output
    post_call = sig_service._sm.post_execution_updates.call_args
    tool_output = post_call[0][2]
    assert tool_output["error_info"]["exit_code"] == 1


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_sends_signatures_on_exception(
    mock_send_email, email_smtp_injector
):
    """Unhandled exception still sends signatures with error info."""
    mock_send_email.side_effect = RuntimeError("unexpected")

    email_smtp_injector.process_message(_data())

    sig_service = email_smtp_injector.signature_service
    sig_service._sm.send_signatures.assert_called_once()

    post_call = sig_service._sm.post_execution_updates.call_args
    tool_output = post_call[0][2]
    assert tool_output["error_info"]["exit_code"] == 1


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_sends_empty_extra_signatures(
    mock_send_email, email_smtp_injector
):
    """Email indicators go via output_structured, not extra signature data."""
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")

    email_smtp_injector.process_message(_data())

    sig_service = email_smtp_injector.signature_service
    build_call = sig_service._sm.build_payload.call_args
    extra = build_call.kwargs["extra_signatures"]
    assert extra.detection == {}
    assert extra.prevention == {}
    assert extra.vulnerability == {}


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_signature_send_failure_does_not_crash(
    mock_send_email, email_smtp_injector
):
    """Signature transmission failure is logged but does not raise."""
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")
    sig_service = email_smtp_injector.signature_service
    sig_service._sm.send_signatures.side_effect = Exception("network error")

    # Should not raise
    email_smtp_injector.process_message(_data())

    # Execution callback was still sent successfully
    callback_data = (
        email_smtp_injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
    )
    assert callback_data["execution_status"] == "SUCCESS"


# ---------------------------------------------------------------------------
# Contract output tests
# ---------------------------------------------------------------------------


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_output_structured_contains_email_signatures(
    mock_send_email, email_smtp_injector
):
    """Execution callback includes all email address signatures in output_structured."""
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")

    email_smtp_injector.process_message(_data())

    callback_data = (
        email_smtp_injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
    )
    import json

    output = json.loads(callback_data["execution_output_structured"])
    sigs = output["expectation_signatures"]
    assert sigs["sender_email"] == ["sender@example.com"]
    assert sigs["recipient_email"] == ["recipient@example.com"]


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_output_structured_includes_all_address_fields(
    mock_send_email, email_smtp_injector
):
    """All email address fields are captured in output_structured."""
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "from": "sender@example.com",
        "mail_from": "bounce@example.com",
        "to": "victim@example.com",
        "cc": "copy@example.com",
        "bcc": "hidden@example.com",
        "reply_to": "reply@example.com",
        "subject": "Subject",
        "body": "Body",
    }

    email_smtp_injector.process_message(_data(content=content))

    callback_data = (
        email_smtp_injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
    )
    import json

    output = json.loads(callback_data["execution_output_structured"])
    sigs = output["expectation_signatures"]
    assert sigs["sender_email"] == ["sender@example.com", "bounce@example.com"]
    assert sigs["recipient_email"] == [
        "victim@example.com",
        "copy@example.com",
        "hidden@example.com",
    ]
    assert sigs["reply_to_email"] == ["reply@example.com"]


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_output_structured_empty_when_no_addresses(
    mock_send_email, email_smtp_injector
):
    """When all address fields are empty, output_structured is explicitly empty."""
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "from": "",
        "to": "",
        "subject": "Subject",
        "body": "Body",
    }

    email_smtp_injector.process_message(_data(content=content))

    callback_data = (
        email_smtp_injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
    )
    import json

    output = json.loads(callback_data["execution_output_structured"])
    assert output == {}


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_output_structured_includes_url_hashes(
    mock_send_email, email_smtp_injector
):
    """URL hashes from body content are included in output_structured."""
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "from": "sender@example.com",
        "to": "victim@example.com",
        "subject": "Subject",
        "body": "Click here: https://evil.com/phish",
    }

    email_smtp_injector.process_message(_data(content=content))

    callback_data = (
        email_smtp_injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
    )
    import hashlib
    import json

    output = json.loads(callback_data["execution_output_structured"])
    sigs = output["expectation_signatures"]
    expected_hash = hashlib.sha256(b"https://evil.com/phish").hexdigest()
    assert sigs["url_hash"] == [expected_hash]


@patch("email_smtp.injector.openaev_email_smtp.EmailClient.send_email")
def test_process_message_output_structured_includes_attachment_hashes(
    mock_send_email, email_smtp_injector
):
    """Attachment hashes are included in output_structured."""
    mock_send_email.return_value = ExecutionResult(success=True, message="sent")

    attachment_content = b"malicious-pdf-content"
    mock_response = {"status_code": 200, "content": attachment_content}
    email_smtp_injector.helper.api.document.download.return_value = mock_response

    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "from": "sender@example.com",
        "to": "victim@example.com",
        "subject": "Subject",
        "body": "See attached",
    }
    documents = [
        {
            "document_attached": True,
            "document_name": "report.pdf",
            "document_id": "doc-1",
        }
    ]

    email_smtp_injector.process_message(_data(content=content, documents=documents))

    callback_data = (
        email_smtp_injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
    )
    import hashlib
    import json

    output = json.loads(callback_data["execution_output_structured"])
    sigs = output["expectation_signatures"]
    expected_hash = hashlib.sha256(attachment_content).hexdigest()
    assert sigs["attachment_hash"] == [expected_hash]
