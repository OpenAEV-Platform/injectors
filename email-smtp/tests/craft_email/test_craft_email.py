from unittest.mock import patch

import pytest
from email_smtp.contracts import EmailContractId
from email_smtp.models.exceptions import InvalidContractError, MissingRequiredFieldError
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
