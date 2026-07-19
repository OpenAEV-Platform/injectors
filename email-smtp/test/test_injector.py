import importlib.util
from unittest import TestCase, skipUnless
from unittest.mock import MagicMock, patch

from email_smtp_injector.client.email_client import ExecutionResult

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None
_HAS_INJECTOR_COMMON = importlib.util.find_spec("injector_common") is not None
_HAS_INJECTOR_RUNTIME = _HAS_PYOAEV and _HAS_INJECTOR_COMMON

if _HAS_INJECTOR_RUNTIME:
    from email_smtp_injector.contracts_email import CONTRACT_ID
    from email_smtp_injector.openaev_email_smtp import OpenAEVEmailInjector
else:
    CONTRACT_ID = "openaev_email_smtp"


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


@skipUnless(
    _HAS_INJECTOR_RUNTIME,
    "pyoaev and injector_common are required to import the injector entrypoint",
)
class OpenAEVEmailInjectorTest(TestCase):
    def _injector(self):
        injector = OpenAEVEmailInjector.__new__(OpenAEVEmailInjector)
        injector.helper = MagicMock()
        return injector

    def test_execute_rejects_unknown_contract(self):
        injector = self._injector()

        with self.assertRaisesRegex(ValueError, "Unsupported contract"):
            injector.execute(_data(contract_id="other"))

    @patch("email_smtp_injector.openaev_email_smtp.EmailClient.send_email")
    def test_execute_sends_email_with_downloaded_attachments(self, mock_send_email):
        injector = self._injector()
        injector.helper.api.document.download.return_value = {
            "status_code": 200,
            "content": b"attachment",
        }
        mock_send_email.return_value = ExecutionResult(success=True, message="sent")

        result = injector.execute(
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

        self.assertTrue(result.success)
        injector.helper.api.document.download.assert_called_once_with("document-1")
        self.assertEqual(
            mock_send_email.call_args.kwargs["attachments"],
            [("report.txt", b"attachment")],
        )

    def test_extract_attachments_requires_document_id(self):
        injector = self._injector()

        with self.assertRaisesRegex(ValueError, "missing a document_id"):
            injector._extract_attachments(
                _data(
                    documents=[
                        {
                            "document_attached": True,
                            "document_name": "report.txt",
                        }
                    ]
                )
            )

    @patch("email_smtp_injector.openaev_email_smtp.EmailClient.send_email")
    def test_process_message_reports_execution_status(self, mock_send_email):
        injector = self._injector()
        mock_send_email.return_value = ExecutionResult(success=False, message="failed")

        injector.process_message(_data())

        injector.helper.api.inject.execution_reception.assert_called_once_with(
            inject_id="inject-1", data={"tracking_total_count": 1}
        )
        callback_data = injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
        self.assertEqual(callback_data["execution_status"], "ERROR")
        self.assertEqual(callback_data["execution_message"], "failed")
