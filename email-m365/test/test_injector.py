import importlib.util
from unittest import TestCase, skipUnless
from unittest.mock import MagicMock

from email_m365_injector.client.m365_client import ExecutionResult
from email_m365_injector.contracts_email_m365 import (
    CONTRACT_ID,
    KEY_BODY,
    KEY_FROM,
    KEY_SUBJECT,
    KEY_TO,
)

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None

if _HAS_PYOAEV:
    from email_m365_injector.openaev_email_m365 import OpenAEVEmailM365Injector


def _data(contract_id=CONTRACT_ID, content=None, documents=None):
    return {
        "injection": {
            "inject_id": "inject-1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content or {},
            "inject_documents": documents or [],
        }
    }


@skipUnless(_HAS_PYOAEV, "pyoaev is required to import the injector entrypoint")
class ExecuteTest(TestCase):
    def _injector(self):
        obj = OpenAEVEmailM365Injector.__new__(OpenAEVEmailM365Injector)
        obj.helper = MagicMock()
        obj.client = MagicMock()
        obj.client.send_mail.return_value = ExecutionResult(success=True, message="ok")
        return obj

    def _content(self):
        return {
            KEY_FROM: "sender@contoso.com",
            KEY_TO: "to@example.com",
            KEY_SUBJECT: "t",
            KEY_BODY: "b",
        }

    def test_rejects_unknown_contract(self):
        obj = self._injector()
        with self.assertRaises(ValueError):
            obj.execute(_data(contract_id="other", content=self._content()))

    def test_sends_mail(self):
        obj = self._injector()
        result = obj.execute(_data(content=self._content()))
        self.assertTrue(result.success)
        obj.client.send_mail.assert_called_once()
        kwargs = obj.client.send_mail.call_args.kwargs
        self.assertEqual(kwargs["sender"], "sender@contoso.com")

    def test_requires_recipient(self):
        obj = self._injector()
        content = {KEY_FROM: "sender@contoso.com", KEY_SUBJECT: "t", KEY_BODY: "b"}
        with self.assertRaises(ValueError):
            obj.execute(_data(content=content))

    def test_rejects_attachment_without_document_id(self):
        obj = self._injector()
        with self.assertRaisesRegex(ValueError, "document_id"):
            obj._extract_attachments(
                _data(documents=[{"document_attached": True, "document_name": "a.txt"}])
            )

    def test_downloads_attached_documents(self):
        obj = self._injector()
        obj.helper.api.document.download.return_value = {
            "status_code": 200,
            "content": b"file-bytes",
        }
        documents = [
            {
                "document_id": "doc-1",
                "document_name": "report.pdf",
                "document_attached": True,
            },
            {
                "document_id": "doc-2",
                "document_name": "ignored.txt",
                "document_attached": False,
            },
        ]
        extracted = obj._extract_attachments(_data(documents=documents))
        self.assertEqual(extracted, [("report.pdf", b"file-bytes")])
        obj.helper.api.document.download.assert_called_once_with("doc-1")

    def test_attachment_download_failure_includes_status_code(self):
        obj = self._injector()
        obj.helper.api.document.download.return_value = {"status_code": 404}
        documents = [
            {
                "document_id": "doc-1",
                "document_name": "report.pdf",
                "document_attached": True,
            }
        ]
        with self.assertRaisesRegex(ValueError, r"report\.pdf \(HTTP 404\)"):
            obj._extract_attachments(_data(documents=documents))

    def test_no_attachments_when_documents_are_none(self):
        obj = self._injector()
        data = _data()
        data["injection"]["inject_documents"] = None
        self.assertEqual(obj._extract_attachments(data), [])


@skipUnless(_HAS_PYOAEV, "pyoaev is required to import the injector entrypoint")
class ProcessMessageTest(TestCase):
    def _injector(self):
        obj = OpenAEVEmailM365Injector.__new__(OpenAEVEmailM365Injector)
        obj.helper = MagicMock()
        obj.client = MagicMock()
        return obj

    def _content(self):
        return {
            KEY_FROM: "sender@contoso.com",
            KEY_TO: "to@example.com",
            KEY_SUBJECT: "t",
            KEY_BODY: "b",
        }

    def test_reports_success(self):
        obj = self._injector()
        obj.client.send_mail.return_value = ExecutionResult(
            success=True, message="sent"
        )
        obj.process_message(_data(content=self._content()))
        obj.helper.api.inject.execution_reception.assert_called_once()
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "SUCCESS")

    def test_reports_error_when_graph_fails(self):
        obj = self._injector()
        obj.client.send_mail.return_value = ExecutionResult(
            success=False, message="Microsoft Graph API error"
        )
        obj.process_message(_data(content=self._content()))
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "ERROR")

    def test_reports_error_on_exception(self):
        obj = self._injector()
        # Missing recipient raises inside execute -> reported as ERROR.
        content = {KEY_FROM: "sender@contoso.com", KEY_SUBJECT: "t", KEY_BODY: "b"}
        obj.process_message(_data(content=content))
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "ERROR")
