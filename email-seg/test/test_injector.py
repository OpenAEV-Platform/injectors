import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import email_seg.openaev_email_seg as mod
from email_seg.contracts_email_seg import SEG_ASSESSMENT_CONTRACT
from email_seg.helpers.email_sender import EmailSender, SendResult

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "email-seg--test",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVEmailSeg()
    injector.helper = MagicMock()
    return injector


def _data(content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {
                "injector_contract_id": SEG_ASSESSMENT_CONTRACT
            },
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_success(self):
        injector = make_injector()
        injector.sender = MagicMock()
        injector.sender.build_message.return_value = MagicMock()
        injector.sender.send.return_value = SendResult(True, "delivered")
        injector.process_message(
            _data(
                {
                    "payload": ["eicar_body"],
                    "mail_from": "a@x.com",
                    "mail_to": "b@y.com",
                    "smtp_host": "gw",
                    "smtp_port": ["587"],
                    "smtp_use_tls": True,
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")

    def test_send_failure_reports_error(self):
        injector = make_injector()
        injector.sender = MagicMock()
        injector.sender.build_message.return_value = MagicMock()
        injector.sender.send.return_value = SendResult(False, "blocked")
        injector.process_message(
            _data(
                {
                    "payload": ["eicar_body"],
                    "mail_from": "a@x.com",
                    "mail_to": "b@y.com",
                    "smtp_host": "gw",
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_exception_reports_error(self):
        injector = make_injector()
        injector.sender = MagicMock()
        injector.sender.build_message.side_effect = ValueError("bad payload")
        injector.process_message(
            _data(
                {
                    "payload": ["eicar_body"],
                    "mail_from": "a@x.com",
                    "mail_to": "b@y.com",
                    "smtp_host": "gw",
                }
            )
        )
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertEqual(callback["execution_message"], "bad payload")

    def test_disable_tls_via_string_list(self):
        injector = make_injector()
        injector.sender = MagicMock()
        injector.sender.build_message.return_value = MagicMock()
        injector.sender.send.return_value = SendResult(True, "delivered")
        injector.process_message(
            _data(
                {
                    "payload": ["eicar_body"],
                    "mail_from": ["a@x.com"],
                    "mail_to": ["b@y.com"],
                    "smtp_host": ["gw"],
                    "smtp_use_tls": ["false"],
                }
            )
        )
        self.assertFalse(injector.sender.send.call_args.kwargs["use_tls"])
        self.assertEqual(injector.sender.send.call_args.kwargs["host"], "gw")

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class AsBoolTest(TestCase):
    def test_defaults_true(self):
        self.assertTrue(mod.OpenAEVEmailSeg._as_bool(None))

    def test_bool_passthrough(self):
        self.assertTrue(mod.OpenAEVEmailSeg._as_bool(True))
        self.assertFalse(mod.OpenAEVEmailSeg._as_bool(False))

    def test_string_and_list_values(self):
        self.assertFalse(mod.OpenAEVEmailSeg._as_bool("false"))
        self.assertFalse(mod.OpenAEVEmailSeg._as_bool(["false"]))
        self.assertTrue(mod.OpenAEVEmailSeg._as_bool(["true"]))
        self.assertTrue(mod.OpenAEVEmailSeg._as_bool("on"))


class EmailSenderSendTest(TestCase):
    def _message(self):
        return EmailSender().build_message("eicar_body", "a@x.com", "b@y.com", "subj")

    @patch("email_seg.helpers.email_sender.smtplib.SMTP")
    def test_send_success(self, smtp):
        server = MagicMock()
        smtp.return_value.__enter__.return_value = server
        result = EmailSender().send(self._message(), "gw", 587, use_tls=True)
        self.assertTrue(result.success)
        server.starttls.assert_called_once()

    @patch("email_seg.helpers.email_sender.smtplib.SMTP")
    def test_send_with_auth(self, smtp):
        server = MagicMock()
        smtp.return_value.__enter__.return_value = server
        EmailSender().send(self._message(), "gw", 587, username="u", password="p")
        server.login.assert_called_once_with("u", "p")

    @patch("email_seg.helpers.email_sender.smtplib.SMTP")
    def test_send_smtp_error(self, smtp):
        import smtplib

        smtp.return_value.__enter__.side_effect = smtplib.SMTPException("nope")
        result = EmailSender().send(self._message(), "gw", 587)
        self.assertFalse(result.success)

    @patch(
        "email_seg.helpers.email_sender.smtplib.SMTP",
        side_effect=OSError("conn refused"),
    )
    def test_send_connection_error(self, _smtp):
        result = EmailSender().send(self._message(), "gw", 587)
        self.assertFalse(result.success)
