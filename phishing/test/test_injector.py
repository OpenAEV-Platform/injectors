import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import phishing_injector.openaev_phishing as mod
from phishing_injector.contracts_phishing import PHISHING_CAMPAIGN_CONTRACT
from phishing_injector.helpers.phishing_sender import PhishingSender, SendResult

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "phishing--test",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "TrackingServer"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVPhishing(start_server=False)
    injector.helper = MagicMock()
    injector.sender = MagicMock()
    injector.sender.send.return_value = SendResult(True, "sent")
    return injector


def _data(content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {
                "injector_contract_id": PHISHING_CAMPAIGN_CONTRACT
            },
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_success_sends_to_recipients(self):
        injector = make_injector()
        injector.process_message(
            _data(
                {
                    "recipients": "a@x.com, b@y.com",
                    "template": ["password_reset"],
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        self.assertEqual(injector.sender.send.call_count, 2)

    def test_custom_html_and_subject(self):
        injector = make_injector()
        injector.process_message(
            _data(
                {
                    "recipients": "a@x.com",
                    "custom_html": '<a href="{link}">x</a><img src="{pixel}">',
                    "subject": ["Custom"],
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")

    def test_no_recipients_reports_error(self):
        injector = make_injector()
        injector.process_message(_data({"recipients": ""}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_all_sends_fail_reports_error(self):
        injector = make_injector()
        injector.sender.send.return_value = SendResult(False, "smtp down")
        injector.process_message(_data({"recipients": "a@x.com"}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class PhishingSenderTest(TestCase):
    def _sender(self):
        return PhishingSender("gw", 587, "from@x.com", use_tls=True)

    def test_build_message_is_html(self):
        message = self._sender().build_message("b@y.com", "subj", "<b>hi</b>")
        self.assertEqual(message["To"], "b@y.com")

    @patch("phishing_injector.helpers.phishing_sender.smtplib.SMTP")
    def test_send_success(self, smtp):
        server = MagicMock()
        smtp.return_value.__enter__.return_value = server
        message = self._sender().build_message("b@y.com", "subj", "<b>hi</b>")
        self.assertTrue(self._sender().send(message).success)
        server.starttls.assert_called_once()

    @patch(
        "phishing_injector.helpers.phishing_sender.smtplib.SMTP",
        side_effect=OSError("refused"),
    )
    def test_send_connection_error(self, _smtp):
        message = self._sender().build_message("b@y.com", "subj", "<b>hi</b>")
        self.assertFalse(self._sender().send(message).success)
