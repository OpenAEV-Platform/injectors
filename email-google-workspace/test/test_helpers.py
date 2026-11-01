import base64
from email import message_from_bytes
from unittest import TestCase

from email_gws_injector.contracts_email_gws import (
    BODY_FORMAT_TEXT,
    KEY_BCC,
    KEY_BODY,
    KEY_BODY_FORMAT,
    KEY_CC,
    KEY_FROM,
    KEY_REPLY_TO,
    KEY_SUBJECT,
    KEY_TO,
)
from email_gws_injector.helpers.email_helper import EmailMessageBuilder


def _decode(raw: str):
    return message_from_bytes(base64.urlsafe_b64decode(raw))


class BuildMessageTest(TestCase):
    def _content(self, **overrides):
        content = {
            KEY_FROM: "sender@corp.com",
            KEY_TO: "to1@example.com, to2@example.com",
            KEY_SUBJECT: "Security drill",
            KEY_BODY: "<b>Hello</b>",
        }
        content.update(overrides)
        return content

    def test_build_sets_headers_and_defaults_html(self):
        payload = EmailMessageBuilder.build(self._content())
        self.assertEqual(payload["sender"], "sender@corp.com")
        msg = _decode(payload["raw"])
        self.assertEqual(msg["From"], "sender@corp.com")
        self.assertEqual(msg["To"], "to1@example.com, to2@example.com")
        self.assertEqual(msg["Subject"], "Security drill")
        self.assertEqual(msg.get_content_type(), "text/html")

    def test_build_includes_cc_bcc_reply_to_and_text_format(self):
        payload = EmailMessageBuilder.build(
            self._content(
                **{
                    KEY_CC: "cc@example.com",
                    KEY_BCC: "bcc@example.com",
                    KEY_REPLY_TO: "reply@example.com",
                    KEY_BODY_FORMAT: BODY_FORMAT_TEXT,
                }
            )
        )
        msg = _decode(payload["raw"])
        self.assertEqual(msg["Cc"], "cc@example.com")
        self.assertEqual(msg["Bcc"], "bcc@example.com")
        self.assertEqual(msg["Reply-To"], "reply@example.com")
        self.assertEqual(msg.get_content_type(), "text/plain")

    def test_build_is_base64url(self):
        payload = EmailMessageBuilder.build(self._content())
        # base64url uses -/_ and never +/ ; ensure it round-trips.
        self.assertNotIn("+", payload["raw"])
        self.assertNotIn("/", payload["raw"])
        self.assertIsNotNone(_decode(payload["raw"]))

    def test_build_attaches_documents(self):
        payload = EmailMessageBuilder.build(
            self._content(), attachments=[("report.pdf", b"hello")]
        )
        msg = _decode(payload["raw"])
        names = [
            part.get_filename()
            for part in msg.walk()
            if part.get_filename() is not None
        ]
        self.assertIn("report.pdf", names)

    def test_build_requires_sender(self):
        with self.assertRaises(ValueError):
            EmailMessageBuilder.build(self._content(**{KEY_FROM: "  "}))

    def test_build_requires_recipient(self):
        with self.assertRaises(ValueError):
            EmailMessageBuilder.build(self._content(**{KEY_TO: " , "}))

    def test_build_rejects_header_injection_in_subject(self):
        with self.assertRaises(ValueError):
            EmailMessageBuilder.build(
                self._content(**{KEY_SUBJECT: "Subject\r\nBcc: attacker@example.com"})
            )
