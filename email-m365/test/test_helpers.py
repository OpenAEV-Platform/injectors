import base64
from unittest import TestCase

from email_m365_injector.contracts_email_m365 import (
    BODY_FORMAT_TEXT,
    KEY_BCC,
    KEY_BODY,
    KEY_BODY_FORMAT,
    KEY_CC,
    KEY_FROM,
    KEY_REPLY_TO,
    KEY_SAVE_TO_SENT,
    KEY_SUBJECT,
    KEY_TO,
)
from email_m365_injector.helpers.email_helper import EmailMessageBuilder


class BuildMessageTest(TestCase):
    def _content(self, **overrides):
        content = {
            KEY_FROM: "sender@contoso.com",
            KEY_TO: "to1@example.com, to2@example.com",
            KEY_SUBJECT: "Security drill",
            KEY_BODY: "<b>Hello</b>",
        }
        content.update(overrides)
        return content

    def test_build_maps_recipients_and_defaults_html(self):
        payload = EmailMessageBuilder.build(self._content())
        self.assertEqual(payload["sender"], "sender@contoso.com")
        message = payload["message"]
        self.assertEqual(message["body"]["contentType"], "HTML")
        self.assertEqual(
            [r["emailAddress"]["address"] for r in message["toRecipients"]],
            ["to1@example.com", "to2@example.com"],
        )
        self.assertEqual(
            message["from"]["emailAddress"]["address"], "sender@contoso.com"
        )
        # Optional collections omitted when empty.
        self.assertNotIn("ccRecipients", message)
        self.assertNotIn("bccRecipients", message)
        self.assertNotIn("replyTo", message)
        self.assertNotIn("attachments", message)
        # save_to_sent defaults to True when the field is absent.
        self.assertTrue(payload["save_to_sent"])

    def test_build_includes_cc_bcc_reply_to_and_text_format(self):
        payload = EmailMessageBuilder.build(
            self._content(
                **{
                    KEY_CC: "cc@example.com",
                    KEY_BCC: "bcc1@example.com, bcc2@example.com",
                    KEY_REPLY_TO: "reply@example.com",
                    KEY_BODY_FORMAT: BODY_FORMAT_TEXT,
                    KEY_SAVE_TO_SENT: False,
                }
            )
        )
        message = payload["message"]
        self.assertEqual(message["body"]["contentType"], "Text")
        self.assertEqual(
            message["ccRecipients"][0]["emailAddress"]["address"], "cc@example.com"
        )
        self.assertEqual(len(message["bccRecipients"]), 2)
        self.assertEqual(
            message["replyTo"][0]["emailAddress"]["address"], "reply@example.com"
        )
        self.assertFalse(payload["save_to_sent"])

    def test_build_encodes_attachments_as_file_attachments(self):
        payload = EmailMessageBuilder.build(
            self._content(), attachments=[("report.pdf", b"hello")]
        )
        attachment = payload["message"]["attachments"][0]
        self.assertEqual(attachment["@odata.type"], "#microsoft.graph.fileAttachment")
        self.assertEqual(attachment["name"], "report.pdf")
        self.assertEqual(base64.b64decode(attachment["contentBytes"]), b"hello")

    def test_build_requires_sender(self):
        with self.assertRaises(ValueError):
            EmailMessageBuilder.build(self._content(**{KEY_FROM: "  "}))

    def test_build_requires_recipient(self):
        with self.assertRaises(ValueError):
            EmailMessageBuilder.build(self._content(**{KEY_TO: " , "}))
