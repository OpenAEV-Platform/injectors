from unittest import TestCase

from email_smtp_injector.helpers.email_helper import EmailPayloadBuilder


class EmailPayloadBuilderTest(TestCase):

    def test_email_payload_builder(self):
        content = {
            "smtp_hostname": "smtp.example.com",
            "smtp_port": "587",
            "smtp_use_tls": True,
            "smtp_username": "user",
            "smtp_password": "pass",
            "from": "sender@example.com",
            "mail_from": "bounce@example.com",
            "reply_to": "reply@example.com",
            "to": "recipient@example.com",
            "cc": "cc1@example.com, cc2@example.com",
            "bcc": "bcc@example.com",
            "subject": "Hello",
            "body": "World",
        }

        payload = EmailPayloadBuilder.build(content)

        self.assertEqual(payload["smtp_hostname"], "smtp.example.com")
        self.assertEqual(payload["smtp_port"], 587)
        self.assertTrue(payload["smtp_use_tls"])
        self.assertEqual(payload["smtp_username"], "user")
        self.assertEqual(payload["smtp_password"], "pass")
        self.assertEqual(payload["from"], "sender@example.com")
        self.assertEqual(payload["mail_from"], "bounce@example.com")
        self.assertEqual(payload["reply_to"], "reply@example.com")
        self.assertEqual(payload["to"], "recipient@example.com")
        self.assertEqual(payload["cc"], ["cc1@example.com", "cc2@example.com"])
        self.assertEqual(payload["bcc"], ["bcc@example.com"])
        self.assertEqual(payload["subject"], "Hello")
        self.assertEqual(payload["body"], "World")

    def test_email_payload_builder_defaults(self):
        content = {
            "smtp_hostname": "smtp.example.com",
            "smtp_port": "25",
            "from": "sender@example.com",
            "to": "recipient@example.com",
            "subject": "Hello",
            "body": "World",
        }

        payload = EmailPayloadBuilder.build(content)

        self.assertEqual(payload["smtp_hostname"], "smtp.example.com")
        self.assertEqual(payload["smtp_port"], 25)
        self.assertFalse(payload["smtp_use_tls"])
        self.assertIsNone(payload["smtp_username"])
        self.assertIsNone(payload["smtp_password"])
        self.assertEqual(payload["mail_from"], "sender@example.com")
        self.assertIsNone(payload["reply_to"])
        self.assertEqual(payload["cc"], [])
        self.assertEqual(payload["bcc"], [])

    def test_email_payload_builder_empty_mail_from_falls_back_to_from(self):
        content = {
            "smtp_hostname": "smtp.example.com",
            "smtp_port": "25",
            "from": "sender@example.com",
            "mail_from": "",
            "to": "recipient@example.com",
            "subject": "Hello",
            "body": "World",
        }

        payload = EmailPayloadBuilder.build(content)

        self.assertEqual(payload["mail_from"], "sender@example.com")

    def test_email_payload_builder_whitespace_optional_emails_treated_as_omitted(self):
        content = {
            "smtp_hostname": "smtp.example.com",
            "smtp_port": "25",
            "from": "sender@example.com",
            "mail_from": "   ",
            "reply_to": "   ",
            "to": "recipient@example.com",
            "subject": "Hello",
            "body": "World",
        }

        payload = EmailPayloadBuilder.build(content)

        self.assertEqual(payload["mail_from"], "sender@example.com")
        self.assertIsNone(payload["reply_to"])

    def test_email_payload_builder_strips_optional_emails(self):
        content = {
            "smtp_hostname": "smtp.example.com",
            "smtp_port": "25",
            "from": "sender@example.com",
            "mail_from": " bounce@example.com ",
            "reply_to": " reply@example.com ",
            "to": "recipient@example.com",
            "subject": "Hello",
            "body": "World",
        }

        payload = EmailPayloadBuilder.build(content)

        self.assertEqual(payload["mail_from"], "bounce@example.com")
        self.assertEqual(payload["reply_to"], "reply@example.com")

    def test_email_payload_builder_parse_bool_from_string(self):
        content = {
            "smtp_hostname": "smtp.example.com",
            "smtp_port": "25",
            "smtp_use_tls": "yes",
            "from": "sender@example.com",
            "to": "recipient@example.com",
            "subject": "Hello",
            "body": "World",
        }

        payload = EmailPayloadBuilder.build(content)

        self.assertTrue(payload["smtp_use_tls"])

    def test_email_payload_builder_parse_bool_from_empty_string(self):
        content = {
            "smtp_hostname": "smtp.example.com",
            "smtp_port": "25",
            "smtp_use_tls": "",
            "from": "sender@example.com",
            "to": "recipient@example.com",
            "subject": "Hello",
            "body": "World",
        }

        payload = EmailPayloadBuilder.build(content)

        self.assertFalse(payload["smtp_use_tls"])
