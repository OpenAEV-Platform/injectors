import zipfile
from io import BytesIO
from unittest import TestCase

from email_seg.contracts_email_seg import SEG_ASSESSMENT_CONTRACT, EmailSegContracts
from email_seg.helpers.email_sender import EICAR_TEST_STRING, EmailSender


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = EmailSegContracts.build_contract()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_id"], SEG_ASSESSMENT_CONTRACT)


class MessageBuilderTest(TestCase):
    def setUp(self):
        self.sender = EmailSender()

    def _build(self, payload, **kwargs):
        return self.sender.build_message(
            payload=payload,
            mail_from="attacker@example.com",
            mail_to="victim@example.com",
            subject="test",
            **kwargs,
        )

    def test_eicar_body_contains_signature(self):
        message = self._build("eicar_body")
        self.assertIn(EICAR_TEST_STRING, message.get_content())

    def test_eicar_attachment_present(self):
        message = self._build("eicar_attachment")
        attachments = list(message.iter_attachments())
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0].get_filename(), "eicar.com")

    def test_eicar_zip_contains_eicar(self):
        message = self._build("eicar_zip")
        attachment = next(message.iter_attachments())
        with zipfile.ZipFile(BytesIO(attachment.get_payload(decode=True))) as archive:
            self.assertIn("eicar.com", archive.namelist())

    def test_malicious_url_requires_url(self):
        with self.assertRaises(ValueError):
            self._build("malicious_url")

    def test_malicious_url_in_body(self):
        message = self._build("malicious_url", malicious_url="http://test.example/x")
        self.assertIn("http://test.example/x", message.get_content())

    def test_unknown_payload_raises(self):
        with self.assertRaises(ValueError):
            self._build("nope")
