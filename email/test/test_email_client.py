from unittest.mock import patch

from email_injector.client.email_client import SMTP_TIMEOUT_SECONDS, EmailClient


def test_send_email_success():
    with patch("smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value

        result = EmailClient.send_email(
            smtp_hostname="localhost",
            smtp_port=1025,
            smtp_use_tls=True,
            smtp_username="user",
            smtp_password="password",
            from_email="from@example.com",
            to_email="to@example.com",
            cc_emails=["cc@example.com"],
            bcc_emails=["bcc@example.com"],
            subject="Test Subject",
            body="Test Body",
            attachments=[],
        )

        assert result.success is True
        assert "Email crafted successfully" in result.message

        mock_smtp.assert_called_with("localhost", 1025, timeout=SMTP_TIMEOUT_SECONDS)
        instance.starttls.assert_called_once()
        instance.login.assert_called_with("user", "password")
        instance.send_message.assert_called_once()
        sent_message = instance.send_message.call_args.args[0]
        assert sent_message["Cc"] == "cc@example.com"
        assert instance.send_message.call_args.kwargs["to_addrs"] == [
            "to@example.com",
            "cc@example.com",
            "bcc@example.com",
        ]
        mock_smtp.return_value.__exit__.assert_called_once()


def test_send_email_no_auth_no_tls():
    with patch("smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value

        result = EmailClient.send_email(
            smtp_hostname="localhost",
            smtp_port=1025,
            smtp_use_tls=False,
            smtp_username=None,
            smtp_password=None,
            from_email="from@example.com",
            to_email="to@example.com",
            cc_emails=[],
            bcc_emails=[],
            subject="Test Subject",
            body="Test Body",
            attachments=[],
        )

        assert result.success is True
        mock_smtp.assert_called_with("localhost", 1025, timeout=SMTP_TIMEOUT_SECONDS)
        instance.starttls.assert_not_called()
        instance.login.assert_not_called()
        instance.send_message.assert_called_once()


def test_send_email_with_attachment():
    with patch("smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value

        result = EmailClient.send_email(
            smtp_hostname="localhost",
            smtp_port=1025,
            smtp_use_tls=False,
            smtp_username=None,
            smtp_password=None,
            from_email="from@example.com",
            to_email="to@example.com",
            cc_emails=[],
            bcc_emails=[],
            subject="Attachment Subject",
            body="Attachment Body",
            attachments=[("test.txt", b"hello")],
        )

        assert result.success is True
        sent_message = instance.send_message.call_args.args[0]
        attachment_parts = [
            part
            for part in sent_message.get_payload()
            if part.get_filename() == "test.txt"
        ]
        assert len(attachment_parts) == 1


def test_send_email_with_multiple_attachments():
    with patch("smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value

        result = EmailClient.send_email(
            smtp_hostname="localhost",
            smtp_port=1025,
            smtp_use_tls=False,
            smtp_username=None,
            smtp_password=None,
            from_email="from@example.com",
            to_email="to@example.com",
            cc_emails=[],
            bcc_emails=[],
            subject="Attachment Subject",
            body="Attachment Body",
            attachments=[("a.txt", b"a"), ("b.txt", b"b")],
        )

        assert result.success is True
        sent_message = instance.send_message.call_args.args[0]
        attachment_parts = [
            part.get_filename()
            for part in sent_message.get_payload()
            if part.get_filename() is not None
        ]
        assert attachment_parts == ["a.txt", "b.txt"]


def test_send_email_closes_connection_on_send_failure():
    with patch("smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value
        instance.send_message.side_effect = Exception("Send error")

        result = EmailClient.send_email(
            smtp_hostname="localhost",
            smtp_port=1025,
            smtp_use_tls=False,
            smtp_username=None,
            smtp_password=None,
            from_email="from@example.com",
            to_email="to@example.com",
            cc_emails=[],
            bcc_emails=[],
            subject="Test Subject",
            body="Test Body",
            attachments=[],
        )

        assert result.success is False
        assert "Failed to craft email: Send error" in result.message
        mock_smtp.return_value.__exit__.assert_called_once()


def test_send_email_failure():
    with patch("smtplib.SMTP") as mock_smtp:
        mock_smtp.side_effect = Exception("Connection error")

        result = EmailClient.send_email(
            smtp_hostname="localhost",
            smtp_port=1025,
            smtp_use_tls=False,
            smtp_username=None,
            smtp_password=None,
            from_email="from@example.com",
            to_email="to@example.com",
            cc_emails=[],
            bcc_emails=[],
            subject="Test Subject",
            body="Test Body",
            attachments=[],
        )

        assert result.success is False
        assert "Failed to craft email: Connection error" in result.message
