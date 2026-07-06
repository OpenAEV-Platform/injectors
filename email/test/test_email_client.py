from unittest.mock import MagicMock, patch

from email_injector.client.email_client import EmailClient


def test_send_email_success():
    with patch("smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value

        result = EmailClient.send_email(
            smtp_hostname="localhost",
            smtp_port=1025,
            smtp_use_tls=True,
            smtp_username="user",
            smtp_password="password",
            from_email="from@example.com",
            to_email="to@example.com",
            subject="Test Subject",
            body="Test Body",
        )

        assert result.success is True
        assert "Email sent successfully" in result.message

        mock_smtp.assert_called_with("localhost", 1025)
        instance.starttls.assert_called_once()
        instance.login.assert_called_with("user", "password")
        instance.send_message.assert_called_once()
        instance.quit.assert_called_once()


def test_send_email_no_auth_no_tls():
    with patch("smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value

        result = EmailClient.send_email(
            smtp_hostname="localhost",
            smtp_port=1025,
            smtp_use_tls=False,
            smtp_username=None,
            smtp_password=None,
            from_email="from@example.com",
            to_email="to@example.com",
            subject="Test Subject",
            body="Test Body",
        )

        assert result.success is True
        mock_smtp.assert_called_with("localhost", 1025)
        instance.starttls.assert_not_called()
        instance.login.assert_not_called()
        instance.send_message.assert_called_once()


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
            subject="Test Subject",
            body="Test Body",
        )

        assert result.success is False
        assert "Failed to send email: Connection error" in result.message
