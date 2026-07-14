"""SMTP sender for native phishing emails (stdlib smtplib/email)."""

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Optional


@dataclass
class SendResult:
    success: bool
    message: str


class PhishingSender:
    def __init__(
        self,
        host: str,
        port: int,
        mail_from: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
        timeout: int = 60,
        logger=None,
    ):
        self.host = host
        self.port = port
        self.mail_from = mail_from
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout
        self.logger = logger

    def build_message(self, to_email: str, subject: str, html: str) -> EmailMessage:
        message = EmailMessage()
        message["From"] = self.mail_from
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content("This message requires an HTML capable client.")
        message.add_alternative(html, subtype="html")
        return message

    def send(self, message: EmailMessage) -> SendResult:
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(message)
        except smtplib.SMTPException as exc:
            return SendResult(False, f"SMTP error: {exc}")
        except OSError as exc:
            return SendResult(False, f"Connection error: {exc}")
        return SendResult(True, f"Sent to {message['To']}")
