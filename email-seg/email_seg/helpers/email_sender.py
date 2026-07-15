"""Builds and sends email-gateway test messages via SMTP.

Payloads are safe, industry-standard antivirus test artifacts (EICAR) plus a
configurable benign test URL, so the injector measures what the Secure Email
Gateway strips/blocks without shipping real malware.
"""

import io
import smtplib
import zipfile
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Optional

# The EICAR standard antivirus test string. It is not malware; every SEG/AV
# engine is expected to flag it, which is exactly what we want to measure.
EICAR_TEST_STRING = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


@dataclass
class SendResult:
    success: bool
    message: str


class EmailSender:
    def __init__(self, logger=None):
        self.logger = logger

    @staticmethod
    def _eicar_zip_bytes() -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("eicar.com", EICAR_TEST_STRING)
        return buffer.getvalue()

    def build_message(
        self,
        payload: str,
        mail_from: str,
        mail_to: str,
        subject: str,
        malicious_url: Optional[str] = None,
    ) -> EmailMessage:
        message = EmailMessage()
        message["From"] = mail_from
        message["To"] = mail_to
        message["Subject"] = subject

        if payload == "eicar_body":
            message.set_content("OpenAEV email gateway test.\n\n" + EICAR_TEST_STRING)
        elif payload == "eicar_attachment":
            message.set_content("OpenAEV email gateway test - EICAR attachment.")
            message.add_attachment(
                EICAR_TEST_STRING.encode(),
                maintype="application",
                subtype="octet-stream",
                filename="eicar.com",
            )
        elif payload == "eicar_zip":
            message.set_content(
                "OpenAEV email gateway test - EICAR inside a zip archive."
            )
            message.add_attachment(
                self._eicar_zip_bytes(),
                maintype="application",
                subtype="zip",
                filename="eicar.zip",
            )
        elif payload == "malicious_url":
            if not malicious_url:
                raise ValueError("A test URL is required for the malicious_url payload")
            message.set_content(
                "OpenAEV email gateway URL-filtering test.\n\n"
                f"Test link: {malicious_url}"
            )
        else:
            raise ValueError(f"Unknown payload type: {payload}")

        return message

    def send(
        self,
        message: EmailMessage,
        host: str,
        port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
        timeout: int = 60,
    ) -> SendResult:
        try:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                if use_tls:
                    server.starttls()
                # SMTP AUTH requires BOTH a username and a password. The
                # credential fields are optional in the contract, so a blank
                # value (None or "") means "relay without authentication".
                # Only log in when a full credential pair is present rather
                # than erroring on a half-provided pair.
                if username and password:
                    server.login(username, password)
                server.send_message(message)
        except smtplib.SMTPException as exc:
            return SendResult(False, f"SMTP error: {exc}")
        except OSError as exc:
            return SendResult(False, f"Connection error: {exc}")

        return SendResult(
            True,
            f"Test email delivered to the gateway for {message['To']}",
        )
