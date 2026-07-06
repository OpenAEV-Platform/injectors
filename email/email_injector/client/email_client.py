import smtplib
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional


@dataclass
class ExecutionResult:
    success: bool
    message: str


class EmailClient:

    @staticmethod
    def send_email(
        smtp_hostname: str,
        smtp_port: int,
        smtp_use_tls: bool,
        smtp_username: Optional[str],
        smtp_password: Optional[str],
        from_email: str,
        to_email: str,
        subject: str,
        body: str,
    ) -> ExecutionResult:
        try:
            msg = MIMEMultipart()
            msg["From"] = from_email
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(smtp_hostname, smtp_port)
            if smtp_use_tls:
                server.starttls()
            if smtp_username and smtp_password:
                server.login(smtp_username, smtp_password)
            server.send_message(msg)
            server.quit()

            return ExecutionResult(
                success=True,
                message=f"Email sent successfully to {to_email}",
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                message=f"Failed to send email: {str(e)}",
            )
