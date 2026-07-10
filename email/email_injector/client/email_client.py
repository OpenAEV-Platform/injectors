import smtplib
from dataclasses import dataclass
from email.mime.application import MIMEApplication
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
        reply_to: Optional[str],
        to_email: str,
        cc_emails: list[str],
        bcc_emails: list[str],
        subject: str,
        body: str,
        attachments: list[tuple[str, bytes]] | None = None,
    ) -> ExecutionResult:
        try:
            msg = MIMEMultipart()
            msg["From"] = from_email
            if reply_to:
                msg["Reply-To"] = reply_to
            msg["To"] = to_email
            if cc_emails:
                msg["Cc"] = ", ".join(cc_emails)
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            for attachment_filename, attachment_content in attachments or []:
                attachment_part = MIMEApplication(attachment_content)
                attachment_part.add_header(
                    "Content-Disposition", "attachment", filename=attachment_filename
                )
                msg.attach(attachment_part)
            recipients = [to_email, *cc_emails, *bcc_emails]

            server = smtplib.SMTP(smtp_hostname, smtp_port)
            if smtp_use_tls:
                server.starttls()
            if smtp_username and smtp_password:
                server.login(smtp_username, smtp_password)
            server.send_message(msg, to_addrs=recipients)
            server.quit()

            return ExecutionResult(
                success=True,
                message=f"Email crafted successfully for {to_email}",
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                message=f"Failed to craft email: {str(e)}",
            )
