"""Build a Gmail API ``users.messages.send`` body from an inject content.

The Gmail API takes a single ``raw`` field: the full RFC 2822 MIME message,
base64url-encoded (``-``/``_`` alphabet, as required by the API - not standard
base64). Recipients (including Bcc) are taken from the MIME headers.
"""

import base64
from email.message import EmailMessage
from typing import Dict, List, Optional, Tuple

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


class EmailMessageBuilder:

    @staticmethod
    def parse_recipients(value: Optional[str]) -> List[str]:
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    @staticmethod
    def parse_optional(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        stripped = value.strip()
        return stripped or None

    @staticmethod
    def build(
        content: Dict, attachments: Optional[List[Tuple[str, bytes]]] = None
    ) -> Dict:
        sender = (content.get(KEY_FROM) or "").strip()
        if not sender:
            raise ValueError("A sender (from) is required to send an email")

        to_recipients = EmailMessageBuilder.parse_recipients(content.get(KEY_TO))
        if not to_recipients:
            raise ValueError("At least one recipient (to) is required to send an email")

        cc_recipients = EmailMessageBuilder.parse_recipients(content.get(KEY_CC))
        bcc_recipients = EmailMessageBuilder.parse_recipients(content.get(KEY_BCC))
        reply_to = EmailMessageBuilder.parse_optional(content.get(KEY_REPLY_TO))
        body_format = (content.get(KEY_BODY_FORMAT) or "").strip().lower()

        message = EmailMessage()
        message["From"] = sender
        message["To"] = ", ".join(to_recipients)
        if cc_recipients:
            message["Cc"] = ", ".join(cc_recipients)
        if bcc_recipients:
            message["Bcc"] = ", ".join(bcc_recipients)
        if reply_to:
            message["Reply-To"] = reply_to
        message["Subject"] = content.get(KEY_SUBJECT) or ""

        body = content.get(KEY_BODY) or ""
        if body_format == BODY_FORMAT_TEXT:
            message.set_content(body)
        else:
            message.set_content(body, subtype="html")

        for name, file_content in attachments or []:
            message.add_attachment(
                file_content,
                maintype="application",
                subtype="octet-stream",
                filename=name,
            )

        # Gmail requires base64url (URL-safe) encoding of the raw MIME bytes.
        # as_bytes() enforces the stdlib email policy, which rejects header
        # values that contain embedded headers (CRLF injection).
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
        return {"sender": sender, "raw": raw}
