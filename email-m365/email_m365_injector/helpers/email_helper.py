"""Build a Microsoft Graph ``sendMail`` message from an inject content.

The Graph ``sendMail`` API expects a ``message`` resource plus a
``saveToSentItems`` flag. Recipients are objects of the form
``{"emailAddress": {"address": "..."}}`` and attachments are
``#microsoft.graph.fileAttachment`` items carrying base64-encoded bytes.
"""

import base64
from typing import Dict, List, Optional, Tuple

from email_m365_injector.contracts_email_m365 import (
    BODY_FORMAT_HTML,
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

# Microsoft Graph body contentType values, keyed by the contract selector.
_CONTENT_TYPE_BY_FORMAT = {
    BODY_FORMAT_HTML: "HTML",
    BODY_FORMAT_TEXT: "Text",
}


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
    def parse_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return False

    @staticmethod
    def _recipients(addresses: List[str]) -> List[Dict]:
        return [{"emailAddress": {"address": address}} for address in addresses]

    @staticmethod
    def _content_type(value: Optional[str]) -> str:
        key = (value or BODY_FORMAT_HTML).strip().lower()
        return _CONTENT_TYPE_BY_FORMAT.get(key, "HTML")

    @staticmethod
    def _attachments(attachments: List[Tuple[str, bytes]]) -> List[Dict]:
        return [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": name,
                "contentBytes": base64.b64encode(content).decode("ascii"),
            }
            for name, content in attachments
        ]

    @staticmethod
    def build(
        content: Dict, attachments: Optional[List[Tuple[str, bytes]]] = None
    ) -> Dict:
        sender = (content.get(KEY_FROM) or "").strip()
        if not sender:
            raise ValueError("A sender mailbox (from) is required to send an email")

        to_recipients = EmailMessageBuilder.parse_recipients(content.get(KEY_TO))
        if not to_recipients:
            raise ValueError("At least one recipient (to) is required to send an email")

        cc_recipients = EmailMessageBuilder.parse_recipients(content.get(KEY_CC))
        bcc_recipients = EmailMessageBuilder.parse_recipients(content.get(KEY_BCC))
        reply_to = EmailMessageBuilder.parse_optional(content.get(KEY_REPLY_TO))

        message: Dict = {
            "subject": content.get(KEY_SUBJECT) or "",
            "body": {
                "contentType": EmailMessageBuilder._content_type(
                    content.get(KEY_BODY_FORMAT)
                ),
                "content": content.get(KEY_BODY) or "",
            },
            "from": {"emailAddress": {"address": sender}},
            "toRecipients": EmailMessageBuilder._recipients(to_recipients),
        }
        if cc_recipients:
            message["ccRecipients"] = EmailMessageBuilder._recipients(cc_recipients)
        if bcc_recipients:
            message["bccRecipients"] = EmailMessageBuilder._recipients(bcc_recipients)
        if reply_to:
            message["replyTo"] = EmailMessageBuilder._recipients([reply_to])
        if attachments:
            message["attachments"] = EmailMessageBuilder._attachments(attachments)

        return {
            "sender": sender,
            "message": message,
            "save_to_sent": EmailMessageBuilder.parse_bool(
                content.get(KEY_SAVE_TO_SENT, True)
            ),
        }
