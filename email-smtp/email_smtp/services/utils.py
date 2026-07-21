import re
from typing import Dict, List, Optional

from email_smtp.models.exceptions import CustomHeaderValidationError

HEADER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")


class EmailPayloadBuilder:
    @staticmethod
    def parse_optional_email(value: str | None) -> Optional[str]:
        if not value:
            return None
        stripped = value.strip()
        return stripped or None

    @staticmethod
    def parse_recipients(value: str | None) -> List[str]:
        if not value:
            return []
        return [
            recipient.strip() for recipient in value.split(",") if recipient.strip()
        ]

    @staticmethod
    def parse_bool(value: bool | str | None) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return False

    @staticmethod
    def parse_custom_headers(value: str | None) -> List[tuple[str, str]]:
        if not value:
            return []

        headers: List[tuple[str, str]] = []
        for line_number, raw_line in enumerate(value.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            if ":" not in line:
                raise CustomHeaderValidationError(
                    f"Invalid custom header at line {line_number}: expected 'name: value'"
                )

            header_name, header_value = line.split(":", 1)
            header_name = header_name.strip()
            header_value = header_value.strip()

            if not header_name:
                raise CustomHeaderValidationError(
                    f"Invalid custom header at line {line_number}: header name is required"
                )
            if not HEADER_NAME_PATTERN.fullmatch(header_name):
                raise CustomHeaderValidationError(
                    f"Invalid custom header at line {line_number}: unsafe header name"
                )
            if not header_value:
                raise CustomHeaderValidationError(
                    f"Invalid custom header at line {line_number}: header value is required"
                )
            if any(ord(char) < 32 or ord(char) == 127 for char in header_value):
                raise CustomHeaderValidationError(
                    f"Invalid custom header at line {line_number}: unsafe header value"
                )

            headers.append((header_name, header_value))

        return headers

    @staticmethod
    def build(content: Dict) -> Dict:
        return {
            "smtp_hostname": content["smtp_hostname"],
            "smtp_port": int(content["smtp_port"]),
            "smtp_use_tls": EmailPayloadBuilder.parse_bool(content.get("smtp_use_tls")),
            "smtp_username": content.get("smtp_username"),
            "smtp_password": content.get("smtp_password"),
            "from": content["from"],
            "mail_from": EmailPayloadBuilder.parse_optional_email(
                content.get("mail_from")
            )
            or content["from"],
            "reply_to": EmailPayloadBuilder.parse_optional_email(
                content.get("reply_to")
            ),
            "to": content["to"],
            "cc": EmailPayloadBuilder.parse_recipients(content.get("cc")),
            "bcc": EmailPayloadBuilder.parse_recipients(content.get("bcc")),
            "subject": content["subject"],
            "body": content["body"],
            "custom_headers": EmailPayloadBuilder.parse_custom_headers(
                content.get("custom_headers")
            ),
        }
