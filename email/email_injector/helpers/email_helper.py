from typing import Dict, List


class EmailPayloadBuilder:
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
    def build(content: Dict) -> Dict:
        return {
            "smtp_hostname": content["smtp_hostname"],
            "smtp_port": int(content["smtp_port"]),
            "smtp_use_tls": EmailPayloadBuilder.parse_bool(content.get("smtp_use_tls")),
            "smtp_username": content.get("smtp_username"),
            "smtp_password": content.get("smtp_password"),
            "from": content["from"],
            "mail_from": content.get("mail_from") or content["from"],
            "reply_to": content.get("reply_to"),
            "to": content["to"],
            "cc": EmailPayloadBuilder.parse_recipients(content.get("cc")),
            "bcc": EmailPayloadBuilder.parse_recipients(content.get("bcc")),
            "subject": content["subject"],
            "body": content["body"],
        }
