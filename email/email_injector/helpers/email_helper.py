from typing import Dict


class EmailPayloadBuilder:

    @staticmethod
    def build(content: Dict) -> Dict:
        return {
            "smtp_hostname": content["smtp_hostname"],
            "smtp_port": int(content["smtp_port"]),
            "smtp_use_tls": content.get("smtp_use_tls", False),
            "smtp_username": content.get("smtp_username"),
            "smtp_password": content.get("smtp_password"),
            "from": content["from"],
            "to": content["to"],
            "subject": content["subject"],
            "body": content["body"],
        }
