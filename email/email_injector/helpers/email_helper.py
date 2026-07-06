from typing import Dict


class EmailPayloadBuilder:

    @staticmethod
    def build(content: Dict) -> Dict:
        return {
            "from": content["from"],
            "to": content["to"],
            "subject": content["subject"],
            "body": content["body"],
        }
