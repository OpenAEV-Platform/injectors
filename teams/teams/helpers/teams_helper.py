from typing import Dict


class TeamsPayloadBuilder:

    @staticmethod
    def build(content: Dict) -> Dict:
        return {
            "title": content["title"],
            "message": content["message"],
        }
