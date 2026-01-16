from typing import Dict


class DataHelpers:

    @staticmethod
    def get_injector_contract_id(data: Dict) -> str:
        try:
            return data["injection"]["inject_injector_contract"]["injector_contract_id"]
        except KeyError as e:
            raise ValueError("Invalid data: missing injector contract id") from e

    @staticmethod
    def get_content(data: Dict) -> Dict:
        try:
            return data["injection"]["inject_content"]
        except KeyError as e:
            raise ValueError("Invalid data: missing inject content") from e

    @staticmethod
    def get_inject_id(data: Dict) -> str:
        try:
            return data["injection"]["inject_id"]
        except KeyError as e:
            raise ValueError("Invalid data: missing inject id") from e
