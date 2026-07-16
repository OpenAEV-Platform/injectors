from pyoaev.helpers import OpenAEVInjectorHelper

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.targets import TargetProperty, Targets


class MessageData:
    def __init__(self, data: dict, helper: OpenAEVInjectorHelper):
        self.inject_id = data["injection"]["inject_id"]
        self.contract_id = data["injection"]["inject_injector_contract"][
            "injector_contract_id"
        ]

        self.inject_content = data["injection"]["inject_content"]
        self.selector_key = self.inject_content[TARGET_SELECTOR_KEY]
        self.selector_property = self.inject_content[TARGET_PROPERTY_SELECTOR_KEY]

        self.target_results = Targets.extract_targets(
            self.selector_key, self.selector_property, data, helper
        )
        self.targets_meta = Targets.extract_target_meta(
            self.selector_key, self.selector_property, data, helper
        )

        self.expectation_types = [
            expectation.get("expectation_type")
            for expectation in self.inject_content.get("expectations", [])
            if expectation.get("expectation_type")
        ]

        # fallback
        self.raw_data = data

    def get_targets(self) -> list:
        targets = self.target_results.targets
        # Handle empty targets as an error
        if not targets:
            message = f"No target identified for the property {TargetProperty[self.selector_property.upper()].value}"
            raise ValueError(message)

        return targets
