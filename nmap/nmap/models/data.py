from pyoaev.helpers import OpenAEVInjectorHelper

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.targets import TargetProperty, Targets


class MessageData:
    def __init__(self, data: dict, helper: OpenAEVInjectorHelper):
        self.inject_id = data["injection"]["inject_id"]
        self.contract_id = data["injection"]["inject_injector_contract"][
            "injector_contract_id"
        ]

        content = data["injection"]["inject_content"]
        self.selector_key = content[TARGET_SELECTOR_KEY]
        self.selector_property = content[TARGET_PROPERTY_SELECTOR_KEY]

        self.target_results = Targets.extract_targets(
            self.selector_key, self.selector_property, data, helper
        )
        self.targets_meta = Targets.extract_target_meta(
            self.selector_key, self.selector_property, data, helper
        )

        self.expectation_types = [
            expectation.get("expectation_type")
            for expectation in content.get("expectations", [])
            if expectation.get("expectation_type")
        ]

        # fallback
        self.raw_data = data

    def get_targets(self) -> list:
        targets = self.target_results.targets
        # Handle empty targets as an error
        if not targets:
            message = (
                "No target identified for the property "
                + self._selector_property_label()
            )
            raise ValueError(message)

        return targets

    def _selector_property_label(self) -> str:
        # The selector property comes straight from the payload; resolve its
        # human-readable label defensively so an unexpected value still yields
        # the intended ValueError message instead of a KeyError/AttributeError
        # exposing the raw enum key.
        try:
            return TargetProperty[self.selector_property.upper()].value
        except (KeyError, AttributeError):
            return str(self.selector_property)
