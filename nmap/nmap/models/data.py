from pyoaev.helpers import OpenAEVInjectorHelper

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.targets import TargetProperty, Targets
from nmap.contracts.nmap_constants import TUNING_KEYS


class MessageData:
    def __init__(self, data: dict, helper: OpenAEVInjectorHelper):
        self.inject_id = data["injection"]["inject_id"]
        self.contract_id = data["injection"]["inject_injector_contract"][
            "injector_contract_id"
        ]

        content = data["injection"]["inject_content"]
        self.selector_key = content[TARGET_SELECTOR_KEY]
        # The contract shows the property selector for assets and asset groups
        # only: a manual target list carries no such field, so default it.
        self.selector_property = content.get(
            TARGET_PROPERTY_SELECTOR_KEY, TargetProperty.AUTOMATIC.name.lower()
        )

        self.target_results = Targets.extract_targets(
            self.selector_key, self.selector_property, data, helper
        )
        self.targets_meta = Targets.extract_target_meta(
            self.selector_key, self.selector_property, data, helper
        )

        # Optional timing, retry and port selection fields, validated when the
        # command is built.
        self.scan_options = {key: content.get(key) for key in TUNING_KEYS}

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
            # Every asset was skipped: say how many and why, one line per asset.
            if Targets.skipped_of(self.target_results):
                message += ": " + self.target_results.describe_skipped()
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
