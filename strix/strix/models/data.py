from pyoaev.helpers import OpenAEVInjectorHelper

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.targets import TargetProperty, Targets
from strix.strix_contracts.strix_constants import CODE_ASSESSMENT_CONTRACT


class MessageData:
    """Unpacks a RabbitMQ inject payload into the fields the injector needs.

    Two contract shapes are supported:
      * network / web / API assessment - targets come from OpenAEV assets,
        asset groups or a manual list (the shared Targets helper);
      * code assessment - a single repository URL / path in the content, with
        no asset resolution.
    """

    def __init__(self, data: dict, helper: OpenAEVInjectorHelper):
        self.inject_id = data["injection"]["inject_id"]
        self.contract_id = data["injection"]["inject_injector_contract"][
            "injector_contract_id"
        ]

        self.inject_content = data["injection"]["inject_content"]
        self.is_code_assessment = self.contract_id == CODE_ASSESSMENT_CONTRACT

        if self.is_code_assessment:
            # Code target: no asset resolution, an empty asset map so the parser
            # and per-target traces behave uniformly with the network path.
            self.selector_key = "manual"
            self.selector_property = TargetProperty.AUTOMATIC.name.lower()
            self.target_results = None
            self.targets_meta = []
            self.ip_to_asset_id_map = {}
        else:
            self.selector_key = self.inject_content[TARGET_SELECTOR_KEY]
            self.selector_property = self.inject_content[TARGET_PROPERTY_SELECTOR_KEY]
            self.target_results = Targets.extract_targets(
                self.selector_key, self.selector_property, data, helper
            )
            self.targets_meta = Targets.extract_target_meta(
                self.selector_key, self.selector_property, data, helper
            )
            self.ip_to_asset_id_map = self.target_results.ip_to_asset_id_map

        self.expectation_types = [
            expectation.get("expectation_type")
            for expectation in self.inject_content.get("expectations", [])
            if expectation.get("expectation_type")
        ]

        self.raw_data = data

    def get_targets(self) -> list:
        """Return the target list to hand to Strix (--target values)."""
        if self.is_code_assessment:
            repository = (self.inject_content.get("repository") or "").strip()
            if not repository:
                raise ValueError("No code target (repository) provided for the inject")
            return [repository]

        targets = self.target_results.targets
        if not targets:
            raise ValueError(
                "No target identified for the property "
                + self._selector_property_label()
            )
        return targets

    def _selector_property_label(self) -> str:
        try:
            return TargetProperty[self.selector_property.upper()].value
        except (KeyError, AttributeError):
            return str(self.selector_property)
