"""OpenAEV runtime boundary for the Prowler injector."""

import json
from collections.abc import Mapping
from time import monotonic

from pyoaev.helpers import OpenAEVInjectorHelper

from prowler.contracts import DEFAULT_PROWLER_CONTRACTS, ProwlerContracts
from prowler.contracts.base import BaseProwlerContract
from prowler.models import ConfigLoader
from prowler.models.provider_inputs import ProviderInput

_SAFE_EXECUTION_ERROR = "Prowler contract execution failed safely"


class ProwlerInjector:
    """Register the foundation injector without assessment contracts."""

    def __init__(
        self,
        config: ConfigLoader,
        helper: OpenAEVInjectorHelper,
        *,
        registry: ProwlerContracts = DEFAULT_PROWLER_CONTRACTS,
    ) -> None:
        """Initialize the injector with its configuration and helper."""
        self.config = config
        self.helper = helper
        self.registry = registry

    def start(self) -> None:
        """Start the injector listener after zero-contract registration."""
        self.config.to_daemon_config(self.registry)
        self.helper.listen(message_callback=self.process_message)

    def process_message(self, data: dict[str, object]) -> None:
        """Receive, validate, dispatch once, and send one terminal callback."""
        started = monotonic()
        injection = data.get("injection")
        if not isinstance(injection, Mapping):
            return
        inject_id = injection.get("inject_id")
        if not isinstance(inject_id, str) or not inject_id:
            return
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        contract: BaseProwlerContract | None = None
        provider: ProviderInput | None = None
        try:
            contract_id = self._contract_id(injection)
            content = injection.get("inject_content")
            if not isinstance(content, Mapping):
                raise ValueError("inject content is missing or invalid")
            contract = self.registry.resolve(contract_id)
            provider = contract.parse_input(content)
            outcome = contract.execute(self.config.prowler, provider)
            if outcome.error is not None or outcome.command_result.return_code != 0:
                raise RuntimeError("Prowler assessment did not complete successfully")
            duration = int(monotonic() - started)
            callback = {
                "execution_message": contract.render_trace(
                    provider, outcome.findings, duration
                ),
                "execution_output_structured": json.dumps(
                    contract.output_payload(outcome.findings),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                "execution_status": "SUCCESS",
                "execution_duration": duration,
                "execution_action": "complete",
            }
        except Exception:
            duration = int(monotonic() - started)
            callback = {
                "execution_message": self._render_safe_error(
                    contract, provider, duration
                ),
                "execution_status": "ERROR",
                "execution_duration": duration,
                "execution_action": "complete",
            }
        self.helper.api.inject.execution_callback(inject_id=inject_id, data=callback)

    @staticmethod
    def _render_safe_error(
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        duration: int,
    ) -> str:
        """Use a resolved contract's renderer without admitting exception details."""
        if contract is None:
            return _SAFE_EXECUTION_ERROR
        return contract.render_trace(
            provider,
            (),
            duration,
            is_error=True,
            error_message=_SAFE_EXECUTION_ERROR,
        )

    @staticmethod
    def _contract_id(injection: Mapping[str, object]) -> str:
        """Extract one unambiguous ID from both observed message shapes."""
        primary = injection.get("injector_contract_id")
        nested = injection.get("inject_injector_contract")
        if isinstance(nested, Mapping):
            nested_id = nested.get("injector_contract_id")
            if primary is not None and nested_id is not None and primary != nested_id:
                raise ValueError("conflicting Prowler contract identifiers")
            if primary is None:
                primary = nested_id
        converted = injection.get("convertedContent")
        fallback = (
            converted.get("contract_id") if isinstance(converted, Mapping) else None
        )
        if primary is not None and fallback is not None and primary != fallback:
            raise ValueError("conflicting Prowler contract identifiers")
        selected = primary if primary is not None else fallback
        if not isinstance(selected, str) or not selected:
            raise ValueError("Prowler contract identifier is missing")
        return selected
