"""Universal selectable CHK.017 contract over the unchanged CHK.004 seam."""

import threading
from dataclasses import dataclass, replace
from typing import ClassVar, Mapping, Sequence, cast, get_args

from pydantic import ValidationError
from pyoaev.contracts.contract_config import ContractElement, ContractSelect
from pyoaev.contracts.contract_utils import ContractCardinality
from pyoaev.credential.utils import build_single_referenced_credential_element

from prowler._core.prowler_client import ComplianceSelector, ServiceSelector
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.findings import OcsfPreviewRecord, OpenAevFinding
from prowler.models.provider_inputs import (PROVIDER_INPUT_ADAPTER,
                                            AwsProviderInput,
                                            AzureProviderInput,
                                            GcpProviderInput,
                                            KubernetesProviderInput,
                                            ProviderInput)
from prowler.services.output_trace import generate

from .base import (CREDENTIAL_REFERENCE_KEY, BaseProwlerContract,
                   ClientFactoryPort, ContractExecutionOutcome,
                   ContractInputError, ContractInputIssue)
from .provider_fields import _PROVIDER_FIELDS, ProviderName
from .provider_fields import build_provider_fields as _build_provider_fields
from .registry import stable_contract_id
from .selectable import SERVICE_SELECT_VALUES, STATIC_SELECT_LABELS

__all__ = [
    "COMPLIANCE_SCOPE_CHOICES",
    "COMPLIANCE_SCOPE_OPTIONS",
    "SERVICE_SCOPE_CHOICES",
    "SERVICE_SCOPE_OPTIONS",
    "ScopeOption",
    "UniversalProwlerContract",
]

PROVIDER_KEY = "prowler_provider"
SERVICE_KEYS: Mapping[str, str] = {
    "aws": "prowler_service_aws",
    "azure": "prowler_service_azure",
    "gcp": "prowler_service_gcp",
}
COMPLIANCE_KEY = "prowler_compliance"
_SELECT_KEYS = (PROVIDER_KEY, *SERVICE_KEYS.values(), COMPLIANCE_KEY)
NONE_SCOPE = "__none__"
NONE_SCOPE_LABEL = "None (base scan)"
PROVIDER_SELECT_VALUES = ("aws", "azure", "gcp", "kubernetes")

# Human labels for the provider select and the two literals that
# selectable.STATIC_SELECT_LABELS does not cover.
PROVIDER_SELECT_LABELS: Mapping[str, str] = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "kubernetes": "Kubernetes",
}
KUBERNETES_STATIC_SELECT_LABELS: Mapping[str, str] = {
    "cis_1.12_kubernetes": "CIS 1.12 (Kubernetes)",
    "iso27001_2022_kubernetes": "ISO 27001:2022 (Kubernetes)",
}


@dataclass(frozen=True, slots=True)
class ScopeOption:
    """One offered scope: canonical route, provider, and CHK.004 literal."""

    route: str
    provider: str
    literal: str


def _compliance_route_parts(literal: str) -> tuple[str, str]:
    """Split one compliance literal into (framework, provider)."""
    provider = literal.rsplit("_", maxsplit=1)[1]
    framework = literal.rsplit("_", maxsplit=1)[0].split("_", maxsplit=1)[0]
    return framework, provider


# Single derivation site: the six contracts' own service values and the
# CHK.004 compliance selector literals; no third copy of either set.
SERVICE_SCOPE_OPTIONS: tuple[ScopeOption, ...] = tuple(
    ScopeOption(f"{provider}/{value}", provider, value)
    for provider, values in SERVICE_SELECT_VALUES.items()
    for value in values
)

COMPLIANCE_SCOPE_OPTIONS: tuple[ScopeOption, ...] = tuple(
    ScopeOption(f"{framework}/{provider}", provider, literal)
    for literal in get_args(ComplianceSelector)
    for framework, provider in (_compliance_route_parts(literal),)
)

SERVICE_SCOPE_BY_ROUTE: Mapping[str, ScopeOption] = {
    option.route: option for option in SERVICE_SCOPE_OPTIONS
}
COMPLIANCE_SCOPE_BY_ROUTE: Mapping[str, ScopeOption] = {
    option.route: option for option in COMPLIANCE_SCOPE_OPTIONS
}


def _service_scope_label(option: "ScopeOption") -> str:
    """Build the provider-qualified label for one service scope option."""
    label = STATIC_SELECT_LABELS[option.literal]
    return f"{label} ({PROVIDER_SELECT_LABELS[option.provider]})"


SERVICE_SCOPE_CHOICES: Mapping[str, str] = {
    option.route: _service_scope_label(option) for option in SERVICE_SCOPE_OPTIONS
}
COMPLIANCE_SCOPE_CHOICES: Mapping[str, str] = {
    option.route: (
        KUBERNETES_STATIC_SELECT_LABELS[option.literal]
        if option.literal in KUBERNETES_STATIC_SELECT_LABELS
        else STATIC_SELECT_LABELS[option.literal]
    )
    for option in COMPLIANCE_SCOPE_OPTIONS
}

_CREDENTIAL_FIELD_KEYS: Mapping[ProviderName, tuple[str, ...]] = {
    provider: tuple(spec.key for spec in specs)
    for provider, specs in _PROVIDER_FIELDS.items()
}


def _select_input_error(
    location: tuple[str, ...], error_type: str
) -> ContractInputError:
    """Build the single value-free issue for one select rejection."""
    return ContractInputError.from_validation(
        (ContractInputIssue(location, error_type),)
    )


class UniversalProwlerContract(BaseProwlerContract):
    """Pick one provider and optionally one service or one compliance route.

    The registry holds one shared instance per contract, but the pinned
    pyoaev 2.260521.0 ``ListenQueue._process_message`` acks each RabbitMQ
    message on receipt and then starts a fresh worker thread for that
    message, so same-contract injections process concurrently against the
    shared instance. Binding the parsed provider and both scope selections
    to the parsing worker thread keeps them private per injection, and the
    reset at the top of every ``parse_input`` guarantees that a failed parse
    never exposes a prior selection on a reused thread.
    """

    contract_id: ClassVar[str] = str(stable_contract_id("universal"))
    external_id: ClassVar[str] = "prowler:universal"
    route_name: ClassVar[str] = "universal"
    provider = "all"
    family = "universal"
    label: ClassVar[str] = "Prowler Universal"

    def __init__(self, client_factory: ClientFactoryPort | None = None) -> None:
        """Start the instance with no worker thread holding a selection."""
        super().__init__(client_factory)
        self._selection = threading.local()

    def build_provider_fields(self) -> list[ContractElement]:
        """Declare the provider select, conditional credentials, and scope selects.

        pyoaev pins one immutable key on every credential-reference element, so
        the four provider field sets cannot each contribute one without
        colliding. This form therefore exposes exactly one unconditioned
        credential reference, built from the ``all`` meta-token so the platform
        applies no provider-specific credential filter: the operator picks the
        provider through ``prowler_provider`` instead.
        """
        fields: list[ContractElement] = [
            ContractSelect(
                key=PROVIDER_KEY,
                label="Provider (select one)",
                mandatory=True,
                cardinality=ContractCardinality.One.value,
                defaultValue=["aws"],
                choices=dict(PROVIDER_SELECT_LABELS),
                visibleConditionFields=[],
                visibleConditionValues={},
                mandatoryConditionFields=[],
                mandatoryConditionValues={},
            ),
            build_single_referenced_credential_element(self.provider),
        ]
        for provider_name in _CREDENTIAL_FIELD_KEYS:
            for element in _build_provider_fields(provider_name):
                if element.key == CREDENTIAL_REFERENCE_KEY:
                    continue
                element.visibleConditionFields = [PROVIDER_KEY]
                element.visibleConditionValues = {PROVIDER_KEY: provider_name}
                if element.mandatory:
                    element.mandatoryConditionFields = [PROVIDER_KEY]
                    element.mandatoryConditionValues = {PROVIDER_KEY: provider_name}
                    element.mandatory = False
                else:
                    element.mandatoryConditionFields = []
                    element.mandatoryConditionValues = {}
                fields.append(element)
        for service_provider, service_key in SERVICE_KEYS.items():
            fields.append(
                ContractSelect(
                    key=service_key,
                    label="Service (select one)",
                    mandatory=False,
                    cardinality=ContractCardinality.One.value,
                    defaultValue=[NONE_SCOPE],
                    choices={
                        NONE_SCOPE: NONE_SCOPE_LABEL,
                        **{
                            option.route: SERVICE_SCOPE_CHOICES[option.route]
                            for option in SERVICE_SCOPE_OPTIONS
                            if option.provider == service_provider
                        },
                    },
                    visibleConditionFields=[PROVIDER_KEY],
                    visibleConditionValues={PROVIDER_KEY: service_provider},
                    mandatoryConditionFields=[],
                    mandatoryConditionValues={},
                )
            )
        fields.append(
            ContractSelect(
                key=COMPLIANCE_KEY,
                label="Compliance framework (select one)",
                mandatory=False,
                cardinality=ContractCardinality.One.value,
                defaultValue=[NONE_SCOPE],
                choices={NONE_SCOPE: NONE_SCOPE_LABEL, **COMPLIANCE_SCOPE_CHOICES},
                visibleConditionFields=[],
                visibleConditionValues={},
                mandatoryConditionFields=[],
                mandatoryConditionValues={},
            )
        )
        return fields

    def parse_input(self, raw_input: Mapping[str, object]) -> ProviderInput:
        """Validate the closed selects before the strict provider model."""
        # Clear this thread's selection before any rejection path can run,
        # so no early return can expose a selection from an earlier parse.
        self._selection.provider = None
        self._selection.service_route = None
        self._selection.compliance_route = None
        if "provider" in raw_input:
            raise _select_input_error(("provider",), "extra_forbidden")
        selected_provider = self._parse_provider_select(raw_input)
        service_key = SERVICE_KEYS.get(selected_provider)
        service_route = self._parse_scope_select(
            raw_input,
            service_key,
            SERVICE_SCOPE_BY_ROUTE,
        )
        compliance_route = self._parse_scope_select(
            raw_input, COMPLIANCE_KEY, COMPLIANCE_SCOPE_BY_ROUTE
        )
        if service_route is not None and compliance_route is not None:
            if service_key is None:
                raise RuntimeError("a selected service route requires a service key")
            raise _select_input_error((service_key, COMPLIANCE_KEY), "scope_conflict")
        for key, route, options in (
            (service_key, service_route, SERVICE_SCOPE_BY_ROUTE),
            (COMPLIANCE_KEY, compliance_route, COMPLIANCE_SCOPE_BY_ROUTE),
        ):
            if (
                key is not None
                and route is not None
                and options[route].provider != selected_provider
            ):
                raise _select_input_error((key,), "scope_provider_mismatch")
        foreign_keys = {
            key
            for provider_name, keys in _CREDENTIAL_FIELD_KEYS.items()
            if provider_name != selected_provider
            for key in keys
        }
        candidate = {
            key: value
            for key, value in raw_input.items()
            if key not in _SELECT_KEYS
            and key not in foreign_keys
            and key != CREDENTIAL_REFERENCE_KEY
        }
        if selected_provider == "aws":
            for field in ("aws_session_token", "aws_endpoint_url"):
                value = candidate.get(field)
                if type(value) is str and value == "":
                    candidate[field] = None
        candidate["provider"] = selected_provider
        try:
            parsed = PROVIDER_INPUT_ADAPTER.validate_python(candidate)
        except ValidationError as error:
            issues = tuple(
                ContractInputIssue(
                    tuple(str(part) for part in item["loc"]),
                    item["type"],
                )
                for item in error.errors(
                    include_url=False, include_context=False, include_input=False
                )
            )
            raise ContractInputError.from_validation(issues) from None
        self._selection.provider = selected_provider
        self._selection.service_route = service_route
        self._selection.compliance_route = compliance_route
        return parsed

    @staticmethod
    def _parse_provider_select(raw_input: Mapping[str, object]) -> str:
        """Validate the mandatory closed provider select."""
        submitted = raw_input.get(PROVIDER_KEY)
        if submitted is None or submitted == "" or submitted == []:
            raise _select_input_error((PROVIDER_KEY,), "select_missing")
        if isinstance(submitted, list):
            if len(submitted) > 1:
                raise _select_input_error((PROVIDER_KEY,), "select_multiple")
            element = submitted[0]
        else:
            element = submitted
        if type(element) is not str or element not in PROVIDER_SELECT_VALUES:
            raise _select_input_error((PROVIDER_KEY,), "select_unknown_value")
        return element

    @staticmethod
    def _parse_scope_select(
        raw_input: Mapping[str, object],
        key: str | None,
        options: Mapping[str, ScopeOption],
    ) -> str | None:
        """Validate one optional closed scope select, reporting None when empty."""
        if key is None or key not in raw_input:
            return None
        submitted = raw_input[key]
        if submitted is None or submitted == "" or submitted == []:
            return None
        if isinstance(submitted, list):
            if len(submitted) > 1:
                raise _select_input_error((key,), "select_multiple")
            element = submitted[0]
        else:
            element = submitted
        if element == NONE_SCOPE:
            return None
        if type(element) is not str or element not in options:
            raise _select_input_error((key,), "select_unknown_value")
        return element

    def _selection_state(self) -> tuple[str | None, str | None, str | None]:
        """Return (provider, service route, compliance route) held by this thread."""
        provider = getattr(self._selection, "provider", None)
        service_route = getattr(self._selection, "service_route", None)
        compliance_route = getattr(self._selection, "compliance_route", None)
        return (
            provider if isinstance(provider, str) else None,
            service_route if isinstance(service_route, str) else None,
            compliance_route if isinstance(compliance_route, str) else None,
        )

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run the held provider scope exactly once through the CHK.004 seam."""
        held_provider, service_route, compliance_route = self._selection_state()
        if held_provider is None:
            raise ValueError(
                "universal requires a parsed provider selection before execution"
            )
        if not self._provider_model_matches(held_provider, provider):
            raise ValueError(
                "universal requires a provider input matching its parsed selection"
            )
        if service_route is not None:
            return self._execute_service(
                config,
                provider,
                cast(ServiceSelector, SERVICE_SCOPE_BY_ROUTE[service_route].literal),
            )
        if compliance_route is not None:
            return self._execute_compliance(
                config,
                provider,
                cast(
                    ComplianceSelector,
                    COMPLIANCE_SCOPE_BY_ROUTE[compliance_route].literal,
                ),
            )
        outcome = super().execute(config, provider)
        if outcome.error is not None or outcome.command_result.return_code != 0:
            return outcome
        return replace(
            outcome,
            findings=self._provider_findings(outcome.findings),
        )

    @staticmethod
    def _provider_model_matches(provider_name: str, provider: ProviderInput) -> bool:
        """Return True only when the model class matches the held provider name."""
        if provider_name == "aws":
            return type(provider) is AwsProviderInput
        if provider_name == "azure":
            return type(provider) is AzureProviderInput
        if provider_name == "gcp":
            return type(provider) is GcpProviderInput
        return type(provider) is KubernetesProviderInput

    def _provider_findings(
        self, findings: Sequence[OpenAevFinding]
    ) -> tuple[OpenAevFinding, ...]:
        """Retain source order and normalize findings for the held provider."""
        held_provider, _service_route, _compliance_route = self._selection_state()
        if held_provider is None:
            return ()
        return tuple(
            finding.model_copy(update={"cloud_provider": held_provider})
            for finding in findings
            if finding.cloud_provider.casefold() == held_provider
        )

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Report the held scope and provider as closed literals only."""
        info = super().safe_request_info(provider)
        held_provider, service_route, compliance_route = self._selection_state()
        if provider is None or held_provider is None:
            info["filters"] = "unselected"
            info["selected_provider"] = "unselected"
        elif service_route is not None:
            info["filters"] = f"service={service_route}"
            info["selected_provider"] = held_provider
        elif compliance_route is not None:
            info["filters"] = f"compliance={compliance_route}"
            info["selected_provider"] = held_provider
        else:
            info["filters"] = "base"
            info["selected_provider"] = held_provider
        return info

    def render_trace(
        self,
        provider: ProviderInput | None,
        findings: Sequence[OpenAevFinding],
        duration: int,
        *,
        raw_record_count: int = 0,
        raw_output_bytes: int = 0,
        raw_preview: Sequence[OcsfPreviewRecord] = (),
        is_error: bool = False,
        error_message: str = "",
    ) -> str:
        """Render the trace with the held provider name and closed error channel.

        ``provider_name`` resolves to the parsed provider model, else the held
        provider selection, else ``"unselected"`` — never the ``all`` meta-token.
        The error channel carries the injector's closed failure classification
        (static kinds, summaries, and sanitized statics), exactly as the fixed
        routes forward it; raw exception text, credentials, stderr, temp paths,
        and form text never reach the trace.
        """
        held_provider, _service_route, _compliance_route = self._selection_state()
        provider_name: str = (
            provider.provider
            if provider is not None
            else (held_provider or "unselected")
        )
        return generate(
            route_name=self.route_name,
            provider_name=provider_name,
            request_info=self.safe_request_info(provider),
            findings=findings,
            raw_record_count=raw_record_count,
            raw_output_bytes=raw_output_bytes,
            raw_preview=raw_preview,
            duration=duration,
            trace_config=self.output_trace_config(),
            is_error=is_error,
            error_message=error_message,
        )
