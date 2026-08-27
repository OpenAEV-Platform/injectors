"""Executable CHK.006 contract-base behaviour specification."""

from __future__ import annotations

import importlib
import inspect
import json
from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import SecretStr

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import (
    AwsProviderInput,
    AzureProviderInput,
    GcpProviderInput,
    KubernetesProviderInput,
)


def _subject() -> Any:
    try:
        return importlib.import_module("prowler.contracts")
    except ModuleNotFoundError as error:
        pytest.fail(f"CHK.006 contract base is not implemented: {error}")


PROVIDER_CASES = {
    "aws": (
        AwsProviderInput,
        {
            "aws_access_key_id": "AKIA_TEST_PLACEHOLDER",
            "aws_secret_access_key": "aws-secret-placeholder",
            "aws_account_id": "123456789012",
            "aws_region": "eu-west-1",
        },
    ),
    "azure": (
        AzureProviderInput,
        {
            "azure_tenant_id": "tenant-placeholder",
            "azure_client_id": "client-placeholder",
            "azure_client_secret": "azure-secret-placeholder",
            "azure_subscription_id": "subscription-placeholder",
            "azure_provider": "AzureCloud",
        },
    ),
    "gcp": (
        GcpProviderInput,
        {
            "gcp_service_account_json": (
                '{"type":"service_account","private_key":"placeholder"}'
            ),
            "gcp_project_id": "project-placeholder",
        },
    ),
    "kubernetes": (
        KubernetesProviderInput,
        {
            "kubernetes_kubeconfig": "apiVersion: v1\nkind: Config\n",
            "kubernetes_context": "context-placeholder",
        },
    ),
}


def _contract_class(provider: str, **overrides: Any) -> type[Any]:
    subject = _subject()
    attributes = {
        "contract_id": "9d5b71f8-f36f-50ee-a896-d7ff41f541f9",
        "external_id": "CHK.006.TEST",
        "route_name": provider,
        "provider": provider,
        "family": "base",
        "label": f"Prowler {provider} test",
        "check_filters": ("first-check", "second-check"),
        **overrides,
    }
    return type(
        f"Test{provider.title()}Contract", (subject.BaseProwlerContract,), attributes
    )


def _specification() -> ExecutionSpecification:
    return ExecutionSpecification(
        executable="/usr/local/bin/prowler",
        arguments=(),
        environment=(),
        working_directory=None,
        input_bytes=b"",
        output=OutputSpecification(),
        timeout_seconds=1.0,
        maximum_accepted_output_bytes=1024,
    )


@dataclass
class _Factory:
    result: CommandResult
    calls: list[tuple[Any, Any, tuple[str, ...]]] = field(default_factory=list)

    def run(
        self, config: Any, provider: Any, *, check_filters: Any = ()
    ) -> CommandResult:
        self.calls.append((config, provider, tuple(check_filters)))
        return self.result


def test_minimal_subclass_builds_provider_specific_openaev_contract() -> None:
    """A subclass supplies IDs and receives only its provider's fields."""
    assert inspect.isabstract(_subject().BaseProwlerContract)
    contract = _contract_class("aws")().build_contract()

    assert contract.contract_id == "9d5b71f8-f36f-50ee-a896-d7ff41f541f9"
    assert contract.external_id == "CHK.006.TEST"
    fields = {item.key: item for item in contract.fields}
    assert tuple(fields) == tuple(PROVIDER_CASES["aws"][1]) + ("aws_session_token",)
    assert "plaintext" in fields["aws_secret_access_key"].label.lower()
    assert "plaintext" in fields["aws_session_token"].label.lower()
    assert all(field.defaultValue == "" for field in fields.values())
    assert fields["aws_session_token"].mandatory is False
    assert all(
        field.mandatory for key, field in fields.items() if key != "aws_session_token"
    )


@pytest.mark.parametrize("provider", tuple(PROVIDER_CASES))
def test_provider_input_is_converted_immediately_to_strict_model(provider: str) -> None:
    """Each provider's raw form data enters the exact CHK.002 model."""
    expected_type, raw = PROVIDER_CASES[provider]

    parsed = _contract_class(provider)().parse_input(dict(raw))

    assert type(parsed) is expected_type
    secret_fields = {
        "aws": ("aws_secret_access_key",),
        "azure": ("azure_client_secret",),
        "gcp": ("gcp_service_account_json",),
        "kubernetes": ("kubernetes_kubeconfig",),
    }[provider]
    assert all(isinstance(getattr(parsed, key), SecretStr) for key in secret_fields)


def test_invalid_input_error_contains_structure_but_not_raw_values() -> None:
    """Validation reports safe locations without rejected values."""
    subject = _subject()
    marker = "DO_NOT_ECHO_THIS_CREDENTIAL"
    raw = {**PROVIDER_CASES["aws"][1], "aws_secret_access_key": marker}
    raw["azure_client_secret"] = "cross-provider-placeholder"  # noqa: S105

    with pytest.raises(subject.ContractInputError) as raised:
        _contract_class("aws")().parse_input(raw)

    rendered = str(raised.value)
    details = repr(raised.value.issues)
    assert "azure_client_secret" in rendered
    assert marker not in rendered
    assert marker not in details
    assert "cross-provider-placeholder" not in rendered
    assert "cross-provider-placeholder" not in details


def test_execution_preserves_exact_command_error_without_mapping() -> None:
    """Expected command failure objects cross the base unchanged."""
    exact_error = RuntimeError("safe command failure")
    factory = _Factory(CommandResult(specification=_specification(), error=exact_error))
    instance = _contract_class("aws")(client_factory=factory)
    provider = instance.parse_input(dict(PROVIDER_CASES["aws"][1]))

    outcome = instance.execute(ProwlerConfig(), provider)

    assert outcome.error is exact_error
    assert outcome.findings == ()
    assert len(factory.calls) == 1


def test_execution_maps_success_and_passes_route_filters_once(
    ocsf_record: dict[str, Any],
) -> None:
    """Successful raw output is mapped after one filtered client run."""
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=json.dumps([ocsf_record]).encode(),
    )
    factory = _Factory(result)
    instance = _contract_class("aws")(client_factory=factory)
    provider = instance.parse_input(dict(PROVIDER_CASES["aws"][1]))

    outcome = instance.execute(ProwlerConfig(), provider)

    assert outcome.error is None
    assert len(outcome.findings) == 1
    assert factory.calls[0][2] == ("first-check", "second-check")
    assert len(factory.calls) == 1


EXPECTED_ROUTES = (
    ("aws", "aws", "base"),
    ("azure", "azure", "base"),
    ("gcp", "gcp", "base"),
    ("kubernetes", "kubernetes", "base"),
    ("aws/iam", "aws", "service"),
    ("aws/s3", "aws", "service"),
    ("aws/ec2", "aws", "service"),
    ("azure/iam", "azure", "service"),
    ("azure/storage", "azure", "service"),
    ("gcp/iam", "gcp", "service"),
    ("gcp/compute", "gcp", "service"),
    ("cis/aws", "aws", "compliance"),
    ("cis/azure", "azure", "compliance"),
    ("cis/gcp", "gcp", "compliance"),
    ("cis/kubernetes", "kubernetes", "compliance"),
    ("nis2/aws", "aws", "compliance"),
    ("nis2/azure", "azure", "compliance"),
    ("nis2/gcp", "gcp", "compliance"),
    ("iso27001/aws", "aws", "compliance"),
    ("iso27001/azure", "azure", "compliance"),
    ("iso27001/gcp", "gcp", "compliance"),
    ("iso27001/kubernetes", "kubernetes", "compliance"),
    ("mitre/aws", "aws", "compliance"),
    ("mitre/azure", "azure", "compliance"),
    ("mitre/gcp", "gcp", "compliance"),
)


def test_route_catalog_is_the_immutable_canonical_catalog() -> None:
    """All 25 provider/family route descriptors stay fixed and ordered."""
    catalog = _subject().ROUTE_CATALOG
    assert type(catalog) is tuple
    assert (
        tuple((r.route_name, r.provider, r.family) for r in catalog) == EXPECTED_ROUTES
    )
    assert all(
        "/" in route.route_name or route.route_name in PROVIDER_CASES
        for route in catalog
    )


def test_filtering_deduplicates_in_canonical_order() -> None:
    """Filtering uses set membership but emits catalog order."""
    dispatcher = _subject().ContractDispatcher({})
    filtered = dispatcher.filter_routes(("gcp/compute", "aws", "aws", "aws/iam"))
    assert tuple(route.route_name for route in filtered) == (
        "aws",
        "aws/iam",
        "gcp/compute",
    )


def test_dispatch_delegates_once_and_returns_exact_result() -> None:
    """A known implemented route delegates once without result wrapping."""
    expected = object()
    calls: list[tuple[str, object]] = []

    def handler(route: Any, request: object) -> object:
        calls.append((route.route_name, request))
        return expected

    request = object()
    result = _subject().ContractDispatcher({"aws": handler}).dispatch("aws", request)
    assert result is expected
    assert calls == [("aws", request)]


def test_unknown_dispatch_is_rejected_before_handler() -> None:
    """An unknown route cannot reach any injected handler."""
    subject = _subject()
    calls: list[object] = []

    def handler(route: Any, request: object) -> object:
        calls.append(request)
        return object()

    with pytest.raises(subject.RouteNotFoundError):
        subject.ContractDispatcher({"aws": handler}).dispatch("unknown/route", object())
    assert calls == []


def test_startup_remains_zero_contract_registration() -> None:
    """Declarations do not mutate the CHK.001 startup surface."""
    from unittest.mock import Mock

    from prowler.injector import ProwlerInjector

    config = Mock()
    helper = Mock()
    ProwlerInjector(config, helper).start()
    assert helper.register_contracts.call_count == 0
