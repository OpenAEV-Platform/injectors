"""Credential-reference path of the contract input boundary."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar
from unittest.mock import Mock

import pytest
from pyoaev.credential import CredentialAttachment  # type: ignore[import-untyped]

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
    ContractInputIssue,
    ProwlerContracts,
    stable_contract_id,
)
from prowler.models.provider_inputs import (
    LEGACY_CREDENTIAL_KEYS,
    AwsProviderInput,
    AwsReferenceProviderInput,
    AzureProviderInput,
    AzureReferenceProviderInput,
    CredentialReferenceProviderInput,
    GcpProviderInput,
    GcpReferenceProviderInput,
    KubernetesProviderInput,
    KubernetesReferenceProviderInput,
)

REFERENCE = "3f1c1e5e-0000-4000-8000-000000000001"
AUTHORISATION_CODE = "AUTHORISATION-CODE-CANARY"
ATTACHMENT = CredentialAttachment(REFERENCE, AUTHORISATION_CODE)

NON_CREDENTIAL_FORMS: dict[str, dict[str, str]] = {
    "aws": {"aws_account_id": "123456789012", "aws_region": "eu-west-1"},
    "azure": {
        "azure_subscription_id": "subscription-id",
        "azure_provider": "AzureCloud",
    },
    "gcp": {"gcp_project_id": "project-id"},
    "kubernetes": {"kubernetes_context": "context-id"},
}
LEGACY_CREDENTIAL_FORMS: dict[str, dict[str, str]] = {
    "aws": {
        "aws_access_key_id": "LEGACY-ACCESS-KEY-CANARY",
        "aws_secret_access_key": "LEGACY-SECRET-CANARY",
        "aws_session_token": "LEGACY-TOKEN-CANARY",
    },
    "azure": {
        "azure_tenant_id": "LEGACY-TENANT-CANARY",
        "azure_client_id": "LEGACY-CLIENT-CANARY",
        "azure_client_secret": "LEGACY-SECRET-CANARY",
    },
    "gcp": {"gcp_service_account_json": "LEGACY-JSON-CANARY"},
    "kubernetes": {"kubernetes_kubeconfig": "LEGACY-KUBECONFIG-CANARY"},
}
LEGACY_MODELS: dict[str, type[Any]] = {
    "aws": AwsProviderInput,
    "azure": AzureProviderInput,
    "gcp": GcpProviderInput,
    "kubernetes": KubernetesProviderInput,
}
REFERENCE_MODELS: dict[str, type[Any]] = {
    "aws": AwsReferenceProviderInput,
    "azure": AzureReferenceProviderInput,
    "gcp": GcpReferenceProviderInput,
    "kubernetes": KubernetesReferenceProviderInput,
}
PROVIDERS = tuple(NON_CREDENTIAL_FORMS)
# One route of each executable shape (base, fixed service, fixed compliance,
# selectable service, selectable compliance) and its extra select inputs.
ROUTE_CASES: tuple[tuple[str, str, dict[str, str]], ...] = (
    ("aws", "aws", {}),
    ("azure/iam", "azure", {}),
    ("cis/gcp", "gcp", {}),
    ("kubernetes", "kubernetes", {}),
    ("aws/select-service", "aws", {"prowler_service": "s3"}),
    ("gcp/select-compliance", "gcp", {"prowler_compliance": "cis_3.0_gcp"}),
)


def _contract(route: str) -> BaseProwlerContract:
    """Resolve one shared registry instance by route name."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))


def _outputs(provider_input: Any) -> tuple[str, str, str]:
    """Return every ordinary textual rendering of a parsed provider input."""
    return (
        repr(provider_input),
        str(provider_input),
        json.dumps(provider_input.model_dump(mode="json")),
    )


def _specification() -> ExecutionSpecification:
    """Build the immutable fake execution specification."""
    return ExecutionSpecification(
        executable="/fake/prowler",
        arguments=("/fake/prowler",),
        environment=(),
        working_directory=None,
        input_bytes=b"",
        output=OutputSpecification(),
        timeout_seconds=30.0,
        maximum_accepted_output_bytes=1024,
    )


@dataclass
class _ClientFactory:
    """Record the provider input each CHK.004 client-factory call receives."""

    providers: list[Any] = field(default_factory=list)

    def run(
        self,
        config: Any,
        provider: Any,
        *,
        check_filters: Sequence[str] = (),
        service_selector: object = None,
        compliance_selector: object = None,
    ) -> CommandResult:
        """Record the provider and return an empty successful result."""
        del config, check_filters, service_selector, compliance_selector
        self.providers.append(provider)
        return CommandResult(
            specification=_specification(), return_code=0, parsed=b"[]"
        )


def test_legacy_credential_keys_are_exactly_the_credential_text_fields() -> None:
    """Only credential fields are dropped on the reference path."""
    assert dict(LEGACY_CREDENTIAL_KEYS) == {
        provider: frozenset(fields)
        for provider, fields in LEGACY_CREDENTIAL_FORMS.items()
    }


@pytest.mark.parametrize("provider", PROVIDERS)
def test_reference_models_keep_every_non_credential_field(provider: str) -> None:
    """The reference model is the legacy model minus its credential fields."""
    legacy_fields = set(LEGACY_MODELS[provider].model_fields)
    reference_fields = set(REFERENCE_MODELS[provider].model_fields)
    assert reference_fields == (legacy_fields - LEGACY_CREDENTIAL_KEYS[provider]) | {
        "credential_attachment"
    }
    assert issubclass(REFERENCE_MODELS[provider], CredentialReferenceProviderInput)


@pytest.mark.parametrize(("route", "provider", "selects"), ROUTE_CASES)
def test_reference_with_empty_legacy_fields_parses_the_reference_model(
    route: str, provider: str, selects: dict[str, str]
) -> None:
    """A reference needs no legacy credential field at all."""
    parsed = _contract(route).parse_input(
        {
            **NON_CREDENTIAL_FORMS[provider],
            **selects,
            "credential_reference": REFERENCE,
        },
        credential_attachment=ATTACHMENT,
    )

    assert type(parsed) is REFERENCE_MODELS[provider]
    assert parsed.credential_attachment == ATTACHMENT
    for key, value in NON_CREDENTIAL_FORMS[provider].items():
        assert getattr(parsed, key) == value


@pytest.mark.parametrize(("route", "provider", "selects"), ROUTE_CASES)
def test_reference_with_blank_legacy_fields_parses_the_reference_model(
    route: str, provider: str, selects: dict[str, str]
) -> None:
    """Blank legacy fields submitted by the form are not validated."""
    blank_credentials = dict.fromkeys(LEGACY_CREDENTIAL_FORMS[provider], "")
    parsed = _contract(route).parse_input(
        {**NON_CREDENTIAL_FORMS[provider], **blank_credentials, **selects},
        credential_attachment=ATTACHMENT,
    )

    assert type(parsed) is REFERENCE_MODELS[provider]


@pytest.mark.parametrize(("route", "provider", "selects"), ROUTE_CASES)
def test_reference_ignores_filled_legacy_fields(
    route: str, provider: str, selects: dict[str, str]
) -> None:
    """The reference wins: filled legacy credentials are dropped, not merged."""
    parsed = _contract(route).parse_input(
        {
            **NON_CREDENTIAL_FORMS[provider],
            **LEGACY_CREDENTIAL_FORMS[provider],
            **selects,
        },
        credential_attachment=ATTACHMENT,
    )

    assert type(parsed) is REFERENCE_MODELS[provider]
    for key in LEGACY_CREDENTIAL_FORMS[provider]:
        assert not hasattr(parsed, key)
    for output in _outputs(parsed):
        assert "CANARY" not in output


@pytest.mark.parametrize(("route", "provider", "selects"), ROUTE_CASES)
def test_no_reference_keeps_the_strict_legacy_model(
    route: str, provider: str, selects: dict[str, str]
) -> None:
    """Without an attachment, the legacy credential fields stay mandatory."""
    contract = _contract(route)
    form = {**NON_CREDENTIAL_FORMS[provider], **selects}

    parsed = contract.parse_input({**form, **LEGACY_CREDENTIAL_FORMS[provider]})
    assert type(parsed) is LEGACY_MODELS[provider]

    with pytest.raises(ContractInputError) as raised:
        contract.parse_input(form)
    assert {issue.error_type for issue in raised.value.issues} == {"missing"}


@pytest.mark.parametrize(("route", "provider", "selects"), ROUTE_CASES)
def test_reference_still_validates_non_credential_fields(
    route: str, provider: str, selects: dict[str, str]
) -> None:
    """Dropping the credential fields does not relax the other fields."""
    form = {**NON_CREDENTIAL_FORMS[provider], **selects}
    missing_key = next(iter(NON_CREDENTIAL_FORMS[provider]))
    del form[missing_key]

    with pytest.raises(ContractInputError) as raised:
        _contract(route).parse_input(form, credential_attachment=ATTACHMENT)
    assert raised.value.issues == (
        ContractInputIssue((provider, missing_key), "missing"),
    )


def test_reference_rejects_an_invalid_aws_account_without_echoing_it() -> None:
    """The AWS account pattern still applies on the reference path."""
    with pytest.raises(ContractInputError) as raised:
        _contract("aws").parse_input(
            {**NON_CREDENTIAL_FORMS["aws"], "aws_account_id": "ACCOUNT-CANARY"},
            credential_attachment=ATTACHMENT,
        )
    assert raised.value.issues == (
        ContractInputIssue(("aws", "aws_account_id"), "string_pattern_mismatch"),
    )
    assert "ACCOUNT-CANARY" not in str(raised.value)


def test_reference_rejects_an_unsafe_aws_endpoint() -> None:
    """The AWS endpoint override keeps its validator on the reference path."""
    with pytest.raises(ContractInputError) as raised:
        _contract("aws").parse_input(
            {
                **NON_CREDENTIAL_FORMS["aws"],
                "aws_endpoint_url": "https://user:pass@example.test",
            },
            credential_attachment=ATTACHMENT,
        )
    assert raised.value.issues == (
        ContractInputIssue(("aws", "aws_endpoint_url"), "value_error"),
    )


def test_reference_normalizes_a_blank_aws_endpoint_to_none() -> None:
    """An empty optional endpoint is treated as absent, as on the legacy path."""
    parsed = _contract("aws").parse_input(
        {**NON_CREDENTIAL_FORMS["aws"], "aws_endpoint_url": ""},
        credential_attachment=ATTACHMENT,
    )
    assert isinstance(parsed, AwsReferenceProviderInput)
    assert parsed.aws_endpoint_url is None


def test_form_cannot_forge_a_credential_attachment() -> None:
    """Only the job attachment reaches the model, never a form value."""
    forged = {**NON_CREDENTIAL_FORMS["aws"], "credential_attachment": "forged"}

    with pytest.raises(ContractInputError) as raised:
        _contract("aws").parse_input({**forged, **LEGACY_CREDENTIAL_FORMS["aws"]})
    assert raised.value.issues == (
        ContractInputIssue(("aws", "credential_attachment"), "extra_forbidden"),
    )

    parsed = _contract("aws").parse_input(forged, credential_attachment=ATTACHMENT)
    assert isinstance(parsed, AwsReferenceProviderInput)
    assert parsed.credential_attachment is ATTACHMENT


@pytest.mark.parametrize("provider", PROVIDERS)
def test_authorisation_code_never_reaches_ordinary_output(provider: str) -> None:
    """The authorisation code is kept out of repr, str, dumps and log metadata."""
    parsed = REFERENCE_MODELS[provider](
        provider=provider,
        credential_attachment=ATTACHMENT,
        **NON_CREDENTIAL_FORMS[provider],
    )

    for output in (*_outputs(parsed), json.dumps(parsed.safe_log_metadata())):
        assert AUTHORISATION_CODE not in output
    assert "credential_attachment" not in parsed.model_dump()


@pytest.mark.parametrize("provider", PROVIDERS)
def test_reference_log_metadata_names_the_reference_only(provider: str) -> None:
    """Log metadata carries the reference id and the non-credential context."""
    parsed = REFERENCE_MODELS[provider](
        provider=provider,
        credential_attachment=ATTACHMENT,
        **NON_CREDENTIAL_FORMS[provider],
    )

    metadata = parsed.safe_log_metadata()
    assert metadata["credential_reference_present"] is True
    assert metadata["credential_reference"] == REFERENCE
    for key, value in NON_CREDENTIAL_FORMS[provider].items():
        assert metadata[key] == value


@pytest.mark.parametrize(("route", "provider", "selects"), ROUTE_CASES)
def test_reference_input_passes_the_contract_execution_type_gates(
    route: str, provider: str, selects: dict[str, str]
) -> None:
    """Every contract shape forwards the reference input to the CHK.004 seam."""
    factory = _ClientFactory()
    contract = type(_contract(route))(factory)
    parsed = contract.parse_input(
        {**NON_CREDENTIAL_FORMS[provider], **selects},
        credential_attachment=ATTACHMENT,
    )

    outcome = contract.execute(Mock(), parsed)

    assert outcome.error is None
    assert factory.providers == [parsed]
    assert contract.safe_request_info(parsed)["route"] == route


@pytest.mark.parametrize("provider", PROVIDERS)
def test_universal_reference_is_scoped_to_the_selected_provider(provider: str) -> None:
    """Universal drops every provider's credentials and keeps the selected scope."""
    every_credential = {
        key: value
        for credentials in LEGACY_CREDENTIAL_FORMS.values()
        for key, value in credentials.items()
    }
    factory = _ClientFactory()
    contract = type(_contract("universal"))(factory)
    parsed = contract.parse_input(
        {
            "prowler_provider": provider,
            **NON_CREDENTIAL_FORMS[provider],
            **every_credential,
            "credential_reference": REFERENCE,
        },
        credential_attachment=ATTACHMENT,
    )

    assert type(parsed) is REFERENCE_MODELS[provider]
    for output in _outputs(parsed):
        assert "CANARY" not in output
    contract.execute(Mock(), parsed)
    assert factory.providers == [parsed]
    assert contract.safe_request_info(parsed)["selected_provider"] == provider


def test_universal_without_reference_keeps_the_strict_legacy_model() -> None:
    """Universal still requires the selected provider's legacy credentials."""
    contract = _contract("universal")
    with pytest.raises(ContractInputError) as raised:
        contract.parse_input({"prowler_provider": "gcp", **NON_CREDENTIAL_FORMS["gcp"]})
    assert raised.value.issues == (
        ContractInputIssue(("gcp", "gcp_service_account_json"), "missing"),
    )


class _RecordingContract(BaseProwlerContract):
    """Record the attachment handed to the parse boundary by the runtime."""

    contract_id: ClassVar[str] = str(stable_contract_id("aws"))
    external_id = "prowler:aws"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Reference runtime test"
    attachments: ClassVar[list[Any]] = []

    def parse_input(self, raw_input: Any, **kwargs: Any) -> Any:
        self.attachments.append(kwargs.get("credential_attachment"))
        return super().parse_input(raw_input, **kwargs)

    def execute(self, config: Any, provider: Any) -> ContractExecutionOutcome:
        del config, provider
        return ContractExecutionOutcome(
            command_result=CommandResult(specification=_specification(), return_code=0)
        )


def _process(attachments: object, content: dict[str, str]) -> Mock:
    """Process one job message and return the helper that received the callback."""
    from prowler.injector import ProwlerInjector

    _RecordingContract.attachments = []
    helper = Mock()
    injector = ProwlerInjector(
        Mock(), helper, registry=ProwlerContracts((_RecordingContract,))
    )
    injector.process_message(
        {
            "injection": {
                "inject_id": "inject-test",
                "injector_contract_id": _RecordingContract.contract_id,
                "inject_content": content,
            },
            "attachments": attachments,
        }
    )
    return helper


def _callback_status(helper: Mock) -> str:
    """Return the terminal execution status sent to the platform."""
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    return str(callback["execution_status"])


def test_runtime_forwards_the_first_reference_of_the_job_attachment() -> None:
    """The job attachment reaches the parse boundary as a CredentialAttachment."""
    helper = _process(
        {
            "credential_references": [REFERENCE, "second-reference"],
            "authorisation_code": AUTHORISATION_CODE,
        },
        {**NON_CREDENTIAL_FORMS["aws"], "credential_reference": REFERENCE},
    )

    assert _RecordingContract.attachments == [ATTACHMENT]
    assert _callback_status(helper) == "SUCCESS"


@pytest.mark.parametrize("attachments", (None, {}, {"credential_references": []}))
def test_runtime_without_reference_keeps_the_legacy_path(attachments: object) -> None:
    """No attachment or no reference means the legacy fields are parsed."""
    helper = _process(
        attachments,
        {**NON_CREDENTIAL_FORMS["aws"], **LEGACY_CREDENTIAL_FORMS["aws"]},
    )

    assert _RecordingContract.attachments == [None]
    assert _callback_status(helper) == "SUCCESS"
    helper.api.inject.resolve_attachment_secret.assert_not_called()


def test_runtime_reference_without_authorisation_code_ends_in_error() -> None:
    """A reference without its authorisation code never reaches the parser."""
    helper = _process(
        {"credential_references": [REFERENCE]},
        {**NON_CREDENTIAL_FORMS["aws"], **LEGACY_CREDENTIAL_FORMS["aws"]},
    )

    assert _RecordingContract.attachments == []
    assert _callback_status(helper) == "ERROR"
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert "CANARY" not in json.dumps(callback, default=str)
