"""Credential failure kinds of the Prowler failure taxonomy."""

# ruff: noqa: D101, D102, D103

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import Mock

import pytest
from pyoaev.credential import (  # type: ignore[import-untyped]
    CredentialErrorCode,
    CredentialResolutionError,
    CredentialType,
    InvalidResolvedSecretError,
    UnsupportedSecretTypeError,
)

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
from prowler.injector import ProwlerInjector
from prowler.injector.failure_taxonomy import (
    _GUIDANCE_BY_FAILURE_KIND,
    _SUMMARY_BY_FAILURE_KIND,
)

REFERENCE = "3f1c1e5e-0000-4000-8000-000000000001"
AUTHORISATION_CODE = "AUTHORISATION-CODE-CANARY"

PLATFORM_CODES = (
    (CredentialErrorCode.CREDENTIAL_NOT_FOUND, "credential_not_found"),
    (CredentialErrorCode.CREDENTIAL_INACTIVE, "credential_inactive"),
    (CredentialErrorCode.CREDENTIAL_ACCESS_DENIED, "credential_access_denied"),
)
INJECTOR_ERRORS = (
    CredentialResolutionError(
        CredentialErrorCode.CREDENTIAL_INCOMPATIBLE,
        REFERENCE,
        expected_type=CredentialType.CLOUD_AWS,
    ),
    CredentialResolutionError(CredentialErrorCode.CREDENTIAL_INCOMPATIBLE, REFERENCE),
    UnsupportedSecretTypeError("HASH", REFERENCE),
    InvalidResolvedSecretError(REFERENCE),
)
# The failure kinds and texts that existed before the credential kinds.
PREVIOUS_FAILURE_KINDS = frozenset(
    {
        "cli_engine_error",
        "policy_rejected",
        "policy_evaluation_failed",
        "resolution_failed",
        "execution_failed",
        "timeout",
        "process_start_failed",
        "unsuccessful_process",
        "output_too_large_after_capture",
        "parsing_failed",
        "output_artifact_missing",
        "output_artifact_nonregular",
        "output_artifact_unreadable",
        "output_artifact_oversized",
        "output_workspace_preparation_failed",
        "output_workspace_cleanup_failed",
        "invalid_input",
        "structured_output_failed",
        "structured_output_too_large",
        "rendering_failed",
        "reception_failed",
        "callback_failed",
        "unexpected_failure",
    }
)
AWS_SCOPE = {"aws_account_id": "123456789012", "aws_region": "eu-west-1"}


def _injector() -> ProwlerInjector:
    return ProwlerInjector(Mock(), Mock())


def _classify(stage: str, error: Exception) -> Any:
    return _injector()._classifier._classify_exception_failure(stage, error)


def _parse_error(route: str, content: dict[str, str]) -> ContractInputError:
    contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))
    with pytest.raises(ContractInputError) as raised:
        contract.parse_input(content)
    return raised.value


@pytest.mark.parametrize(("code", "failure_kind"), PLATFORM_CODES)
@pytest.mark.parametrize(
    "stage", ("input_validation", "credential_resolution", "assessment_execution")
)
def test_platform_codes_map_to_their_failure_kind_at_any_stage(
    code: CredentialErrorCode, failure_kind: str, stage: str
) -> None:
    failure = _classify(stage, CredentialResolutionError(code, REFERENCE))

    assert failure.stage == stage
    assert failure.failure_kind == failure_kind
    assert failure.credential_error_code == code.value
    assert failure.credential_reference == REFERENCE


@pytest.mark.parametrize(
    "error",
    (
        *(CredentialResolutionError(code, REFERENCE) for code, _ in PLATFORM_CODES),
        *INJECTOR_ERRORS,
    ),
    ids=lambda error: f"{type(error).__name__}-{error.code.value}",
)
def test_summary_and_guidance_are_the_fixed_taxonomy_message(
    error: CredentialResolutionError,
) -> None:
    failure = _classify("credential_resolution", error)

    assert f"{failure.failure_summary} {failure.operator_guidance}" == error.message
    assert failure.credential_error_code == error.code.value


def test_incompatible_credential_names_the_expected_type() -> None:
    failure = _classify("credential_resolution", INJECTOR_ERRORS[0])

    assert failure.failure_kind == "credential_incompatible"
    assert failure.operator_guidance == (
        "Select a credential of type CLOUD_AWS on the inject, then run it again."
    )


@pytest.mark.parametrize("reference", (None, "bad reference\nCANARY", "x" * 129))
def test_an_unsafe_reference_never_reaches_the_trace(reference: str | None) -> None:
    error = CredentialResolutionError(
        CredentialErrorCode.CREDENTIAL_INACTIVE, reference
    )

    failure = _classify("credential_resolution", error)

    assert failure.credential_reference is None
    assert failure.failure_summary == (
        "The credential unknown reference is inactive at the moment of execution."
    )


@pytest.mark.parametrize(
    ("route", "content"),
    (
        ("aws", AWS_SCOPE),
        (
            "aws",
            {**AWS_SCOPE, "aws_access_key_id": "", "aws_secret_access_key": ""},
        ),
        ("azure/iam", {"azure_subscription_id": "sub", "azure_provider": "Azure"}),
        ("gcp", {"gcp_project_id": "project"}),
        ("universal", {"prowler_provider": "gcp", "gcp_project_id": "project"}),
    ),
)
def test_no_reference_and_no_credential_is_credential_missing(
    route: str, content: dict[str, str]
) -> None:
    error = _parse_error(route, content)

    failure = _classify("input_validation", error)

    assert failure.failure_kind == "credential_missing"
    assert failure.credential_error_code == "CREDENTIAL_MISSING"
    assert failure.credential_reference is None
    assert failure.operator_guidance == (
        "Select a credential on the inject, then run it again."
    )
    assert failure.issues


@pytest.mark.parametrize(
    ("route", "content"),
    (
        ("aws", {**AWS_SCOPE, "aws_access_key_id": "AKIA-CANARY"}),
        ("aws", {"aws_access_key_id": "AKIA", "aws_secret_access_key": "CANARY"}),
        ("kubernetes", {"kubernetes_context": "context"}),
    ),
)
def test_partial_or_non_cloud_credentials_stay_invalid_input(
    route: str, content: dict[str, str]
) -> None:
    failure = _classify("input_validation", _parse_error(route, content))

    assert failure.failure_kind == "invalid_input"
    assert not hasattr(failure, "credential_error_code")


def test_untrusted_missing_issues_stay_invalid_input() -> None:
    error = ContractInputError(
        (
            ContractInputIssue(("aws", "aws_access_key_id"), "missing"),
            ContractInputIssue(("aws", "aws_secret_access_key"), "missing"),
        )
    )

    assert _classify("input_validation", error).failure_kind == "invalid_input"


def test_presentation_shows_the_code_the_reference_and_the_fixed_message() -> None:
    injector = _injector()
    error = CredentialResolutionError(
        CredentialErrorCode.CREDENTIAL_NOT_FOUND, REFERENCE
    )
    failure = injector._classifier._classify_exception_failure(
        "credential_resolution", error
    )

    rendered = injector._presenter._plain_safe_error(
        failure, inject_id="inject-test", contract=None
    )

    assert rendered.splitlines()[:3] == [
        "Error code: credential_not_found",
        f"Reason: The credential configured on this inject ({REFERENCE}) no longer "
        "exists at the moment of execution.",
        "Action: Select an existing credential on the inject, then run it again.",
    ]
    assert "Credential error code: CREDENTIAL_NOT_FOUND" in rendered
    assert f"Credential reference: {REFERENCE}" in rendered


def test_failure_metadata_carries_the_code_and_no_secret() -> None:
    injector = _injector()
    failure = injector._classifier._classify_exception_failure(
        "credential_resolution",
        CredentialResolutionError(CredentialErrorCode.CREDENTIAL_INACTIVE, REFERENCE),
    )

    metadata = injector._failure_metadata(0.0, "inject-test", None, None, failure)

    assert metadata["failure_kind"] == "credential_inactive"
    assert metadata["credential_error_code"] == "CREDENTIAL_INACTIVE"
    assert metadata["credential_reference"] == REFERENCE


def test_previous_failure_kinds_are_unchanged() -> None:
    assert set(_SUMMARY_BY_FAILURE_KIND) == PREVIOUS_FAILURE_KINDS
    assert set(_GUIDANCE_BY_FAILURE_KIND) == PREVIOUS_FAILURE_KINDS


def test_other_exceptions_are_still_unexpected_failures() -> None:
    failure = _classify("credential_resolution", RuntimeError("CANARY"))

    assert failure.failure_kind == "unexpected_failure"
    assert "CANARY" not in repr(failure)


def test_other_invalid_input_is_still_invalid_input() -> None:
    error = _parse_error(
        "aws",
        {
            **AWS_SCOPE,
            "aws_account_id": "not-an-account",
            "aws_access_key_id": "AKIA",
            "aws_secret_access_key": "secret",
        },
    )

    failure = _classify("input_validation", error)

    assert failure.failure_kind == "invalid_input"
    assert failure.operator_guidance == (
        "AWS account ID must contain exactly 12 ASCII digits."
    )


class _TraceContract(BaseProwlerContract):
    """Return the safe error unchanged so the trace can be asserted exactly."""

    contract_id: ClassVar[str] = str(stable_contract_id("aws"))
    external_id = "prowler:aws"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Credential failure test"
    executed: ClassVar[int] = 0

    def execute(self, config: Any, provider: Any) -> ContractExecutionOutcome:
        del config, provider
        type(self).executed += 1
        return ContractExecutionOutcome(
            command_result=CommandResult(
                specification=ExecutionSpecification(
                    executable="/fake/prowler",
                    arguments=("/fake/prowler",),
                    environment=(),
                    working_directory=None,
                    input_bytes=b"",
                    output=OutputSpecification(),
                    timeout_seconds=30.0,
                    maximum_accepted_output_bytes=1024,
                ),
                return_code=0,
            )
        )

    def render_trace(
        self, provider: Any, findings: Any, duration: int, **kwargs: Any
    ) -> str:
        del provider, findings, duration
        return str(kwargs.get("error_message", ""))


def _process(helper: Mock, content: dict[str, str], attachments: object) -> Any:
    _TraceContract.executed = 0
    injector = ProwlerInjector(
        Mock(), helper, registry=ProwlerContracts((_TraceContract,))
    )
    injector.process_message(
        {
            "injection": {
                "inject_id": "inject-test",
                "injector_contract_id": _TraceContract.contract_id,
                "inject_content": content,
            },
            "attachments": attachments,
        }
    )
    return helper.api.inject.execution_callback.call_args.kwargs["data"]


@pytest.mark.parametrize(("code", "failure_kind"), PLATFORM_CODES)
def test_runtime_reports_each_platform_code_in_the_trace(
    code: CredentialErrorCode, failure_kind: str
) -> None:
    helper = Mock()
    error = CredentialResolutionError(code, REFERENCE)
    helper.api.inject.resolve_attachment_secret.side_effect = error

    callback = _process(
        helper,
        AWS_SCOPE,
        {
            "credential_references": [REFERENCE],
            "authorisation_code": AUTHORISATION_CODE,
        },
    )

    assert callback["execution_status"] == "ERROR"
    assert _TraceContract.executed == 0
    message = callback["execution_message"]
    expected = _classify("credential_resolution", error)
    assert f"Error code: {failure_kind}" in message
    assert f"Reason: {expected.failure_summary}" in message
    assert f"Action: {expected.operator_guidance}" in message
    assert f"Credential error code: {code.value}" in message
    assert AUTHORISATION_CODE not in message


def test_runtime_reports_a_missing_authorisation_code_as_access_denied() -> None:
    callback = _process(Mock(), AWS_SCOPE, {"credential_references": [REFERENCE]})

    assert callback["execution_status"] == "ERROR"
    assert "Credential error code: CREDENTIAL_ACCESS_DENIED" in (
        callback["execution_message"]
    )


def test_runtime_reports_a_missing_credential() -> None:
    helper = Mock()

    callback = _process(helper, AWS_SCOPE, None)

    assert callback["execution_status"] == "ERROR"
    assert "Credential error code: CREDENTIAL_MISSING" in callback["execution_message"]
    helper.api.inject.resolve_attachment_secret.assert_not_called()
