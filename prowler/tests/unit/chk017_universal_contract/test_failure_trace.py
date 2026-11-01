"""Runtime traces for the universal route keep the parsed selection."""

from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

from pyoaev.configuration import ConfigLoaderOAEV  # type: ignore[import-untyped]

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
    ValidatedCommandRequest,
)
from prowler._core.prowler_client import OutputArtifactError
from prowler.contracts import DEFAULT_PROWLER_CONTRACTS, stable_contract_id
from prowler.injector import ProwlerInjector
from prowler.models.configs.config_loader import ConfigLoader, ProwlerConfig
from prowler.models.configs.injector_config_override import InjectorConfigOverride


def _completed_result(parsed: bytes | None = None) -> CommandResult:
    request = ValidatedCommandRequest(
        executable="/usr/local/bin/prowler",
        arguments=["aws"],
        environment={},
        working_directory=None,
        input_bytes=b"",
        output=OutputSpecification(parser="raw"),
        timeout_seconds=60.0,
        maximum_accepted_output_bytes=1024,
    )
    return CommandResult(
        ExecutionSpecification.from_request(request), return_code=0, parsed=parsed
    )


class _NoFindingsClientFactory:
    """What the client returns when Prowler completed without findings."""

    def run(self, config: Any, provider: Any, **selectors: Any) -> CommandResult:
        return _completed_result(parsed=b"[]")


class _NonregularArtifactClientFactory:
    """A completed run whose OCSF artifact was not a regular file."""

    def run(self, config: Any, provider: Any, **selectors: Any) -> CommandResult:
        raise OutputArtifactError("nonregular", command_result=_completed_result())


_FORM_VALUES = ("123456789012", "eu-west-1", "SECRET-CANARY", "AKIAEXAMPLEKEYID")


def _run_universal_aws(client_factory: Any) -> tuple[str, dict[str, Any]]:
    universal = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))
    universal._client_factory = client_factory
    config = cast(
        ConfigLoader,
        ConfigLoader.model_construct(
            openaev=ConfigLoaderOAEV(url="http://127.0.0.1:8080", token="t"),
            injector=InjectorConfigOverride(id="prowler-injector"),
            prowler=ProwlerConfig(executable_path=Path("/usr/local/bin/prowler")),
        ),
    )
    helper = Mock()
    injector = ProwlerInjector(config, helper, registry=DEFAULT_PROWLER_CONTRACTS)
    injector.process_message(
        {
            "injection": {
                "inject_id": "inject-universal",
                "injector_contract_id": str(stable_contract_id("universal")),
                "inject_content": {
                    "prowler_provider": "aws",
                    "aws_access_key_id": "AKIAEXAMPLEKEYID",
                    "aws_secret_access_key": "SECRET-CANARY",
                    "aws_account_id": "123456789012",
                    "aws_region": "eu-west-1",
                },
            }
        }
    )
    data = helper.api.inject.execution_callback.call_args.kwargs["data"]
    return data["execution_message"], data


def test_universal_run_without_findings_succeeds_with_its_selection() -> None:
    """A universal AWS run without findings is a success that keeps its selection."""
    trace, data = _run_universal_aws(_NoFindingsClientFactory())

    assert data["execution_status"] == "SUCCESS"
    assert "selected_provider: aws" in trace
    assert "filters: base" in trace


def test_universal_failure_trace_reports_selection_not_form_values() -> None:
    """A failed universal AWS run keeps its selection but no submitted form values."""
    trace, data = _run_universal_aws(_NonregularArtifactClientFactory())

    assert data["execution_status"] == "ERROR"
    assert "Error code: output_artifact_nonregular" in trace
    assert "selected_provider: aws" in trace
    assert "filters: base" in trace
    for form_value in _FORM_VALUES:
        assert form_value not in trace
