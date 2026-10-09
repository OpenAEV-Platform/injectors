"""Runtime failure traces for the universal route keep the parsed selection."""

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


class _NoFindingsClientFactory:
    """A completed Prowler run that wrote no OCSF artifact (no findings)."""

    def run(self, config: Any, provider: Any, **selectors: Any) -> CommandResult:
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
        result = CommandResult(
            ExecutionSpecification.from_request(request), return_code=0
        )
        raise OutputArtifactError("missing", command_result=result)


def test_universal_run_without_findings_reports_selection_not_form_values() -> None:
    """A universal AWS run with no findings keeps its selection in the error trace."""
    universal = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))
    universal._client_factory = _NoFindingsClientFactory()
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
                "inject_id": "inject-universal-no-findings",
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

    trace = helper.api.inject.execution_callback.call_args.kwargs["data"][
        "execution_message"
    ]
    assert "Error code: no_findings_reported" in trace
    assert "selected_provider: aws" in trace
    assert "filters: base" in trace
    for form_value in (
        "123456789012",
        "eu-west-1",
        "SECRET-CANARY",
        "AKIAEXAMPLEKEYID",
    ):
        assert form_value not in trace
