"""Closed runtime presentation for CHK.004 artifact lifecycle failures."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, cast
from unittest.mock import Mock

import pytest
from pyoaev.configuration import \
    ConfigLoaderOAEV  # type: ignore[import-untyped]

from prowler._core.cli_engine import (CommandResult, ExecutionSpecification,
                                      OutputSpecification)
from prowler._core.prowler_client import (OutputArtifactError,
                                          OutputWorkspaceCleanupError,
                                          OutputWorkspacePreparationError)
from prowler.contracts import (BaseProwlerContract, ContractExecutionOutcome,
                               ProwlerContracts, stable_contract_id)
from prowler.injector import ProwlerInjector
from prowler.models.configs.config_loader import (ConfigLoader, InjectorConfig,
                                                  ProwlerConfig)

_CONTRACT_ID = str(stable_contract_id("aws"))


def _specification() -> ExecutionSpecification:
    return ExecutionSpecification(
        executable="/opt/prowler/bin/prowler",
        arguments=("ARGUMENT-CANARY",),
        environment=(("ENVIRONMENT-CANARY", "CREDENTIAL-CANARY"),),
        working_directory="/TEMP-PATH-CANARY",
        input_bytes=b"STDIN-CANARY",
        output=OutputSpecification(parser="raw"),
        timeout_seconds=3600.0,
        maximum_accepted_output_bytes=4 * 1024 * 1024,
    )


class _FailureContract(BaseProwlerContract):
    contract_id = _CONTRACT_ID
    external_id = "prowler:aws"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Artifact failure test"
    failure: ClassVar[Exception]

    def execute(self, config: Any, provider: Any) -> ContractExecutionOutcome:
        del config, provider
        raise self.failure


def _runtime(error: Exception) -> tuple[ProwlerInjector, Mock]:
    _FailureContract.failure = error
    config = cast(
        ConfigLoader,
        ConfigLoader.model_construct(
            openaev=ConfigLoaderOAEV(
                url="http://127.0.0.1:8080", token="runtime-test-token"
            ),
            injector=InjectorConfig(id="prowler-injector"),
            prowler=ProwlerConfig(executable_path=Path("/opt/prowler/bin/prowler")),
        ),
    )
    helper = Mock()
    return (
        ProwlerInjector(config, helper, registry=ProwlerContracts((_FailureContract,))),
        helper,
    )


def _message() -> dict[str, Any]:
    return {
        "injection": {
            "inject_id": "inject-artifact-failure",
            "injector_contract_id": _CONTRACT_ID,
            "inject_content": {
                "aws_access_key_id": "ACCESS-KEY-CANARY",
                "aws_secret_access_key": "SECRET-CANARY",
                "aws_account_id": "123456789012",
                "aws_region": "eu-west-1",
            },
        }
    }


@pytest.mark.parametrize(
    ("error", "expected_kind", "expected_stage", "has_result"),
    (
        (
            OutputArtifactError("missing"),
            "output_artifact_missing",
            "artifact_capture",
            True,
        ),
        (
            OutputArtifactError("nonregular"),
            "output_artifact_nonregular",
            "artifact_capture",
            True,
        ),
        (
            OutputArtifactError("unreadable"),
            "output_artifact_unreadable",
            "artifact_capture",
            True,
        ),
        (
            OutputArtifactError("oversized"),
            "output_artifact_oversized",
            "artifact_capture",
            True,
        ),
        (
            OutputWorkspacePreparationError(),
            "output_workspace_preparation_failed",
            "output_workspace_preparation",
            False,
        ),
        (
            OutputWorkspaceCleanupError(),
            "output_workspace_cleanup_failed",
            "output_workspace_cleanup",
            True,
        ),
    ),
)
def test_artifact_failures_have_distinct_safe_log_and_ui_diagnostics(
    error: Exception,
    expected_kind: str,
    expected_stage: str,
    has_result: bool,
) -> None:
    """Each typed lifecycle failure has one closed classification on both surfaces."""
    if has_result:
        error.command_result = CommandResult(  # type: ignore[attr-defined]
            _specification(),
            return_code=0,
            stdout=b"STDOUT-CONTENT-CANARY",
            stderr=b"STDERR-CONTENT-CANARY",
        )
    injector, helper = _runtime(error)

    injector.process_message(_message())

    metadata = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    trace = callback["execution_message"]
    assert metadata["failure_kind"] == expected_kind
    assert metadata["stage"] == expected_stage
    assert metadata["failure_summary"]
    assert metadata["operator_guidance"]
    assert f"Error code: {expected_kind}" in trace
    assert f"Reason: {metadata['failure_summary']}" in trace
    assert f"Action: {metadata['operator_guidance']}" in trace
    assert callback["execution_status"] == "ERROR"
    if has_result:
        assert metadata["return_code"] == 0
        assert metadata["stdout_bytes"] == len(b"STDOUT-CONTENT-CANARY")
        assert metadata["stderr_bytes"] == len(b"STDERR-CONTENT-CANARY")
        assert "Return code: 0" in trace
    else:
        assert "return_code" not in metadata
        assert "stdout_bytes" not in metadata
        assert "stderr_bytes" not in metadata
    rendered = repr(metadata) + trace
    for canary in (
        "ARGUMENT-CANARY",
        "ENVIRONMENT-CANARY",
        "CREDENTIAL-CANARY",
        "TEMP-PATH-CANARY",
        "STDIN-CANARY",
        "STDOUT-CONTENT-CANARY",
        "STDERR-CONTENT-CANARY",
        "ACCESS-KEY-CANARY",
        "SECRET-CANARY",
    ):
        assert canary not in rendered
