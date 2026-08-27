"""Rich trace behavior required by the shared CHK.006 contract boundary."""

from importlib import import_module
from typing import Any

from pydantic import BaseModel


def _output_trace() -> Any:
    """Import the production renderer inside tests so absent behavior is RED."""
    return import_module("prowler.services.output_trace")


class _DisplayModel(BaseModel):
    value: str
    expectation_result: str
    severity: str
    nested: dict[str, Any] = {}


def _generate(findings: list[Any], **overrides: Any) -> str:
    arguments = {
        "route_name": "aws_iam",
        "provider_name": "aws",
        "request_info": {
            "provider": "aws",
            "account": "123456789012",
            "region": "eu-west-1",
            "route": "aws_iam",
        },
        "findings": findings,
        "duration": 7,
    }
    arguments.update(overrides)
    return _output_trace().generate(**arguments)


def test_dynamic_columns_use_models_dicts_and_flattened_paths() -> None:
    """A Censys-shaped contract config controls columns without raw OCSF paths."""
    config = {
        "header": {"title": "PROWLER - IAM"},
        "tables": [
            {
                "header": {"title": "IAM checks"},
                "config": {
                    "columns": [
                        {"title": "Check", "path": "value"},
                        {"title": "Outcome", "path": "expectation_result"},
                        {"title": "First", "path": "nested.items.0.name"},
                        {"title": "All", "path": "nested.items.*.name"},
                        {"title": "Fallback", "path": "absent|nested.backup"},
                        {"title": "Missing", "path": "missing.path"},
                    ]
                },
            }
        ],
    }
    findings: list[Any] = [
        _DisplayModel(
            value="check-model",
            expectation_result="FAILED",
            severity="HIGH",
            nested={
                "items": [{"name": "one"}, {"name": "two"}],
                "backup": "safe-fallback",
            },
        ),
        {
            "value": "check-dict",
            "expectation_result": "SUCCESS",
            "severity": "LOW",
            "nested": {},
        },
    ]

    trace = _generate(findings, trace_config=config)

    for expected in (
        "PROWLER - IAM",
        "IAM checks",
        "check-model",
        "check-dict",
        "one",
        "two",
        "safe-fallback",
        "-",
    ):
        assert expected in trace
    assert "finding_info" not in trace


def test_defaults_summaries_empty_state_and_error_are_deterministic() -> None:
    """Fallback columns, summaries, no-data, and safe errors are stable."""
    findings = [
        {
            "value": "flat check",
            "expectation_result": "IGNORED",
            "severity": "MEDIUM",
            "asset_name": "asset-a",
            "region": "eu-west-1",
            "cloud_account": "account-a",
        }
    ]
    trace = _generate(findings)
    assert trace == _generate(findings)
    for expected in (
        "PROWLER - AWS_IAM",
        "Call Success",
        "Status Summary",
        "IGNORED=1",
        "Severity Summary",
        "MEDIUM=1",
        "flat check",
        "asset-a",
        "account-a",
    ):
        assert expected in trace

    assert "No findings to display" in _generate([])
    error = _generate(
        [], is_error=True, error_message="Prowler contract execution failed safely"
    )
    assert "Call Failed" in error
    assert "Prowler contract execution failed safely" in error


def test_trace_limits_rows_cells_and_request_values() -> None:
    """Execution messages cannot grow without bound."""
    config = {
        "columns": [{"title": "Check", "path": "value"}],
        "options": {"max_rows": 2, "max_cell_length": 18},
    }
    trace = _generate(
        [
            {"value": "A" * 80, "expectation_result": "SUCCESS", "severity": "LOW"},
            {"value": "second", "expectation_result": "SUCCESS", "severity": "LOW"},
            {"value": "third-hidden", "expectation_result": "SUCCESS", "severity": "LOW"},
        ],
        trace_config=config,
    )
    assert "AAA..." in trace
    assert "+1 more finding" in trace
    assert "third-hidden" not in trace


def test_renderer_only_displays_supplied_safe_inputs() -> None:
    """Canary secrets and command internals are absent from safe display inputs."""
    canaries = (
        "CANARY-ACCESS-KEY",
        "CANARY-SECRET",
        "CANARY-SESSION",
        "CANARY-SERVICE-JSON",
        "CANARY-KUBECONFIG",
        "/tmp/openaev-prowler-credential-canary",
        "--aws-secret-access-key",
        "raw-stderr-canary",
    )
    trace = _generate([], request_info={"provider": "aws", "region": "eu-west-1"})
    assert all(canary not in trace for canary in canaries)
