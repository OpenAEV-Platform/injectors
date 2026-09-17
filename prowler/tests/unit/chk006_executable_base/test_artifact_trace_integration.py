"""Artifact-to-mapping-to-trace integration required by CHK.006."""

from __future__ import annotations

import importlib
import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from prowler._core.cli_engine import (CommandResult, ExecutionSpecification,
                                      OutputSpecification)
from prowler.contracts import BaseProwlerContract
from prowler.models.configs.config_loader import ProwlerConfig


def _specification() -> ExecutionSpecification:
    return ExecutionSpecification(
        executable="/usr/local/bin/prowler",
        arguments=(),
        environment=(),
        working_directory=None,
        input_bytes=b"",
        output=OutputSpecification(parser="raw"),
        timeout_seconds=1.0,
        maximum_accepted_output_bytes=1024,
    )


@dataclass
class _Factory:
    result: CommandResult
    calls: int = 0

    def run(
        self, config: Any, provider: Any, *, check_filters: Any = ()
    ) -> CommandResult:
        del config, provider, check_filters
        self.calls += 1
        return self.result


class _Contract(BaseProwlerContract):
    contract_id = "9d5b71f8-f36f-50ee-a896-d7ff41f541f9"
    external_id = "CHK.006.ARTIFACT.TRACE"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Artifact trace test"


def _provider(contract: BaseProwlerContract) -> Any:
    return contract.parse_input(
        {
            "aws_access_key_id": "ACCESS-KEY-CANARY",
            "aws_secret_access_key": "SECRET-CANARY",
            "aws_account_id": "123456789012",
            "aws_region": "eu-west-1",
        }
    )


def _record(index: int) -> dict[str, Any]:
    return {
        "finding_info": {
            "uid": f"check-{index}",
            "title": f"Check {index}",
            "desc": "DESCRIPTION-CANARY",
        },
        "status": "New",
        "status_code": "PASS",
        "severity": "High",
        "resources": [
            {
                "uid": f"resource-{index}",
                "name": f"asset-{index}",
                "data": {"RESOURCE-DATA-CANARY": "SECRET-CANARY"},
            }
        ],
        "cloud": {
            "provider": "aws",
            "region": "eu-west-1",
            "account": {"uid": "account-safe"},
        },
        "remediation": {
            "desc": "REMEDIATION-CANARY",
            "references": ["https://REMEDIATION-URL-CANARY.invalid"],
        },
        "unmapped": {"ARBITRARY-UNMAPPED-CANARY": "CREDENTIAL-CANARY"},
    }


def test_large_artifact_is_mapped_once_and_raw_trace_is_bounded(
    monkeypatch: Any,
) -> None:
    """A large decoded set leaves only mapped findings and ten safe raw projections."""
    records = [_record(index) for index in range(2410)]
    artifact = json.dumps(records, separators=(",", ":")).encode()
    factory = _Factory(
        CommandResult(
            _specification(),
            return_code=0,
            stdout=b"\x1b[31mCONSOLE-NON-JSON-CANARY\x1b[0m",
            parsed=artifact,
        )
    )
    contract = _Contract(client_factory=factory)
    provider = _provider(contract)

    findings_module = importlib.import_module("prowler.models.findings")
    original_decode = findings_module.decode_ocsf_output
    decode_calls = 0

    def counted_decode(payload: bytes | str) -> tuple[dict[str, Any], ...]:
        nonlocal decode_calls
        decode_calls += 1
        return original_decode(payload)

    monkeypatch.setattr(findings_module, "decode_ocsf_output", counted_decode)

    outcome = contract.execute(ProwlerConfig(), provider)

    assert factory.calls == 1
    assert decode_calls == 1
    assert outcome.error is None
    assert len(outcome.findings) == 2410
    assert outcome.raw_record_count == 2410
    assert outcome.raw_output_bytes == len(artifact)
    assert len(outcome.raw_preview) == 10
    assert not hasattr(outcome, "raw_records")
    assert not hasattr(outcome, "decoded_records")
    assert outcome.raw_preview[0].model_dump() == {
        "finding_title": "Check 0",
        "finding_uid": "check-0",
        "status": "New",
        "status_code": "PASS",
        "severity": "High",
        "resource_name": "asset-0",
        "resource_uid": "resource-0",
        "cloud_provider": "aws",
        "cloud_region": "eu-west-1",
        "cloud_account": "account-safe",
        "provider_uid": None,
    }
    preview_text = repr(outcome.raw_preview)
    assert all(
        canary not in preview_text
        for canary in (
            "DESCRIPTION-CANARY",
            "RESOURCE-DATA-CANARY",
            "REMEDIATION-CANARY",
            "REMEDIATION-URL-CANARY",
            "ARBITRARY-UNMAPPED-CANARY",
            "CREDENTIAL-CANARY",
            "CONSOLE-NON-JSON-CANARY",
            "ACCESS-KEY-CANARY",
            "SECRET-CANARY",
        )
    )
    structured = contract.output_payload(outcome.findings[:1])
    assert tuple(structured) == ("findings", "vulnerabilities")
    assert "ARBITRARY-UNMAPPED-CANARY" not in repr(structured)

    trace = contract.render_trace(
        provider,
        outcome.findings[:1],
        2,
        raw_record_count=outcome.raw_record_count,
        raw_output_bytes=outcome.raw_output_bytes,
        raw_preview=outcome.raw_preview,
    )

    assert trace.index("Prowler Findings") < trace.index(
        "[PROWLER] Raw OCSF evidence (bounded preview)"
    )
    assert "Total raw records: 2410" in trace
    assert f"Artifact bytes: {len(artifact)}" in trace
    assert "Records omitted: 2400" in trace
    assert "Check 0" in trace and "Check 9" in trace
    assert "Check 10" not in trace
    assert len(trace) < 20_000
    assert all(
        canary not in trace
        for canary in (
            "DESCRIPTION-CANARY",
            "RESOURCE-DATA-CANARY",
            "REMEDIATION-CANARY",
            "REMEDIATION-URL-CANARY",
            "ARBITRARY-UNMAPPED-CANARY",
            "CREDENTIAL-CANARY",
            "CONSOLE-NON-JSON-CANARY",
            "ACCESS-KEY-CANARY",
            "SECRET-CANARY",
        )
    )


def test_empty_artifact_is_valid_and_reports_zero_raw_evidence() -> None:
    """An empty captured artifact maps and renders as a successful empty result."""
    factory = _Factory(
        CommandResult(
            _specification(),
            return_code=0,
            stdout=b"diagnostic console",
            parsed=b"",
        )
    )
    contract = _Contract(client_factory=factory)
    provider = _provider(contract)

    outcome = contract.execute(ProwlerConfig(), provider)
    trace = contract.render_trace(
        provider,
        outcome.findings,
        0,
        raw_record_count=outcome.raw_record_count,
        raw_output_bytes=outcome.raw_output_bytes,
        raw_preview=outcome.raw_preview,
    )

    assert outcome.findings == ()
    assert outcome.raw_record_count == 0
    assert outcome.raw_output_bytes == 0
    assert outcome.raw_preview == ()
    assert "No findings to display" in trace
    assert "Total raw records: 0" in trace
    assert "Artifact bytes: 0" in trace
    assert "Records omitted: 0" in trace


def test_unmapped_preview_uses_only_safe_provider_uid() -> None:
    """The legacy provider branch cannot expose arbitrary unmapped values."""
    record = _record(1)
    record.pop("cloud")
    record["resources"][0]["namespace"] = "eu-west-1"
    record["unmapped"] = {
        "provider": "aws",
        "provider_uid": "safe-provider-uid",
        "UNMAPPED-DATA-CANARY": deepcopy(record),
    }
    artifact = json.dumps([record], separators=(",", ":")).encode()
    contract = _Contract(
        client_factory=_Factory(
            CommandResult(_specification(), return_code=0, parsed=artifact)
        )
    )

    outcome = contract.execute(ProwlerConfig(), _provider(contract))

    assert outcome.raw_preview[0].provider_uid == "safe-provider-uid"
    assert outcome.raw_preview[0].cloud_provider is None
    assert "UNMAPPED-DATA-CANARY" not in repr(outcome.raw_preview)
