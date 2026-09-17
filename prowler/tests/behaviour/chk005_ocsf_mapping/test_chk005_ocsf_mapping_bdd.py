"""Raw-pytest bindings for the CHK.005 feature."""

import json
from dataclasses import FrozenInstanceError
from typing import Any, Callable

import pytest
from pydantic import ValidationError

from prowler._core.cli_engine import (CommandResult, ExecutionSpecification,
                                      OutputSpecification)
from prowler.models.findings import (OcsfDecodeError, OcsfMappingError,
                                     OpenAevFinding, decode_ocsf_output,
                                     map_command_result, map_ocsf_finding)


def _success(payload: bytes) -> CommandResult:
    specification = ExecutionSpecification(
        executable="/usr/local/bin/prowler",
        arguments=("aws", "-M", "json-ocsf"),
        environment=(),
        working_directory=None,
        input_bytes=b"",
        output=OutputSpecification(parser="raw"),
        timeout_seconds=3600,
        maximum_accepted_output_bytes=100 * 1024 * 1024,
    )
    return CommandResult(
        specification=specification,
        stdout=payload,
        return_code=0,
        parsed=payload,
    )


def test_maps_json_array_to_exact_immutable_findings_in_order(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """Map each array object to one frozen 14-field finding in order."""
    first = copy_record()
    second = copy_record()
    second["finding_info"]["uid"] = "second"
    payload = json.dumps([first, second]).encode()

    findings = map_command_result(_success(payload))

    assert tuple(finding.type for finding in findings) == (
        "prowler.aws.iam.root_user_access_key",
        "second",
    )
    assert tuple(OpenAevFinding.model_fields) == (
        "type",
        "value",
        "expectation_result",
        "severity",
        "severity_weight",
        "asset_reference",
        "asset_name",
        "cloud_provider",
        "region",
        "cloud_account",
        "compliance_tags",
        "remediation",
        "remediation_url",
        "description",
    )
    with pytest.raises((ValidationError, FrozenInstanceError)):
        findings[0].severity = "LOW"  # type: ignore[misc]


def test_maps_json_lines_and_ignores_blank_lines(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """Ignore blank JSONL lines without disturbing record order."""
    first = copy_record()
    second = copy_record()
    second["finding_info"]["uid"] = "second"
    payload = f"{json.dumps(first)}\n\n  \n{json.dumps(second)}\n".encode()

    findings = map_command_result(_success(payload))

    assert tuple(finding.type for finding in findings) == (
        "prowler.aws.iam.root_user_access_key",
        "second",
    )


@pytest.mark.parametrize(
    ("status", "status_code", "expected"),
    [
        ("New", "PASS", "SUCCESS"),
        ("New", "pass", "SUCCESS"),
        ("New", "FAIL", "FAILED"),
        ("New", "failed", "FAILED"),
        ("Suppressed", "FAIL", "IGNORED"),
        ("suppressed", "PASS", "IGNORED"),
        ("MUTED", "FAIL", "IGNORED"),
        ("manual", "PASS", "IGNORED"),
        ("New", "ERROR", "IGNORED"),
        ("New", "UNKNOWN", "IGNORED"),
        ("New", " PASS ", "IGNORED"),
    ],
)
def test_normalizes_status_without_trimming(
    copy_record: Callable[[], dict[str, Any]],
    status: str,
    status_code: str,
    expected: str,
) -> None:
    """Normalize status case but not unapproved surrounding whitespace."""
    record = copy_record()
    record["status"] = status
    record["status_code"] = status_code

    assert map_ocsf_finding(record, record_index=7).expectation_result == expected


@pytest.mark.parametrize(
    ("source", "label", "weight"),
    [
        ("critical", "CRITICAL", 4),
        ("HIGH", "HIGH", 3),
        ("medium", "MEDIUM", 2),
        ("LOW", "LOW", 1),
        ("informational", "INFO", 0),
        ("unknown", "INFO", 0),
    ],
)
def test_normalizes_severity_case_insensitively(
    copy_record: Callable[[], dict[str, Any]],
    source: str,
    label: str,
    weight: int,
) -> None:
    """Normalize declared severity labels and weights without case sensitivity."""
    record = copy_record()
    record["severity"] = source

    finding = map_ocsf_finding(record)

    assert (finding.severity, finding.severity_weight) == (label, weight)


def test_maps_all_fields_and_preserves_compliance_values(
    ocsf_record: dict[str, Any],
) -> None:
    """Map every authoritative path and retain compliance encounter order."""
    finding = map_ocsf_finding(ocsf_record)

    assert finding.model_dump() == {
        "type": "prowler.aws.iam.root_user_access_key",
        "value": "Root user access keys should be removed",
        "expectation_result": "SUCCESS",
        "severity": "HIGH",
        "severity_weight": 3,
        "asset_reference": "arn:aws:iam::123456789012:root",
        "asset_name": "root",
        "cloud_provider": "aws",
        "region": "eu-west-1",
        "cloud_account": "123456789012",
        "compliance_tags": (
            "CIS-1.5:1.1",
            "CIS-1.5:1.2",
            "ENS-RD2022:op.acc.6",
        ),
        "remediation": "Delete the root user access keys.",
        "remediation_url": "https://example.test/remediation",
        "description": "The root user has active access keys.",
    }


def test_optional_values_have_safe_fallbacks(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """Use approved fallbacks for absent severity, compliance, and URL."""
    record = copy_record()
    del record["severity"]
    del record["unmapped"]["compliance"]
    record["remediation"]["references"] = []

    finding = map_ocsf_finding(record)

    assert (finding.severity, finding.severity_weight) == ("INFO", 0)
    assert finding.compliance_tags == ()
    assert finding.remediation_url is None


def test_cloudless_finding_uses_unmapped_provider_and_resource_namespace(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """Map Kubernetes/provider identity when the OCSF cloud object is absent."""
    record = copy_record()
    del record["cloud"]
    record["unmapped"].update(provider="kubernetes", provider_uid="cluster-production")
    record["resources"][0]["namespace"] = "payments"

    finding = map_ocsf_finding(record)

    assert (
        finding.cloud_provider,
        finding.cloud_account,
        finding.region,
    ) == ("kubernetes", "cluster-production", "payments")


@pytest.mark.parametrize("payload", [b"\xffsecret", b'[{"token":"secret"}'])
def test_decode_errors_do_not_echo_sensitive_payload(payload: bytes) -> None:
    """Keep malformed payload content out of structured decode errors."""
    with pytest.raises(OcsfDecodeError) as caught:
        decode_ocsf_output(payload)

    assert caught.value.code in {"invalid_utf8", "invalid_json"}
    assert caught.value.message == "unable to decode Prowler OCSF output"
    assert "secret" not in str(caught.value)


def test_non_object_record_has_safe_index() -> None:
    """Identify a non-object array member by index without echoing it."""
    with pytest.raises(OcsfDecodeError) as caught:
        decode_ocsf_output(b'[{"ok": true}, "sensitive"]')

    assert caught.value.code == "non_object_record"
    assert caught.value.record_index == 1
    assert "sensitive" not in str(caught.value)


def test_missing_required_path_has_structured_mapping_error(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """Report the missing required path and source record index."""
    record = copy_record()
    del record["cloud"]["account"]["uid"]

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=4)

    assert caught.value.code == "missing_source_path"
    assert caught.value.record_index == 4
    assert caught.value.source_path == "cloud.account.uid"
    assert "123456789012" not in str(caught.value)


def test_empty_resources_has_structured_mapping_error(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """Treat the required first resource as a path-aware mapping failure."""
    record = copy_record()
    record["resources"] = []

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=2)

    assert caught.value.code == "missing_source_path"
    assert caught.value.source_path == "resources[0]"
    assert caught.value.record_index == 2
