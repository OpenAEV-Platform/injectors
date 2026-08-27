"""Path-level dual-shape error coordinates for the CHK.005 mapper."""

from typing import Any

import pytest

from prowler.models.findings import (
    OcsfMappingError,
    OpenAevFinding,
    map_ocsf_finding,
)

_CANARY = "CANARY-SECRET-VALUE"


def _mapped(record: dict[str, Any], record_index: int = 0) -> OpenAevFinding:
    """Map a record expected to succeed, surfacing absent behavior clearly.

    The frozen OcsfMappingError dataclass cannot survive the contextlib
    traceback reassignment in this host's pytest runner, so an escaped
    structured error is converted into an explicit failure carrying its
    rendered code, record index, and source path.
    """
    try:
        return map_ocsf_finding(record, record_index=record_index)
    except OcsfMappingError as error:
        pytest.fail(f"dual-shape behavior absent: {error}")


def _nested_record() -> dict[str, Any]:
    """One nested 3.11.3-style record with canary-tainted content everywhere."""
    return {
        "finding": {
            "uid": "prowler-aws-s3-x-123456789012-us-east-1-123456789012",
            "title": "Check.",
            "desc": "Check.",
            "remediation": {
                "desc": "Enable the block.",
                "kb_articles": ["https://kb.test"],
            },
        },
        "resources": [
            {"uid": "arn:aws:iam::123456789012:root", "name": "123456789012"}
        ],
        "cloud": {
            "provider": "aws",
            "region": "us-east-1",
            "account": {"uid": "123456789012"},
        },
        "status": "Failure",
        "severity": "High",
        "compliance": {
            "status": _CANARY,
            "requirements": ["NIST-800-53-Revision-5: ac_3"],
            "status_detail": _CANARY,
        },
        "message": _CANARY,
        "severity_id": 4,
        "state": "New",
        "state_id": 0,
    }


def test_missing_both_finding_blocks_reports_union_path() -> None:
    """E1: neither finding block → missing_source_path finding_info|finding."""
    record = _nested_record()
    del record["finding"]

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=4)

    assert caught.value.code == "missing_source_path"
    assert caught.value.record_index == 4
    assert caught.value.source_path == "finding_info|finding"
    assert _CANARY not in str(caught.value)


def test_present_non_object_finding_info_has_structured_error() -> None:
    """E2a: a present non-object finding_info → invalid_source_value finding_info."""
    record = _nested_record()
    record["finding_info"] = _CANARY

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=9)

    assert caught.value.code == "invalid_source_value"
    assert caught.value.record_index == 9
    assert caught.value.source_path == "finding_info"
    assert _CANARY not in str(caught.value)


def test_present_non_object_finding_block_has_structured_error() -> None:
    """E2b: a present non-object finding block → invalid_source_value finding."""
    record = _nested_record()
    record["finding"] = _CANARY

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=9)

    assert caught.value.code == "invalid_source_value"
    assert caught.value.record_index == 9
    assert caught.value.source_path == "finding"
    assert _CANARY not in str(caught.value)


def test_missing_remediation_everywhere_reports_union_path() -> None:
    """E3: no top-level and no block remediation → union-path error."""
    record = _nested_record()
    del record["finding"]["remediation"]

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=3)

    assert caught.value.code == "missing_source_path"
    assert caught.value.record_index == 3
    assert caught.value.source_path == "remediation|finding.remediation"
    assert _CANARY not in str(caught.value)


def test_block_remediation_without_desc_reports_block_desc_path() -> None:
    """E4: block remediation with kb_articles but no desc → desc path error."""
    record = _nested_record()
    del record["finding"]["remediation"]["desc"]

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=8)

    assert caught.value.code == "missing_source_path"
    assert caught.value.record_index == 8
    assert caught.value.source_path == "finding.remediation.desc"
    assert _CANARY not in str(caught.value)


@pytest.mark.parametrize(
    ("mutation", "source_path"),
    [
        (
            lambda record: record["finding"]["remediation"].update(kb_articles=42),
            "finding.remediation.kb_articles",
        ),
        (
            lambda record: record["finding"]["remediation"].update(kb_articles=[42]),
            "finding.remediation.kb_articles[0]",
        ),
        (
            lambda record: record["finding"]["remediation"].update(references=42),
            "finding.remediation.references",
        ),
        (
            lambda record: record["finding"]["remediation"].update(references=[42]),
            "finding.remediation.references[0]",
        ),
    ],
)
def test_block_remediation_type_errors_report_precise_paths(
    mutation: Any, source_path: str
) -> None:
    """E5: non-list lists and non-string heads → precise invalid_source_value."""
    record = _nested_record()
    mutation(record)

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=2)

    assert caught.value.code == "invalid_source_value"
    assert caught.value.record_index == 2
    assert caught.value.source_path == source_path
    assert _CANARY not in str(caught.value)


def test_non_mapping_top_level_compliance_reports_compliance_path() -> None:
    """E6a: top-level compliance that is not a mapping → invalid at compliance."""
    record = _nested_record()
    record["compliance"] = _CANARY

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=11)

    assert caught.value.code == "invalid_source_value"
    assert caught.value.record_index == 11
    assert caught.value.source_path == "compliance"
    assert _CANARY not in str(caught.value)


def test_string_requirements_are_accepted_as_single_tag() -> None:
    """E6b: a single-string requirements value is accepted as one tag."""
    record = _nested_record()
    record["compliance"]["requirements"] = "one-string"

    assert _mapped(record).compliance_tags == ("one-string",)


@pytest.mark.parametrize(
    ("requirements", "source_path"),
    [
        (42, "compliance.requirements"),
        (["a", 42], "compliance.requirements[1]"),
        ({"K": ["v"]}, "compliance.requirements"),
    ],
)
def test_invalid_requirements_grammar_reports_precise_paths(
    requirements: Any, source_path: str
) -> None:
    """E6c: non-string leaves and mappings → precise invalid_source_value."""
    record = _nested_record()
    record["compliance"]["requirements"] = requirements

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=13)

    assert caught.value.code == "invalid_source_value"
    assert caught.value.record_index == 13
    assert caught.value.source_path == source_path
    assert _CANARY not in str(caught.value)


def test_missing_flat_remediation_everywhere_reports_union_path() -> None:
    """E7: flat finding_info record with remediation nowhere → union-path error."""
    record = {
        "finding_info": {
            "uid": "prowler.aws.iam.root_user_access_key",
            "title": "Root user access keys should be removed.",
            "desc": "The root user has active access keys.",
        },
        "resources": [
            {"uid": "arn:aws:iam::123456789012:root", "name": "root"}
        ],
        "cloud": {
            "provider": "aws",
            "region": "eu-west-1",
            "account": {"uid": "123456789012"},
        },
        "status": "PASS",
        "severity": "High",
        "message": _CANARY,
    }

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=14)

    assert caught.value.code == "missing_source_path"
    assert caught.value.record_index == 14
    assert caught.value.source_path == "remediation|finding_info.remediation"
    assert _CANARY not in str(caught.value)


def test_block_kb_articles_head_is_used_without_url_validation() -> None:
    """E8: a non-URL kb_articles head maps through without URL validation."""
    record = _nested_record()
    record["finding"]["remediation"]["kb_articles"] = ["not a url"]

    finding = _mapped(record)

    assert finding.remediation_url == "not a url"
