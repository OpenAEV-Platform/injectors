"""Raw-pytest bindings for the CHK.005 dual-shape (Prowler 3.x nested) contract."""

from copy import deepcopy
from typing import Any, Callable

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


def test_maps_prowler_3_11_3_nested_shape_to_exact_immutable_findings(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """H1: map the fully pinned nested record to the exact 14-field vector."""
    finding = _mapped(ocsf_nested_record)

    assert finding.model_dump() == {
        "type": (
            "prowler-aws-s3_account_level_public_access_blocks-"
            "123456789012-us-east-1-123456789012"
        ),
        "value": "Check S3 Account Level Public Access Block.",
        "expectation_result": "FAILED",
        "severity": "HIGH",
        "severity_weight": 3,
        "asset_reference": "arn:aws:iam::123456789012:root",
        "asset_name": "123456789012",
        "cloud_provider": "aws",
        "region": "us-east-1",
        "cloud_account": "123456789012",
        "compliance_tags": (
            "NIST-800-53-Revision-5: ac_2_6, ac_3, ac_3_7, ac_4_21, ac_6, "
            "ac_17_b, ac_17_1, ac_17_4_a, ac_17_9, ac_17_10, cm_6_a, cm_9_b, "
            "mp_2, sc_7_2, sc_7_3, sc_7_7, sc_7_9_a, sc_7_11, sc_7_12, "
            "sc_7_16, sc_7_20, sc_7_21, sc_7_24_b, sc_7_25, sc_7_26, "
            "sc_7_27, sc_7_28, sc_7_a, sc_7_b, sc_7_c, sc_25",
            "GxP-21-CFR-Part-11: 11.10-d, 11.10-g",
            "CIS-1.4: 2.1.5",
            "AWS-Well-Architected-Framework-Security-Pillar: SEC03-BP07",
            "FFIEC: d3-pc-im-b-1",
            "FedRamp-Moderate-Revision-4: ac-3, ac-6, ac-17-1, ac-21-b, "
            "cm-2, sc-4, sc-7-3, sc-7",
            "CIS-2.0: 2.1.5",
            "AWS-Foundational-Security-Best-Practices: s3",
            "NIST-800-53-Revision-4: sc_7_3, sc_7",
            "CISA: your-systems-3, your-data-2",
            "NIST-800-171-Revision-2: 3_1_1, 3_1_2, 3_1_3, 3_1_14, "
            "3_1_20, 3_3_8, 3_4_6, 3_13_2, 3_13_5",
            "FedRAMP-Low-Revision-4: ac-3, ac-17, cm-2, sc-7",
            "NIST-CSF-1.1: ac_3, ac_5, ds_5, ip_8, pt_3",
            "MITRE-ATTACK: T1530",
            "CIS-1.5: 2.1.5",
            "HIPAA: 164_308_a_1_ii_b, 164_308_a_3_i",
        ),
        "remediation": (
            "You can enable Public Access Block at the account level to "
            "prevent the exposure of your data stored in S3."
        ),
        "remediation_url": "https://docs.bridgecrew.io/docs/bc_aws_s3_21#cloudformation",
        "description": "Check S3 Account Level Public Access Block.",
    }


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("FAILURE", "FAILED"),
        ("failure", "FAILED"),
        ("Muted", "IGNORED"),
        ("Manual", "IGNORED"),
        ("Suppressed", "IGNORED"),
    ],
)
def test_normalizes_prowler_3x_status_rows(
    copy_record: Callable[[], dict[str, Any]], source: str, expected: str
) -> None:
    """Additive 3.x status rows; all existing status rows stay unchanged."""
    record = copy_record()
    del record["status_code"]
    record["status"] = source

    assert _mapped(record, record_index=7).expectation_result == expected


def test_finding_info_block_wins_when_both_blocks_present(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """Select finding_info and never read the finding block's content."""
    record = copy_record()
    record["finding"] = {"uid": _CANARY, "title": _CANARY, "desc": _CANARY}

    finding = _mapped(record)

    assert finding.type == "prowler.aws.iam.root_user_access_key"
    assert finding.value == "Root user access keys should be removed"
    assert finding.description == "The root user has active access keys."
    assert _CANARY not in finding.model_dump_json()


def test_top_level_remediation_wins_over_block_remediation(
    copy_record: Callable[[], dict[str, Any]],
    ocsf_nested_record: dict[str, Any],
) -> None:
    """A present top-level remediation keeps its exact flat mapping."""
    record = copy_record()
    record["finding"] = deepcopy(ocsf_nested_record["finding"])
    record["message"] = _CANARY

    finding = _mapped(record)

    assert finding.remediation == "Delete the root user access keys."
    assert finding.remediation_url == "https://example.test/remediation"
    assert _CANARY not in finding.model_dump_json()


def test_unmapped_compliance_wins_over_erroring_top_level_compliance(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """A non-null unmapped.compliance wins even when top-level would error."""
    record = ocsf_nested_record
    record["unmapped"] = {"compliance": {"CIS-1.5": ["1.1", "1.2"]}}
    record["compliance"] = 42

    finding = _mapped(record)

    assert finding.compliance_tags == ("CIS-1.5:1.1", "CIS-1.5:1.2")


def test_block_remediation_references_precede_kb_articles(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """Within one block remediation, references presence wins over kb_articles."""
    record = ocsf_nested_record
    record["finding"]["remediation"]["references"] = ["https://ref.test"]

    finding = _mapped(record)

    assert finding.remediation_url == "https://ref.test"


def test_empty_block_references_win_presence_over_kb_articles(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """A present empty references list resolves the URL to absent."""
    record = ocsf_nested_record
    record["finding"]["remediation"]["references"] = []

    assert _mapped(record).remediation_url is None


def test_empty_present_finding_info_never_defers_to_finding(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """C1: an empty present finding_info errors at finding_info.uid."""
    record = ocsf_nested_record
    record["finding_info"] = {}
    record["message"] = _CANARY

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=5)

    assert caught.value.code == "missing_source_path"
    assert caught.value.record_index == 5
    assert caught.value.source_path == "finding_info.uid"
    assert _CANARY not in str(caught.value)


def test_null_finding_info_is_invalid_value_without_finding_fallback(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """C2: a null finding_info is invalid_source_value at finding_info."""
    record = ocsf_nested_record
    record["finding_info"] = None
    record["message"] = _CANARY

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=6)

    assert caught.value.code == "invalid_source_value"
    assert caught.value.record_index == 6
    assert caught.value.source_path == "finding_info"
    assert _CANARY not in str(caught.value)


def test_empty_block_kb_articles_without_references_leaves_url_absent(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """C3: selected block remediation with kb_articles=[] and no references."""
    record = ocsf_nested_record
    record["finding"]["remediation"]["kb_articles"] = []

    finding = _mapped(record)

    assert finding.remediation_url is None
    assert finding.remediation.startswith("You can enable Public Access Block")


def test_null_unmapped_compliance_defers_to_top_level_requirements(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """C4: a null unmapped.compliance defers to the 16 requirement strings."""
    record = ocsf_nested_record
    record["unmapped"] = {"compliance": None}

    finding = _mapped(record)

    assert finding.compliance_tags == tuple(record["compliance"]["requirements"])
    assert len(finding.compliance_tags) == 16


def test_present_empty_unmapped_compliance_wins_with_empty_tags(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """C5: {} is a valid present value; precedence keeps tags empty."""
    record = ocsf_nested_record
    record["unmapped"] = {"compliance": {}}

    assert _mapped(record).compliance_tags == ()


def test_top_level_remediation_ignores_kb_articles(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """C6: kb_articles inside a top-level remediation is ignored."""
    record = copy_record()
    del record["remediation"]["references"]
    record["remediation"]["kb_articles"] = ["https://kb.test"]

    assert _mapped(record).remediation_url is None


def test_present_top_level_compliance_without_requirements_maps_empty_tags(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """A present top-level compliance without requirements maps to empty tags."""
    record = ocsf_nested_record
    record["compliance"] = {"status": "Failure"}

    assert _mapped(record).compliance_tags == ()


def test_present_top_level_compliance_with_null_requirements_maps_empty_tags(
    ocsf_nested_record: dict[str, Any],
) -> None:
    """A present top-level compliance with requirements=None maps to empty tags."""
    record = ocsf_nested_record
    record["compliance"] = {"requirements": None}

    assert _mapped(record).compliance_tags == ()
