"""Local fixtures for CHK.005 behaviour."""

from copy import deepcopy
from typing import Any

import pytest


@pytest.fixture
def ocsf_record() -> dict[str, Any]:
    """Return one representative Prowler 5.36 detection finding."""
    return {
        "finding_info": {
            "uid": "prowler.aws.iam.root_user_access_key",
            "title": "Root user access keys should be removed",
            "desc": "The root user has active access keys.",
        },
        "status": "PASS",
        "severity": "High",
        "resources": [{"uid": "arn:aws:iam::123456789012:root", "name": "root"}],
        "cloud": {
            "provider": "aws",
            "region": "eu-west-1",
            "account": {"uid": "123456789012"},
        },
        "unmapped": {
            "compliance": {
                "CIS-1.5": ["1.1", "1.2"],
                "ENS-RD2022": "op.acc.6",
            }
        },
        "remediation": {
            "desc": "Delete the root user access keys.",
            "references": ["https://example.test/remediation"],
        },
    }


@pytest.fixture
def copy_record(ocsf_record: dict[str, Any]):
    """Return a factory that isolates mutable source records."""

    def factory() -> dict[str, Any]:
        return deepcopy(ocsf_record)

    return factory


@pytest.fixture
def ocsf_nested_record() -> dict[str, Any]:
    """Return one isolated Prowler 3.11.3 nested detection finding."""
    return deepcopy(
        {
            "finding": {
                "title": "Check S3 Account Level Public Access Block.",
                "desc": "Check S3 Account Level Public Access Block.",
                "supporting_data": {
                    "Risk": (
                        "Public access policies may be applied to sensitive data buckets."
                    ),
                    "Notes": "",
                },
                "remediation": {
                    "kb_articles": [
                        "https://docs.bridgecrew.io/docs/bc_aws_s3_21#cloudformation",
                        "https://docs.bridgecrew.io/docs/bc_aws_s3_21#terraform",
                        "aws s3control put-public-access-block "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true "
                        "--account-id <account_id>",
                        "https://github.com/cloudmatos/matos/tree/master/"
                        "remediations/aws/s3/s3control/block-public-access",
                        "https://docs.aws.amazon.com/AmazonS3/latest/"
                        "userguide/access-control-block-public-access.html",
                    ],
                    "desc": (
                        "You can enable Public Access Block at the account level to "
                        "prevent the exposure of your data stored in S3."
                    ),
                },
                "types": ["Data Protection"],
                "src_url": "",
                "uid": (
                    "prowler-aws-s3_account_level_public_access_blocks-"
                    "123456789012-us-east-1-123456789012"
                ),
                "related_events": [],
            },
            "resources": [
                {
                    "group": {"name": "s3"},
                    "region": "us-east-1",
                    "name": "123456789012",
                    "uid": "arn:aws:iam::123456789012:root",
                    "labels": [],
                    "type": "AwsS3Bucket",
                    "details": "",
                }
            ],
            "status_detail": (
                "Block Public Access is not configured for the account "
                "123456789012."
            ),
            "compliance": {
                "status": "Failure",
                "requirements": [
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
                ],
                "status_detail": (
                    "Block Public Access is not configured for the account "
                    "123456789012."
                ),
            },
            "message": (
                "Block Public Access is not configured for the account "
                "123456789012."
            ),
            "severity_id": 4,
            "severity": "High",
            "cloud": {
                "account": {"name": "", "uid": "123456789012"},
                "region": "us-east-1",
                "org": {"uid": "", "name": ""},
                "provider": "aws",
                "project_uid": "",
            },
            "time": "2026-05-26 15:14:30.983675",
            "metadata": {
                "original_time": "2026-05-26T15:14:30.983675",
                "profiles": ["default"],
                "product": {
                    "language": "en",
                    "name": "Prowler",
                    "version": "3.11.3",
                    "vendor_name": "Prowler/ProwlerPro",
                    "feature": {
                        "name": "s3_account_level_public_access_blocks",
                        "uid": "s3_account_level_public_access_blocks",
                        "version": "3.11.3",
                    },
                },
                "version": "1.0.0-rc.3",
            },
            "state_id": 0,
            "state": "New",
            "status_id": 2,
            "status": "Failure",
            "type_uid": 200101,
            "type_name": "Security Finding: Create",
            "impact_id": 0,
            "impact": "Unknown",
            "confidence_id": 0,
            "confidence": "Unknown",
            "activity_id": 1,
            "activity_name": "Create",
            "category_uid": 2,
            "category_name": "Findings",
            "class_uid": 2001,
            "class_name": "Security Finding",
        }
    )
