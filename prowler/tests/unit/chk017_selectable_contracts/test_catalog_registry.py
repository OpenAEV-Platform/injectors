"""R07/R08 catalog and registry invariants for CHK.017."""

from __future__ import annotations

import json
from pathlib import Path

from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    ROUTE_CATALOG,
    stable_contract_id,
)

_PRE_EXISTING_25 = (
    "aws",
    "azure",
    "gcp",
    "kubernetes",
    "aws/iam",
    "aws/s3",
    "aws/ec2",
    "azure/iam",
    "azure/storage",
    "gcp/iam",
    "gcp/compute",
    "cis/aws",
    "cis/azure",
    "cis/gcp",
    "cis/kubernetes",
    "nis2/aws",
    "nis2/azure",
    "nis2/gcp",
    "iso27001/aws",
    "iso27001/azure",
    "iso27001/gcp",
    "iso27001/kubernetes",
    "mitre/aws",
    "mitre/azure",
    "mitre/gcp",
)
_NEW_6 = (
    "aws/select-service",
    "aws/select-compliance",
    "azure/select-service",
    "azure/select-compliance",
    "gcp/select-service",
    "gcp/select-compliance",
)
_LOCAL_SNAPSHOT = Path("/tmp/opencode/chk017-pre-change-contracts.json")  # noqa: S108
_REPO_SNAPSHOT = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "chk017-pre-change-contracts.json"
)
_SNAPSHOT = _LOCAL_SNAPSHOT if _LOCAL_SNAPSHOT.exists() else _REPO_SNAPSHOT


def test_catalog_appends_exactly_six_descriptors_in_order() -> None:
    """Assert the catalog appends exactly six descriptors in order."""
    routes = tuple(r.route_name for r in ROUTE_CATALOG)
    assert routes == _PRE_EXISTING_25 + _NEW_6 + ("universal",)
    added = ROUTE_CATALOG[25:31]
    assert [(d.route_name, d.provider, d.family) for d in added] == [
        ("aws/select-service", "aws", "service"),
        ("aws/select-compliance", "aws", "compliance"),
        ("azure/select-service", "azure", "service"),
        ("azure/select-compliance", "azure", "compliance"),
        ("gcp/select-service", "gcp", "service"),
        ("gcp/select-compliance", "gcp", "compliance"),
    ]


def test_registry_serializes_32_unique_stable_contracts() -> None:
    """Assert the registry serializes 32 unique stable contracts."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    assert len(serialized) == 32
    ids = [item["contract_id"] for item in serialized]
    assert len(set(ids)) == 32
    assert ids == [
        str(stable_contract_id(route))
        for route in _PRE_EXISTING_25 + _NEW_6 + ("universal",)
    ]


def test_external_ids_follow_route_grammar() -> None:
    """Assert external IDs follow the prowler: route grammar."""
    for item in DEFAULT_PROWLER_CONTRACTS.contracts():
        route = next(
            r
            for r in _PRE_EXISTING_25 + _NEW_6 + ("universal",)
            if str(stable_contract_id(r)) == item["contract_id"]
        )
        contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(item["contract_id"]))
        assert contract.external_id == f"prowler:{route}"


def test_pre_existing_25_serialized_contracts_unchanged() -> None:
    """Assert the pre-existing 25 serialized contracts are unchanged."""
    assert _SNAPSHOT.exists(), (
        "R08 snapshot missing: regenerate "
        "/tmp/opencode/chk017-pre-change-contracts.json before the change"
    )
    snapshot = json.loads(_SNAPSHOT.read_text())
    assert len(snapshot) == 25
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    by_id = {item["contract_id"]: item for item in serialized}
    for entry in snapshot:
        assert by_id[entry["contract_id"]] == entry
