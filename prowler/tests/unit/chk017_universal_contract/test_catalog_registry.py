"""R18 catalog and registry invariants for the universal contract."""

from __future__ import annotations

import json
from pathlib import Path

from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    ROUTE_CATALOG,
    UniversalProwlerContract,
    stable_contract_id,
)

_PRE_EXISTING_31 = (
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
    "aws/select-service",
    "aws/select-compliance",
    "azure/select-service",
    "azure/select-compliance",
    "gcp/select-service",
    "gcp/select-compliance",
)
_ALL_ROUTES = _PRE_EXISTING_31 + ("universal",)
_LOCAL_SNAPSHOT = Path(
    "/tmp/opencode/chk017-universal-pre-change-contracts.json"  # noqa: S108
)
_REPO_SNAPSHOT = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "chk017-universal-pre-change-contracts.json"
)
_SNAPSHOT = _LOCAL_SNAPSHOT if _LOCAL_SNAPSHOT.exists() else _REPO_SNAPSHOT


def test_catalog_appends_universal_descriptor_last() -> None:
    """Assert the catalog appends exactly one universal descriptor, last."""
    routes = tuple(r.route_name for r in ROUTE_CATALOG)
    assert routes == _ALL_ROUTES
    assert (
        ROUTE_CATALOG[-1].route_name,
        ROUTE_CATALOG[-1].provider,
        ROUTE_CATALOG[-1].family,
    ) == ("universal", "all", "universal")


def test_pre_existing_31_descriptors_unchanged_in_content_and_order() -> None:
    """Assert the existing 31 descriptors keep their exact content and order."""
    expected_first_31 = (
        ("aws", "aws", "base"),
        ("azure", "azure", "base"),
        ("gcp", "gcp", "base"),
        ("kubernetes", "kubernetes", "base"),
        ("aws/iam", "aws", "service"),
        ("aws/s3", "aws", "service"),
        ("aws/ec2", "aws", "service"),
        ("azure/iam", "azure", "service"),
        ("azure/storage", "azure", "service"),
        ("gcp/iam", "gcp", "service"),
        ("gcp/compute", "gcp", "service"),
        ("cis/aws", "aws", "compliance"),
        ("cis/azure", "azure", "compliance"),
        ("cis/gcp", "gcp", "compliance"),
        ("cis/kubernetes", "kubernetes", "compliance"),
        ("nis2/aws", "aws", "compliance"),
        ("nis2/azure", "azure", "compliance"),
        ("nis2/gcp", "gcp", "compliance"),
        ("iso27001/aws", "aws", "compliance"),
        ("iso27001/azure", "azure", "compliance"),
        ("iso27001/gcp", "gcp", "compliance"),
        ("iso27001/kubernetes", "kubernetes", "compliance"),
        ("mitre/aws", "aws", "compliance"),
        ("mitre/azure", "azure", "compliance"),
        ("mitre/gcp", "gcp", "compliance"),
        ("aws/select-service", "aws", "service"),
        ("aws/select-compliance", "aws", "compliance"),
        ("azure/select-service", "azure", "service"),
        ("azure/select-compliance", "azure", "compliance"),
        ("gcp/select-service", "gcp", "service"),
        ("gcp/select-compliance", "gcp", "compliance"),
    )
    assert [(d.route_name, d.provider, d.family) for d in ROUTE_CATALOG[:31]] == list(
        expected_first_31
    )


def test_registry_serializes_32_unique_stable_contracts() -> None:
    """Assert the registry serializes 32 unique stable contracts in order."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    assert len(serialized) == 32
    ids = [item["contract_id"] for item in serialized]
    assert len(set(ids)) == 32
    assert ids == [str(stable_contract_id(route)) for route in _ALL_ROUTES]


def test_universal_route_metadata() -> None:
    """Assert the universal route's exact stable identity and metadata."""
    contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))
    assert type(contract) is UniversalProwlerContract
    assert contract.contract_id == "33234db3-946e-5ba1-8912-6e689b9348b0"
    assert contract.contract_id == str(stable_contract_id("universal"))
    assert contract.external_id == "prowler:universal"
    assert contract.route_name == "universal"
    assert contract.provider == "all"
    assert contract.family == "universal"
    assert contract.label == "Prowler Universal"
    assert contract.check_filters == ()


def test_external_ids_follow_route_grammar() -> None:
    """Assert every external ID follows the prowler: route grammar."""
    for item in DEFAULT_PROWLER_CONTRACTS.contracts():
        route = next(
            r for r in _ALL_ROUTES if str(stable_contract_id(r)) == item["contract_id"]
        )
        contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(item["contract_id"]))
        assert contract.external_id == f"prowler:{route}"


def test_universal_route_name_is_collision_free() -> None:
    """Assert universal and the all meta-token collide with no route grammar."""
    route = "universal"
    # Slash-free: not the service grammar <provider>/<service-literal> and
    # not the compliance grammar <framework>/<provider>.
    assert "/" not in route
    # Not a closed provider literal: not a base route.
    assert route not in {"aws", "azure", "gcp", "kubernetes"}
    # The all meta-token is no provider literal and no route segment.
    assert "all" not in {"aws", "azure", "gcp", "kubernetes"}
    for existing in _PRE_EXISTING_31:
        assert "all" not in existing.split("/")
    # The stable ID collides with none of the existing 31.
    universal_id = str(stable_contract_id(route))
    existing_ids = {str(stable_contract_id(name)) for name in _PRE_EXISTING_31}
    assert len(existing_ids) == 31
    assert universal_id not in existing_ids


def test_pre_existing_31_serialized_contracts_unchanged() -> None:
    """Assert the pre-existing 31 serialized contracts match the R18 snapshot."""
    assert _SNAPSHOT.exists(), (
        "R18 snapshot missing: regenerate "
        "/tmp/opencode/chk017-universal-pre-change-contracts.json before the change"
    )
    snapshot = json.loads(_SNAPSHOT.read_text())
    assert len(snapshot) == 31
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    by_id = {item["contract_id"]: item for item in serialized}
    for entry in snapshot:
        assert by_id[entry["contract_id"]] == entry
