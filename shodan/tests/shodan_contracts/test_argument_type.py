"""argumentType on the ip_enumeration / cve_specific_watchlist fields: lets a
discovered IPv4 or CVE finding auto-link into these inputs (see the typing
spec, docs/specs/2026-08-input-and-output-typing.md in the injectors repo)."""

from pyoaev.contracts.contract_config import PrimitiveType

from shodan.contracts.cve_specific_watchlist.contract import CVESpecificWatchlist
from shodan.contracts.ip_enumeration.contract import IPEnumeration
from shodan.contracts.shodan_contracts import InjectorKey, TargetSelectorField


def _field(contract_cls, key):
    fields = contract_cls.contract_with_specific_fields(
        base_fields=[],
        source_selector_key=InjectorKey.TARGET_SELECTOR_KEY,
        target_selector_field=TargetSelectorField,
    )
    return {f.key: f for f in fields}[key]


def test_ip_enumeration_ip_field_is_typed():
    assert _field(IPEnumeration, "ip").argumentType == PrimitiveType.IPv4


def test_cve_specific_watchlist_vulnerability_field_is_typed():
    assert (
        _field(CVESpecificWatchlist, "vulnerability").argumentType == PrimitiveType.CVE
    )
