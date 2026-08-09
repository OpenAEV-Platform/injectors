"""Every Shodan contract must declare its finding-compatible outputs.

Shodan retrieves ports, IPs and CVEs for every query; these must be exposed as
finding-compatible ContractOutputElement so downstream chaining can trigger off
them. This test locks in the per-contract finding declarations.
"""

import json

from shodan.contracts.shodan_contracts import ShodanContractId, ShodanContracts

# Expected finding-compatible output types (serialized enum values) per contract.
EXPECTED_FINDING_TYPES = {
    ShodanContractId.CLOUD_PROVIDER_ASSET_DISCOVERY.value: {"ipv4"},
    ShodanContractId.CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE.value: {
        "portscan",
        "ipv4",
        "cve",
    },
    ShodanContractId.CUSTOM_QUERY.value: {"portscan", "ipv4", "cve"},
    ShodanContractId.CVE_ENUMERATION.value: {"portscan", "ipv4", "cve"},
    ShodanContractId.CVE_SPECIFIC_WATCHLIST.value: {"portscan", "ipv4", "cve"},
    ShodanContractId.DOMAIN_DISCOVERY.value: {"ipv4", "portscan"},
    ShodanContractId.IP_ENUMERATION.value: {"portscan", "ipv4", "cve"},
}


def _finding_types(contract):
    content = json.loads(contract["contract_content"])
    return {
        output["type"] for output in content["outputs"] if output["isFindingCompatible"]
    }


def test_every_contract_declares_expected_finding_outputs():
    contracts = ShodanContracts().contracts()
    assert len(contracts) == len(ShodanContractId)

    for contract in contracts:
        contract_id = contract["contract_id"]
        assert contract_id in EXPECTED_FINDING_TYPES, contract_id
        assert (
            _finding_types(contract) == EXPECTED_FINDING_TYPES[contract_id]
        ), contract_id


def test_base_asset_output_is_not_finding_compatible():
    for contract in ShodanContracts().contracts():
        content = json.loads(contract["contract_content"])
        asset_outputs = [o for o in content["outputs"] if o["type"] == "asset"]
        assert asset_outputs, contract["contract_id"]
        for asset_output in asset_outputs:
            assert asset_output["isFindingCompatible"] is False
