"""TTP mapping on every shodan contract: querying the Shodan scan database
maps to ATT&CK T1596.005 (Search Open Technical Databases: Scan Databases),
so each built contract must carry that external id."""

from shodan.contracts.shodan_contracts import ShodanContractId, ShodanContracts

SCAN_DATABASES_TTP = "T1596.005"


def test_every_contract_carries_the_scan_databases_ttp():
    contracts = ShodanContracts().contracts()
    assert len(contracts) == len(ShodanContractId)
    for contract in contracts:
        assert contract["contract_attack_patterns_external_ids"] == [
            SCAN_DATABASES_TTP
        ], contract["contract_id"]
