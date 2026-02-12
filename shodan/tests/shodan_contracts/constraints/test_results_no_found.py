import pytest
from unittest.mock import patch

from shodan.contracts import ShodanContractId
from shodan.services.client_api import ShodanClientAPI

@pytest.mark.parametrize(
    "contract_id, expected_targets, inject_content, expected_query_fragments_per_target, empty_search_responses, user_info_response",
    [
        (
                ShodanContractId.IP_ENUMERATION,
                ["1.2.3.4"],
                {"ip": "1.2.3.4"},
                [["ip:1.2.3.4"]],
                [{"matches": [], "total": 0}, {"matches": [], "total": 0}],
                {"plan": "basic", "scan_credits": 1000, "query_credits": 1000},
        ),
        (
                ShodanContractId.CVE_ENUMERATION,
                ["filigran.io"],
                {"hostname": "filigran.io", "organization": "filigran.io"},
                [["has_vuln:true", "hostname:filigran.io,*.filigran.io", "org:filigran.io"]],
                [{"matches": [], "total": 0}],
                {"plan": "basic", "scan_credits": 1000, "query_credits": 1000},
        ),
        (
                ShodanContractId.CVE_SPECIFIC_WATCHLIST,
                ["filigran.io"],
                {"vulnerability": "CVE-2023-44487", "hostname": "filigran.io", "organization": "filigran.io"},
                [["vuln:CVE-2023-44487", "hostname:filigran.io,*.filigran.io", "org:filigran.io"]],
                [{"matches": [], "total": 0}],
                {"plan": "basic", "scan_credits": 1000, "query_credits": 1000},
        ),
        (
                ShodanContractId.DOMAIN_DISCOVERY,
                ["filigran.io"],
                {"hostname": "filigran.io", "organization": "filigran.io"},
                [["hostname:filigran.io,*.filigran.io", "org:filigran.io"]],
                [{"matches": [], "total": 0}],
                {"plan": "basic", "scan_credits": 1000, "query_credits": 1000},
        ),
        (
                ShodanContractId.CLOUD_PROVIDER_ASSET_DISCOVERY,
                ["filigran.io"],
                {"cloud_provider": "Google", "hostname": "filigran.io", "organization": "filigran.io"},
                [["cloud.provider:Google", "hostname:filigran.io,*.filigran.io", "org:filigran.io"]],
                [{"matches": [], "total": 0}],
                {"plan": "basic", "scan_credits": 1000, "query_credits": 1000},
        ),
        (
                ShodanContractId.CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE,
                ["filigran.io"],
                {"port": "443", "hostname": "filigran.io", "organization": "filigran.io"},
                [["port:443", "hostname:filigran.io,*.filigran.io", "org:filigran.io"]],
                [{"matches": [], "total": 0}],
                {"plan": "basic", "scan_credits": 1000, "query_credits": 1000},
        ),
    ],
    ids=[
        "empty_search_response_for_ip_enumeration",
        "empty_search_response_for_cve_enumeration",
        "empty_search_response_for_cve_specific_watchlist",
        "empty_search_response_for_domain_discovery",
        "empty_search_response_for_cloud_provider_asset_discovery",
        "empty_search_response_for_critical_ports_and_exposed_admin_interface",
    ]
)
def test_contracts_handle_empty_shodan_results(
        shodan_client_api,
        contract_id,
        inject_content,
        expected_targets,
        expected_query_fragments_per_target,
        empty_search_responses,
        user_info_response,
):
    """Scenario Outline: Execute contract when Shodan returns no matches"""
    # Given I have a valid <contract_name> inject_content with target "<target>"
    inject_content = inject_content

    # When I execute process_shodan_search with the <contract_name> contract
    results, credit_user = _when_execute_contract(
        shodan_client_api,
        contract_id,
        inject_content,
        mock_empty_search_responses=empty_search_responses,
        mock_user_info=user_info_response,
    )

    # Then: The results contain the expected targets and data
    _then_results_contain_expected_targets(results, targets=expected_targets)
    _then_results_are_empty(results, expected_targets)
    _then_results_data_url_contains_expected_query(
        results,
        expected_fragments_per_target=expected_query_fragments_per_target,
    )
    _then_credit_user_is_returned(credit_user, user_info_response)


# --------
# When Methods
# --------


def _when_execute_contract(
        client: ShodanClientAPI,
        contract_id: ShodanContractId,
        inject_content: dict,
        mock_empty_search_responses:  list[dict],
        mock_user_info: dict,
) -> tuple:
    """Execute the domain discovery contract through process_shodan_search.

    Mocks _request_data to return the expected API responses
    without making real HTTP calls. Each target gets its own response
    from mock_empty_search_responses in order.

    Args:
        client: The ShodanClientAPI instance.
        inject_content: The inject content with hostname and organization.
        mock_empty_search_responses: List of mocked search API empty responses, one per target.
        mock_user_info: The mocked user info API response.

    Returns:
        Tuple of (results, shodan_credit_user).

    """
    search_call_index = 0

    def mock_request_data(method, url):
        nonlocal search_call_index
        if "api-info" in url:
            return mock_user_info
        response = mock_empty_search_responses[search_call_index]
        search_call_index += 1
        return response

    with patch.object(client, "_request_data", side_effect=mock_request_data):
        return client.process_shodan_search(
            contract_id=contract_id,
            inject_content=inject_content,
        )



# --------
# Then Methods
# --------


def _then_results_contain_expected_targets(results: dict, targets: list[str]) -> None:
    """Verify that the results contain the expected targets.

    Args:
        results: The results dict returned by process_shodan_search.
        targets: The expected list of targets.

    """
    assert results["targets"] == targets  # noqa: S101

def _then_results_are_empty(results, expected_targets):
    """Verify that each target result is empty."""
    assert results["targets"] == expected_targets
    assert len(results["data"]) == len(expected_targets)

    for entry in results["data"]:
        assert entry["result"]["total"] == 0
        assert entry["result"]["matches"] == []
        assert "test-api-key" not in entry["url"]

def _then_results_data_url_contains_expected_query(
        results: dict,
        expected_fragments_per_target: list[list[str]],
) -> None:
    """Verify that each entry's URL contains the expected query fragments.

    Args:
        results: The results dict returned by process_shodan_search.
        expected_fragments_per_target: List of fragment lists, one per target.

    """
    assert len(results["data"]) == len(expected_fragments_per_target)  # noqa: S101

    for entry, expected_fragments in zip(
            results["data"], expected_fragments_per_target
    ):
        url = entry["url"]

        for fragment in expected_fragments:
            assert (
                    fragment in url
            ), f"Expected '{fragment}' in URL '{url}'"  # noqa: S101

        # Verify the API key is NOT exposed in the secured URL
        assert "test-api-key" not in url  # noqa: S101


def _then_credit_user_is_returned(credit_user: dict, expected_user_info: dict) -> None:
    """Verify the credit user info is returned correctly.

    Args:
        credit_user: The credit user info returned by process_shodan_search.
        expected_user_info: The expected user info response.

    """
    assert credit_user == expected_user_info  # noqa: S101
