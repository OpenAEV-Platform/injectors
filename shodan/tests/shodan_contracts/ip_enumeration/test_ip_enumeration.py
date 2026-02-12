"""Essential tests for Shodan IP Enumeration contract - Gherkin GWT Format."""

from unittest.mock import patch

import pytest

from shodan.contracts import InjectorKey, ShodanContractId
from shodan.services.client_api import ShodanClientAPI


# --------
# Scenarios
# --------


# Scenario Outline: Execute IP Enumeration with valid IP address
@pytest.mark.parametrize(
    "ip_address, expected_targets, expected_query_fragments_per_target, search_responses, user_info_response",
    [
        (
            "51.38.220.153",
            ["51.38.220.153"],
            [
                [
                    "ip:51.38.220.153",
                ]
            ],
            [
                {
                    "matches": [
                        {
                            "hostnames": ["automation.filigran.io"],
                            "ip_str": "51.38.220.153",
                            "port": 443,
                            "vulns": {
                                "CVE-2023-44487": {"cvss": 7.5},
                                "CVE-2025-23419": {"cvss": 4.3},
                            },
                        }
                    ],
                    "total": 1,
                }
            ],
            {"scan_credits": 1000, "query_credits": 1000, "plan": "basic"},
        ),
        (
            "51.38.220.153, 142.250.80.46",
            ["51.38.220.153", "142.250.80.46"],
            [
                [
                    "ip:51.38.220.153"
                ],
                [
                    "ip:142.250.80.46"
                ],
            ],
            [
                {
                    "matches": [
                        {
                            "hostnames": ["automation.filigran.io"],
                            "ip_str": "51.38.220.153",
                            "port": 443,
                            "vulns": {
                                "CVE-2023-44487": {"cvss": 7.5},
                            },
                        }
                    ],
                    "total": 1,
                },
                {
                    "matches": [
                        {
                            "hostnames": ["www.google.com"],
                            "ip_str": "142.250.80.46",
                            "port": 443,
                            "vulns": {
                                "CVE-2019-8936": {"cvss": 6.1},
                            },
                        }
                    ],
                    "total": 1,
                },
            ],
            {"scan_credits": 1000, "query_credits": 1000, "plan": "basic"},
        ),
    ],
    ids=[
        "single_ip_address",
        "multi_ip_address",
    ],
)
def test_ip_enumeration_with_valid_ip_address(
    shodan_client_api,
    ip_address,
    expected_targets,
    expected_query_fragments_per_target,
    search_responses,
    user_info_response,
):
    """Scenario Outline: Execute IP Enumeration with valid IP address"""
    # Given: A IP Enumeration inject_content with valid IP address
    inject_content = _given_ip_enumeration_inject_content(
        ip_address=ip_address,
    )

    # When: I execute the IP Enumeration contract via process_shodan_search
    results, credit_user = _when_execute_ip_enumeration(
        shodan_client_api,
        inject_content,
        mock_search_responses=search_responses,
        mock_user_info=user_info_response,
    )

    # Then: The results contain the expected targets and data
    _then_results_contain_expected_targets(results, expected_targets)
    _then_results_data_contains_search_responses(results, search_responses)
    _then_results_data_url_contains_expected_query(
        results,
        expected_query_fragments_per_target,
    )
    _then_credit_user_is_returned(credit_user, user_info_response)


# --------
# Given Methods
# --------


def _given_ip_enumeration_inject_content(
    ip_address: str,
) -> dict:
    """Create inject_content as received from the real injection payload.

    Mirrors the structure from _shodan_execution in openaev_shodan.py:
    data["injection"]["inject_content"]

    Args:
        ip_address: The IP address to search for.

    Returns:
        Dictionary matching the real inject_content structure.

    """
    return {
        InjectorKey.TARGET_SELECTOR_KEY: "manual",
        "ip": ip_address,
    }


# --------
# When Methods
# --------


def _when_execute_ip_enumeration(
    client: ShodanClientAPI,
    inject_content: dict,
    mock_search_responses: list[dict],
    mock_user_info: dict,
) -> tuple:
    """Execute the IP Enumeration contract through process_shodan_search.

    Mocks _request_data to return the expected API responses
    without making real HTTP calls. Each target gets its own response
    from mock_search_responses in order.

    Args:
        client: The ShodanClientAPI instance.
        inject_content: The inject content with IP address.
        mock_search_responses: List of mocked search API responses, one per target.
        mock_user_info: The mocked user info API response.

    Returns:
        Tuple of (results, shodan_credit_user).

    """
    search_call_index = 0

    def mock_request_data(method, url):
        nonlocal search_call_index
        if "api-info" in url:
            return mock_user_info
        response = mock_search_responses[search_call_index]
        search_call_index += 1
        return response

    with patch.object(client, "_request_data", side_effect=mock_request_data):
        return client.process_shodan_search(
            contract_id=ShodanContractId.IP_ENUMERATION,
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
    assert results["targets"] == targets


def _then_results_data_contains_search_responses(
    results: dict, expected_responses: list[dict]
) -> None:
    """Verify that each entry in results data contains its expected search response.

    Args:
        results: The results dict returned by process_shodan_search.
        expected_responses: List of expected Shodan API responses, one per target.

    """
    assert len(results["data"]) == len(expected_responses)

    for entry, expected_response in zip(results["data"], expected_responses):
        assert entry["target"] in results["targets"]
        assert entry["result"] == expected_response


def _then_results_data_url_contains_expected_query(
    results: dict,
    expected_fragments_per_target: list[list[str]],
) -> None:
    """Verify that each entry's URL contains the expected query fragments.

    Args:
        results: The results dict returned by process_shodan_search.
        expected_fragments_per_target: List of fragment lists, one per target.

    """
    for entry, expected_fragments in zip(
        results["data"], expected_fragments_per_target
    ):
        url = entry["url"]

        for fragment in expected_fragments:
            assert fragment in url, f"Expected '{fragment}' in URL '{url}'"

        # Verify the API key is NOT exposed in the secured URL
        assert "test-api-key" not in url


def _then_credit_user_is_returned(credit_user: dict, expected_user_info: dict) -> None:
    """Verify the credit user info is returned correctly.

    Args:
        credit_user: The credit user info returned by process_shodan_search.
        expected_user_info: The expected user info response.

    """
    assert credit_user == expected_user_info
