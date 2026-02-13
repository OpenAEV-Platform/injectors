"""Essential tests for Organization resolution per hostname - Gherkin GWT Format."""

from unittest.mock import patch

import pytest

from shodan.contracts import InjectorKey, ShodanContractId
from shodan.services.client_api import ShodanClientAPI

# --------
# Scenarios
# --------


# Scenario Outline: Organization defaults to hostname when not provided
@pytest.mark.parametrize(
    "hostname, expected_query_fragments_per_target",
    [
        # Organization not provided -> derived from hostname
        (
            "filigran.io",
            [
                [
                    "hostname:filigran.io,*.filigran.io",
                    "org:filigran.io",
                ],
            ],
        ),
        (
            "filigran.io,google.com",
            [
                [
                    "hostname:filigran.io,*.filigran.io",
                    "org:filigran.io",
                ],
                [
                    "hostname:google.com,*.google.com",
                    "org:google.com",
                ],
            ],
        ),
    ],
    ids=[
        "single_hostname_organization_not_provided",
        "multi_hostname_organization_not_provided",
    ],
)
def test_organization_resolution_organization_not_provided(
    shodan_client_api: ShodanClientAPI,
    hostname: str,
    expected_query_fragments_per_target: list[list[str]],
):
    """Scenario Outline: Organization defaults to hostname when not provided"""
    # Given I have a valid inject_content with hostname "<hostname>" and no organization
    inject_content = _given_contract_inject_content(
        hostname=hostname,
        organization=None,
    )
    # When: When I execute process_shodan_search
    hostnames = [h.strip() for h in hostname.split(",")]
    results, credit_user = _when_execute_process_shodan_search(
        shodan_client_api,
        ShodanContractId.DOMAIN_DISCOVERY,
        inject_content,
        mock_search_responses=[{"matches": [], "total": 0} for _ in hostnames],
        mock_user_info={"plan": "basic", "scan_credits": 1000, "query_credits": 1000},
    )

    # Then each result URL contains the expected organization derived from its hostname
    _then_results_data_url_contains_expected_query(
        results, expected_query_fragments_per_target
    )


# Scenario Outline: Organization is explicitly provided
@pytest.mark.parametrize(
    "hostname, organization, expected_query_fragments_per_target",
    [
        # Organization explicitly provided -> same for all hostnames
        (
            "filigran.io",
            "filigran.io",
            [
                [
                    "hostname:filigran.io,*.filigran.io",
                    "org:filigran.io",
                ],
            ],
        ),
        (
            "filigran.io,google.com",
            "filigran.io",
            [
                [
                    "hostname:filigran.io,*.filigran.io",
                    "org:filigran.io",
                ],
                [
                    "hostname:google.com,*.google.com",
                    "org:filigran.io",
                ],
            ],
        ),
    ],
    ids=[
        "single_hostname_organization_provided",
        "multi_hostname_organization_provided",
    ],
)
def test_organization_resolution_organization_provided(
    shodan_client_api,
    hostname,
    organization,
    expected_query_fragments_per_target,
):
    """Scenario Outline: Organization is explicitly provided"""
    # Given I have a valid inject_content with hostname "<hostname>" and organization "<organization>"
    inject_content = _given_contract_inject_content(
        hostname=hostname,
        organization=organization,
    )
    # When: When I execute process_shodan_search
    hostnames = [h.strip() for h in hostname.split(",")]
    results, credit_user = _when_execute_process_shodan_search(
        shodan_client_api,
        ShodanContractId.DOMAIN_DISCOVERY,
        inject_content,
        mock_search_responses=[{"matches": [], "total": 0} for _ in hostnames],
        mock_user_info={"plan": "basic", "scan_credits": 1000, "query_credits": 1000},
    )

    # Then the provided organization "<organization>" is applied to all hostnames
    _then_results_data_url_contains_expected_query(
        results, expected_query_fragments_per_target
    )


# --------
# Given Methods
# --------


def _given_contract_inject_content(
    hostname: str,
    organization: str | None,
) -> dict:
    """Create inject_content as received from the real injection payload.

    Mirrors the structure from _shodan_execution in openaev_shodan.py:
    data["injection"]["inject_content"]

    Args:
        hostname: The hostname to search for.
        organization: The organization to filter by.

    Returns:
        Dictionary matching the real inject_content structure.

    """
    return {
        InjectorKey.TARGET_SELECTOR_KEY: "manual",
        "hostname": hostname,
        "organization": organization,
    }


# --------
# When Methods
# --------


def _when_execute_process_shodan_search(
    client: ShodanClientAPI,
    contract_id: ShodanContractId,
    inject_content: dict,
    mock_search_responses: list[dict],
    mock_user_info: dict,
) -> tuple:
    """Execute the Critical Ports contract through process_shodan_search.

    Mocks _request_data to return the expected API responses
    without making real HTTP calls. Each target gets its own response
    from mock_search_responses in order.

    Args:
        client: The ShodanClientAPI instance.
        inject_content: The inject content with hostname and organization.
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
            contract_id=contract_id,
            inject_content=inject_content,
        )


# --------
# Then Methods
# --------


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
