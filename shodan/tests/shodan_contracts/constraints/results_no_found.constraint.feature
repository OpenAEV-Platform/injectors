Feature: Contracts handle empty Shodan search results
	As a Security Analyst
	I want contracts to safely handle empty Shodan search results
	So that no errors occur and results remain consistent

	Scenario Outline: Execute contract when Shodan returns no matches
		Given I have a valid <contract_name> inject_content with target "<target>"
			And the Shodan search API returns an empty result set
			And the Shodan user info API returns plan "<plan>" with <scan_credits> scan credits and <query_credits> query credits
		When I execute process_shodan_search with the <contract_name> contract
		Then the results targets are ["<target>"]
			And the results data contains 0 matches
			And the results data URL does not expose the API key
			And the credit user info matches the user info response

		Examples:
			| contract_name                                | target        | plan  | scan_credits | query_credits |
			| IP_ENUMERATION                               | 1.2.3.4       | basic | 1000         | 1000          |
			| CVE_ENUMERATION                              | filigran.io   | basic | 1000         | 1000          |
			| CVE_SPECIFIC_WATCHLIST                       | filigran.io   | basic | 1000         | 1000          |
			| DOMAIN_DISCOVERY                             | filigran.io   | basic | 1000         | 1000          |
			| CLOUD_PROVIDER_ASSET_DISCOVERY               | filigran.io   | basic | 1000         | 1000          |
			| CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE   | filigran.io   | basic | 1000         | 1000          |