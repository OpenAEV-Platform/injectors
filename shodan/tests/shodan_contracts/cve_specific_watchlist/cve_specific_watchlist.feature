Feature: CVE-specific Watchlist using the Shodan injector
	As a Security Analyst (Standard user)
	I want to detect hosts vulnerable to a specific CVE
	So that i can prioritize remediation and reduce exposure

	Scenario Outline: Execute CVE Specific Watchlist with valid vulnerability, hostname and organization
		Given I have a CVE Specific Watchlist inject_content with vulnerability "<vulnerability>", hostname "<hostname>" and organization "<organization>"
			And the Shodan search API returns <search_total> matches
			And the Shodan user info API returns plan "<plan>" with <scan_credits> scan credits and <query_credits> query credits
		When I execute process_shodan_search with the CVE_SPECIFIC_WATCHLIST contract
		Then the results targets are ["<hostname>"]
			And the results data contains <search_total> matches
			And the results data URL contains "vuln:<vulnerability>"
			And the results data URL contains "hostname:<hostname>,*.<hostname>"
			And the results data URL contains "org:<organization>"
			And the results data URL does not expose the API key
			And the credit user info matches the user info response

		Examples:
			| vulnerability | hostname | organization | search_total | plan | scan_credits | query_credits |
			| CVE-2023-44487                | filigran.io           | filigran.io  |            1 | basic  |          1000 |           1000 |
			| CVE-2023-44487,CVE-2019-8936 | filigran.io,google.com | -            |            2 | basic  |          1000 |           1000 |