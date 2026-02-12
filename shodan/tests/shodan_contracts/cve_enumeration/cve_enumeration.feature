Feature: CVE Enumeration using the Shodan injector
	As a Security Analyst (Standard user)
	I want to detect hosts vulnerable to a CVE enumeration
	So that i can prioritize remediation and reduce exposure

	Scenario Outline: Execute CVE Enumeration with valid hostname and organization
		Given I have a CVE Enumeration inject_content with hostname "<hostname>" and organization "<organization>"
			And the Shodan search API returns <search_total> matches
			And the Shodan user info API returns plan "<plan>" with <scan_credits> scan credits and <query_credits> query credits
		When I execute process_shodan_search with the CVE_ENUMERATION contract
		Then the results targets are ["<hostname>"]
			And the results data contains <search_total> matches
			And the results data URL contains "has_vuln:true"
			And the results data URL contains "hostname:<hostname>,*.<hostname>"
			And the results data URL contains "org:<organization>"
			And the results data URL does not expose the API key
			And the credit user info matches the user info response

		Examples:
			| hostname               | organization | search_total | plan | scan_credits | query_credits |
			| filigran.io            | filigran.io  |            1 | basic  |          1000 |           1000 |
			| filigran.io,google.com | -            |            2 | basic  |          1000 |           1000 |