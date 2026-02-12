Feature: Shodan - Domain Discovery Contract
	As a security analyst,
	I want to execute the Domain Discovery contract with a hostname and organisation,
	So that I can retrieve all exposed assets matching the domain from Shodan.

	Scenario Outline: Execute domain discovery with valid hostname and organisation
		Given I have a domain discovery inject_content with hostname "<hostname>" and organisation "<organization>"
			And the Shodan search API returns <search_total> matches
			And the Shodan user info API returns plan "<plan>" with <scan_credits> scan credits and <query_credits> query credits
		When I execute process_shodan_search with the DOMAIN_DISCOVERY contract
		Then the results targets are ["<hostname>"]
			And the results data contains <search_total> matches
			And the results data URL contains "hostname:<hostname>,*.<hostname>"
			And the results data URL contains "org:<organization>"
			And the results data URL does not expose the API key
			And the credit user info matches the user info response

		Examples:
			| hostname               | organization | search_total | plan | scan_credits | query_credits |
			| filigran.io            | filigran.io  |            2 | basic  |          1000 |           1000 |
			| filigran.io,google.com | filigran.io  |            4 | basic  |          1000 |           1000 |
			| filigran.io,google.com | -            |            4 | basic  |          1000 |           1000 |