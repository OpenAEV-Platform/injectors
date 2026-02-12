Feature: IP Enumeration using the Shodan injector
	As a Security Analyst (Standard user)
	I want to collect ports and vulnerabilities from a specific IP
	So that i can identify exposed services and potential attack vectors

	Scenario Outline: Execute IP Enumeration with valid IP address
		Given I have a IP Enumeration inject_content with IP "<ip_address>"
			And the Shodan search API returns <search_total> matches
			And the Shodan user info API returns plan "<plan>" with <scan_credits> scan credits and <query_credits> query credits
		When I execute process_shodan_search with the IP_ENUMERATION contract
		Then the results targets are ["<ip_address>"]
			And the results data contains <search_total> matches
			And the results data URL contains "ip:<ip_address>"
			And the results data URL does not expose the API key
			And the credit user info matches the user info response

		Examples:
			| ip_address | search_total | plan | scan_credits | query_credits |
			| 51.38.220.153                |            1 | basic  |          1000 |           1000 |
			| 51.38.220.153, 142.250.80.46 |            2 | basic  |          1000 |           1000 |