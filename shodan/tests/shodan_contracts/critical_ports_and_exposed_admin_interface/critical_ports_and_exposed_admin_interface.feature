Feature: Detection of critical or sensitive open ports using the Shodan injector
    As a Security Analyst (Standard user)
    I want to identify critical ports (RDP/SSH/SMB) and exposed admin interfaces
    So that i can identify critical or vulnerable services exposed to the Internet on my organization’s infrastructure and reduce the associated risks

    Scenario Outline: Execute Critical Ports with port, hostname and organisation
        Given I have a Critical Ports inject_content with ports "<port>", hostname "<hostname>" and organization "<organization>"
            And the Shodan search API returns <search_total> matches
            And the Shodan user info API returns plan "<plan>" with <scan_credits> scan credits and <query_credits> query credits
        When I execute process_shodan_search with the CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE contract
        Then the results targets are ["<hostname>"]
            And the results data contains <search_total> matches
            And the results data URL contains all default critical ports
            And the results data URL contains "port:<port>"
            And the results data URL contains "hostname:<hostname>"
            And the results data URL contains "org:<organization>"
            And the results data URL does not expose the API key
            And the credit user info matches the user info response

        Examples:
          | port        | hostname                | organization | search_total | plan  | scan_credits | query_credits |
          | 443         | filigran.io             | filigran.io  | 1            | basic | 1000         | 1000          |
          | 22,443,8080 | filigran.io,google.com  | -            | 3            | basic | 1000         | 1000          |
