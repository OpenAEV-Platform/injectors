Feature: Cloud provider asset discovery using the Shodan injector
    As a Security Analyst (Standard user)
    I want to discover assets hosted by cloud providers
    So that i can track and control cloud exposure linked to my hostname / organization

    Scenario Outline: Execute Cloud Provider Asset Discovery with valid cloud_provider, hostname and organization
        Given I have a Cloud Provider Asset Discovery inject_content with cloud_provider "<cloud_provider>", hostname "<hostname>" and organization "<organization>"
            And the Shodan search API returns <search_total> matches
            And the Shodan user info API returns plan "<plan>" with <scan_credits> scan credits and <query_credits> query credits
        When I execute process_shodan_search with the CLOUD_PROVIDER_ASSET_DISCOVERY contract
        Then the results targets are ["<hostname>"]
            And the results data contains <search_total> matches
            And the results data URL contains all default cloud_provider
            And the results data URL contains "cloud.provider:<cloud_provider>"
            And the results data URL contains "hostname:<hostname>,*.<hostname>"
            And the results data URL contains "org:<organization>"
            And the results data URL does not expose the API key
            And the credit user info matches the user info response

        Examples:
            | cloud_provider | hostname               | organization | search_total | plan  | scan_credits | query_credits |
            | Google         | filigran.io            | -            | 1            | basic | 1000         | 1000          |
            | Google,Amazon  | filigran.io,google.com | filigran.io  | 3            | basic | 1000         | 1000          |