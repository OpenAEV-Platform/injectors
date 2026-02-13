Feature: Organization resolution per hostname
    As a Security Analyst
    I want organization to be correctly resolved for each hostname
    So that Shodan queries remain accurate

    Scenario Outline: Organization defaults to hostname when not provided
        Given I have a valid inject_content with hostname "<hostname>" and no organization
        When I execute process_shodan_search
        Then the organization is defined according to each iteration of the hostname
            And each result URL contains an organization derived from its hostname

        Examples:
            | hostname               |
            | filigran.io            |
            | filigran.io,google.com |


    Scenario Outline: Organization is explicitly provided
        Given I have a valid inject_content with hostname "<hostname>" and organization "<organization>"
        When I execute process_shodan_search
        Then the provided organization "<organization>" is applied to all hostnames
            And each result URL contains "org:<organization>"

        Examples:
            | hostname                     | organization |
            | filigran.io                  | filigran.io  |
            | filigran.io,google.com       | filigran.io  |