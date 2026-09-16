Feature: Prowler catalog registration and project scaffold
  Scenario: Discoverable Prowler catalog registration
    Given a Prowler injector project is available
    When its catalog registration and configuration are completed
    Then Prowler is discoverable in the OpenAEV catalog
    And its available configuration is clearly identified

  # ---- Constraints identified ----
  Scenario: Foundation configuration excludes future provider settings
    Given CHK.001 owns only the injector configuration foundation
    When the available configuration is inspected
    Then only the standard OpenAEV and injector settings are present

  Scenario: Foundation startup registers no assessment contracts
    Given assessment contracts are deferred to CHK.006
    When the Prowler injector starts
    Then it registers with an empty contract catalog

  Scenario Outline: Startup failures are logged without sensitive exception details
    Given startup fails with a <failure type> containing a sensitive canary
    When the Prowler injector handles the startup failure
    Then it emits a safe ERROR log without the exception or a traceback
    And it exits with status <exit status>

    Examples:
      | failure type         | exit status |
      | configuration error  | 2           |
      | unexpected exception | 1           |
