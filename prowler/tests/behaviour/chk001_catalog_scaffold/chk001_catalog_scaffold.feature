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
