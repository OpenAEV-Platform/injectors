Feature: Prowler client assessments

  Background:
    Given a configured Prowler client with a process-local assessment backend

  Scenario: Starting an assessment returns an opaque handle
    When the client starts an assessment with ordered check filters
    Then it returns a non-empty assessment handle
    And the backend receives the filters in their original order

  Scenario Outline: Polling reports an explicit assessment state
    Given a started assessment in the <state> state
    When the client polls its assessment handle
    Then the returned status is <state>

    Examples:
      | state     |
      | queued    |
      | running   |
      | succeeded |
      | failed    |
      | cancelled |

  Scenario: Polling a failed assessment returns structured error data
    Given a started assessment with a structured failure
    When the client polls its assessment handle
    Then the status includes that structured failure

  # ---- Constraints identified ----

  Scenario: Empty or malformed check filters return a structured error
    When the client starts an assessment without usable check filters
    Then it returns an error with code, message, and safe details

  Scenario: An unknown or malformed assessment handle returns a structured error
    When the client polls an invalid assessment handle
    Then it returns an error with code, message, and safe details

  Scenario Outline: Parsing Prowler output preserves object record order
    Given <format> output containing object records in source order
    When the client parses the output
    Then it returns the records in the same order

    Examples:
      | format     |
      | JSON array |
      | JSON Lines |

  Scenario: Malformed or non-object output returns a safe structured error
    Given invalid Prowler output containing sensitive text
    When the client parses the output
    Then the error does not echo the raw output
