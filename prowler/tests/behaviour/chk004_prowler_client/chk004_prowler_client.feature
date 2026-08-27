Feature: Synchronous Prowler CLI assessments

  Background:
    Given a configured Prowler runtime and one supported provider input

  Scenario: Creating a client has no execution side effect
    When the factory creates a provider client
    Then no Prowler command has run

  Scenario: Running a full assessment returns the CLI result unchanged
    When the client runs with no check filters
    Then Prowler receives the provider invocation without a check selector
    And the exact CLI command result is returned

  Scenario: The factory quick-access run is equivalent to a created client run
    When the same assessment is run through both public entry points
    Then both entry points submit equivalent command requests

  Scenario: Check filters preserve order and duplicates
    When the client runs checks check-z, check-a, and check-z
    Then Prowler receives each check as a separate ordered argument

  Scenario Outline: Each provider uses its explicit authentication boundary
    Given a <provider> provider input
    When the client runs the provider assessment
    Then only the required <provider> environment and arguments are submitted

    Examples:
      | provider   |
      | AWS        |
      | Azure      |
      | GCP        |
      | Kubernetes |

  # ---- Constraints identified ----

  Scenario: Blank check filters are rejected before execution
    When the client receives a blank check filter
    Then no Prowler command runs

  Scenario: Configured executable and bounded raw execution are mandatory
    When the client runs an assessment
    Then the request uses the exact configured executable and raw byte parser
    And stdin and working directory are empty with explicit resource limits

  Scenario: File-backed credentials are owner-only and short-lived
    Given a GCP or Kubernetes provider input
    When the synchronous assessment succeeds, fails, or raises
    Then the credential file exists with owner-only permissions only during execution
    And the credential content is absent from command arguments and errors
