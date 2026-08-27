Feature: CHK.009 GCP base provider
  The registered GCP route validates local input, requests the complete GCP
  provider scope once, and emits deterministic mapped GCP findings.

  Scenario: The default registry exposes the stable GCP contract
    Given the canonical routes "aws", "azure", and "gcp"
    When the default contracts are serialized
    Then exactly three contracts are registered in canonical order
    And the GCP UUIDv5 and external ID are stable
    And it inherits the GCP fields and shared outputs

  Scenario: Invalid GCP input is rejected locally
    Given a blank service-account or project value
    When the GCP contract parses the form
    Then it rejects the request without authenticating or dispatching Prowler

  Scenario: Valid GCP input requests the complete provider scope
    Given complete GCP service-account credentials and a project
    When the GCP contract executes
    Then the client is invoked exactly once
    And one temporary JSON credential lease exists during fake engine execution
    And the lease is cleaned after execution
    And no service, check, or compliance narrowing is present

  Scenario: Only normalized GCP findings are emitted
    Given ordered OCSF records for GCP and other cloud providers
    When a successful command result is mapped
    Then only case-normalized GCP findings are retained in source order
    And every retained finding preserves all 14 mapped fields
    And text output contains every finding while vulnerability output contains only failures

  Scenario: OpenAEV runtime success is completed end to end
    Given a fake Prowler client and a valid GCP injection
    When the injector receives the message
    Then reception occurs before one SUCCESS callback
    And structured output and the dynamic Rich trace contain the same mapped findings
    And credentials and process internals are absent

  Scenario: OpenAEV runtime failure is safe
    Given an invalid GCP injection containing secret canaries
    When the injector receives the message
    Then no Prowler request is made
    And one ERROR callback contains no secret canary
