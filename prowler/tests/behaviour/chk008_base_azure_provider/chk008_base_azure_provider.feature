Feature: CHK.008 Azure base provider
  The registered Azure route validates local input, requests the complete Azure
  provider scope once, and emits deterministic mapped Azure findings.

  Scenario: The default registry exposes the stable Azure contract
    Given the canonical routes "aws" and "azure"
    When the default contracts are serialized
    Then exactly two contracts are registered in canonical order
    And the Azure UUIDv5 and external ID are stable
    And it inherits the Azure fields and shared outputs

  Scenario: Invalid Azure input is rejected locally
    Given a blank tenant, client, secret, subscription, or provider value
    When the Azure contract parses the form
    Then it rejects the request without authenticating or dispatching Prowler

  Scenario: Valid Azure input requests the complete provider scope
    Given complete Azure service-principal credentials and target details
    When the Azure contract executes
    Then the client is invoked exactly once
    And the command contains the Azure authentication, subscription, provider, and OCSF arguments
    And no service, check, or compliance narrowing is present

  Scenario: Only normalized Azure findings are emitted
    Given ordered OCSF records for Azure and other cloud providers
    When a successful command result is mapped
    Then only case-normalized Azure findings are retained in source order
    And every retained finding preserves all 14 mapped fields
    And text output contains every finding while vulnerability output contains only failures

  Scenario: OpenAEV runtime success is completed end to end
    Given a fake Prowler client and a valid Azure injection
    When the injector receives the message
    Then reception occurs before one SUCCESS callback
    And structured output and the dynamic Rich trace contain the same mapped findings
    And credentials and process internals are absent

  Scenario: OpenAEV runtime failure is safe
    Given an invalid Azure injection containing secret canaries
    When the injector receives the message
    Then no Prowler request is made
    And one ERROR callback contains no secret canary
