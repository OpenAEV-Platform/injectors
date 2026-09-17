Feature: CHK.007 AWS base provider
  The registered AWS route validates local input, requests the complete AWS
  provider scope once, and emits deterministic mapped AWS findings.

  Scenario: The default registry exposes one stable AWS contract
    Given the canonical route "aws"
    When the default contracts are serialized
    Then exactly one contract is registered in canonical order
    And its UUIDv5 and external ID are stable
    And it inherits the AWS fields and shared outputs

  Scenario: Invalid AWS input is rejected locally
    Given missing credentials, a blank region, or a non-12-digit account ID
    When the AWS contract parses the form
    Then it rejects the request without authenticating or dispatching Prowler

  Scenario: Valid AWS input requests the complete provider scope
    Given complete AWS credentials and target details
    When the AWS contract executes
    Then the client is invoked exactly once
    And the command contains the AWS provider, region, and OCSF output arguments
    And no service, check, or compliance narrowing is present

  Scenario: Only normalized AWS findings are emitted
    Given ordered OCSF records for AWS and other cloud providers
    When a successful command result is mapped
    Then only case-normalized AWS findings are retained in source order
    And every retained finding preserves all 14 mapped fields

  Scenario: OpenAEV runtime success is completed end to end
    Given a fake Prowler client and a valid AWS injection
    When the injector receives the message
    Then reception occurs before one SUCCESS callback
    And structured output and the Rich trace contain the same mapped findings
    And credentials and process internals are absent

  Scenario: OpenAEV runtime failure is safe
    Given an invalid AWS injection containing secret canaries
    When the injector receives the message
    Then no Prowler request is made
    And one ERROR callback contains no secret canary
