Feature: CHK.010 Kubernetes base provider
  The registered Kubernetes route validates local input, requests the complete Kubernetes
  provider scope once, and emits deterministic mapped Kubernetes findings.

  Scenario: The default registry exposes the stable Kubernetes contract
    Given the canonical routes "aws", "azure", "gcp", and "kubernetes"
    When the default contracts are serialized
    Then exactly four contracts are registered in canonical order
    And the Kubernetes UUIDv5 and external ID are stable
    And it inherits the Kubernetes fields and shared outputs

  Scenario: Invalid Kubernetes input is rejected locally
    Given a blank kubeconfig or context value
    When the Kubernetes contract parses the form
    Then it rejects the request without authenticating or dispatching Prowler

  Scenario: Valid Kubernetes input requests the complete provider scope
    Given a nonblank Kubernetes kubeconfig and context
    When the Kubernetes contract executes
    Then the client is invoked exactly once
    And one closed temporary YAML credential lease is usable during fake engine execution
    And the lease is cleaned after every execution outcome
    And no service, check, or compliance narrowing is present

  Scenario: Only normalized Kubernetes findings are emitted
    Given ordered OCSF records for Kubernetes and other cloud providers
    When a successful command result is mapped
    Then only case-normalized Kubernetes findings are retained in source order
    And every retained finding preserves all 14 mapped fields
    And text output contains every finding while vulnerability output contains only failures

  Scenario: OpenAEV runtime success is completed end to end
    Given a fake Prowler client and a valid Kubernetes injection
    When the injector receives the message
    Then reception occurs before one SUCCESS callback
    And structured output and the dynamic Rich trace contain the same mapped findings
    And credentials and process internals are absent

  Scenario: OpenAEV runtime failure is safe
    Given an invalid Kubernetes injection containing secret canaries
    When the injector receives the message
    Then no Prowler request is made
    And one ERROR callback contains no secret canary
