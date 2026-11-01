Feature: CHK.016 executable MITRE ATT&CK compliance routes
  The final Prowler catalog exposes one fixed MITRE ATT&CK assessment per
  supported cloud provider while preserving the existing finding boundary.

  Scenario: Register the complete canonical contract catalog
    Given the final ordered catalog of 25 Prowler routes
    When the default contracts are serialized and resolved
    Then all 25 routes are executable in canonical order
    And each MITRE contract exposes only its provider credential fields
    And each MITRE contract declares the shared Text and Vulnerability outputs

  Scenario Outline: Execute a fixed provider MITRE assessment
    Given the executable MITRE route "<route>" for "<provider>"
    When its validated provider input is executed
    Then the client is called once with compliance selector "<selector>"
    And neither check nor service selection is requested

    Examples:
      | route       | provider | selector           |
      | mitre/aws   | aws      | mitre_attack_aws   |
      | mitre/azure | azure    | mitre_attack_azure |
      | mitre/gcp   | gcp      | mitre_attack_gcp   |

  Scenario: Preserve mapped findings and MITRE compliance values
    Given ordered CHK.005 OCSF findings with duplicate MITRE compliance values
    When a MITRE compliance contract maps the successful result
    Then provider findings and duplicate occurrences retain source order
    And MITRE and compliance values remain in compliance_tags without deduplication
    And the same findings feed Text, Vulnerability, and dynamic Rich presentation
    And no technique coverage report or additional output is produced

  Scenario: Reject unsupported internal MITRE selection before the client
    Given a MITRE route whose provider and fixed selector do not agree
    When its validated provider input is executed
    Then the request is rejected before the client is called

  Scenario: Preserve provider runtime boundaries
    Given fake engines and provider-specific credential adapters
    When each MITRE route runs through the injector runtime
    Then exactly one fake Prowler request ends in its fixed compliance selector
    And environment credentials and temporary credential leases retain their lifecycle
    And credential, stderr, and temporary-path canaries do not enter callbacks

  # ---- Constraints identified ----

  Scenario: Preserve existing check, service, and compliance selection
    Given the final MITRE selector values are admitted internally
    When existing assessment families execute
    Then check, service, CIS, NIS2, and ISO27001 behavior remains unchanged
    And no public compliance selector field is introduced
