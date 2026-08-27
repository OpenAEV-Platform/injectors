Feature: Map raw Prowler OCSF output to OpenAEV findings
  A successful Prowler assessment is translated without executing another command.

  Scenario: Map an OCSF JSON array in source order
    Given successful raw Prowler output containing two OCSF findings
    When the output is mapped to OpenAEV findings
    Then two immutable findings are returned in source order
    And every finding declares exactly the 14 OpenAEV fields

  Scenario: Map OCSF JSON Lines while ignoring blank lines
    Given successful raw Prowler JSON Lines output separated by blank lines
    When the output is mapped to OpenAEV findings
    Then each object becomes one finding in source order

  Scenario Outline: Normalize finding status
    Given an OCSF finding with lifecycle status "<status>" and result status code "<status_code>"
    When the finding is mapped
    Then expectation_result is "<result_status>"

    Examples:
      | status     | status_code | result_status |
      | New        | PASS        | SUCCESS       |
      | New        | pass        | SUCCESS       |
      | New        | FAIL        | FAILED        |
      | New        | failed      | FAILED        |
      | Suppressed | FAIL        | IGNORED       |
      | suppressed | PASS        | IGNORED       |
      | MUTED      | FAIL        | IGNORED       |
      | manual     | PASS        | IGNORED       |
      | New        | ERROR       | IGNORED       |
      | New        | UNKNOWN     | IGNORED       |
      | New        |  PASS       | IGNORED       |

  Scenario Outline: Normalize finding severity
    Given an OCSF finding with severity "<source_severity>"
    When the finding is mapped
    Then severity is "<normalized_severity>"
    And severity_weight is <weight>

    Examples:
      | source_severity | normalized_severity | weight |
      | critical        | CRITICAL            | 4      |
      | HIGH            | HIGH                | 3      |
      | medium          | MEDIUM              | 2      |
      | LOW             | LOW                 | 1      |
      | informational   | INFO                | 0      |
      | unknown         | INFO                | 0      |

  Scenario: Preserve Prowler 5.36 compliance value order
    Given an OCSF finding with ordered compliance values under unmapped.compliance
    When the finding is mapped
    Then compliance_tags contains every value in source order

  Scenario: Use safe fallbacks for optional values
    Given an OCSF finding without severity or compliance and with no remediation reference
    When the finding is mapped
    Then severity is INFO with weight zero
    And compliance_tags is empty
    And remediation_url is absent

  Scenario: Map a cloudless Kubernetes finding
    Given an OCSF finding without cloud and with provider identity under unmapped
    When the finding is mapped
    Then provider and account come from unmapped and region comes from the resource namespace

  # ---- Constraints identified ----

  Scenario: Reject malformed raw output without disclosing it
    Given raw output containing malformed or non-UTF-8 sensitive data
    When the output is decoded
    Then a structured safe decode error is returned without the raw data

  Scenario: Reject a missing required source path without a lookup exception
    Given an OCSF finding missing a required mapped source path
    When the finding is mapped
    Then a structured mapping error identifies the record index and source path

  Scenario: Reject an empty required resource collection
    Given an OCSF finding with no resources
    When the finding is mapped
    Then a structured mapping error identifies resources[0]

  Scenario: Reject whitespace-padded status code rather than silently normalizing it
    Given an OCSF finding with whitespace around a recognized status code
    When the finding is mapped
    Then expectation_result is IGNORED

  # ---- Prowler 3.x nested dual-shape contract ----

  Scenario: Map a Prowler 3.11.3 nested detection finding
    Given an OCSF finding with a finding block, nested remediation, and top-level compliance
    When the finding is mapped
    Then all 14 OpenAEV fields are mapped from the nested shape
    And compliance_tags keeps the compound requirement strings in order without splitting or deduplication
    And remediation_url is the first kb_articles entry without URL validation
    And unmapped nested fields such as severity_id, status_detail, and state have no effect

  Scenario: Preserve a nested Prowler 3.x result when status_code is absent
    Given a nested OCSF finding whose legacy result is carried by status
    When the finding is mapped
    Then the legacy status vocabulary maps without changing the nested field shape

  Scenario: Select the present finding block by precedence
    Given an OCSF finding with both finding_info and finding blocks
    When the finding is mapped
    Then finding_info is selected and the finding block is never read
    And an empty present finding_info reports missing finding_info.uid without fallback
    And a null finding_info is an invalid value at finding_info without fallback

  Scenario: Resolve remediation across top level and finding blocks
    Given an OCSF finding whose selected finding block carries its own remediation
    When the finding is mapped
    Then a present top-level remediation always wins with its exact flat mapping
    And kb_articles inside a top-level remediation is ignored leaving remediation_url absent
    And references presence wins over kb_articles within one block even when references is empty
    And an empty kb_articles without references leaves remediation_url absent
    And neither location present is a structured error at remediation|finding.remediation

  Scenario: Resolve compliance across unmapped and top level
    Given an OCSF finding with top-level compliance requirements
    When the finding is mapped
    Then a present non-null unmapped.compliance always wins with framework-preserving flattening
    And a null unmapped.compliance defers to top-level compliance requirements
    And a present empty unmapped.compliance wins with empty tags
    And string or list requirements become tags in encounter order without splitting or deduplication
    And a non-string requirements leaf or a mapping is a precise-path structured error
    And absent or null requirements produce empty tags

  Scenario: Report a missing finding block with a union source path
    Given an OCSF finding without finding_info or finding
    When the finding is mapped
    Then a structured mapping error uses source path finding_info|finding

  Scenario: Keep dual-shape error coordinates content-free
    Given a nested OCSF finding violating a required or typed nested path
    When the finding is mapped
    Then the structured mapping error carries only code, record index, and source path
