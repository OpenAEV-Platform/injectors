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
    Given an OCSF finding with status "<source_status>"
    When the finding is mapped
    Then expectation_result is "<result_status>"

    Examples:
      | source_status | result_status |
      | PASS          | SUCCESS       |
      | passed        | SUCCESS       |
      | FAIL          | FAILED        |
      | failed        | FAILED        |
      | MUTED         | IGNORED       |
      | manual        | IGNORED       |
      | SUPPRESSED    | IGNORED       |
      | ERROR         | MUTED         |
      | UNKNOWN       | MUTED         |

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

  Scenario: Reject whitespace-padded status rather than silently normalizing it
    Given an OCSF finding with whitespace around a recognized status
    When the finding is mapped
    Then expectation_result is MUTED
