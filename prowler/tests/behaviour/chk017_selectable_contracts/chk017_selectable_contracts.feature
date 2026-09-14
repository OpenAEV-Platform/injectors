Feature: CHK.017 selectable service and compliance contracts
  CHK.017 adds six additive single-selection routes over the unchanged
  CHK.004 seam: one service select and one compliance select per supported
  cloud provider. The dropdown choices are derived from the CHK.004 selector
  literals, so the form and the parse boundary cannot drift.

  Scenario Outline: Selectable service executes the chosen service once
    Given the selectable service contract for "<provider>"
    And form input with its provider fields and service "<service>"
    When it is executed against the fake client seam
    Then the seam is called exactly once with service selector "<service>" and no check filters
    And the mapped findings and raw evidence survive the common mapper
    And the safe request summary reports "service=<selected>"

    Examples:
      | route              | provider | service |
      | aws/select-service   | aws      | s3      |
      | azure/select-service | azure    | storage |
      | gcp/select-service   | gcp      | compute |

  Scenario Outline: Selectable compliance executes the chosen framework once
    Given the selectable compliance contract for "<provider>"
    And form input with its provider fields and framework "<framework>"
    When it is executed against the fake client seam
    Then the seam is called exactly once with compliance selector "<framework>" and no service selector or check filters
    And the mapped findings and raw evidence survive the common mapper
    And the safe request summary reports "compliance=<selected>"

    Examples:
      | route                  | provider | framework           |
      | aws/select-compliance    | aws      | nis2_aws            |
      | azure/select-compliance  | azure    | iso27001_2022_azure |
      | gcp/select-compliance    | gcp      | mitre_attack_gcp    |

  Scenario: The select field is a closed single selection
    Given each selectable contract is serialized
    Then every one declares exactly one select field
    And the field is mandatory with cardinality one
    And defaultValue is the first derived choice
    And the choices equal the offered selector values with readable labels

  Scenario: A missing select value is rejected before any client call
    Given any selectable contract
    When form input omits the select key, supplies a non-list value, or an empty list
    Then the parse fails with select_missing before any client call
    And no submitted value appears in the error

  Scenario: An unknown select value is rejected before any client call
    Given any selectable contract
    When form input supplies a value outside the closed set (including case or whitespace variants)
    Then the parse fails with select_unknown_value (or select_multiple) before any client call
    And no submitted value appears in the error

  Scenario: Provider-field rejection is unchanged for selectable contracts
    Given any selectable contract
    When form input contains a cross-provider field or the provider key
    Then it is rejected with the same safe structure as the fixed contracts
    And the provider key is rejected first even when the select value is also invalid

  Scenario: Dropdown choices are derived from the selector literals
    Given the six selectable contracts
    Then their choices equal the CHK.004 selector literal values in both directions
    And no kubernetes selectable route exists

  Scenario: The registry admits the full 31-contract catalog with stable identities
    Given the default registry is serialized
    Then 31 routes are executable in canonical order
    And each carries its stable UUID and external ID
    And the new route names cannot collide with existing or grammatically valid future routes
    And the twenty-five pre-existing serialized contracts are unchanged

  Scenario: A failed selectable run preserves the error unchanged
    Given the selectable service contract for "aws" selecting "iam"
    And a fake client seam that returns a nonzero result with an engine error
    When its parsed provider input is executed
    Then the outcome preserves the error and returns no findings
    And the failure classification, trace, and callback behave as on a fixed service route
