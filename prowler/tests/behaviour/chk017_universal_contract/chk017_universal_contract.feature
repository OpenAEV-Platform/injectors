Feature: CHK.017 universal selectable contract
  The universal contract picks one provider, shows only that provider's
  fields, and optionally narrows to one service or one compliance route.

  Scenario: The form conditions every credential field on the provider select
    Given the universal contract is serialized
    Then it declares 20 fields in order: provider select, fifteen credential fields, three provider service selects, compliance select
    And the provider select is mandatory single-valued with default ["aws"] and the four provider choices
    And every credential field is visible and (for the thirteen required ones) mandatory only when prowler_provider equals its own provider
    And each provider service select is visible only for its scalar provider and contains only that provider's routes plus "None (base scan)"
    And no Kubernetes service select exists
    And all four optional scope selects default to ["__none__"] and compliance remains global with fourteen routes plus none
    And outputs and manual flag are unchanged

  Scenario Outline: Empty scope selects run the provider base once
    Given the universal contract with provider "<provider>" and valid credential fields
    And neither scope select set
    When it is executed against the fake client seam
    Then the seam is called exactly once with no service selector, no compliance selector, and no check filters
    And findings are retained only for provider "<provider>" in source order
    And the safe request summary reports selected_provider "<provider>" and filters "base"
    And the trace provider line reports "<provider>"

    Examples:
      | provider   |
      | aws        |
      | kubernetes |

  Scenario: A service scope runs exactly that service once
    Given the universal contract with provider "aws" and valid AWS fields
    And service scope "aws/s3"
    When it is executed against the fake client seam
    Then the seam is called exactly once with service selector "s3"
    And the safe request summary reports "service=aws/s3" and selected_provider "aws"

  Scenario: A compliance scope runs exactly that framework once
    Given the universal contract with provider "kubernetes" and valid kubeconfig fields
    And compliance scope "cis/kubernetes"
    When it is executed against the fake client seam
    Then the seam is called exactly once with compliance selector "cis_1.12_kubernetes"
    And the safe request summary reports "compliance=cis/kubernetes" and selected_provider "kubernetes"

  Scenario: Setting both scope selects is rejected before any client call
    Given the universal contract with provider "gcp" and valid GCP fields
    And both service scope "gcp/iam" and compliance scope "iso27001/gcp" set
    When the contract parses the form input
    Then a single contract input error reports the closed both-set conflict type at the two scope locations
    And no client seam is invoked and no submitted value appears in the error

  Scenario: Global compliance whose provider disagrees with the selected provider is rejected
    Given the universal contract with provider "azure" and valid Azure fields
    And compliance scope "mitre/aws"
    When the contract parses the form input
    Then a contract input error reports the closed provider-scope mismatch type at the compliance location
    And no client seam is invoked and no submitted value appears in the error

  Scenario: Wrong-provider credential fields cannot satisfy the selected provider
    Given the universal contract with provider "aws" selected
    And the form carries valid azure fields but no aws fields
    When the contract parses the form input
    Then it is rejected with the same safe structure as the fixed aws contract for the missing aws fields
    And the azure fields are ignored without producing any issue
    And no client seam is invoked

  Scenario: A missing provider select is rejected before any client call
    Given form input with valid aws credential fields but no provider select
    When the universal contract parses it
    Then a contract input error identifies the provider select location with the stable missing type
    And a "provider" key is still rejected as forbidden before any other check
    And no client seam is invoked and no submitted value appears in the error

  Scenario: A failed universal run preserves the error unchanged
    Given the universal contract with provider "gcp" and service scope "gcp/compute"
    And a fake client seam that returns a nonzero result with an engine error
    When its parsed provider input is executed
    Then the outcome preserves the error and returns no findings
    And the failure classification, trace, and callback behave as on the fixed gcp service route

  Scenario: The registry admits the full 32-contract catalog with stable identities
    Given the universal contract registered with the existing thirty-one
    When the default contracts are serialized and resolved
    Then 32 routes are executable, each with its stable UUID and external ID
    And the new route name collides with no existing or grammatically valid future route
    And the thirty-one pre-existing serialized contracts are unchanged against the baseline snapshot

  Scenario: Scope choices are derived from the selector literals
    Given the universal scope choice maps and the CHK.004 selector literal types
    When the drift guard compares both directions against the route catalog
    Then the seven service and fourteen compliance choices equal the catalog routes in canonical order
    And kubernetes offers compliance only (cis, iso27001) and no service option
