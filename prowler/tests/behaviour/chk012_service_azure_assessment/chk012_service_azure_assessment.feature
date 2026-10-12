Feature: CHK.012 service-specific Azure assessments
  OpenAEV operators can run one supported Azure service assessment without changing
  the existing Prowler check-filter behavior or exposing routing controls as input.

  Scenario Outline: A canonical Azure service route selects exactly one Prowler service
    Given the executable Prowler registry contains the canonical route "<route>"
    When a valid Azure assessment is executed through "<route>"
    Then the Prowler client is called exactly once with service "<service>"
    And no check filter is supplied

    Examples:
      | route         | service |
      | azure/iam     | iam     |
      | azure/storage | storage |

  Scenario: The nine executable contracts have stable canonical identities
    Given the executable Prowler registry
    Then it contains the four base routes, three AWS routes, azure/iam, and azure/storage
    And every Azure service route has service-identifying labels and no selector field

  Scenario: Unsupported service combinations stop before the client
    Given an Azure service contract is paired with an unsupported selector
    When the invalid contract execution is attempted
    Then the request is rejected before the Prowler client is called

  Scenario: Service findings preserve CHK.005 mapping order in shared outputs
    Given ordered mapped and non-Azure OCSF records for azure/storage
    When the azure/storage assessment completes
    Then mapped Azure findings retain their order in Text and Vulnerability outputs
    And the same mapped findings appear in the dynamic Rich trace

  Scenario Outline: Runtime dispatch emits exact service argv without real execution
    Given a fake CLI engine and valid Azure runtime message for "<route>"
    When the injector processes the runtime message
    Then exactly one fake CLI request contains "--services" followed by "<service>"
    And credentials, stderr, and path canaries are absent from the callback

    Examples:
      | route         | service |
      | azure/iam     | iam     |
      | azure/storage | storage |

# ---- Constraints identified ----
  Scenario: Existing check filters retain their dedicated CLI flag
    Given a fake Azure Prowler client request with an existing check filter
    When that request is rendered without a service selector
    Then the check filter still uses "-c" and no "--services" argument is emitted

  Scenario: An Azure service selector cannot target another provider
    Given a fake AWS Prowler client request with Azure service "storage"
    When the client request is validated
    Then it is rejected before the fake CLI engine is called

  Scenario: Azure inputs receive structural validation only
    Given an Azure service form whose provider fields are nonblank
    When the service contract parses the form
    Then the values are accepted without cloud access or semantic identifier lookup
