Feature: CHK.013 service-specific GCP assessments
  OpenAEV operators can run one supported GCP service assessment without changing
  the existing Prowler check-filter behavior or exposing routing controls as input.

  Scenario Outline: A canonical GCP service route selects exactly one Prowler service
    Given the executable Prowler registry contains the canonical route "<route>"
    When a valid GCP assessment is executed through "<route>"
    Then the Prowler client is called exactly once with service "<service>"
    And no check filter is supplied

    Examples:
      | route       | service |
      | gcp/iam     | iam     |
      | gcp/compute | compute |

  Scenario: The eleven executable contracts have stable canonical identities
    Given the executable Prowler registry
    Then it contains the four base routes and all seven service routes in canonical order
    And every GCP service route has service-identifying labels and no selector field

  Scenario: Unsupported service combinations stop before the client
    Given a GCP service contract is paired with an unsupported selector
    When the invalid contract execution is attempted
    Then the request is rejected before the Prowler client is called

  Scenario: Service findings preserve CHK.005 mapping order and duplicates
    Given ordered duplicate mapped and non-GCP OCSF records for gcp/compute
    When the gcp/compute assessment completes
    Then mapped GCP findings retain their order and duplicates in Text and Vulnerability outputs
    And the same dynamic mapped findings appear in the Rich trace

  Scenario Outline: Runtime dispatch emits exact service argv without real execution
    Given a fake CLI engine and valid GCP runtime message for "<route>"
    When the injector processes the runtime message
    Then exactly one fake CLI request contains "--services" followed by "<service>"
    And the credential lease is cleaned after that request
    And credentials, stderr, and path canaries are absent from the callback

    Examples:
      | route       | service |
      | gcp/iam     | iam     |
      | gcp/compute | compute |

# ---- Constraints identified ----
  Scenario: Existing check filters retain their dedicated CLI flag
    Given a fake GCP Prowler client request with an existing check filter
    When that request is rendered without a service selector
    Then the check filter still uses "-c" and no "--services" argument is emitted

  Scenario: A GCP service selector cannot target another provider
    Given a fake AWS Prowler client request with GCP service "compute"
    When the client request is validated
    Then it is rejected before the credential lease or fake CLI engine is used

  Scenario: GCP inputs receive structural validation only
    Given a GCP service form whose provider fields are nonblank
    When the service contract parses the form
    Then the values are accepted without cloud access or semantic identifier lookup
