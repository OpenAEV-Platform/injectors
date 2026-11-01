Feature: CHK.014 CIS benchmark assessments
  OpenAEV operators can run the supported Prowler 5.36 CIS benchmark for each
  provider without exposing framework routing as form input or changing existing
  check and service selection channels.

  Scenario Outline: A canonical CIS route selects one exact Prowler compliance framework
    Given the executable Prowler registry contains the canonical route "<route>"
    When a valid provider assessment is executed through "<route>"
    Then the Prowler client is called exactly once with compliance "<compliance>"
    And no check filter or service selector is supplied

    Examples:
      | route          | compliance          |
      | cis/aws        | cis_3.0_aws         |
      | cis/azure      | cis_3.0_azure       |
      | cis/gcp        | cis_3.0_gcp         |
      | cis/kubernetes | cis_1.12_kubernetes |

  Scenario: The fifteen executable contracts have stable canonical identities
    Given the executable Prowler registry
    Then it contains the existing eleven routes followed by the four CIS routes
    And every CIS route has compliance-identifying labels and no selector field

  Scenario: Unsupported compliance combinations stop before the client
    Given a CIS contract is paired with another provider's compliance selector
    When the invalid contract execution is attempted
    Then the request is rejected before the Prowler client is called

  Scenario: CIS findings preserve the CHK.005 model and compliance values
    Given ordered duplicate provider and non-provider OCSF records for a CIS route
    When the CIS assessment completes
    Then provider findings retain source order, duplicates, and compliance tags
    And the same findings feed shared Text and Vulnerability outputs and dynamic Rich trace

  Scenario Outline: Runtime dispatch emits exact compliance argv without real execution
    Given a fake CLI engine and valid provider runtime message for "<route>"
    When the injector processes the runtime message
    Then exactly one fake CLI request contains "--compliance" followed by "<compliance>"
    And provider credentials and temporary leases follow their existing lifecycle
    And credentials, stderr, and temporary-path canaries are absent from the callback

    Examples:
      | route          | compliance          |
      | cis/aws        | cis_3.0_aws         |
      | cis/azure      | cis_3.0_azure       |
      | cis/gcp        | cis_3.0_gcp         |
      | cis/kubernetes | cis_1.12_kubernetes |

# ---- Constraints identified ----
  Scenario: Existing check and service channels remain dedicated
    Given fake Prowler requests using an existing check filter or service selector
    When those requests are rendered without compliance selection
    Then check filters still use "-c" and services still use "--services"
    And neither request emits "--compliance"

  Scenario: A compliance selector cannot target another provider
    Given a fake AWS Prowler client request with Azure CIS compliance
    When the client request is validated
    Then it is rejected before credential materialization or fake CLI execution

  Scenario: CIS routing constants are internal
    Given a serialized CIS OpenAEV contract
    When its fields are inspected
    Then only the existing provider fields are public
    And no compliance or framework selector field is present
