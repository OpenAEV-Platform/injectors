Feature: CHK.015 NIS2 and ISO 27001 assessments
  OpenAEV operators can run the provider-supported Prowler 5.36 NIS2 and ISO
  27001 frameworks through fixed routes without exposing framework routing as
  form input or changing existing check and service selection channels.

  Scenario Outline: A canonical route selects one exact Prowler compliance framework
    Given the executable Prowler registry contains the canonical route "<route>"
    When a valid provider assessment is executed through "<route>"
    Then the Prowler client is called exactly once with compliance "<compliance>"
    And no check filter or service selector is supplied

    Examples:
      | route                   | compliance                    |
      | nis2/aws                | nis2_aws                      |
      | nis2/azure              | nis2_azure                    |
      | nis2/gcp                | nis2_gcp                      |
      | iso27001/aws            | iso27001_2022_aws             |
      | iso27001/azure          | iso27001_2022_azure           |
      | iso27001/gcp            | iso27001_2022_gcp             |
      | iso27001/kubernetes     | iso27001_2022_kubernetes      |

  Scenario: The twenty-two executable contracts have stable canonical identities
    Given the executable Prowler registry
    Then it contains the existing fifteen routes followed by the seven CHK.015 routes
    And every CHK.015 route has compliance-identifying labels and no selector field

  Scenario: Unsupported compliance combinations stop before the client
    Given a CHK.015 contract is paired with unsupported route metadata
    When the invalid contract execution is attempted
    Then the request is rejected before the Prowler client is called

  Scenario: Findings preserve the CHK.005 model and compliance values
    Given ordered duplicate provider and non-provider OCSF records for a CHK.015 route
    When the compliance assessment completes
    Then provider findings retain source order, duplicates, and compliance tags
    And the same findings feed shared Text and Vulnerability outputs and dynamic Rich trace

  Scenario Outline: Runtime dispatch emits exact compliance argv without real execution
    Given a fake CLI engine and valid provider runtime message for "<route>"
    When the injector processes the runtime message
    Then exactly one fake CLI request contains "--compliance" followed by "<compliance>"
    And provider credentials and temporary leases follow their existing lifecycle
    And credentials, stderr, and temporary-path canaries are absent from the callback

    Examples:
      | route                   | compliance                    |
      | nis2/aws                | nis2_aws                      |
      | nis2/azure              | nis2_azure                    |
      | nis2/gcp                | nis2_gcp                      |
      | iso27001/aws            | iso27001_2022_aws             |
      | iso27001/azure          | iso27001_2022_azure           |
      | iso27001/gcp            | iso27001_2022_gcp             |
      | iso27001/kubernetes     | iso27001_2022_kubernetes      |

# ---- Constraints identified ----
  Scenario: Existing check and service channels remain dedicated
    Given fake Prowler requests using an existing check filter or service selector
    When those requests are rendered without compliance selection
    Then check filters still use "-c" and services still use "--services"
    And neither request emits "--compliance"

  Scenario: A compliance selector cannot target another provider
    Given a fake provider request with another provider's NIS2 or ISO 27001 compliance
    When the client request is validated
    Then it is rejected before credential materialization or fake CLI execution

  Scenario: Framework routing constants are internal
    Given a serialized CHK.015 OpenAEV contract
    When its fields are inspected
    Then only the existing provider fields are public
    And no compliance or framework selector field is present

  Scenario: Existing finding semantics are not replaced by reports
    Given duplicate OCSF findings from one selected framework
    When the assessment output is built
    Then duplicate findings and compliance tags remain unchanged
    And no framework report, aggregation, or deduplication output is invented
