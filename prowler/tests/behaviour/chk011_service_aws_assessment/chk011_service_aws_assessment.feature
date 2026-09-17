Feature: CHK.011 service-specific AWS assessments
  OpenAEV operators can run one supported AWS service assessment without changing
  the existing Prowler check-filter behavior or exposing routing controls as input.

  Scenario Outline: A canonical AWS service route selects exactly one Prowler service
    Given the executable Prowler registry contains the canonical route "<route>"
    When a valid AWS assessment is executed through "<route>"
    Then the Prowler client is called exactly once with service "<service>"
    And no check filter is supplied

    Examples:
      | route   | service |
      | aws/iam | iam     |
      | aws/s3  | s3      |
      | aws/ec2 | ec2     |

  Scenario: The seven executable contracts have stable canonical identities
    Given the executable Prowler registry
    Then it contains the four base routes followed by aws/iam, aws/s3, and aws/ec2
    And every AWS service route has service-identifying labels and no selector field

  Scenario: Unsupported service combinations stop before the client
    Given an AWS service contract is paired with an unsupported selector
    When the invalid contract execution is attempted
    Then the request is rejected before the Prowler client is called

  Scenario: Service findings preserve CHK.005 mapping order in shared outputs
    Given ordered mapped and non-AWS OCSF records for aws/iam
    When the aws/iam assessment completes
    Then mapped AWS findings retain their order and shared output schema
    And the Rich trace identifies the route and safe service filter

  Scenario Outline: Runtime dispatch emits exact service argv without real execution
    Given a fake CLI engine and valid AWS runtime message for "<route>"
    When the injector processes the runtime message
    Then exactly one fake CLI request contains "--services" followed by "<service>"
    And credentials, stderr, and path canaries are absent from the callback

    Examples:
      | route   | service |
      | aws/iam | iam     |
      | aws/s3  | s3      |
      | aws/ec2 | ec2     |

# ---- Constraints identified ----
  Scenario: Existing check filters retain their dedicated CLI flag
    Given a fake AWS Prowler client request with an existing check filter
    When that request is rendered without a service selector
    Then the check filter still uses "-c" and no "--services" argument is emitted

  Scenario: A service selector cannot target a non-AWS provider
    Given a fake non-AWS Prowler client request with service "iam"
    When the client request is validated
    Then it is rejected before the fake CLI engine is called
