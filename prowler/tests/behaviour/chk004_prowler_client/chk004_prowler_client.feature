Feature: Synchronous Prowler CLI assessments

  Background:
    Given a configured Prowler runtime and one supported provider input

  Scenario: Creating a client has no execution side effect
    When the factory creates a provider client
    Then no Prowler command has run

  Scenario: Running a full assessment returns the CLI result unchanged
    When the client runs with no check filters
    Then Prowler receives the provider invocation without a check selector
    And the exact CLI command result is returned

  Scenario: The factory quick-access run is equivalent to a created client run
    When the same assessment is run through both public entry points
    Then both entry points submit equivalent command requests

  Scenario: Check filters preserve order and duplicates
    When the client runs checks check-z, check-a, and check-z
    Then Prowler receives each check as a separate ordered argument

  Scenario Outline: Each provider uses its explicit authentication boundary
    Given a <provider> provider input
    When the client runs the provider assessment
    Then only the required <provider> environment and arguments are submitted

    Examples:
      | provider   |
      | AWS        |
      | Azure      |
      | GCP        |
      | Kubernetes |

  Scenario: A configured AWS provider endpoint is scoped to its invocation environment
    Given an AWS provider input with an endpoint override and optional session token
    When the client runs an AWS provider assessment
    Then the endpoint is submitted as a plain AWS_ENDPOINT_URL environment value
    And the optional session token remains in the exact AWS environment
    And the endpoint is absent from command arguments

  Scenario: An unset AWS provider endpoint preserves the exact AWS environment
    Given an AWS provider input without an endpoint override
    When the client runs an AWS provider assessment
    Then the exact AWS credential environment remains unchanged
    And the endpoint is absent from command arguments

  Scenario: Kubernetes selects a kubeconfig context with Prowler 5.36 syntax
    Given a Kubernetes provider input with a named context
    When the client runs the provider assessment
    Then Prowler receives the context through --context
    And the stale --kube-context option is absent

  # ---- Constraints identified ----

  Scenario: Blank check filters are rejected before execution
    When the client receives a blank check filter
    Then no Prowler command runs

  Scenario: An unset AWS provider endpoint ignores the ambient parent endpoint
    Given AWS credentials without an optional session token
    And the parent process has an ambient AWS_ENDPOINT_URL
    When the client runs an AWS provider assessment without an endpoint override
    Then only the exact required AWS credential environment is submitted

  Scenario: Configured executable and bounded raw execution are mandatory
    When the client runs an assessment
    Then the request uses the exact configured executable and raw byte parser
    And stdin and working directory are empty with explicit resource limits

  Scenario: File-backed credentials are private and scoped to one run
    Given a GCP or Kubernetes provider input
    When the synchronous assessment succeeds, fails, or raises
    Then the credential file exists in a unique private temporary directory only during execution
    And the credential content is absent from command arguments and errors

  Scenario: Native platforms apply their available temporary-file protection
    Given a GCP or Kubernetes provider input
    When its credential lease is created on POSIX or Windows
    Then POSIX applies directory mode 0700 and file mode 0600
    And Windows relies on the current user's temporary-directory ACL without claiming POSIX-equivalent permissions

  Scenario: Credential resources close before execution and clean deterministically
    Given a file-backed provider input
    When Prowler returns, rejects a result, fails to start, or times out
    Then the closed credential file remains readable for the command runtime
    And the file and its private directory are removed afterward

  Scenario: Credential creation cannot strand a partial lease
    Given a credential file write fails
    When the factory abandons the lease creation
    Then its partial file and private directory are removed

  Scenario: Cleanup failure preserves a safe deterministic outcome
    Given credential cleanup fails without exposing credential material
    When command execution otherwise returns
    Then a safe credential cleanup error is raised
    But when command execution raises its primary exception is preserved with a safe cleanup note

  Scenario: A created client consumes its credential input once
    Given a client retains a copied provider input before its first run
    When the first run reaches any terminal path
    Then the client releases its provider reference
    And a second run is rejected with a safe consumed-client error

  Scenario: Operators are told the residual plaintext-file risk
    When an operator reads the injector documentation
    Then contract-runtime persistence and crash residue are disclosed for containers, pods, POSIX, and Windows
