Feature: Synchronous Prowler CLI assessments

  Background:
    Given a configured Prowler runtime and one supported provider input

  Scenario: Creating a client has no execution side effect
    When the factory creates a provider client
    Then no Prowler command has run

  Scenario: Running a full assessment captures OCSF from a controlled artifact
    When the client runs with no check filters
    Then Prowler receives the provider invocation without a check selector
    And every severity is selected explicitly before the controlled output options
    And OCSF is read from findings.ocsf.json rather than console output
    And the process result and console streams are preserved

  Scenario: The factory quick-access run is equivalent to a created client run
    When the same assessment is run through both public entry points
    Then both entry points submit equivalent command requests

  Scenario: Check filters preserve order and duplicates
    When the client runs checks check-z, check-a, and check-z
    Then Prowler receives each check as a separate ordered argument
    And the all-severity base-run override is absent

  Scenario: Provider and output options have one parser-safe order
    When the client runs an assessment
    Then provider options and selectors precede the controlled output directory and filename
    And ignore-exit-code-3, log-only, and no-color controls are present
    And json-ocsf is the final output-format argument

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
    And stdin and working directory are empty with a four-MiB console limit
    And the OCSF artifact has a distinct one-hundred-MiB limit

  Scenario: Successful execution requires one safe bounded artifact
    Given Prowler reports success
    When the exact output artifact is missing, nonregular, a symlink, unreadable, or oversized
    Then the client fails with a typed closed artifact error
    But an exact-limit regular artifact is accepted

  Scenario: Failed execution ignores partial output artifacts
    When Prowler returns code 3, another nonzero code, or an engine error
    Then the exact engine result is returned without reading a partial artifact

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
    Given credential or output-workspace cleanup fails without exposing runtime material
    When command execution otherwise returns
    Then a safe cleanup error is raised
    But when a process or artifact failure already exists it remains primary with only a safe secondary marker

  Scenario: Output workspaces prefer memory and clean only their owned tree
    Given the runtime is POSIX with a writable /dev/shm directory
    When concurrent assessments prepare unique private workspaces
    Then each workspace uses the memory_tmpfs backend and POSIX mode 0700
    And every owned artifact and nested compliance directory is removed idempotently
    But unrelated temporary paths are untouched

  Scenario: Output workspaces fall back portably
    Given /dev/shm is missing, non-directory, or unwritable, or the runtime is Windows
    When an assessment prepares its output workspace
    Then the filesystem_temp backend uses the system temporary location
    And Windows makes no POSIX permission claim

  Scenario: Runtime logs are safe and bounded
    When preparation, process, artifact, and cleanup phases run
    Then fixed phase messages and closed aggregate metadata are logged best-effort
    And arguments, environments, credentials, paths, content, exceptions, and tracebacks are absent

  Scenario: A created client consumes its credential input once
    Given a client retains a copied provider input before its first run
    When the first run reaches any terminal path
    Then the client releases its provider reference
    And a second run is rejected with a safe consumed-client error

  Scenario: Operators are told the residual plaintext-file risk
    When an operator reads the injector documentation
    Then contract-runtime persistence and crash residue are disclosed for containers, pods, POSIX, and Windows
