Feature: Executable Prowler contract infrastructure and route catalog
  CHK.006 gives later provider contracts a registered-output, registry, and
  synchronous runtime boundary without registering a future assessment contract.

  Scenario: A minimal subclass builds one provider-specific OpenAEV contract
    Given a concrete AWS test subclass with fixed identifiers
    When it builds its OpenAEV contract
    Then the contract uses the subclass identifiers and exact ordered AWS input fields
    And credential labels state that their current boundary is plaintext
    And the endpoint URL is an optional single-line field with a clear label
    And the session token remains optional while all other AWS fields are mandatory
    And no credential field has a default

  Scenario Outline: Provider form input becomes the exact strict provider model
    Given a concrete test subclass for "<provider>"
    And valid form input for that provider
    When the subclass parses the form input
    Then the result is the CHK.002 "<provider>" model
    And credential values are SecretStr-backed immediately

    Examples:
      | provider   |
      | aws        |
      | azure      |
      | gcp        |
      | kubernetes |

  Scenario: The AWS endpoint URL is validated by the strict provider model
    Given a concrete AWS test subclass
    When it parses form input with a valid endpoint URL
    Then the endpoint URL is preserved in the AWS provider model
    But an invalid endpoint URL is rejected with a structured contract input error

  Scenario Outline: Empty optional AWS form controls are omitted
    Given a concrete AWS test subclass
    And its form input contains an empty "<field>" control
    When the subclass parses the form input
    Then the optional value is absent from the strict AWS provider model
    And client adaptation omits its environment variable
    And the original form mapping remains unchanged

    Examples:
      | field                |
      | aws_session_token    |
      | aws_endpoint_url     |
      | both optional fields |

  # ---- Constraints identified ----

  Scenario: Empty optional AWS normalization is limited to the form boundary
    Given direct strict-model input and AWS form input with non-empty invalid values
    When those inputs are validated
    Then direct model validation still rejects empty optional strings
    And whitespace-only, malformed non-string, and required blank form values remain invalid
    And valid non-empty optional values are preserved exactly

  Scenario: Invalid form input reports only safe structure
    Given form input containing a credential marker and a cross-provider field
    When the AWS test subclass parses the form input
    Then a structured contract input error identifies validation locations
    And neither the exception nor its structured details contain the marker

  Scenario: The base execution template preserves command errors
    Given a parsed provider and a client result containing an exact command error
    When the AWS test subclass executes its route
    Then that exact error is preserved in the typed outcome
    And mapping is not attempted

  Scenario: The base execution template maps successful raw output
    Given a parsed provider and a successful raw Prowler result
    When the AWS test subclass executes its route
    Then the injected factory runs exactly once with the route check filters
    And the typed outcome contains mapped CHK.005 findings

  Scenario: Contract outputs preserve findings and project vulnerabilities
    Given mapped SUCCESS, FAILED, and IGNORED findings
    When the base prepares registered outputs and an execution payload
    Then every finding is a deterministic full JSON text value
    And only FAILED findings become platform vulnerabilities
    And cloud resource identifiers are not projected as OpenAEV asset identifiers

  Scenario: The execution trace is deterministic, dynamic, and secret-safe
    Given mapped SUCCESS, FAILED, and IGNORED findings
    When the base prepares its execution trace
    Then Rich reports the route, execution status, and status and severity summaries
    And contract-specific columns read flattened finding fields
    And allowlisted request context excludes credentials and temporary paths

  Scenario: Trace extraction tolerates heterogeneous display data
    Given model and dictionary findings with nested lists and missing values
    When configured columns use numeric, wildcard, and fallback paths
    Then available display values are rendered without changing structured output
    And missing values use a stable placeholder

  Scenario: Trace output remains bounded and useful at result boundaries
    Given no findings or more findings and cell content than display limits
    When the base prepares its execution trace
    Then empty results show a no-data panel
    And large results and cells are deterministically truncated

  Scenario: Runtime callbacks use the contract renderer on every terminal path
    Given a supplied registry with one concrete test contract
    When that contract succeeds or fails safely
    Then SUCCESS and ERROR execution messages come from its renderer
    And structured success output remains unchanged and errors expose no command internals

  Scenario: Runtime lifecycle diagnostics are fixed and value-free
    Given a supplied registry with one concrete test contract
    When the listener starts or an assessment reaches a terminal callback
    Then fixed prefixed lifecycle events report only canonical route and provider metadata
    And terminal events contain only bounded status, duration, and finding counts
    And malformed envelopes are rejected with a fixed warning that contains no payload

  Scenario: Runtime failures expose only closed diagnostic metadata
    Given invalid form input or a failed assessment result containing sensitive internals
    When the runtime prepares the existing safe ERROR callback
    Then missing or non-mapping form content is invalid input with no issues
    And input diagnostics contain only capped, normalized, value-free issue locations and types
    And a real malformed AWS account receives exact bounded account guidance
    And forged or unknown input issues receive generic bounded guidance
    And assessment diagnostics use only allowlisted CLI failure kinds, fixed operator guidance, and an optional return code
    And the OpenAEV trace shows the same failure kind and operator guidance as the log
    And unexpected exceptions collapse to unexpected_failure without exception details
    And no log contains form values, credentials, process internals, callback data, finding content, or temporary paths

  Scenario: Runtime observability cannot change assessment delivery semantics
    Given a supplied registry with one concrete test contract
    When lifecycle logging, trace rendering, or callback delivery raises
    Then logging failures do not prevent parsing, execution, or the terminal callback attempt
    And a renderer failure uses a plain bounded code-and-guidance fallback without a second render attempt
    And callback delivery is attempted once without retrying or exposing exception details
    And ERROR records explicitly disable exception information

  Scenario: Error traces identify failed assessments
    Given a terminal assessment failure with a closed failure presentation
    When the base renders the OpenAEV trace
    Then its heading says the assessment failed
    And its error text contains the safe failure code and one matching guidance string
    But a successful assessment heading still says the assessment completed

  Scenario: Stable route identities are deterministic and unique
    When platform identifiers are derived for the canonical routes
    Then repeated derivation is stable
    And every canonical route has a distinct UUIDv5 and external identifier

  Scenario: Only concrete coherent contracts enter the registry
    Given a concrete contract whose identifier, route, and provider agree
    When it is added to a registry
    Then the registry resolves it and serializes only that contract

  Scenario: Invalid registry entries are rejected
    Then abstract, duplicate, unstable, and provider-mismatched entries cannot register

  Scenario: Runtime dispatch accepts either observed contract identifier shape
    Given a supplied registry with one concrete test contract
    When an inject identifies that contract using either supported shape
    Then reception occurs before parse and dispatch
    And inject_content alone is parsed and executed exactly once
    And one SUCCESS callback separates structured output from its trace

  Scenario: Conflicting or unknown contract identifiers fail safely
    Given an inject with conflicting or unknown contract identity
    When the runtime processes it
    Then no client execution occurs
    And exactly one ERROR callback contains no raw form values or success output

  Scenario: The canonical catalog is immutable and ordered
    Then exactly 25 route descriptors exist in canonical order
    And every route has the correct provider and family
    And route descriptors contain route names rather than platform UUIDs

  Scenario: Filtering is canonical and naturally deduplicated
    Given duplicate requested route names in a noncanonical order
    When the dispatcher filters the catalog
    Then each known route occurs once in canonical order

  Scenario: Dispatch delegates exactly once and propagates the result
    Given one known route and one injected handler
    When the dispatcher dispatches the route
    Then the handler is called exactly once
    And its exact result is returned

  Scenario: Unknown dispatch is rejected before a handler runs
    Given an unknown route name
    When the dispatcher dispatches the route
    Then a route-not-found error is raised
    And no handler is called

  Scenario: Startup remains at zero contracts
    When the Prowler injector starts
    Then it does not register CHK.006 or future contracts
