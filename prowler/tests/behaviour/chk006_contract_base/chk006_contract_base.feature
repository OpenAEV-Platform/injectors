Feature: Inheritable Prowler contract base and route catalog
  CHK.006 gives later provider contracts a synchronous, secret-safe boundary
  without registering any future assessment contract.

  Scenario: A minimal subclass builds one provider-specific OpenAEV contract
    Given a concrete AWS test subclass with fixed identifiers
    When it builds its OpenAEV contract
    Then the contract uses the subclass identifiers and only AWS input fields
    And credential labels state that their current boundary is plaintext
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

  # ---- Constraints identified ----

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
