@cli-engine
Feature: Safe CLI engine orchestration

  Scenario: Create an immutable execution specification
    Given a validated CLI request and resolvable command inputs
    When the engine creates an execution specification
    Then its executable, ordered arguments, environment, working context, input bytes, and parser selection are fixed

  Scenario: Invoke without shell interpolation
    Given an allowed request containing shell metacharacters as arguments
    When the engine runs the request
    Then the executable and every argument are supplied as separate structured values

  Scenario: Reject a disallowed request
    Given a request that violates command policy
    When the engine runs the request
    Then it returns a policy error before resolution or execution

  Scenario: Report an unresolved command value
    Given an allowed request whose command cannot be resolved
    When the engine runs the request
    Then it returns a resolution error before execution

  Scenario: Report a process failure
    Given a resolved execution specification
    When process startup fails or the process outcome is unsuccessful
    Then the engine returns an execution error retaining captured output bytes

  Scenario: Report unparseable output
    Given a successful process whose output cannot be parsed
    When the engine parses the output
    Then it returns a parsing error retaining the original output bytes

  Scenario: Preserve bytes through execution and parsing
    Given input, output, and error streams containing arbitrary bytes
    When the engine transfers the payload and returns a successful result
    Then every byte remains unchanged and the parsed result is returned with captured streams

# ---- Constraints identified ----

  Scenario: Do not parse an unsuccessful process outcome
    Given a process returns an unsuccessful outcome
    When the engine runs the request
    Then parsing is not attempted

  Scenario: Preserve empty structured boundaries
    Given an allowed executable with no arguments, environment entries, working context, or input bytes
    When the engine runs the request
    Then the empty values remain distinct and unchanged
