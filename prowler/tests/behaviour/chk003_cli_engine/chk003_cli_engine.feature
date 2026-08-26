@cli-engine
Feature: Safe local CLI engine orchestration
  The CLI engine executes one policy-approved immutable specification and
  reports expected failures in a result envelope.

  Scenario: Preserve one deeply immutable execution specification
    Given mutable validated command inputs
    When an execution specification is constructed
    Then executable, argv, environment, cwd, stdin, parser, timeout, and output acceptance limit are fixed

  Scenario: Keep shell syntax inert
    Given an allowed structured command containing shell metacharacters
    When the engine runs the command
    Then every value reaches the executor as a separate argument

  Scenario: Preserve the policy-approved specification through every boundary
    Given a policy-approved immutable execution specification
    When resolution validates and the engine runs it
    Then policy, resolution, execution, and parsing observe that exact specification

  Scenario Outline: Return distinct expected failures without raising
    Given the <boundary> boundary reports an expected failure
    When the engine runs the command
    Then CommandResult.error is a <error> error
    And later boundaries are not called

    Examples:
      | boundary   | error           |
      | policy     | PolicyError     |
      | resolution | ResolutionError |
      | execution  | ExecutionError  |
      | parsing    | ParsingError    |

  Scenario: Retain exact bytes for an unsuccessful process
    Given a process returns nonzero with arbitrary stdout and stderr bytes
    When the engine runs the command
    Then its execution error retains the return code and exact process bytes

  Scenario: Own parser-error evidence at the engine boundary
    Given a parser reports forged or missing process evidence
    When the engine handles the parser failure
    Then its parsing error contains actual process stdout and stderr
    And safe parser context and cause detail are retained

  Scenario Outline: Parse supported process output
    Given successful output for parser <parser>
    When the engine runs the command
    Then the parsed value is <value>

    Examples:
      | parser | value          |
      | raw    | exact bytes    |
      | text   | text           |
      | json   | structured data|
      | lines  | text lines     |
      | regex  | captures       |

# ---- Constraints identified ----

  Scenario: Classify oversized captured output honestly
    Given process output has already been captured beyond the accepted size
    When the engine handles the process outcome
    Then it returns an output_too_large_after_capture execution error with exact bytes

  Scenario: Preserve arbitrary bytes without decoding
    Given stdin, stdout, and stderr contain invalid UTF-8, NULs, and newlines
    When execution succeeds with the raw parser
    Then all bytes remain exact

  Scenario: Expose only the core CLI engine API
    Given CHK.003 is installed
    Then prowler._core.cli_engine is importable
    And prowler.cli_engine and prowler.cli_engine_errors are absent
