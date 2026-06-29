# CLI Engine

Detailed feature documentation for the injectors-sdk CLI Engine: architecture, public interface, dependency injection model, advanced nmap example, and error semantics.

## Architecture

The engine follows **Clean Architecture / Port-Adapter** principles with hexagonal layout, justified by three I/O seams: subprocess execution, filesystem/output file handling, and shell rendering.

```
injectors_sdk/
└── _core/
    └── engine/
        ├── ports/              # Protocol interfaces (what adapters must satisfy)
        │   └── protocols.py        CommandRendererPort, CommandExecutorPort, OutputParserPort
        ├── contracts/          # Frozen Pydantic value objects
        │   ├── specs.py            BinarySpec, CommandSpec, OptionSpec, ArgumentSpec, OutputSpec, OptionKind, OutputFormat
        │   └── exec_policy.py      ExecPolicy
        ├── adapters/           # Concrete implementations
        │   ├── renderer.py         DefaultCommandRenderer
        │   ├── executor.py         SubprocessExecutor  ← only subprocess.run user
        │   └── parser.py           DefaultOutputParser
        └── core/               # Orchestrator
            └── cli_engine.py       CliEngine, EngineResult, SUCCESS_ANY
```

**Key design principles:**

- **Ports are Protocols**: `typing.Protocol` with `@runtime_checkable`, not ABC
- **Adapters satisfy structurally**: no inheritance from Ports required
- **Subprocess isolation**: `subprocess.run` exists in exactly one file (`executor.py`)
- **Public API is stable**: internal restructuring never breaks consumers
- **Specs are frozen Pydantic models**: immutable, validatable, serializable

## Public Interface and Breaking Change Protection

The SDK has two safety layers that guarantee internal refactoring never breaks your code.

### Layer 1: Ports (the structural contract)

Ports define **what** the SDK does, not **how**. They are Python Protocol interfaces with fixed method signatures:

```python
# These signatures are the contract. They NEVER change without a major version bump.
class CommandExecutorPort(Protocol):
    def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        stdin: str | bytes | None = None,
    ) -> ExecResult: ...

class CommandRendererPort(Protocol):
    def render(
        self,
        binary: str,
        command: CommandSpec,
        *,
        options: dict[str, object] | None = None,
        args: dict[str, object] | None = None,
        raw_args: list[str] | None = None,
    ) -> list[str]: ...

class OutputParserPort(Protocol):
    def parse(
        self,
        result: ExecResult,
        output_spec: OutputSpec,
        model: type[BaseModel] | None = None,
        context: dict[str, object] | None = None,
    ) -> Any: ...
```

As long as these signatures don't change, any internal adapter can be completely rewritten (different algorithm, different library, different filename) and your code still works. Ports are the wall between "your code" and "our implementation details."

### Layer 2: `__all__` contract (the symbol contract)

A bidirectional CI test enforces that:

- Every symbol in `__all__` is importable from `injectors_sdk`
- Every exported symbol is explicitly listed in `__all__`

This catches accidental leaks (new symbol exported without review) and accidental breakage (symbol removed from exports silently).

### What this means for you

| You want to... | Safe? | Why |
|---|---|---|
| Refactor internal adapter code | Always | Port signatures unchanged |
| Rename or move private files | Always | `__init__.py` re-exports the same names |
| Add a new public symbol | Requires deliberate `__all__` update | CI enforces the change |
| Change a Port method signature | Breaking change | Requires major version bump |
| Change Pydantic model fields | Breaking change | Users depend on field names |

### The import boundary

```
Your code
  └─ imports from: injectors_sdk  (top-level __all__ — 24 symbols)
       └─ re-exports from: _core/engine/  (single private boundary)
            └─ wires: ports/ ←→ adapters/ ←→ core/
                      ↑ stable        ↑ freely refactorable
```

Users never import from `_core/` directly. The top-level `__init__.py` is the only allowed crossing point.

## Dependency Injection

`create_cli_engine()` wires default adapters automatically. Pass custom implementations for testing or alternative backends:

```python
from injectors_sdk import CliEngine, ExecPolicy, create_cli_engine

# Default (recommended) — binary name string, not a BinarySpec
engine = create_cli_engine("ffprobe")

# With custom execution policy
engine = create_cli_engine(
    "ffprobe",
    policy=ExecPolicy(timeout=60, env_overrides={"LANG": "C"}),
)

# Inject custom adapter implementations
engine = CliEngine(
    "ffprobe",
    renderer=MyCustomRenderer(),   # must satisfy CommandRendererPort
    executor=MyCustomExecutor(),   # must satisfy CommandExecutorPort
    parser=MyCustomParser(),       # must satisfy OutputParserPort
)
```

`create_cli_engine` signature:

```python
def create_cli_engine(
    binary: str,
    *,
    policy: ExecPolicy | None = None,
    renderer: CommandRendererPort | None = None,
    executor: CommandExecutorPort | None = None,
    parser: OutputParserPort | None = None,
    success_codes: frozenset[int] | None = None,
) -> CliEngine: ...
```

## Adapter Reference

### DefaultCommandRenderer

Renders an argv list in order: `[binary] + static_argv + rendered_options + positional_args + raw_args`

| Behavior | Detail |
|---|---|
| Unknown option key | `CliContractError` |
| Missing required option | `CliContractError` |
| `OptionKind.BOOL` with non-bool value | `CliContractError` |
| `OptionKind.LIST` with non-list value | `CliContractError` |
| `choices` violation | `CliContractError` |
| `equals=True` | Renders `--flag=value` instead of `--flag value` |
| `allow_raw_args=False` + raw_args passed | `CliContractError` |

### SubprocessExecutor

Wraps `subprocess.run` under `ExecPolicy` controls. This is the only file in the SDK that calls `subprocess.run`.

| Behavior | Detail |
|---|---|
| Shell metachar detection (`\|;&$\`><`) with `shell=True` | Fail-closed: `CliContractError` |
| Shell metachar detection with `shell=False` | `UserWarning` |
| `shell=True` without `acknowledge_shell_risk=True` | Pydantic validation error at `ExecPolicy` construction |
| `check_binary_exists=True` (default) | `shutil.which` check before execution; `BinaryNotFoundError` on miss |
| Timeout | `CliExecutionError(returncode=124)` |
| `FileNotFoundError` from subprocess | `BinaryNotFoundError` |
| `max_output_bytes` set | stdout and stderr truncated to that byte count with `[truncated]` suffix |
| Environment | `os.environ` + `policy.env_overrides` + per-call `env` |

**`ExecPolicy` fields:**

| Field | Type | Default | Purpose |
|---|---|---|---|
| `timeout` | `int` | `30` | Max seconds to wait |
| `shell` | `bool \| "auto"` | `False` | Shell execution mode (`"auto"` = Windows-only shell) |
| `acknowledge_shell_risk` | `bool` | `False` | Must be `True` when `shell=True` |
| `env_overrides` | `dict[str, str]` | `{}` | Merged on top of `os.environ` |
| `max_output_bytes` | `int \| None` | `None` | Output capture ceiling (unlimited if None) |
| `working_directory` | `Path \| None` | `None` | Default cwd for all runs |
| `check_binary_exists` | `bool` | `True` | Pre-flight `shutil.which` check |
| `text` | `bool` | `True` | Text mode capture vs binary mode |
| `retries` | `int` | `0` | Typed placeholder (not yet active) |

### DefaultOutputParser

Parses `ExecResult.stdout` according to an `OutputSpec`.

| Format | Behavior |
|---|---|
| `TEXT` | Returns stdout as-is (string passthrough) |
| `RAW` | Returns stdout as-is (string passthrough) |
| `LINES` | `stdout.splitlines()` — returns `list[str]` |
| `JSON` | `json.loads(stdout)` — `CliParseError` on invalid JSON |
| `REGEX` | `re.search(pattern, stdout).groupdict()` — `CliParseError` if no match |

For `JSON` and `REGEX`, passing `output_model` to `engine.run()` validates the parsed result against a Pydantic model. `TEXT`, `RAW`, and `LINES` reject `output_model` with `CliContractError`.

## The Engine Run Pipeline

`engine.run()` raises `CliExecutionError` when the returncode is not in the active `success_codes` set. On success, it returns an `EngineResult`.

```python
result = engine.run(
    command,              # CommandSpec — passed directly, not looked up by name
    *,
    options={...},        # Named option values (validated against CommandSpec.options)
    args={...},           # Named positional argument values
    raw_args=[...],       # Verbatim tokens appended last (requires allow_raw_args=True)
    output_spec=...,      # OutputSpec for parsing (defaults to raw stdout if None)
    output_model=...,     # Pydantic model for JSON/REGEX validation
    success_codes=...,    # Per-run override (defaults to engine-level success_codes)
    env={...},            # Per-run env overrides (layered on top of policy.env_overrides)
    cwd="...",            # Per-run working directory override
    stdin=...,            # stdin to pass to the subprocess
    output_file="...",    # Path to a file merged into stdout before parsing (then deleted)
) -> EngineResult
```

### Dry-run with `engine.render()`

Preview the exact argv without executing:

```python
argv = engine.render(cmd, options={"timing": "4"}, args={"target": "localhost"})
# ['nmap', '-T', '4', 'localhost']
```

### `output_file` merge

Some CLI tools write results to a file instead of stdout (e.g. `nmap -oN /tmp/scan.txt`). Pass `output_file` to automatically read the file, merge its content into stdout before parsing, and delete the file:

```python
result = engine.run(
    SCAN_COMMAND,
    options={"timing": "4", "output_normal": "/tmp/scan.txt"},
    args={"target": "localhost"},
    output_file="/tmp/scan.txt",
    output_spec=SCAN_COMMAND.output,
)
# result.raw.stdout contains both subprocess stdout AND file content
```

If the file doesn't exist, no error is raised.

### `EngineResult`

Frozen dataclass returned on success:

```python
@dataclass(frozen=True)
class EngineResult:
    parsed: Any        # Parser output (or raw stdout if output_spec is None)
    raw: ExecResult    # Full subprocess result (stdout, stderr, returncode, argv)
    success: bool      # Always True (failures raise CliExecutionError)
    argv: list[str]    # The rendered argv that was executed
```

`EngineResult.pipe()` chains to another engine run, forwarding raw stdout as stdin:

```python
first = engine_a.run(cmd_a, args={"input": "data"}, output_spec=cmd_a.output)
second = first.pipe(engine_b, cmd_b)  # first.raw.stdout becomes cmd_b's stdin
```

`SUCCESS_ANY = frozenset(range(256))` accepts any exit code (0-255). The engine default is `frozenset({0})` (only 0 is success). Use `SUCCESS_ANY` when any exit code is acceptable, or pass custom `success_codes` per command.

## Advanced Example: nmap

nmap stress-tests the SDK across every CLI pattern: boolean scan flags, `--flag=value` rate controls, repeated `--script` options, a strict timing enum, a required positional target, non-zero success codes (host-down exits `1`), and regex output parsing. If the SDK handles nmap, it handles any tool.

### Specs and engine

```python
from injectors_sdk import (
    ArgumentSpec,
    BinarySpec,
    CliEngine,
    CommandSpec,
    ExecPolicy,
    OptionKind,
    OptionSpec,
    OutputFormat,
    OutputSpec,
    create_cli_engine,
)

# CommandSpecs defined at module level — engine.run() takes them directly
SCAN_COMMAND = CommandSpec(
    name="scan",
    options={
        # 1. OptionKind.BOOL — presence/absence flag
        "version_detection": OptionSpec(
            name="version_detection", flag="-sV", kind=OptionKind.BOOL,
        ),
        "os_detection": OptionSpec(
            name="os_detection", flag="-O", kind=OptionKind.BOOL,
        ),
        "aggressive": OptionSpec(
            name="aggressive", flag="-A", kind=OptionKind.BOOL,
        ),
        # 2. OptionKind.VALUE — flag followed by a separate value token
        "output_normal": OptionSpec(name="output_normal", flag="-oN"),
        # 3. OptionKind.LIST — repeats flag once per item
        #    ["http-title", "ssl-cert"] → --script http-title --script ssl-cert
        "scripts": OptionSpec(name="scripts", flag="--script", kind=OptionKind.LIST),
        # 4. equals=True — renders --min-rate=1000 instead of --min-rate 1000
        "min_rate": OptionSpec(name="min_rate", flag="--min-rate", equals=True),
        # 5. choices — rejects values outside this list at render time
        # 6. required=True — CliContractError if caller omits this option
        "timing": OptionSpec(
            name="timing", flag="-T", required=True,
            choices=["0", "1", "2", "3", "4", "5"],
        ),
    },
    # 7. Positional argument — appended after all flags
    arguments=[ArgumentSpec(name="target", required=True)],
    # 10. REGEX output — re.search returns groupdict() for the first match
    output=OutputSpec(
        format=OutputFormat.REGEX,
        regex=r"(?P<port>\d+)/tcp\s+open\s+(?P<service>\S+)",
    ),
    # 11. nmap exits 0 (host up) or 1 (host down) — both are valid outcomes
    success_codes={0, 1},
    # 8. allow_raw_args=True — escape hatch for undeclared flags
    allow_raw_args=True,
)

# 9. Multiple CommandSpecs for one binary
PING_SWEEP_COMMAND = CommandSpec(
    name="ping_sweep",
    argv=["-sn"],   # baked in — disables port scan
    options={
        "timing": OptionSpec(
            name="timing", flag="-T",
            choices=["0", "1", "2", "3", "4", "5"],
        ),
    },
    arguments=[ArgumentSpec(name="target", required=True)],
    output=OutputSpec(format=OutputFormat.TEXT),
    success_codes={0, 1},
)

# BinarySpec is optional — useful for grouping/documentation or sharing specs
NMAP_SPEC = BinarySpec(
    name="nmap",
    binary="nmap",
    version_args=["--version"],
    commands={
        "scan": SCAN_COMMAND,
        "ping_sweep": PING_SWEEP_COMMAND,
    },
)

# create_cli_engine takes a binary name string, not a BinarySpec
engine = create_cli_engine("nmap", policy=ExecPolicy(timeout=120))
```

### Domain adapter

```python
# 12. Domain adapter — typed methods hide engine.run() from application code
class NmapAdapter:
    def __init__(self, engine: CliEngine) -> None:
        self._engine = engine

    def scan(
        self,
        target: str,
        *,
        timing: str = "3",
        version_detection: bool = True,
        os_detection: bool = False,
        scripts: list[str] | None = None,
        min_rate: str | None = None,
        output_file: str | None = None,
    ) -> EngineResult:
        options: dict[str, object] = {
            "timing": timing,
            "version_detection": version_detection,
            "os_detection": os_detection,
        }
        if scripts:
            options["scripts"] = scripts
        if min_rate:
            options["min_rate"] = min_rate
        if output_file:
            options["output_normal"] = output_file
        return self._engine.run(
            SCAN_COMMAND,
            options=options,
            args={"target": target},
            output_spec=SCAN_COMMAND.output,
        )

    def ping_sweep(self, target: str, *, timing: str = "3") -> EngineResult:
        return self._engine.run(
            PING_SWEEP_COMMAND,
            options={"timing": timing},
            args={"target": target},
            output_spec=PING_SWEEP_COMMAND.output,
        )

    def raw_probe(self, target: str, extra_flags: list[str]) -> EngineResult:
        """8. raw_args — forward undeclared flags verbatim."""
        return self._engine.run(
            SCAN_COMMAND,
            options={"timing": "3"},
            args={"target": target},
            raw_args=extra_flags,
        )


# Usage
adapter = NmapAdapter(engine)

# Full scan: -sV -O --script http-title --script ssl-cert --min-rate=1000 -T4 192.168.1.1
result = adapter.scan(
    "192.168.1.1",
    timing="4",
    version_detection=True,
    os_detection=True,
    scripts=["http-title", "ssl-cert"],
    min_rate="1000",
    output_file="/tmp/scan.txt",
)
# result.parsed → {"port": "80", "service": "http"}  (regex groupdict, first open port)
# result.success → True (exit 0 or 1 both in success_codes)

# Ping sweep over a subnet
sweep = adapter.ping_sweep("192.168.1.0/24", timing="2")

# Escape hatch — flags not declared in the spec
raw = adapter.raw_probe("10.0.0.1", ["--max-retries", "1", "-p", "22,80,443"])
```

### Feature map

| # | Feature | Where |
|---|---|---|
| 1 | `OptionKind.BOOL` | `version_detection`, `os_detection`, `aggressive` |
| 2 | `OptionKind.VALUE` | `output_normal` (`-oN <file>`) |
| 3 | `OptionKind.LIST` | `scripts` (`--script` repeated per item) |
| 4 | `equals=True` | `min_rate` (`--min-rate=1000`, no space) |
| 5 | `choices` | `timing` — rejects values outside `"0"`–`"5"` |
| 6 | `required=True` | `timing` — `CliContractError` if omitted |
| 7 | `ArgumentSpec` | `target` — positional, appended after all flags |
| 8 | `raw_args` | `raw_probe()` passes undeclared flags verbatim |
| 9 | Multiple `CommandSpec` | `SCAN_COMMAND` + `PING_SWEEP_COMMAND` for one binary |
| 10 | `OutputFormat.REGEX` | `re.search` → `groupdict()` for first open port |
| 11 | `success_codes={0, 1}` | Host-down exit is not an error |
| 12 | Domain adapter | `NmapAdapter` wraps `CliEngine` for clean call sites |

## Error Handling

The SDK uses a strict exception hierarchy where each type has a single, clear meaning:

```
CliError                    base — catch-all for any SDK error
├── CliContractError        programmer mistake in spec or call site
├── CliParseError           command ran fine, output didn't match expected format
└── CliExecutionError       binary ran but returned a failing exit code
    └── BinaryNotFoundError binary not found on PATH (exit code 127)
```

| Exception | When it fires | What to do |
|---|---|---|
| `CliContractError` | Unknown command option, missing required option, invalid type, bad `choices` value, malformed spec (`REGEX` format with no `regex` field), invalid argv/env. Always a programmer mistake. | Fix your `CommandSpec` definition or call site. Never catch in production. |
| `CliParseError` | Command executed successfully but stdout didn't match the regex, wasn't valid JSON, or didn't satisfy the Pydantic model. A runtime data condition, not a bug. | Handle gracefully — empty results, retry, or report "no data." |
| `CliExecutionError` | Binary returned a non-zero exit code not in `success_codes`. Carries `.result` (full `ExecResult`) with stdout, stderr, and returncode. Also raised on timeout with `returncode=124`. | Inspect `e.result.stderr`. Decide retry vs permanent failure. |
| `BinaryNotFoundError` | Binary not found via `shutil.which` (pre-flight) or `FileNotFoundError` from subprocess. Subclass of `CliExecutionError`. | Install the dependency or fix the `binary` value. |

```python
from injectors_sdk import (
    BinaryNotFoundError,
    CliContractError,
    CliExecutionError,
    CliParseError,
)

try:
    result = engine.run(SCAN_COMMAND, options={"timing": "4"}, args={"target": "localhost"})
except CliContractError as e:
    # Programmer error — unknown option, missing required, bad spec
    # Should never occur in production; fix the spec
    raise
except CliParseError as e:
    # Output didn't match — valid runtime scenario (e.g., no open ports found)
    print(f"No parseable output: {e}")
except BinaryNotFoundError as e:
    print(f"Binary not installed: {e.binary}")
except CliExecutionError as e:
    # Timeout, non-zero exit not in success_codes
    print(f"Execution failed (exit {e.returncode}): {e.result.stderr}")
```

**Key distinction:** `CliContractError` means "your spec or call is wrong" — fix your code, do not catch it in production logic. `CliParseError` means "the command worked but output was empty or unexpected" — handle it at runtime as a normal condition. Never conflate the two.
