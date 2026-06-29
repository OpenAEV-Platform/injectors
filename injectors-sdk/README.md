# injectors-sdk

![version](https://img.shields.io/badge/version-0.1.0-blue)
![python](https://img.shields.io/badge/python-%3E%3D3.12-informational)
![license](https://img.shields.io/badge/license-Internal-lightgrey)

Python SDK for building OpenAEV injector extensions with declarative CLI specs, type-safe contracts, and pluggable adapters.

## Install

```bash
uv add injectors-sdk
```

Or with pip:

```bash
pip install injectors-sdk
```

Requires Python 3.12+. Runtime dependency: `pydantic>=2.0,<3.0`.

## Quick Start

```python
from injectors_sdk import (
    ArgumentSpec,
    CommandSpec,
    OptionSpec,
    OutputFormat,
    OutputSpec,
    create_cli_engine,
)

# 1. Define a command spec
PROBE_CMD = CommandSpec(
    name="probe",
    argv=["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams"],
    options={
        "select_streams": OptionSpec(name="select_streams", flag="-select_streams"),
    },
    arguments=[ArgumentSpec(name="source")],
    output=OutputSpec(format=OutputFormat.JSON),
)

# 2. Create the engine (wires default adapters automatically)
engine = create_cli_engine("ffprobe")

# 3. Run a command — pass the CommandSpec directly
result = engine.run(
    PROBE_CMD,
    args={"source": "/path/to/video.mp4"},
    output_spec=PROBE_CMD.output,
)
print(result.parsed)   # Parsed JSON dict
print(result.success)  # True if returncode in success_codes
print(result.argv)     # ['ffprobe', '-v', 'quiet', ..., '/path/to/video.mp4']
```

## Features

- **Base Injector** — Lifecycle Protocol, configuration model, and execution reporting for injector extensions
- **CLI Engine** — Declarative specs, type-safe contracts, and pluggable adapters for CLI binary injection. [Full documentation →](docs/cli-engine.md)

## Module Map

| Group | Symbols | What it provides |
|---|---|---|
| Base | `BaseInjector`, `InjectorConfig`, `InjectorContext`, `ExecutionCallback`, `ExecutionStatus` | Lifecycle Protocol, config model, message parsing, execution reporting |
| Errors | `CliError`, `CliContractError`, `CliExecutionError`, `CliParseError`, `BinaryNotFoundError`, `ExecResult` | Exception hierarchy + structured execution result |
| Contracts | `BinarySpec`, `CommandSpec`, `OptionSpec`, `ArgumentSpec`, `OutputSpec`, `ExecPolicy`, `OptionKind`, `OutputFormat` | Frozen Pydantic models defining CLI shape and execution policy |
| Ports | `CommandRendererPort`, `CommandExecutorPort`, `OutputParserPort` | `typing.Protocol` interfaces for custom adapter implementations |
| Adapters | `DefaultCommandRenderer`, `SubprocessExecutor`, `DefaultOutputParser` | Default concrete implementations wired by the factory |
| Core | `CliEngine`, `EngineResult`, `SUCCESS_ANY` | Orchestrator, result dataclass, default success code set |
| Factory | `create_cli_engine` | Recommended entry point — wires defaults when custom ports are not provided |

## Import Convention

Always import from the package root:

```python
from injectors_sdk import CliEngine, CommandSpec, CliContractError
```

Never import from private submodules:

```python
# Wrong — internal layout may change without notice
from injectors_sdk._core.engine.core.cli_engine import CliEngine
```

The 29 symbols in `__all__` are the stable public API. Everything under `_core/` is an implementation detail. A bidirectional CI test asserts that every symbol in `__all__` is importable and every exported name is listed in `__all__`.

## Documentation

- [CLI Engine](docs/cli-engine.md) — architecture, public interface, dependency injection, advanced nmap example, error handling

## Development

```bash
# Install dev dependencies
uv sync

# Run tests
uv run pytest

# Type checking
uv run mypy --strict injectors_sdk

# Linting
uv run ruff check injectors_sdk
```

### Quality Thresholds

- ≥90% overall test coverage
- ≥95% engine module coverage
- mypy strict: zero errors
- ruff: zero violations
- 100% public API docstrings

## License

Internal SDK — OpenAEV Squad.
