# injectors-sdk

![version](https://img.shields.io/badge/version-0.1.0-blue)
![python](https://img.shields.io/badge/python-%3E%3D3.12-informational)
![license](https://img.shields.io/badge/license-Internal-lightgrey)

Python SDK for building OpenAEV injector extensions with a DDD + Light Hexagonal Architecture. Provides declarative CLI specs, type-safe contracts, and pluggable adapters, organized in three explicit layers: `public/` (flat API), `contracts/` (stable feature boundaries), and `_core/` (implementation details).

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

- **Base Injector** — Lifecycle Protocol, configuration model, and execution reporting for injector extensions. [Full documentation →](docs/base-injector.md)
- **CLI Engine** — Declarative specs, type-safe contracts, and pluggable adapters for CLI binary injection. [Full documentation →](docs/cli-engine.md)

The two features are **standalone siblings**. An injector that does not shell out to a CLI binary only needs `base_injector`. An injector that purely orchestrates CLI tools can use `cli_engine` without `base_injector`.

## Architecture: Three Layers

```
injectors_sdk/
├── public/             ← Layer 1: 30 symbols, flat re-export (casual consumers)
├── contracts/          ← Layer 2: stable feature boundaries (DDD-aware consumers)
│   ├── base_injector/
│   ├── cli_engine/
│   │   ├── adapters/
│   │   ├── contracts/
│   │   └── ports/
│   └── common/
└── _core/              ← Layer 3: implementation detail (two sibling features)
    ├── base_injector/
    └── cli_engine/
```

`public/` funnels everything through a single crossing point. `contracts/` provides feature-scoped imports for DDD-aware code that wants to express its dependency explicitly. `_core/` is the private implementation — its layout may change without notice, but the port signatures never will without a major version bump.

## Module Map

| Group | Symbols | What it provides |
|---|---|---|
| Base | `BaseInjector`, `DaemonProtocol`, `InjectorConfig`, `InjectorContext`, `ExecutionCallback`, `ExecutionStatus` | Lifecycle Protocol, daemon contract, config model, message parsing, execution reporting |
| Errors | `CliError`, `CliContractError`, `CliExecutionError`, `CliParseError`, `BinaryNotFoundError`, `ExecResult` | Exception hierarchy + structured execution result |
| Contracts | `BinarySpec`, `CommandSpec`, `OptionSpec`, `ArgumentSpec`, `OutputSpec`, `ExecPolicy`, `OptionKind`, `OutputFormat` | Frozen Pydantic models defining CLI shape and execution policy |
| Ports | `CommandRendererPort`, `CommandExecutorPort`, `OutputParserPort` | `typing.Protocol` interfaces for custom adapter implementations |
| Adapters | `DefaultCommandRenderer`, `SubprocessExecutor`, `DefaultOutputParser` | Default concrete implementations wired by the factory |
| Core | `CliEngine`, `EngineResult`, `SUCCESS_ANY` | Orchestrator, result dataclass, default success code set |
| Factory | `create_cli_engine` | Recommended entry point — wires defaults when custom ports are not provided |

## Import Convention

**Casual consumers** always import from the package root:

```python
from injectors_sdk import CliEngine, CommandSpec, CliContractError
```

**DDD-aware consumers** may import from the `contracts/` layer to express feature-scoped dependencies explicitly:

```python
from injectors_sdk.contracts.base_injector import BaseInjector, InjectorConfig
from injectors_sdk.contracts.cli_engine.ports import CommandExecutorPort
from injectors_sdk.contracts.cli_engine.contracts import CommandSpec, ExecPolicy
from injectors_sdk.contracts.common import CliError, CliExecutionError
```

**Internal architecture exploration** is allowed for consumers that want to reason about the port/adapter boundary directly:

```python
# Fine — ports are the stable structural contract
from injectors_sdk._core.cli_engine.ports import CommandExecutorPort
```

Never import concrete implementation modules directly — their paths are not stable:

```python
# Wrong — internal layout may change without notice
from injectors_sdk._core.cli_engine.core.cli_engine import CliEngine
```

The 30 symbols in `__all__` are the stable public API. A bidirectional CI test asserts that every symbol in `__all__` is importable and every exported name is explicitly listed.

## Documentation

- [Base Injector](docs/base-injector.md) — lifecycle Protocol, configuration, message parsing, execution reporting
- [CLI Engine](docs/cli-engine.md) — architecture, public interface, dependency injection, advanced nmap example, error handling

## Deprecation Shim Strategy

`pyoaev.helpers.OpenAEVInjectorHelper` is a deprecated wrapper that proxies to the SDK's `BaseInjector` / `InjectorDaemon`:

```python
# Old path (triggers DeprecationWarning, still works)
from pyoaev.helpers import OpenAEVInjectorHelper

# New path (clean, no warning)
from injectors_sdk import BaseInjector, InjectorConfig
```

The shim in `pyoaev` instantiates `InjectorDaemon` internally and delegates `listen()` calls. Once all connectors are migrated, the shim and `OpenAEVInjectorHelper` are removed from `pyoaev`.

See [SECOND_README.md § Deprecation Shim Strategy](../../SECOND_README.md#deprecation-shim-strategy) for the full lifecycle.

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
