# Base Injector

Lifecycle Protocol, configuration model, and execution reporting for OpenAEV injector extensions.

## Architecture

The BaseInjector feature lives in `_core/base_injector/` and uses a **flat DDD layout** (pure domain models + one Protocol, no I/O concerns, no hex escalation needed):

```
injectors_sdk/
└── _core/
    └── base_injector/
        ├── models/
        │   └── config.py       InjectorConfig, ExecutionStatus, ExecutionCallback,
        │                       InjectorContext
        └── protocols/
            └── base.py         BaseInjector
```

The feature is a **sibling** of `cli_engine` — it does not contain or depend on the CLI Engine. An injector that only makes HTTP calls or uses a Python library satisfies `BaseInjector` without ever touching `CliEngine`.

**Key design principles:**

- **Protocol, not ABC**: `BaseInjector` is a `typing.Protocol` with `@runtime_checkable`. Implementations satisfy it structurally — no inheritance required.
- **Pydantic for data, Protocol for behavior**: Config and callback models are frozen Pydantic; the lifecycle contract is a Protocol.
- **SDK defines the contract, pyoaev provides the wiring**: The SDK owns the abstract lifecycle shape. OpenAEV-specific infrastructure (API client, message queue, ping thread) stays in `pyoaev`.

## The Lifecycle

Every injector extension follows the same three-phase lifecycle, observed across all production injectors (nmap, nuclei, aws, http-query, shodan, teams):

```
__init__()           → configure + connect
  ↓
start()              → begin listening for messages
  ↓
process_message()    → handle one injection (called N times)
  ↓
stop()               → clean shutdown
```

### BaseInjector Protocol

```python
from typing import Any, Protocol, runtime_checkable

@runtime_checkable
class BaseInjector(Protocol):
    def process_message(self, data: dict[str, Any]) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
```

Any class that implements these three methods satisfies the Protocol. No inheritance, no registration, no decorator:

```python
from injectors_sdk import BaseInjector

class MyInjector:
    def process_message(self, data: dict[str, Any]) -> None:
        # handle one injection message
        ...

    def start(self) -> None:
        # begin listening
        ...

    def stop(self) -> None:
        # clean shutdown
        ...

assert isinstance(MyInjector(), BaseInjector)  # True — structural match
```

## Configuration

### InjectorConfig

Frozen Pydantic model capturing the common configuration fields shared by every injector. Mirrors the config dict built in every concrete injector's `__init__`:

```python
from injectors_sdk import InjectorConfig

config = InjectorConfig(
    injector_id="inj-nmap-001",
    injector_name="nmap",
    injector_type="network_scanner",
    injector_contracts=["PORT_SCAN", "SERVICE_DETECTION"],
    injector_category="network",
)
```

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `injector_id` | `str` | Yes | | Unique identifier for this injector instance |
| `injector_name` | `str` | Yes | | Human-readable name |
| `injector_type` | `str` | Yes | | Extension type identifier |
| `injector_contracts` | `list[str]` | No | `[]` | Supported contract IDs |
| `injector_custom_contracts` | `bool` | No | `False` | Whether custom contracts are enabled |
| `injector_category` | `str \| None` | No | `None` | Optional category grouping |
| `injector_executor_commands` | `list[str] \| None` | No | `None` | Executor command definitions |
| `injector_executor_clear_commands` | `list[str] \| None` | No | `None` | Executor cleanup commands |

Validation: `injector_id`, `injector_name`, and `injector_type` reject empty or whitespace-only strings at construction time.

## Message Parsing

### InjectorContext

Every injector manually traverses the same nested dict to extract `inject_id`, `contract_id`, and `inject_content`. `InjectorContext` provides a typed alternative with a factory method:

```python
from injectors_sdk import InjectorContext

# Raw message from the queue
data = {
    "injection": {
        "inject_id": "inject-uuid-001",
        "inject_injector_contract": {
            "convertedContent": {"contract_id": "PORT_SCAN"}
        },
        "inject_content": {"targets": ["192.168.1.1"]},
    }
}

# Before (repeated in every injector):
inject_id = data["injection"]["inject_id"]
contract_id = data["injection"]["inject_injector_contract"]["convertedContent"]["contract_id"]
content = data["injection"]["inject_content"]

# After:
ctx = InjectorContext.from_message(data)
ctx.inject_id     # "inject-uuid-001"
ctx.contract_id   # "PORT_SCAN"
ctx.content       # {"targets": ["192.168.1.1"]}
```

`from_message()` raises `KeyError` when the message structure doesn't match. This is intentional: a malformed message should fail fast, not silently proceed with missing data.

## Execution Reporting

### ExecutionStatus

`StrEnum` with the three status values used across all injectors:

```python
from injectors_sdk import ExecutionStatus

ExecutionStatus.INFO     # "INFO"    — progress update during execution
ExecutionStatus.SUCCESS  # "SUCCESS" — execution completed successfully
ExecutionStatus.ERROR    # "ERROR"   — execution failed
```

### ExecutionCallback

Frozen Pydantic model replacing the raw callback_data dicts every injector builds:

```python
from injectors_sdk import ExecutionCallback, ExecutionStatus

# Progress callback (during execution)
progress = ExecutionCallback(
    execution_message="Executing nmap with: nmap -sV -T4 192.168.1.1",
    execution_status=ExecutionStatus.INFO,
    execution_action="command_execution",
    execution_duration=5,
)

# Success callback (after execution)
success = ExecutionCallback(
    execution_message="Scan completed: 3 ports open",
    execution_status=ExecutionStatus.SUCCESS,
    execution_action="complete",
    execution_duration=42,
    execution_output_structured='{"results": [...]}',
)

# Error callback (on failure)
error = ExecutionCallback(
    execution_message="nmap: command not found",
    execution_status=ExecutionStatus.ERROR,
    execution_action="complete",
    execution_duration=1,
)
```

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `execution_message` | `str` | Yes | | Human-readable status message |
| `execution_status` | `ExecutionStatus` | Yes | | INFO, SUCCESS, or ERROR |
| `execution_action` | `str \| None` | No | `None` | Action identifier (e.g. `"command_execution"`, `"complete"`) |
| `execution_duration` | `int \| None` | No | `None` | Elapsed time in seconds |
| `execution_output_structured` | `str \| None` | No | `None` | JSON-serialized structured output |

## Putting It Together

A complete injector using both the BaseInjector lifecycle and the CLI Engine:

```python
import time
from typing import Any

from injectors_sdk import (
    BaseInjector,
    CliEngine,
    CommandSpec,
    ExecutionCallback,
    ExecutionStatus,
    ExecPolicy,
    InjectorConfig,
    InjectorContext,
    OptionKind,
    OptionSpec,
    create_cli_engine,
)

SCAN_CMD = CommandSpec(
    name="scan",
    options={
        "timing": OptionSpec(
            name="timing", flag="-T", required=True,
            choices=["0", "1", "2", "3", "4", "5"],
        ),
    },
    arguments=[],
    allow_raw_args=True,
)


class NmapInjector:
    """Satisfies BaseInjector Protocol structurally."""

    def __init__(self, config: InjectorConfig, helper: Any) -> None:
        self.config = config
        self.helper = helper
        self.engine = create_cli_engine(
            "nmap", policy=ExecPolicy(timeout=120)
        )

    def process_message(self, data: dict[str, Any]) -> None:
        start = time.time()
        ctx = InjectorContext.from_message(data)

        # Report reception
        self.helper.api.inject.execution_reception(
            inject_id=ctx.inject_id,
            data={"tracking_total_count": 1},
        )

        try:
            result = self.engine.run(
                SCAN_CMD,
                options={"timing": "4"},
                args={"target": ctx.content["targets"][0]},
            )
            callback = ExecutionCallback(
                execution_message="Scan completed",
                execution_status=ExecutionStatus.SUCCESS,
                execution_action="complete",
                execution_duration=int(time.time() - start),
            )
        except Exception as e:
            callback = ExecutionCallback(
                execution_message=str(e),
                execution_status=ExecutionStatus.ERROR,
                execution_action="complete",
                execution_duration=int(time.time() - start),
            )

        self.helper.api.inject.execution_callback(
            inject_id=ctx.inject_id,
            data=callback.model_dump(exclude_none=True),
        )

    def start(self) -> None:
        self.helper.listen(message_callback=self.process_message)

    def stop(self) -> None:
        pass  # cleanup if needed


# Type-check at runtime
assert isinstance(NmapInjector, BaseInjector)
```

## Scope Boundary

The SDK owns the **abstract contract**. OpenAEV-specific infrastructure stays in `pyoaev`:

| Concern | Owner | Why |
|---|---|---|
| Lifecycle shape (`process_message`, `start`, `stop`) | `injectors-sdk` | Injector-specific, shared by all injectors |
| `DaemonProtocol` (`start`, `set_callback`, `get_id`) | `xtm-oaev-sdk` (re-exported) | Shared behavioral contract for daemon runtimes |
| Config field names and validation | `injectors-sdk` | Consistent across all injectors |
| Message parsing (`InjectorContext`) | `injectors-sdk` | Same nested dict traversal everywhere |
| Execution callback structure | `injectors-sdk` | Same payload shape everywhere |
| OpenAEV API client (`OpenAEV(url, token)`) | `pyoaev` | Product API coupling |
| `BaseDaemon` / `CollectorDaemon` (concrete) | `pyoaev` | Platform runtime, API client wiring |
| Message queue (`ListenQueue`, pika) | `pyoaev` | Transport coupling |
| Ping thread (`PingAlive`) | `pyoaev` | Platform lifecycle coupling |
| SSL/TLS context setup | `xtm-oaev-sdk` | Shared across injectors and collectors |
