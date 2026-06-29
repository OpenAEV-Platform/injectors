"""RED tests for BaseInjector lifecycle Protocol and models."""

from typing import Any

import pytest
from injectors_sdk._core.base import (
    BaseInjector,
    ExecutionCallback,
    ExecutionStatus,
    InjectorConfig,
    InjectorContext,
)

# --- GIVEN helpers ---


class _ConcreteInjector:
    """Minimal concrete injector satisfying BaseInjector Protocol."""

    def __init__(self) -> None:
        self._started = False
        self._stopped = False
        self._messages: list[dict[str, Any]] = []

    def process_message(self, data: dict[str, Any]) -> None:
        self._messages.append(data)

    def start(self) -> None:
        self._started = True

    def stop(self) -> None:
        self._stopped = True


class _PartialInjector:
    """Missing process_message — should NOT satisfy Protocol."""

    def start(self) -> None: ...

    def stop(self) -> None: ...


# --- InjectorConfig ---


def test_injector_config_required_fields() -> None:
    config = InjectorConfig(
        injector_id="inj-001",
        injector_name="nmap",
        injector_type="network_scanner",
    )
    assert config.injector_id == "inj-001"
    assert config.injector_name == "nmap"
    assert config.injector_type == "network_scanner"


def test_injector_config_optional_fields_default() -> None:
    config = InjectorConfig(
        injector_id="inj-001",
        injector_name="nmap",
        injector_type="network_scanner",
    )
    assert config.injector_contracts == []
    assert config.injector_custom_contracts is False
    assert config.injector_category is None
    assert config.injector_executor_commands is None
    assert config.injector_executor_clear_commands is None


def test_injector_config_is_frozen() -> None:
    config = InjectorConfig(
        injector_id="inj-001",
        injector_name="nmap",
        injector_type="network_scanner",
    )
    with pytest.raises(Exception):
        config.injector_id = "changed"  # type: ignore[misc]


def test_injector_config_rejects_empty_id() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        InjectorConfig(
            injector_id="",
            injector_name="nmap",
            injector_type="network_scanner",
        )


def test_injector_config_rejects_empty_name() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        InjectorConfig(
            injector_id="inj-001",
            injector_name="",
            injector_type="network_scanner",
        )


# --- ExecutionStatus ---


def test_execution_status_enum_values() -> None:
    assert ExecutionStatus.INFO == "INFO"
    assert ExecutionStatus.SUCCESS == "SUCCESS"
    assert ExecutionStatus.ERROR == "ERROR"


# --- ExecutionCallback ---


def test_execution_callback_defaults() -> None:
    cb = ExecutionCallback(
        execution_message="running scan",
        execution_status=ExecutionStatus.INFO,
    )
    assert cb.execution_action is None
    assert cb.execution_duration is None
    assert cb.execution_output_structured is None


def test_execution_callback_complete() -> None:
    cb = ExecutionCallback(
        execution_message="scan done",
        execution_status=ExecutionStatus.SUCCESS,
        execution_action="complete",
        execution_duration=42,
        execution_output_structured='{"results": []}',
    )
    assert cb.execution_action == "complete"
    assert cb.execution_duration == 42


def test_execution_callback_is_frozen() -> None:
    cb = ExecutionCallback(
        execution_message="msg",
        execution_status=ExecutionStatus.INFO,
    )
    with pytest.raises(Exception):
        cb.execution_message = "changed"  # type: ignore[misc]


# --- InjectorContext ---


def test_injector_context_fields() -> None:
    ctx = InjectorContext(
        inject_id="inject-uuid-001",
        contract_id="contract-001",
        content={"key": "value"},
    )
    assert ctx.inject_id == "inject-uuid-001"
    assert ctx.contract_id == "contract-001"
    assert ctx.content == {"key": "value"}


def test_injector_context_is_frozen() -> None:
    ctx = InjectorContext(
        inject_id="inject-uuid-001",
        contract_id="contract-001",
        content={},
    )
    with pytest.raises(Exception):
        ctx.inject_id = "changed"  # type: ignore[misc]


def test_injector_context_from_message() -> None:
    raw = {
        "injection": {
            "inject_id": "inject-uuid-001",
            "inject_injector_contract": {"convertedContent": {"contract_id": "contract-001"}},
            "inject_content": {"targets": ["192.168.1.1"]},
        }
    }
    ctx = InjectorContext.from_message(raw)
    assert ctx.inject_id == "inject-uuid-001"
    assert ctx.contract_id == "contract-001"
    assert ctx.content == {"targets": ["192.168.1.1"]}


def test_injector_context_from_message_missing_keys() -> None:
    with pytest.raises((KeyError, TypeError)):
        InjectorContext.from_message({"bad": "data"})


# --- BaseInjector Protocol ---


def test_concrete_injector_satisfies_protocol() -> None:
    injector = _ConcreteInjector()
    assert isinstance(injector, BaseInjector)


def test_partial_injector_does_not_satisfy_protocol() -> None:
    partial = _PartialInjector()
    assert not isinstance(partial, BaseInjector)


def test_concrete_injector_lifecycle() -> None:
    injector = _ConcreteInjector()

    injector.start()
    assert injector._started is True

    injector.process_message({"injection": {"inject_id": "test"}})
    assert len(injector._messages) == 1

    injector.stop()
    assert injector._stopped is True
