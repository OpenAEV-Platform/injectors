"""BaseInjector lifecycle Protocol and shared injector models.

This module defines the abstract contract that all injector extensions
implement. The OpenAEV-specific wiring (API client, message queue,
ping thread) stays in pyoaev; this module defines only the
extension-side interface.
"""

from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, field_validator


class InjectorConfig(BaseModel):
    """Common configuration fields shared by all injector extensions.

    Frozen Pydantic model validated at construction time.
    Mirrors the config dict built in every concrete injector's __init__.
    """

    model_config = ConfigDict(frozen=True)

    injector_id: str
    injector_name: str
    injector_type: str
    injector_contracts: list[str] = []
    injector_custom_contracts: bool = False
    injector_category: str | None = None
    injector_executor_commands: list[str] | None = None
    injector_executor_clear_commands: list[str] | None = None

    @field_validator("injector_id", "injector_name", "injector_type")
    @classmethod
    def _must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            msg = "must not be empty"
            raise ValueError(msg)
        return v


class ExecutionStatus(StrEnum):
    """Status values used in execution callback payloads."""

    INFO = "INFO"
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"


class ExecutionCallback(BaseModel):
    """Structured payload for reporting execution progress/completion.

    Maps 1:1 to the callback_data dict every injector sends
    via ``helper.api.inject.execution_callback()``.
    """

    model_config = ConfigDict(frozen=True)

    execution_message: str
    execution_status: ExecutionStatus
    execution_action: str | None = None
    execution_duration: int | None = None
    execution_output_structured: str | None = None


class InjectorContext(BaseModel):
    """Parsed context from an incoming injection message.

    Extracts the three fields every injector needs from the raw
    message dict, providing a typed alternative to manual key traversal.
    """

    model_config = ConfigDict(frozen=True)

    inject_id: str
    contract_id: str
    content: dict[str, Any]

    @classmethod
    def from_message(cls, data: dict[str, Any]) -> "InjectorContext":
        """Extract context from a raw injection message payload.

        Args:
            data: The raw message dict as received from the queue.

        Returns:
            A validated InjectorContext.

        Raises:
            KeyError: When required keys are missing from the message.
        """
        injection = data["injection"]
        return cls(
            inject_id=injection["inject_id"],
            contract_id=injection["inject_injector_contract"][
                "convertedContent"
            ]["contract_id"],
            content=injection["inject_content"],
        )


@runtime_checkable
class BaseInjector(Protocol):
    """Lifecycle contract for injector extensions.

    Every injector implementation must satisfy this Protocol:

    - ``process_message(data)``: handle one injection message.
    - ``start()``: begin listening for messages.
    - ``stop()``: clean shutdown (cancel threads, close connections).

    The Protocol uses structural subtyping: implementations do NOT
    inherit from BaseInjector, they just implement the methods.
    """

    def process_message(self, data: dict[str, Any]) -> None:
        """Handle a single injection message from the queue.

        Args:
            data: The raw message payload dict.
        """
        ...

    def start(self) -> None:
        """Begin the injector's main loop (listen for messages)."""
        ...

    def stop(self) -> None:
        """Perform clean shutdown."""
        ...


__all__ = [
    "BaseInjector",
    "ExecutionCallback",
    "ExecutionStatus",
    "InjectorConfig",
    "InjectorContext",
]
