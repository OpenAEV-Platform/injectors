"""Injector configuration and callback models."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class InjectorConfig(BaseModel):
    """Common configuration fields shared by all injector extensions."""

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
            raise ValueError("must not be empty")
        return v


class ExecutionStatus(StrEnum):
    """Status values used in execution callback payloads."""

    INFO = "INFO"
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"


class ExecutionCallback(BaseModel):
    """Structured payload for reporting execution progress/completion."""

    model_config = ConfigDict(frozen=True)

    execution_message: str
    execution_status: ExecutionStatus
    execution_action: str | None = None
    execution_duration: int | None = None
    execution_output_structured: str | None = None


class InjectorContext(BaseModel):
    """Parsed context from an incoming injection message."""

    model_config = ConfigDict(frozen=True)

    inject_id: str
    contract_id: str
    content: dict[str, Any]

    @classmethod
    def from_message(cls, data: dict[str, Any]) -> "InjectorContext":
        injection = data["injection"]
        return cls(
            inject_id=injection["inject_id"],
            contract_id=injection["inject_injector_contract"]["convertedContent"]["contract_id"],
            content=injection["inject_content"],
        )
