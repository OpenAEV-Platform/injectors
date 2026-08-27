"""CHK.005 Prowler OCSF to OpenAEV finding boundary."""

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict

from prowler._core.cli_engine import CommandResult


@dataclass(frozen=True)
class OcsfDecodeError(ValueError):
    """Safe structured failure while decoding raw OCSF output."""

    code: str
    message: str
    record_index: int | None = None


@dataclass(frozen=True)
class OcsfMappingError(ValueError):
    """Safe structured failure while mapping one OCSF record."""

    code: str
    message: str
    record_index: int | None = None
    source_path: str | None = None


class OpenAevFinding(BaseModel):
    """Project boundary model; pyoaev 2.3.5 has no public finding model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: str
    value: str
    expectation_result: str
    severity: str
    severity_weight: int
    asset_reference: str
    asset_name: str
    cloud_provider: str
    region: str
    cloud_account: str
    compliance_tags: tuple[str, ...]
    remediation: str
    remediation_url: str | None
    description: str


def decode_ocsf_output(payload: bytes | str) -> tuple[dict[str, Any], ...]:
    """Decode raw Prowler JSON array or JSON Lines output."""
    raise NotImplementedError("CHK.005 RED: raw OCSF decoding is not implemented")


def map_ocsf_finding(
    record: dict[str, Any], *, record_index: int = 0
) -> OpenAevFinding:
    """Map one decoded OCSF record to the local OpenAEV boundary model."""
    raise NotImplementedError("CHK.005 RED: OCSF mapping is not implemented")


def map_command_result(result: CommandResult) -> tuple[OpenAevFinding, ...]:
    """Map one successful CHK.004 result without executing another command."""
    raise NotImplementedError("CHK.005 RED: command result mapping is not implemented")
