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

    def __str__(self) -> str:
        """Render only safe structural context."""
        suffix = (
            f" (record_index={self.record_index})"
            if self.record_index is not None
            else ""
        )
        return f"{self.code}: {self.message}{suffix}"


@dataclass(frozen=True)
class OcsfMappingError(ValueError):
    """Safe structured failure while mapping one OCSF record."""

    code: str
    message: str
    record_index: int | None = None
    source_path: str | None = None

    def __str__(self) -> str:
        """Render only safe structural context."""
        context = []
        if self.record_index is not None:
            context.append(f"record_index={self.record_index}")
        if self.source_path is not None:
            context.append(f"source_path={self.source_path}")
        suffix = f" ({', '.join(context)})" if context else ""
        return f"{self.code}: {self.message}{suffix}"


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


class OcsfPreviewRecord(BaseModel):
    """Bounded allowlisted projection of one successfully mapped OCSF record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_title: str | None = None
    finding_uid: str | None = None
    status: str | None = None
    status_code: str | None = None
    severity: str | None = None
    resource_name: str | None = None
    resource_uid: str | None = None
    cloud_provider: str | None = None
    cloud_region: str | None = None
    cloud_account: str | None = None
    provider_uid: str | None = None


@dataclass(frozen=True)
class OcsfMappingResult:
    """Mapped output and bounded artifact evidence, without decoded raw records."""

    findings: tuple[OpenAevFinding, ...]
    raw_record_count: int
    raw_output_bytes: int
    raw_preview: tuple[OcsfPreviewRecord, ...]


def decode_ocsf_output(payload: bytes | str) -> tuple[dict[str, Any], ...]:
    """Lazily preserve the historic decoder export without an import cycle."""
    from prowler.models.ocsf_mapping import decode_ocsf_output as decode

    return decode(payload)


def map_ocsf_finding(
    record: dict[str, Any], *, record_index: int = 0
) -> OpenAevFinding:
    """Lazily preserve the historic mapper export without an import cycle."""
    from prowler.models.ocsf_mapping import map_ocsf_finding as map_finding

    return map_finding(record, record_index=record_index)


def map_command_result(result: CommandResult) -> tuple[OpenAevFinding, ...]:
    """Lazily preserve the historic command mapper without an import cycle."""
    from prowler.models.ocsf_mapping import map_command_result as map_result

    return map_result(result)


def map_command_result_with_evidence(result: CommandResult) -> OcsfMappingResult:
    """Lazily preserve the historic evidence mapper without an import cycle."""
    from prowler.models.ocsf_mapping import (
        map_command_result_with_evidence as map_result,
    )

    return map_result(result)
