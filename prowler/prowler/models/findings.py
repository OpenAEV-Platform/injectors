"""CHK.005 Prowler OCSF to OpenAEV finding boundary."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict

from prowler._core.cli_engine import CommandResult


_MAX_PREVIEW_VALUE_LENGTH = 512


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
class OcsfMappingError(OcsfDecodeError):
    """Safe structured failure while mapping one OCSF record."""

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

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "OcsfPreviewRecord":
        """Project only the approved OCSF paths from one mapped record."""
        finding_value = record.get("finding_info", record.get("finding"))
        finding = finding_value if isinstance(finding_value, Mapping) else {}
        resources_value = record.get("resources")
        resource_value = (
            resources_value[0]
            if isinstance(resources_value, Sequence)
            and not isinstance(resources_value, (str, bytes))
            and resources_value
            else None
        )
        resource = resource_value if isinstance(resource_value, Mapping) else {}
        cloud_value = record.get("cloud")
        cloud = cloud_value if isinstance(cloud_value, Mapping) else {}
        account_value = cloud.get("account")
        account = account_value if isinstance(account_value, Mapping) else {}
        unmapped_value = record.get("unmapped")
        unmapped = unmapped_value if isinstance(unmapped_value, Mapping) else {}
        return cls(
            finding_title=_optional_string(finding.get("title")),
            finding_uid=_optional_string(finding.get("uid")),
            status=_optional_string(record.get("status")),
            status_code=_optional_string(record.get("status_code")),
            severity=_optional_string(record.get("severity")),
            resource_name=_optional_string(resource.get("name")),
            resource_uid=_optional_string(resource.get("uid")),
            cloud_provider=_optional_string(cloud.get("provider")),
            cloud_region=_optional_string(cloud.get("region")),
            cloud_account=_optional_string(account.get("uid")),
            provider_uid=(
                _optional_string(unmapped.get("provider_uid")) if not cloud else None
            ),
        )


def _optional_string(value: object) -> str | None:
    """Admit and bound only text at one statically selected preview path."""
    if not isinstance(value, str):
        return None
    if len(value) <= _MAX_PREVIEW_VALUE_LENGTH:
        return value
    return f"{value[: _MAX_PREVIEW_VALUE_LENGTH - 3]}..."


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
