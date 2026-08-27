"""CHK.005 Prowler OCSF to OpenAEV finding boundary."""

import json
from collections.abc import Mapping, Sequence
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


_STATUS_MAP = {
    "PASS": "SUCCESS",
    "PASSED": "SUCCESS",
    "FAIL": "FAILED",
    "FAILED": "FAILED",
    "FAILURE": "FAILED",
    "MUTED": "IGNORED",
    "MANUAL": "IGNORED",
    "SUPPRESSED": "IGNORED",
}

_SEVERITY_MAP = {
    "CRITICAL": ("CRITICAL", 4),
    "HIGH": ("HIGH", 3),
    "MEDIUM": ("MEDIUM", 2),
    "LOW": ("LOW", 1),
    "INFORMATIONAL": ("INFO", 0),
}

_DECODE_MESSAGE = "unable to decode Prowler OCSF output"
_MAPPING_MESSAGE = "unable to map Prowler OCSF record"


def decode_ocsf_output(payload: bytes | str) -> tuple[dict[str, Any], ...]:
    """Decode raw Prowler JSON array or JSON Lines output."""
    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise OcsfDecodeError("invalid_utf8", _DECODE_MESSAGE) from error
    elif isinstance(payload, str):
        text = payload
    else:
        raise OcsfDecodeError("invalid_payload_type", _DECODE_MESSAGE)

    if not text.strip():
        return ()

    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return _decode_json_lines(text)

    if isinstance(decoded, dict):
        return (decoded,)
    if not isinstance(decoded, list):
        raise OcsfDecodeError("invalid_top_level", _DECODE_MESSAGE)
    return _validate_records(decoded)


def map_ocsf_finding(
    record: dict[str, Any], *, record_index: int = 0
) -> OpenAevFinding:
    """Map one decoded OCSF record to the local OpenAEV boundary model."""
    block_key, finding_block = _selected_finding_block(record, record_index)
    resources = _required_sequence(record, "resources", record_index)
    if not resources:
        raise _mapping_error("missing_source_path", record_index, "resources[0]")
    resource = _mapping_value(resources[0], "resources[0]", record_index)
    cloud = _required_mapping(record, "cloud", record_index)
    account = _required_mapping(cloud, "cloud.account", record_index, key="account")
    if "remediation" in record:
        remediation: Mapping[str, Any] | None = _required_mapping(
            record, "remediation", record_index
        )
    else:
        remediation = None

    status = _required_string(record, "status", record_index)
    severity_value = record.get("severity")
    if severity_value is None:
        severity = ("INFO", 0)
    elif isinstance(severity_value, str):
        severity = _SEVERITY_MAP.get(severity_value.upper(), ("INFO", 0))
    else:
        raise _mapping_error("invalid_source_value", record_index, "severity")

    if remediation is not None:
        references_value = remediation.get("references", ())
        if not isinstance(references_value, Sequence) or isinstance(
            references_value, (str, bytes)
        ):
            raise _mapping_error(
                "invalid_source_value", record_index, "remediation.references"
            )
        remediation_url: str | None = None
        if references_value:
            remediation_url = _string_value(
                references_value[0], "remediation.references[0]", record_index
            )
    else:
        remediation_url = None

    return OpenAevFinding(
        type=_required_string(
            finding_block, f"{block_key}.uid", record_index, key="uid"
        ),
        value=_required_string(
            finding_block, f"{block_key}.title", record_index, key="title"
        ),
        expectation_result=_STATUS_MAP.get(status.upper(), "MUTED"),
        severity=severity[0],
        severity_weight=severity[1],
        asset_reference=_required_string(
            resource, "resources[0].uid", record_index, key="uid"
        ),
        asset_name=_required_string(
            resource, "resources[0].name", record_index, key="name"
        ),
        cloud_provider=_required_string(
            cloud, "cloud.provider", record_index, key="provider"
        ),
        region=_required_string(cloud, "cloud.region", record_index, key="region"),
        cloud_account=_required_string(
            account, "cloud.account.uid", record_index, key="uid"
        ),
        compliance_tags=_compliance_tags(record, record_index),
        remediation=(
            _required_string(remediation, "remediation.desc", record_index, key="desc")
            if remediation is not None
            else _block_remediation(finding_block, block_key, record_index)[0]
        ),
        remediation_url=(
            remediation_url
            if remediation is not None
            else _block_remediation(finding_block, block_key, record_index)[1]
        ),
        description=_required_string(
            finding_block, f"{block_key}.desc", record_index, key="desc"
        ),
    )


def map_command_result(result: CommandResult) -> tuple[OpenAevFinding, ...]:
    """Map one successful CHK.004 result without executing another command."""
    if result.error is not None or result.return_code != 0:
        raise OcsfMappingError(
            "command_not_successful",
            "Prowler command result is not successful",
        )
    payload = (
        result.parsed if isinstance(result.parsed, (bytes, str)) else result.stdout
    )
    records = decode_ocsf_output(payload)
    return tuple(
        map_ocsf_finding(record, record_index=index)
        for index, record in enumerate(records)
    )


def _decode_json_lines(text: str) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    for record_index, line in enumerate(
        line for line in text.splitlines() if line.strip()
    ):
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as error:
            raise OcsfDecodeError(
                "invalid_json", _DECODE_MESSAGE, record_index
            ) from error
        if not isinstance(decoded, dict):
            raise OcsfDecodeError("non_object_record", _DECODE_MESSAGE, record_index)
        records.append(decoded)
    return tuple(records)


def _validate_records(records: list[Any]) -> tuple[dict[str, Any], ...]:
    validated = []
    for record_index, record in enumerate(records):
        if not isinstance(record, dict):
            raise OcsfDecodeError("non_object_record", _DECODE_MESSAGE, record_index)
        validated.append(record)
    return tuple(validated)


def _mapping_error(code: str, record_index: int, source_path: str) -> OcsfMappingError:
    return OcsfMappingError(code, _MAPPING_MESSAGE, record_index, source_path)


def _mapping_value(
    value: object, source_path: str, record_index: int
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _mapping_error("invalid_source_value", record_index, source_path)
    return value


def _required_mapping(
    parent: Mapping[str, Any],
    source_path: str,
    record_index: int,
    *,
    key: str | None = None,
) -> Mapping[str, Any]:
    lookup_key = key or source_path
    if lookup_key not in parent:
        raise _mapping_error("missing_source_path", record_index, source_path)
    return _mapping_value(parent[lookup_key], source_path, record_index)


def _selected_finding_block(
    record: Mapping[str, Any], record_index: int
) -> tuple[str, Mapping[str, Any]]:
    """Select the one present finding block and its source path key."""
    if "finding_info" in record:
        block_key = "finding_info"
    elif "finding" in record:
        block_key = "finding"
    else:
        raise _mapping_error(
            "missing_source_path", record_index, "finding_info|finding"
        )
    return block_key, _mapping_value(record[block_key], block_key, record_index)


def _required_sequence(
    parent: Mapping[str, Any], source_path: str, record_index: int
) -> Sequence[Any]:
    if source_path not in parent:
        raise _mapping_error("missing_source_path", record_index, source_path)
    value = parent[source_path]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise _mapping_error("invalid_source_value", record_index, source_path)
    return value


def _string_value(value: object, source_path: str, record_index: int) -> str:
    if not isinstance(value, str):
        raise _mapping_error("invalid_source_value", record_index, source_path)
    return value


def _required_string(
    parent: Mapping[str, Any],
    source_path: str,
    record_index: int,
    *,
    key: str | None = None,
) -> str:
    lookup_key = key or source_path
    if lookup_key not in parent:
        raise _mapping_error("missing_source_path", record_index, source_path)
    return _string_value(parent[lookup_key], source_path, record_index)


def _block_remediation(
    block: Mapping[str, Any], block_key: str, record_index: int
) -> tuple[str, str | None]:
    """Map the finding-block remediation to its desc and URL value."""
    if "remediation" not in block:
        raise _mapping_error(
            "missing_source_path",
            record_index,
            f"remediation|{block_key}.remediation",
        )
    remediation = _mapping_value(
        block["remediation"], f"{block_key}.remediation", record_index
    )
    desc = _required_string(
        remediation, f"{block_key}.remediation.desc", record_index, key="desc"
    )
    if "references" in remediation:
        return desc, _block_remediation_url(
            remediation, block_key, "references", record_index
        )
    if "kb_articles" in remediation:
        return desc, _block_remediation_url(
            remediation, block_key, "kb_articles", record_index
        )
    return desc, None


def _block_remediation_url(
    remediation: Mapping[str, Any],
    block_key: str,
    key: str,
    record_index: int,
) -> str | None:
    """Resolve one present block URL list to its unvalidated first entry."""
    source_path = f"{block_key}.remediation.{key}"
    value = remediation[key]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise _mapping_error("invalid_source_value", record_index, source_path)
    if not value:
        return None
    return _string_value(value[0], f"{source_path}[0]", record_index)


def _compliance_tags(record: Mapping[str, Any], record_index: int) -> tuple[str, ...]:
    unmapped = record.get("unmapped")
    if unmapped is None:
        return _top_level_compliance_tags(record, record_index)
    unmapped_mapping = _mapping_value(unmapped, "unmapped", record_index)
    compliance = unmapped_mapping.get("compliance")
    if compliance is None:
        return _top_level_compliance_tags(record, record_index)
    return tuple(_flatten_compliance(compliance, "unmapped.compliance", record_index))


def _top_level_compliance_tags(
    record: Mapping[str, Any], record_index: int
) -> tuple[str, ...]:
    """Map a present top-level compliance object to requirement tags."""
    compliance = record.get("compliance")
    if compliance is None:
        return ()
    compliance_mapping = _mapping_value(compliance, "compliance", record_index)
    requirements = compliance_mapping.get("requirements")
    if requirements is None:
        return ()
    return tuple(
        _flatten_requirements(requirements, "compliance.requirements", record_index)
    )


def _flatten_compliance(
    value: object, source_path: str, record_index: int
) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        flattened = []
        for key, nested in value.items():
            flattened.extend(
                _flatten_compliance(nested, f"{source_path}.{key}", record_index)
            )
        return flattened
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        flattened = []
        for index, nested in enumerate(value):
            flattened.extend(
                _flatten_compliance(nested, f"{source_path}[{index}]", record_index)
            )
        return flattened
    raise _mapping_error("invalid_source_value", record_index, source_path)


def _flatten_requirements(
    value: object, source_path: str, record_index: int
) -> list[str]:
    """Flatten a strict string-or-list requirements value in encounter order."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        flattened = []
        for index, nested in enumerate(value):
            flattened.extend(
                _flatten_requirements(nested, f"{source_path}[{index}]", record_index)
            )
        return flattened
    raise _mapping_error("invalid_source_value", record_index, source_path)
