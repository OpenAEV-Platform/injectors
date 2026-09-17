"""OCSF decoding and mapping for the OpenAEV finding boundary."""

import json
from collections.abc import Mapping, Sequence
from typing import Any, Callable, cast

from prowler._core.cli_engine import CommandResult
from prowler.models.findings import (
    OcsfDecodeError,
    OcsfMappingError,
    OcsfMappingResult,
    OcsfPreviewRecord,
    OpenAevFinding,
)

_STATUS_CODE_MAP = {
    "PASS": "SUCCESS",
    "PASSED": "SUCCESS",
    "FAIL": "FAILED",
    "FAILED": "FAILED",
    "FAILURE": "FAILED",
}
_IGNORED_LIFECYCLE_STATUSES = {"SUPPRESSED", "MUTED", "MANUAL"}

_SEVERITY_MAP = {
    "CRITICAL": ("CRITICAL", 4),
    "HIGH": ("HIGH", 3),
    "MEDIUM": ("MEDIUM", 2),
    "LOW": ("LOW", 1),
    "INFORMATIONAL": ("INFO", 0),
}

_DECODE_MESSAGE = "unable to decode Prowler OCSF output"
_MAPPING_MESSAGE = "unable to map Prowler OCSF record"
_MAX_PREVIEW_VALUE_LENGTH = 512


def _expectation_result(status: str, status_code: str) -> str:
    """Keep lifecycle suppression separate from the check result code."""
    if status.upper() in _IGNORED_LIFECYCLE_STATUSES:
        return "IGNORED"
    return _STATUS_CODE_MAP.get(status_code.upper(), "IGNORED")


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
    if "cloud" in record:
        cloud = _required_mapping(record, "cloud", record_index)
        account = _required_mapping(cloud, "cloud.account", record_index, key="account")
        cloud_provider = _required_string(
            cloud, "cloud.provider", record_index, key="provider"
        )
        region = _required_string(cloud, "cloud.region", record_index, key="region")
        cloud_account = _required_string(
            account, "cloud.account.uid", record_index, key="uid"
        )
    else:
        unmapped = _required_mapping(record, "unmapped", record_index)
        cloud_provider = _required_string(
            unmapped, "unmapped.provider", record_index, key="provider"
        )
        cloud_account = _required_string(
            unmapped, "unmapped.provider_uid", record_index, key="provider_uid"
        )
        region = _required_string(
            resource, "resources[0].namespace", record_index, key="namespace"
        )
    if "remediation" in record:
        remediation: Mapping[str, Any] | None = _required_mapping(
            record, "remediation", record_index
        )
    else:
        remediation = None

    status = _required_string(record, "status", record_index)
    status_code = (
        _required_string(record, "status_code", record_index)
        if "status_code" in record
        else status
    )
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
        expectation_result=_expectation_result(status, status_code),
        severity=severity[0],
        severity_weight=severity[1],
        asset_reference=_required_string(
            resource, "resources[0].uid", record_index, key="uid"
        ),
        asset_name=_required_string(
            resource, "resources[0].name", record_index, key="name"
        ),
        cloud_provider=cloud_provider,
        region=region,
        cloud_account=cloud_account,
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
    return map_command_result_with_evidence(result).findings


def map_command_result_with_evidence(result: CommandResult) -> OcsfMappingResult:
    """Map an artifact once and retain only counts and safe bounded previews."""
    if result.error is not None or result.return_code != 0:
        raise OcsfMappingError(
            "command_not_successful",
            "Prowler command result is not successful",
        )
    payload = result.parsed
    if not isinstance(payload, (bytes, str)):
        raise OcsfDecodeError("invalid_payload_type", _DECODE_MESSAGE)
    # Resolve through the historic module path to preserve its patch seam.
    from prowler.models import findings as findings_module

    decode = cast(
        Callable[[bytes | str], tuple[dict[str, Any], ...]],
        findings_module.decode_ocsf_output,
    )
    records = decode(payload)
    findings: list[OpenAevFinding] = []
    previews: list[OcsfPreviewRecord] = []
    for index, record in enumerate(records):
        findings.append(map_ocsf_finding(record, record_index=index))
        if index < 10:
            previews.append(_preview_record(record))
    return OcsfMappingResult(
        findings=tuple(findings),
        raw_record_count=len(records),
        raw_output_bytes=(
            len(payload) if isinstance(payload, bytes) else len(payload.encode("utf-8"))
        ),
        raw_preview=tuple(previews),
    )


def _preview_record(record: Mapping[str, Any]) -> OcsfPreviewRecord:
    """Project only the approved OCSF paths from one already-mapped record."""
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
    return OcsfPreviewRecord(
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
            if nested is True:
                flattened.append(str(key))
            elif nested is False or nested is None:
                continue
            else:
                flattened.extend(
                    f"{key}:{tag}"
                    for tag in _flatten_compliance(
                        nested, f"{source_path}.{key}", record_index
                    )
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
