"""Shared failure, issue, and OCSF taxonomy constants for the Prowler injector."""

import re
from dataclasses import dataclass
from typing import TypedDict, Unpack

_LISTENER_START = "[PROWLER_INJECTOR] - Listener starting"
_INVALID_MESSAGE = "[PROWLER_INJECTOR] - Invalid injection message rejected"
_ASSESSMENT_RECEIVED = "[PROWLER_INJECTOR] - Assessment received"
_RECEPTION_ACKNOWLEDGED = "[PROWLER_INJECTOR] - Reception acknowledged"
_CONTRACT_RESOLVED = "[PROWLER_INJECTOR] - Contract resolved"
_ASSESSMENT_VALIDATED = "[PROWLER_INJECTOR] - Assessment input validated"
_EXECUTION_STARTED = "[PROWLER_INJECTOR] - Assessment execution starting"
_ASSESSMENT_SUCCEEDED = "[PROWLER_INJECTOR] - Assessment completed"
_ASSESSMENT_FAILED = "[PROWLER_INJECTOR] - Assessment failed"
_CALLBACK_COMPLETED = "[PROWLER_INJECTOR] - Assessment callback completed"
_CALLBACK_FAILED = "[PROWLER_INJECTOR] - Assessment callback failed"

_ALLOWED_CLI_FAILURE_KINDS = frozenset(
    {
        "cli_engine_error",
        "policy_rejected",
        "policy_evaluation_failed",
        "resolution_failed",
        "execution_failed",
        "timeout",
        "process_start_failed",
        "unsuccessful_process",
        "output_too_large_after_capture",
        "parsing_failed",
    }
)
_ALLOWED_ISSUE_LOCATIONS = frozenset(
    {
        "provider",
        "aws",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_account_id",
        "aws_region",
        "aws_endpoint_url",
        "aws_session_token",
        "azure",
        "azure_tenant_id",
        "azure_client_id",
        "azure_client_secret",
        "azure_subscription_id",
        "azure_provider",
        "gcp",
        "gcp_service_account_json",
        "gcp_project_id",
        "kubernetes",
        "kubernetes_kubeconfig",
        "kubernetes_context",
    }
)
_ALLOWED_ISSUE_TYPES = frozenset(
    {
        "extra_forbidden",
        "literal_error",
        "missing",
        "string_too_long",
        "string_too_short",
        "string_pattern_mismatch",
        "string_type",
        "union_tag_invalid",
        "union_tag_not_found",
        "value_error",
    }
)
_ISSUE_LOCATION_SENTINEL = "unrecognized_field"
_ISSUE_TYPE_SENTINEL = "invalid"
_MAX_LOG_ISSUES = 16
_MAX_ISSUE_LOCATION_DEPTH = 3
_MAX_ISSUE_LOCATION_LENGTH = 64
_MAX_LOG_COUNT = 1_000_000
_MAX_LOG_DURATION_SECONDS = 86_400
_MAX_ELAPSED_MS = 86_400_000
_MAX_BYTE_COUNT = 1_000_000_000
_MAX_SAFE_TEXT = 512
_MAXIMUM_ACCEPTED_STRUCTURED_OUTPUT_BYTES = 32 * 1024 * 1024
_INJECT_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_INVALID_INJECT_ID_DIGEST_LENGTH = 16
_PROCESS_START_CAUSES = frozenset(
    {
        "FileNotFoundError",
        "PermissionError",
        "IsADirectoryError",
        "NotADirectoryError",
        "OSError",
    }
)
_PARSER_NAMES = frozenset({"raw", "text", "json", "lines", "regex"})
_OCSF_DECODE_CODES = frozenset(
    {
        "invalid_json",
        "invalid_payload_type",
        "invalid_top_level",
        "invalid_utf8",
        "non_object_record",
    }
)
_OCSF_MAPPING_CODES = frozenset(
    {"command_not_successful", "invalid_source_value", "missing_source_path"}
)
_OCSF_CODE_SENTINEL = "unrecognized"
_OCSF_SOURCE_PATH_SENTINEL = "unrecognized_source_path"
_OCSF_SOURCE_PATHS = frozenset(
    {
        "cloud",
        "cloud.account",
        "cloud.account.uid",
        "cloud.provider",
        "cloud.region",
        "compliance",
        "compliance.requirements",
        "finding",
        "finding.desc",
        "finding.remediation",
        "finding.remediation.desc",
        "finding.remediation.kb_articles",
        "finding.remediation.kb_articles[0]",
        "finding.remediation.references",
        "finding.remediation.references[0]",
        "finding.title",
        "finding.uid",
        "finding_info",
        "finding_info.desc",
        "finding_info.remediation",
        "finding_info.remediation.desc",
        "finding_info.remediation.kb_articles",
        "finding_info.remediation.kb_articles[0]",
        "finding_info.remediation.references",
        "finding_info.remediation.references[0]",
        "finding_info.title",
        "finding_info.uid",
        "finding_info|finding",
        "remediation",
        "remediation.desc",
        "remediation.references",
        "remediation.references[0]",
        "remediation|finding.remediation",
        "remediation|finding_info.remediation",
        "resources",
        "resources[0]",
        "resources[0].name",
        "resources[0].namespace",
        "resources[0].uid",
        "severity",
        "status",
        "status_code",
        "unmapped",
        "unmapped.compliance",
        "unmapped.provider",
        "unmapped.provider_uid",
    }
)
_OCSF_INDEXED_SOURCE_PATH_PATTERN = re.compile(
    r"(?:compliance\.requirements|unmapped\.compliance)(?:\[[0-9]{1,6}\])+$"
)
_ARTIFACT_FAILURE_KIND = {
    "missing": "output_artifact_missing",
    "nonregular": "output_artifact_nonregular",
    "unreadable": "output_artifact_unreadable",
    "oversized": "output_artifact_oversized",
}

_GENERIC_INPUT_GUIDANCE = "Correct the listed assessment fields and retry."
_GUIDANCE_BY_FAILURE_KIND = {
    "cli_engine_error": "Review the injector configuration and retry the assessment.",
    "policy_rejected": (
        "Correct the assessment request to satisfy the execution policy."
    ),
    "policy_evaluation_failed": "Review the injector policy configuration and retry.",
    "resolution_failed": (
        "Check that prowler.executable_path points to an available executable."
    ),
    "execution_failed": (
        "Verify the Prowler runtime is available and retry the assessment."
    ),
    "timeout": (
        "Reduce the assessment scope or investigate Prowler runtime performance "
        "before retrying."
    ),
    "process_start_failed": (
        "Verify the Prowler process can start with the configured executable."
    ),
    "unsuccessful_process": (
        "Review the Prowler configuration and retry the assessment."
    ),
    "output_too_large_after_capture": (
        "Reduce the assessment scope so captured output stays within the injector "
        "limit."
    ),
    "parsing_failed": "Verify Prowler emits valid JSON-OCSF output and retry.",
    "output_artifact_missing": (
        "Verify Prowler writes the expected OCSF artifact and retry."
    ),
    "output_artifact_nonregular": (
        "Verify the Prowler OCSF output is a regular file and retry."
    ),
    "output_artifact_unreadable": (
        "Verify the Prowler OCSF artifact is readable and retry."
    ),
    "output_artifact_oversized": (
        "Reduce the assessment scope so the OCSF artifact stays within its limit."
    ),
    "output_workspace_preparation_failed": (
        "Verify temporary output storage is available and retry."
    ),
    "output_workspace_cleanup_failed": (
        "Review temporary output storage cleanup and retry the assessment."
    ),
    "invalid_input": _GENERIC_INPUT_GUIDANCE,
    "structured_output_failed": "Review structured output projection and retry.",
    "structured_output_too_large": (
        "Reduce the assessment scope so structured output stays within its limit."
    ),
    "rendering_failed": "Review injector trace rendering configuration and retry.",
    "reception_failed": "Check OpenAEV connectivity and retry assessment reception.",
    "callback_failed": "Check OpenAEV connectivity and retry callback delivery.",
    "unexpected_failure": "Review injector configuration and retry the assessment.",
}
_SUMMARY_BY_FAILURE_KIND = {
    "cli_engine_error": "The Prowler execution engine rejected the assessment.",
    "policy_rejected": "The assessment did not satisfy the execution policy.",
    "policy_evaluation_failed": "The execution policy could not be evaluated.",
    "resolution_failed": "The configured Prowler executable could not be resolved.",
    "execution_failed": "Prowler execution failed before a successful result.",
    "timeout": "Prowler did not finish within the injector timeout.",
    "process_start_failed": "The Prowler process could not be started.",
    "unsuccessful_process": "Prowler exited with an unsuccessful return code.",
    "output_too_large_after_capture": (
        "Captured Prowler output exceeded the injector safety limit."
    ),
    "parsing_failed": "Captured Prowler output could not be parsed safely.",
    "output_artifact_missing": "The expected Prowler OCSF artifact was not created.",
    "output_artifact_nonregular": (
        "The Prowler OCSF artifact was not an accepted regular file."
    ),
    "output_artifact_unreadable": "The Prowler OCSF artifact could not be read.",
    "output_artifact_oversized": (
        "The Prowler OCSF artifact exceeded the accepted size limit."
    ),
    "output_workspace_preparation_failed": (
        "The temporary Prowler output workspace could not be prepared."
    ),
    "output_workspace_cleanup_failed": (
        "The temporary Prowler output workspace could not be cleaned."
    ),
    "invalid_input": "The assessment input was invalid.",
    "structured_output_failed": (
        "The OpenAEV structured output could not be serialized."
    ),
    "structured_output_too_large": (
        "The OpenAEV structured output exceeded the accepted size limit."
    ),
    "rendering_failed": "The OpenAEV execution trace could not be rendered.",
    "reception_failed": "The assessment reception could not be acknowledged.",
    "callback_failed": "The terminal OpenAEV callback could not be delivered.",
    "unexpected_failure": "The assessment failed at an unexpected internal boundary.",
}
_ISSUE_FIELD_LABELS = {
    "provider": "Provider",
    "aws_access_key_id": "AWS access key ID",
    "aws_secret_access_key": "AWS secret access key",
    "aws_account_id": "AWS account ID",
    "aws_region": "AWS region",
    "aws_endpoint_url": "AWS endpoint URL",
    "aws_session_token": "AWS session token",
    "azure_tenant_id": "Azure tenant ID",
    "azure_client_id": "Azure client ID",
    "azure_client_secret": "Azure client secret",
    "azure_subscription_id": "Azure subscription ID",
    "azure_provider": "Azure provider",
    "gcp_service_account_json": "GCP service account JSON",
    "gcp_project_id": "GCP project ID",
    "kubernetes_kubeconfig": "Kubernetes kubeconfig",
    "kubernetes_context": "Kubernetes context",
}
_ISSUE_TYPE_PHRASES = {
    "extra_forbidden": "is not accepted.",
    "literal_error": "has an invalid selection.",
    "missing": "is required.",
    "string_pattern_mismatch": "has an invalid format.",
    "string_too_long": "is too long.",
    "string_too_short": "is too short.",
    "string_type": "must be text.",
    "union_tag_invalid": "has an invalid provider selection.",
    "union_tag_not_found": "requires a provider selection.",
    "value_error": "has an invalid value.",
}


def _safe_text(value: str) -> str:
    """Bound explicitly approved operational text."""
    printable = "".join(
        character if character.isprintable() else "?" for character in value
    )
    if len(printable) <= _MAX_SAFE_TEXT:
        return printable
    return f"{printable[: _MAX_SAFE_TEXT - 3]}..."


@dataclass(frozen=True)
class _ExecutableEvidence:
    """No-throw executable path and stat evidence."""

    configured_executable_path: str | None = None
    actual_executable_path: str | None = None
    executable_is_absolute: bool | None = None
    executable_exists: bool | None = None
    executable_is_file: bool | None = None
    executable_is_executable: bool | None = None


class _AssessmentFailureRest(TypedDict, total=False):
    """Optional fields carried by ``_AssessmentFailure.from_evidence``."""

    return_code: int | None
    process_start_cause: str | None
    timeout_seconds: float | None
    maximum_accepted_output_bytes: int | None
    parser_name: str | None
    stdout_bytes: int | None
    stderr_bytes: int | None
    ocsf_error_code: str | None
    record_index: int | None
    source_path: str | None


class _OcsfDecodeFailureRest(TypedDict, total=False):
    """Optional fields carried by ``_OcsfDecodeFailure.from_evidence``."""

    ocsf_error_code: str | None
    record_index: int | None
    source_path: str | None


class _ArtifactFailureRest(TypedDict, total=False):
    """Optional fields carried by ``_ArtifactFailure.from_evidence``."""

    return_code: int | None
    stdout_bytes: int | None
    stderr_bytes: int | None


class _InternalFailureRest(TypedDict, total=False):
    """Optional fields carried by ``_InternalFailure.from_evidence``."""

    maximum_accepted_structured_output_bytes: int | None
    structured_output_bytes: int | None


@dataclass(frozen=True)
class _FailurePresentation:
    """One closed classification shared by logs and OpenAEV presentation.

    The base carries the header and executable evidence only; subclasses
    narrow the optional evidence to the fields one construction site can
    populate.
    """

    stage: str
    failure_kind: str
    failure_summary: str
    operator_guidance: str
    configured_executable_path: str | None = None
    actual_executable_path: str | None = None
    executable_is_absolute: bool | None = None
    executable_exists: bool | None = None
    executable_is_file: bool | None = None
    executable_is_executable: bool | None = None


@dataclass(frozen=True)
class _AssessmentFailure(_FailurePresentation):
    """Assessment execution failure with bounded process and parse evidence."""

    return_code: int | None = None
    process_start_cause: str | None = None
    timeout_seconds: float | None = None
    maximum_accepted_output_bytes: int | None = None
    parser_name: str | None = None
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    ocsf_error_code: str | None = None
    record_index: int | None = None
    source_path: str | None = None

    @classmethod
    def from_evidence(
        cls,
        stage: str,
        failure_kind: str,
        failure_summary: str,
        operator_guidance: str,
        evidence: _ExecutableEvidence,
        **rest: Unpack[_AssessmentFailureRest],
    ) -> "_AssessmentFailure":
        """Build one presentation with the executable projection applied once."""
        return cls(
            stage=stage,
            failure_kind=failure_kind,
            failure_summary=failure_summary,
            operator_guidance=operator_guidance,
            configured_executable_path=evidence.configured_executable_path,
            actual_executable_path=evidence.actual_executable_path,
            executable_is_absolute=evidence.executable_is_absolute,
            executable_exists=evidence.executable_exists,
            executable_is_file=evidence.executable_is_file,
            executable_is_executable=evidence.executable_is_executable,
            **rest,
        )


@dataclass(frozen=True)
class _InputValidationFailure(_FailurePresentation):
    """Invalid assessment input with bounded, normalized issue structure."""

    issues: tuple[dict[str, object], ...] | None = None
    issues_omitted: int = 0
    issues_truncated: bool = False


@dataclass(frozen=True)
class _OcsfDecodeFailure(_FailurePresentation):
    """Raised OCSF failure with the safe decode and mapping evidence."""

    ocsf_error_code: str | None = None
    record_index: int | None = None
    source_path: str | None = None

    @classmethod
    def from_evidence(
        cls,
        stage: str,
        failure_kind: str,
        failure_summary: str,
        operator_guidance: str,
        evidence: _ExecutableEvidence,
        **rest: Unpack[_OcsfDecodeFailureRest],
    ) -> "_OcsfDecodeFailure":
        """Build one presentation with the executable projection applied once."""
        return cls(
            stage=stage,
            failure_kind=failure_kind,
            failure_summary=failure_summary,
            operator_guidance=operator_guidance,
            configured_executable_path=evidence.configured_executable_path,
            actual_executable_path=evidence.actual_executable_path,
            executable_is_absolute=evidence.executable_is_absolute,
            executable_exists=evidence.executable_exists,
            executable_is_file=evidence.executable_is_file,
            executable_is_executable=evidence.executable_is_executable,
            **rest,
        )


@dataclass(frozen=True)
class _UnexpectedFailure(_FailurePresentation):
    """Failure at an unexpected internal boundary without added evidence."""

    @classmethod
    def from_evidence(
        cls,
        stage: str,
        failure_kind: str,
        failure_summary: str,
        operator_guidance: str,
        evidence: _ExecutableEvidence,
    ) -> "_UnexpectedFailure":
        """Build one presentation with the executable projection applied once."""
        return cls(
            stage=stage,
            failure_kind=failure_kind,
            failure_summary=failure_summary,
            operator_guidance=operator_guidance,
            configured_executable_path=evidence.configured_executable_path,
            actual_executable_path=evidence.actual_executable_path,
            executable_is_absolute=evidence.executable_is_absolute,
            executable_exists=evidence.executable_exists,
            executable_is_file=evidence.executable_is_file,
            executable_is_executable=evidence.executable_is_executable,
        )


@dataclass(frozen=True)
class _ArtifactFailure(_FailurePresentation):
    """Artifact lifecycle failure with bounded captured-process evidence."""

    return_code: int | None = None
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None

    @classmethod
    def from_evidence(
        cls,
        stage: str,
        failure_kind: str,
        failure_summary: str,
        operator_guidance: str,
        evidence: _ExecutableEvidence,
        **rest: Unpack[_ArtifactFailureRest],
    ) -> "_ArtifactFailure":
        """Build one presentation with the executable projection applied once."""
        return cls(
            stage=stage,
            failure_kind=failure_kind,
            failure_summary=failure_summary,
            operator_guidance=operator_guidance,
            configured_executable_path=evidence.configured_executable_path,
            actual_executable_path=evidence.actual_executable_path,
            executable_is_absolute=evidence.executable_is_absolute,
            executable_exists=evidence.executable_exists,
            executable_is_file=evidence.executable_is_file,
            executable_is_executable=evidence.executable_is_executable,
            **rest,
        )


@dataclass(frozen=True)
class _InternalFailure(_FailurePresentation):
    """Injector-owned internal failure with bounded structured-output evidence."""

    maximum_accepted_structured_output_bytes: int | None = None
    structured_output_bytes: int | None = None

    @classmethod
    def from_evidence(
        cls,
        stage: str,
        failure_kind: str,
        failure_summary: str,
        operator_guidance: str,
        evidence: _ExecutableEvidence,
        **rest: Unpack[_InternalFailureRest],
    ) -> "_InternalFailure":
        """Build one presentation with the executable projection applied once."""
        return cls(
            stage=stage,
            failure_kind=failure_kind,
            failure_summary=failure_summary,
            operator_guidance=operator_guidance,
            configured_executable_path=evidence.configured_executable_path,
            actual_executable_path=evidence.actual_executable_path,
            executable_is_absolute=evidence.executable_is_absolute,
            executable_exists=evidence.executable_exists,
            executable_is_file=evidence.executable_is_file,
            executable_is_executable=evidence.executable_is_executable,
            **rest,
        )


@dataclass(frozen=True)
class _TerminalCallback:
    """One terminal OpenAEV callback payload with a fixed key set."""

    message: str
    status: str
    duration: int
    output_structured: str | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {"execution_message": self.message}
        if self.output_structured is not None:
            data["execution_output_structured"] = self.output_structured
        data["execution_status"] = self.status
        data["execution_duration"] = self.duration
        data["execution_action"] = "complete"
        return data


def _terminal_callback(
    status: str,
    message: str,
    duration: int,
    output_structured: str | None = None,
) -> dict[str, object]:
    """Build the terminal callback dict shared by every terminal path."""
    return _TerminalCallback(message, status, duration, output_structured).to_dict()


# (metadata key, display label) pairs shared by the failure metadata
# projection and the plain safe-error rendering.
_FAILURE_FIELDS: tuple[tuple[str, str], ...] = (
    ("configured_executable_path", "Configured executable"),
    ("actual_executable_path", "Actual executable"),
    ("executable_is_absolute", "Executable absolute"),
    ("executable_exists", "Executable exists"),
    ("executable_is_file", "Executable regular file"),
    ("executable_is_executable", "Executable executable"),
    ("process_start_cause", "Process start cause"),
    ("timeout_seconds", "Timeout seconds"),
    ("maximum_accepted_output_bytes", "Accepted output byte limit"),
    (
        "maximum_accepted_structured_output_bytes",
        "Accepted structured output byte limit",
    ),
    ("structured_output_bytes", "Structured output bytes"),
    ("parser_name", "Parser"),
    ("stdout_bytes", "Captured stdout bytes"),
    ("stderr_bytes", "Captured stderr bytes"),
    ("return_code", "Return code"),
    ("ocsf_error_code", "OCSF error code"),
    ("record_index", "OCSF record index"),
    ("source_path", "OCSF source path"),
)


# (metadata key, display label, contract attribute) pairs shared by the
# correlation context envelope and the plain safe-error rendering.
_CONTRACT_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("contract_id", "Contract", "contract_id"),
    ("route", "Route", "route_name"),
    ("provider", "Provider", "provider"),
)
