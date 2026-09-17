"""Synchronous Prowler client over the safe CLI engine."""

import logging
from collections.abc import Sequence
from dataclasses import replace
from threading import Lock
from time import monotonic

from prowler._core.cli_engine import (
    CommandResult,
    OutputSpecification,
    ValidatedCommandRequest,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import (
    AwsProviderInput,
    AzureProviderInput,
    GcpProviderInput,
    ImmutableProviderInput,
    KubernetesProviderInput,
    ProviderInput,
)

from .contracts import ComplianceSelector, ServiceSelector
from .credentials import CredentialCleanupError
from .output_workspace import (
    DEFAULT_MAXIMUM_ARTIFACT_BYTES,
    OUTPUT_ARTIFACT_BASENAME,
    OutputArtifactError,
    OutputWorkspaceCleanupError,
    OutputWorkspacePreparationError,
)
from .ports import CliEnginePort, OutputWorkspaceFactoryPort
from .provider_adapter import ProviderInvocationAdapter

# A full multi-provider assessment may legitimately run for a substantial period.
DEFAULT_TIMEOUT_SECONDS = 3_600.0
# Canonical console-output bound; OCSF records have a separate artifact bound.
DEFAULT_MAXIMUM_ACCEPTED_CONSOLE_BYTES = 4 * 1024 * 1024
# Deprecated compatibility alias retained for callers using the former name.
DEFAULT_MAXIMUM_ACCEPTED_OUTPUT_BYTES = DEFAULT_MAXIMUM_ACCEPTED_CONSOLE_BYTES

_ALL_SEVERITIES = (
    "--severity",
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)
_OUTPUT_ARGUMENTS_PREFIX = (
    "--output-filename",
    OUTPUT_ARTIFACT_BASENAME,
    "-z",
    "--only-logs",
    "--no-color",
)
_OUTPUT_FORMAT_ARGUMENTS = ("-M", "json-ocsf")
_NARROWING_OPTIONS = frozenset(
    {
        "-c",
        "--check",
        "--checks",
        "-s",
        "--service",
        "--services",
        "--compliance",
    }
)
_LOGGER = logging.getLogger(__name__)


def _safe_log(level: int, message: str, **metadata: object) -> None:
    """Best-effort fixed logging whose failures cannot affect execution."""
    try:
        _LOGGER.log(level, message, extra={"prowler_metadata": metadata})
    except BaseException:
        return


_COMPLIANCE_PROVIDER_TYPES: dict[ComplianceSelector, type[ImmutableProviderInput]] = {
    "cis_3.0_aws": AwsProviderInput,
    "cis_3.0_azure": AzureProviderInput,
    "cis_3.0_gcp": GcpProviderInput,
    "cis_1.12_kubernetes": KubernetesProviderInput,
    "nis2_aws": AwsProviderInput,
    "nis2_azure": AzureProviderInput,
    "nis2_gcp": GcpProviderInput,
    "iso27001_2022_aws": AwsProviderInput,
    "iso27001_2022_azure": AzureProviderInput,
    "iso27001_2022_gcp": GcpProviderInput,
    "iso27001_2022_kubernetes": KubernetesProviderInput,
}


def _validate_compliance_provider(
    provider: ProviderInput, compliance_selector: ComplianceSelector
) -> None:
    """Reject unknown or cross-provider compliance selection before adaptation."""
    provider_type = _COMPLIANCE_PROVIDER_TYPES.get(compliance_selector)
    if provider_type is None:
        raise ValueError("unsupported compliance selector")
    if not isinstance(provider, provider_type):
        raise ValueError("compliance selector requires its matching provider")


class ProwlerClientConsumedError(RuntimeError):
    """Reject reuse of a client whose provider input was already consumed."""


class ProwlerClient:
    """Run one frozen provider input synchronously through Prowler."""

    def __init__(
        self,
        *,
        config: ProwlerConfig,
        provider: ProviderInput,
        engine: CliEnginePort,
        provider_adapter: ProviderInvocationAdapter,
        output_workspace_factory: OutputWorkspaceFactoryPort,
    ) -> None:
        self._config = config.model_copy(deep=True)
        self._provider: ProviderInput | None = provider.model_copy(deep=True)
        self._engine = engine
        self._provider_adapter = provider_adapter
        self._output_workspace_factory = output_workspace_factory
        self._consumption_lock = Lock()

    def run(
        self,
        check_filters: Sequence[str] = (),
        *,
        service_selector: ServiceSelector | None = None,
        compliance_selector: ComplianceSelector | None = None,
    ) -> CommandResult:
        """Run one assessment and capture its controlled OCSF artifact."""
        with self._consumption_lock:
            provider = self._provider
            if provider is None:
                raise ProwlerClientConsumedError(
                    "this Prowler client has already been consumed"
                )
            self._provider = None

        invocation = None
        workspace = None
        result: CommandResult | None = None
        primary_error: BaseException | None = None
        try:
            filters = tuple(check_filters)
            if any(not isinstance(item, str) or not item.strip() for item in filters):
                raise ValueError("check filters must be nonblank strings")
            if service_selector not in (
                None,
                "iam",
                "s3",
                "ec2",
                "storage",
                "compute",
            ):
                raise ValueError("unsupported service selector")
            if service_selector in ("s3", "ec2") and not isinstance(
                provider, AwsProviderInput
            ):
                raise ValueError("AWS service selector requires an AWS provider")
            if service_selector == "storage" and not isinstance(
                provider, AzureProviderInput
            ):
                raise ValueError("Azure service selector requires an Azure provider")
            if service_selector == "compute" and not isinstance(
                provider, GcpProviderInput
            ):
                raise ValueError("GCP service selector requires a GCP provider")
            if service_selector == "iam" and not isinstance(
                provider, AwsProviderInput | AzureProviderInput | GcpProviderInput
            ):
                raise ValueError(
                    "IAM service selector requires an AWS, Azure, or GCP provider"
                )
            if compliance_selector is not None:
                _validate_compliance_provider(provider, compliance_selector)
                if filters or service_selector is not None:
                    raise ValueError(
                        "compliance selector cannot be combined with check or "
                        "service selectors"
                    )

            _safe_log(logging.INFO, "Preparing Prowler output workspace")
            try:
                workspace = self._output_workspace_factory.create()
            except OutputWorkspacePreparationError:
                _safe_log(
                    logging.ERROR,
                    "Prowler output workspace preparation failed",
                    kind="preparation",
                )
                raise
            _safe_log(
                logging.DEBUG,
                "Prowler output workspace metadata",
                backend=workspace.backend,
                provider=provider.provider,
                check_selector=bool(filters),
            )

            invocation = self._provider_adapter.adapt(provider)
            filter_arguments = ("-c", *filters) if filters else ()
            service_arguments = (
                ("--services", service_selector) if service_selector is not None else ()
            )
            compliance_arguments = (
                ("--compliance", compliance_selector)
                if compliance_selector is not None
                else ()
            )
            provider_and_selectors = (
                *invocation.arguments,
                *filter_arguments,
                *service_arguments,
                *compliance_arguments,
            )
            narrowed = any(
                argument in _NARROWING_OPTIONS for argument in provider_and_selectors
            )
            _safe_log(
                logging.DEBUG,
                "Prowler selector metadata",
                selector_present=narrowed,
            )
            severity_arguments = () if narrowed else _ALL_SEVERITIES
            request = ValidatedCommandRequest(
                executable=str(self._config.executable_path),
                arguments=(
                    *provider_and_selectors,
                    *severity_arguments,
                    "--output-directory",
                    str(workspace.directory),
                    *_OUTPUT_ARGUMENTS_PREFIX,
                    *_OUTPUT_FORMAT_ARGUMENTS,
                ),
                environment=invocation.environment,
                working_directory=None,
                input_bytes=b"",
                output=OutputSpecification(parser="raw"),
                timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
                maximum_accepted_output_bytes=DEFAULT_MAXIMUM_ACCEPTED_CONSOLE_BYTES,
            )
            started = monotonic()
            try:
                result = self._engine.run(request)
            finally:
                duration_ms = max(0, int((monotonic() - started) * 1000))
                _safe_log(logging.INFO, "Prowler process completed")
                _safe_log(
                    logging.DEBUG,
                    "Prowler process metadata",
                    duration_ms=duration_ms,
                    return_code=(result.return_code if result is not None else None),
                    stdout_bytes=(len(result.stdout) if result is not None else 0),
                    stderr_bytes=(len(result.stderr) if result is not None else 0),
                )
                del request

            if result.error is not None or result.return_code != 0:
                return result

            try:
                artifact = workspace.read_artifact(
                    maximum_bytes=DEFAULT_MAXIMUM_ARTIFACT_BYTES
                )
            except OutputArtifactError as error:
                error.command_result = result
                _safe_log(
                    logging.ERROR,
                    "Prowler output artifact capture failed",
                    kind=error.kind,
                )
                raise
            _safe_log(logging.INFO, "Prowler output artifact captured")
            _safe_log(
                logging.DEBUG,
                "Prowler output artifact metadata",
                artifact_bytes=len(artifact),
            )
            return replace(result, parsed=artifact)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_failures: list[tuple[str, RuntimeError]] = []
            if invocation is not None:
                for lease in invocation.credential_leases:
                    try:
                        lease.cleanup()
                    except BaseException:
                        cleanup_failures.append(
                            ("credential", CredentialCleanupError())
                        )
            if workspace is not None:
                try:
                    workspace.cleanup()
                except BaseException:
                    cleanup_failures.append(
                        (
                            "output_workspace",
                            OutputWorkspaceCleanupError(command_result=result),
                        )
                    )
                else:
                    _safe_log(logging.INFO, "Prowler output workspace cleaned")

            if cleanup_failures:
                result_is_primary_failure = result is not None and (
                    result.error is not None or result.return_code != 0
                )
                for resource, _cleanup_error in cleanup_failures:
                    _safe_log(
                        logging.WARNING,
                        "Secondary Prowler output cleanup failure",
                        resource=resource,
                    )
                if primary_error is not None:
                    for resource, _cleanup_error in cleanup_failures:
                        note = (
                            "temporary credential cleanup also failed"
                            if resource == "credential"
                            else "temporary output workspace cleanup also failed"
                        )
                        primary_error.add_note(note)
                elif not result_is_primary_failure:
                    raise cleanup_failures[0][1] from None

            del provider
            if invocation is not None:
                del invocation
