"""Canonical synchronous Prowler client API."""

from .client import (
    DEFAULT_MAXIMUM_ACCEPTED_CONSOLE_BYTES,
    DEFAULT_MAXIMUM_ACCEPTED_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    ProwlerClient,
    ProwlerClientConsumedError,
)
from .contracts import (
    AwsServiceSelector,
    AzureServiceSelector,
    ComplianceSelector,
    GcpServiceSelector,
    ServiceSelector,
)
from .credentials import (
    CredentialCleanupError,
    TemporaryCredentialLease,
    TemporaryCredentialLeaseFactory,
)
from .factory import ProwlerClientFactory
from .output_workspace import (
    DEFAULT_MAXIMUM_ARTIFACT_BYTES,
    DEFAULT_MEMORY_TMPFS_SAFETY_MARGIN_BYTES,
    OUTPUT_ARTIFACT_BASENAME,
    OUTPUT_ARTIFACT_FILENAME,
    OutputArtifactError,
    OutputWorkspaceCleanupError,
    OutputWorkspacePreparationError,
    TemporaryOutputWorkspace,
    TemporaryOutputWorkspaceFactory,
)

__all__ = [
    "DEFAULT_MAXIMUM_ACCEPTED_CONSOLE_BYTES",
    "DEFAULT_MAXIMUM_ACCEPTED_OUTPUT_BYTES",
    "DEFAULT_MAXIMUM_ARTIFACT_BYTES",
    "DEFAULT_MEMORY_TMPFS_SAFETY_MARGIN_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "CredentialCleanupError",
    "OUTPUT_ARTIFACT_BASENAME",
    "OUTPUT_ARTIFACT_FILENAME",
    "OutputArtifactError",
    "OutputWorkspaceCleanupError",
    "OutputWorkspacePreparationError",
    "ComplianceSelector",
    "AwsServiceSelector",
    "AzureServiceSelector",
    "GcpServiceSelector",
    "ProwlerClient",
    "ProwlerClientConsumedError",
    "ProwlerClientFactory",
    "ServiceSelector",
    "TemporaryCredentialLease",
    "TemporaryCredentialLeaseFactory",
    "TemporaryOutputWorkspace",
    "TemporaryOutputWorkspaceFactory",
]
