"""Platform definitions for the Stratus Red Team injector.

Each :class:`PlatformSpec` is the single source of truth for one Stratus
platform: its label and its credential fields. A credential field carries
everything needed both to render a contract input and to wire the value into
the Stratus process environment (direct environment variables or a temp file
materialized only for the detonation), so the contract UI and the runtime env
can never drift apart.

Technique -> platform is keyed on ``PlatformSpec.key``, which matches the
Stratus platform prefix of a technique id (``aws``, ``azure``, ``entra-id``,
``gcp``, ``k8s``, ``eks``).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Stable identifiers for the per-platform "custom technique" contracts. Keep
# these constant across releases so a stored inject stays matched to its
# contract. The per-technique contracts derive their ids deterministically from
# the technique id (see ``technique_contract_id`` in the contracts package).
AWS_CUSTOM_CONTRACT = "5ca462c2-9f39-47e2-9a23-94f39dd725e4"
AZURE_CUSTOM_CONTRACT = "ff8faa94-d46f-4a81-be17-c39d9a0a7902"
ENTRA_CUSTOM_CONTRACT = "f147f501-7763-4a0f-8df2-a57fe61afa74"
GCP_CUSTOM_CONTRACT = "14d97434-2986-4432-af05-f7b8dcb7470b"
K8S_CUSTOM_CONTRACT = "6a1b57df-491f-4729-bcf3-e476b58f9381"
EKS_CUSTOM_CONTRACT = "cf21d35a-d2ea-4a96-8660-ebedc56cd625"


@dataclass(frozen=True)
class CredField:
    """A credential contract input and how it maps to the Stratus environment."""

    key: str
    label: str
    mandatory: bool = True
    # Render the input as a multi-line text area (secrets like a kubeconfig or a
    # service account key JSON) instead of a single-line text field.
    textarea: bool = False
    # Environment variables set directly from the (stripped) value.
    env_vars: Tuple[str, ...] = ()
    # When set, the value is written to a temp file for the detonation only and
    # this environment variable points at that file path.
    as_file_env: Optional[str] = None
    file_suffix: str = ""
    # Optional restrictive file mode for materialized secrets (e.g. 0o600).
    file_mode: Optional[int] = None
    # Default applied when the field is optional and left empty.
    default: Optional[str] = None


@dataclass(frozen=True)
class PlatformSpec:
    key: str
    custom_contract_id: str
    label: str
    cred_fields: List[CredField] = field(default_factory=list)


_AWS_CRED_FIELDS = [
    CredField(
        key="aws_access_key_id",
        label="AWS Access Key ID",
        env_vars=("AWS_ACCESS_KEY_ID",),
    ),
    CredField(
        key="aws_secret_access_key",
        label="AWS Secret Access Key",
        env_vars=("AWS_SECRET_ACCESS_KEY",),
    ),
    CredField(
        key="aws_session_token",
        label="AWS Session Token (optional)",
        mandatory=False,
        env_vars=("AWS_SESSION_TOKEN",),
    ),
    CredField(
        key="aws_region",
        label="AWS Region",
        mandatory=False,
        env_vars=("AWS_REGION", "AWS_DEFAULT_REGION"),
        default="us-east-1",
    ),
]

_AZURE_CRED_FIELDS = [
    CredField(
        key="azure_tenant_id", label="Azure Tenant ID", env_vars=("AZURE_TENANT_ID",)
    ),
    CredField(
        key="azure_subscription_id",
        label="Azure Subscription ID",
        env_vars=("AZURE_SUBSCRIPTION_ID",),
    ),
    CredField(
        key="azure_client_id",
        label="Service Principal Client ID",
        env_vars=("AZURE_CLIENT_ID",),
    ),
    CredField(
        key="azure_client_secret",
        label="Service Principal Client Secret",
        env_vars=("AZURE_CLIENT_SECRET",),
    ),
]

_ENTRA_CRED_FIELDS = [
    CredField(
        key="azure_tenant_id", label="Entra ID Tenant ID", env_vars=("AZURE_TENANT_ID",)
    ),
    CredField(
        key="azure_client_id",
        label="Application (Client) ID",
        env_vars=("AZURE_CLIENT_ID",),
    ),
    CredField(
        key="azure_client_secret",
        label="Application Client Secret",
        env_vars=("AZURE_CLIENT_SECRET",),
    ),
    CredField(
        key="azure_subscription_id",
        label="Azure Subscription ID (optional)",
        mandatory=False,
        env_vars=("AZURE_SUBSCRIPTION_ID",),
    ),
]

_GCP_CRED_FIELDS = [
    CredField(
        key="gcp_project_id",
        label="GCP Project ID",
        env_vars=("GOOGLE_PROJECT", "CLOUDSDK_CORE_PROJECT"),
    ),
    CredField(
        key="gcp_service_account_key",
        label="Service Account key (JSON)",
        textarea=True,
        as_file_env="GOOGLE_APPLICATION_CREDENTIALS",
        file_suffix=".json",
        file_mode=0o600,
    ),
]

_K8S_CRED_FIELDS = [
    CredField(
        key="kubeconfig",
        label="Kubeconfig (YAML)",
        textarea=True,
        as_file_env="KUBECONFIG",
        file_suffix=".yaml",
        file_mode=0o600,
    ),
]


PLATFORMS: List[PlatformSpec] = [
    PlatformSpec("aws", AWS_CUSTOM_CONTRACT, "AWS", _AWS_CRED_FIELDS),
    PlatformSpec("azure", AZURE_CUSTOM_CONTRACT, "Azure", _AZURE_CRED_FIELDS),
    PlatformSpec("entra-id", ENTRA_CUSTOM_CONTRACT, "Entra ID", _ENTRA_CRED_FIELDS),
    PlatformSpec("gcp", GCP_CUSTOM_CONTRACT, "Google Cloud Platform", _GCP_CRED_FIELDS),
    PlatformSpec("k8s", K8S_CUSTOM_CONTRACT, "Kubernetes", _K8S_CRED_FIELDS),
    # EKS techniques authenticate to AWS and then to the cluster; they use the
    # same AWS credentials as the AWS platform.
    PlatformSpec("eks", EKS_CUSTOM_CONTRACT, "Amazon EKS", _AWS_CRED_FIELDS),
]

PLATFORMS_BY_KEY: Dict[str, PlatformSpec] = {p.key: p for p in PLATFORMS}
