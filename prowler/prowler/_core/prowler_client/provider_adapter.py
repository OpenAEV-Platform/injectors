"""Translate frozen provider inputs into Prowler 5.36 CLI invocations."""

import os

from pydantic import SecretStr
from pyoaev.credential import (
    AwsAccessKeySecret,
    AwsAssumeRoleSecret,
    AwsSourceIdentityType,
    AzureManagedIdentitySecret,
    AzureServicePrincipalSecret,
    CredentialErrorCode,
    CredentialResolutionError,
    GcpOAuth2Secret,
    GcpServiceAccountSecret,
    MaterializedCredential,
    ResolvedSecret,
)

from prowler._core.cli_engine.contracts import EnvironmentValue
from prowler.models.provider_inputs import (
    AwsProviderInput,
    AwsReferenceProviderInput,
    AzureProviderInput,
    AzureReferenceProviderInput,
    CredentialReferenceProviderInput,
    GcpProviderInput,
    GcpReferenceProviderInput,
    KubernetesProviderInput,
    ProviderInput,
)

from .contracts import ProviderInvocation
from .ports import CredentialLeaseFactoryPort

# Prowler runs with an exact environment. An identity inherited from the injector
# host (no secret in the credential) only works if the variables that describe it
# are handed over, so each such credential lists the host variables it relies on.

# Ambient AWS identity of the injector host, used as the assume-role source, and
# the settings of the EC2 instance metadata service the profile falls back on.
_AWS_INSTANCE_IDENTITY_VARIABLES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_EC2_METADATA_V1_DISABLED",
    "AWS_METADATA_SERVICE_TIMEOUT",
    "AWS_METADATA_SERVICE_NUM_ATTEMPTS",
)

# Endpoints and secrets the Azure platform defines for a managed identity: App
# Service, Container Apps and Functions (IDENTITY_*), Service Fabric, Arc
# (IMDS_ENDPOINT), Azure ML and Cloud Shell (MSI_*), pod identity, and workload
# identity. AZURE_CLIENT_ID is left out on purpose: it would turn the
# system-assigned identity of the credential into a user-assigned one.
_AZURE_MANAGED_IDENTITY_VARIABLES = (
    "IDENTITY_ENDPOINT",
    "IDENTITY_HEADER",
    "IDENTITY_SERVER_THUMBPRINT",
    "IMDS_ENDPOINT",
    "MSI_ENDPOINT",
    "MSI_SECRET",
    "AZURE_POD_IDENTITY_AUTHORITY_HOST",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_TENANT_ID",
)

# Prowler has no setting for the Azure Resource Manager host of a custom cloud.
# A credential with its own authority host (a mocked cloud) serves the Resource
# Manager API from that same host, so it is handed over under this variable.
_AZURE_ARM_ENDPOINT_VARIABLE = "AZURE_ARM_ENDPOINT"


class ProviderInvocationAdapter:
    """Build credential-safe provider arguments and exact environments."""

    def __init__(self, credential_leases: CredentialLeaseFactoryPort) -> None:
        self._credential_leases = credential_leases

    def adapt(self, provider: ProviderInput) -> ProviderInvocation:
        """Return the invocation for one validated provider input."""
        if isinstance(provider, CredentialReferenceProviderInput):
            return self._adapt_reference(provider)
        if isinstance(provider, AwsProviderInput):
            environment: list[tuple[str, EnvironmentValue]] = [
                ("AWS_ACCESS_KEY_ID", SecretStr(provider.aws_access_key_id)),
                ("AWS_SECRET_ACCESS_KEY", provider.aws_secret_access_key),
            ]
            if provider.aws_session_token is not None:
                environment.append(("AWS_SESSION_TOKEN", provider.aws_session_token))
            if provider.aws_endpoint_url is not None:
                environment.append(("AWS_ENDPOINT_URL", provider.aws_endpoint_url))
            return ProviderInvocation(
                arguments=(
                    "aws",
                    "--region",
                    provider.aws_region,
                ),
                environment=tuple(environment),
            )
        if isinstance(provider, AzureProviderInput):
            return ProviderInvocation(
                arguments=(
                    "azure",
                    "--sp-env-auth",
                    "--subscription-ids",
                    provider.azure_subscription_id,
                    "--azure-region",
                    provider.azure_provider,
                ),
                environment=(
                    ("AZURE_TENANT_ID", SecretStr(provider.azure_tenant_id)),
                    ("AZURE_CLIENT_ID", SecretStr(provider.azure_client_id)),
                    ("AZURE_CLIENT_SECRET", provider.azure_client_secret),
                ),
            )
        if isinstance(provider, GcpProviderInput):
            lease = self._credential_leases.create(
                provider.gcp_service_account_json, suffix=".json"
            )
            return ProviderInvocation(
                arguments=(
                    "gcp",
                    "--credentials-file",
                    str(lease.path),
                    "--project-ids",
                    provider.gcp_project_id,
                ),
                environment=(),
                credential_leases=(lease,),
            )
        if isinstance(provider, KubernetesProviderInput):
            lease = self._credential_leases.create(
                provider.kubernetes_kubeconfig, suffix=".yaml"
            )
            return ProviderInvocation(
                arguments=(
                    "kubernetes",
                    "--kubeconfig-file",
                    str(lease.path),
                    "--context",
                    provider.kubernetes_context,
                ),
                environment=(),
                credential_leases=(lease,),
            )
        raise TypeError("provider must be a supported provider input")

    def _adapt_reference(
        self, provider: CredentialReferenceProviderInput
    ) -> ProviderInvocation:
        """Materialize the resolved secret into the exact Prowler environment.

        The legacy credential fields do not exist on a reference input, and
        Prowler runs with an exact environment, so the resolved credential can
        never be combined with another one. Every materialized value is wrapped
        as a secret; the lease removes the materialized files on cleanup.
        """
        resolved = provider.resolved_secret
        if resolved is None:
            raise ValueError("a credential reference must be resolved before use")
        lease = self._credential_leases.materialize(
            resolved, reference=provider.credential_attachment.reference
        )
        try:
            arguments = _reference_arguments(provider, resolved, lease.credential)
            environment: list[tuple[str, EnvironmentValue]] = [
                (name, SecretStr(value))
                for name, value in sorted(lease.credential.env.items())
            ]
            if (
                isinstance(provider, AwsReferenceProviderInput)
                and provider.aws_endpoint_url is not None
                # The endpoint of the credential wins over the form one.
                and "AWS_ENDPOINT_URL" not in lease.credential.env
            ):
                environment.append(("AWS_ENDPOINT_URL", provider.aws_endpoint_url))
            if (
                isinstance(
                    resolved, AzureServicePrincipalSecret | AzureManagedIdentitySecret
                )
                and resolved.azure_authority_host_uri
            ):
                environment.append(
                    (
                        _AZURE_ARM_ENDPOINT_VARIABLE,
                        SecretStr(resolved.azure_authority_host_uri.rstrip("/")),
                    )
                )
            environment.extend(
                _host_environment(_ambient_identity_variables(resolved), environment)
            )
        except BaseException:
            lease.cleanup()
            raise
        return ProviderInvocation(
            arguments=arguments,
            environment=tuple(environment),
            credential_leases=(lease,),
        )


def _ambient_identity_variables(resolved: ResolvedSecret) -> tuple[str, ...]:
    """Name the host variables of a credential whose identity is the host's."""
    if (
        isinstance(resolved, AwsAssumeRoleSecret)
        and resolved.aws_source_identity_type == AwsSourceIdentityType.INSTANCE_DEFAULT
    ):
        return _AWS_INSTANCE_IDENTITY_VARIABLES
    if isinstance(resolved, AzureManagedIdentitySecret):
        return _AZURE_MANAGED_IDENTITY_VARIABLES
    return ()


def _host_environment(
    names: tuple[str, ...], environment: list[tuple[str, EnvironmentValue]]
) -> list[tuple[str, EnvironmentValue]]:
    """Return the listed host variables that are set and not already provided.

    A value the credential materialized itself always wins over the host one.
    Every value is wrapped as a secret, like the materialized ones.
    """
    provided = {name for name, _ in environment}
    return [
        (name, SecretStr(os.environ[name]))
        for name in names
        if name in os.environ and name not in provided
    ]


def _required(value: object) -> str:
    """Return a scope value checked by ``missing_scope_fields`` beforehand."""
    if not isinstance(value, str) or not value:
        raise ValueError("a referenced credential scope value must be checked first")
    return value


def _reference_arguments(
    provider: CredentialReferenceProviderInput,
    resolved: ResolvedSecret,
    credential: MaterializedCredential,
) -> tuple[str, ...]:
    """Pick the Prowler provider flags from the resolved secret type.

    Region, subscription, and project come from the secret only, checked
    beforehand by ``missing_scope_fields``.
    """
    if isinstance(provider, AwsReferenceProviderInput) and isinstance(
        resolved, AwsAccessKeySecret | AwsAssumeRoleSecret
    ):
        # The assume-role profile is selected through AWS_PROFILE.
        region = _required(provider.scope_value("aws_default_region"))
        return ("aws", "--region", region)
    if isinstance(provider, AzureReferenceProviderInput) and isinstance(
        resolved, AzureServicePrincipalSecret | AzureManagedIdentitySecret
    ):
        authentication = (
            "--sp-env-auth"
            if isinstance(resolved, AzureServicePrincipalSecret)
            else "--managed-identity-auth"
        )
        subscription = _required(provider.scope_value("azure_subscription_id"))
        return (
            "azure",
            authentication,
            "--subscription-id",
            subscription,
            "--azure-region",
            resolved.azure_environment,
        )
    if isinstance(provider, GcpReferenceProviderInput) and isinstance(
        resolved, GcpServiceAccountSecret | GcpOAuth2Secret
    ):
        project = _required(provider.scope_value("gcp_project_id"))
        return (
            "gcp",
            "--credentials-file",
            credential.env["GOOGLE_APPLICATION_CREDENTIALS"],
            "--project-id",
            project,
        )
    raise CredentialResolutionError(
        CredentialErrorCode.CREDENTIAL_INCOMPATIBLE,
        provider.credential_attachment.reference,
    )
