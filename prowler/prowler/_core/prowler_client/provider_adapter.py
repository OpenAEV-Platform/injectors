"""Translate frozen provider inputs into Prowler 5.36 CLI invocations."""

from pydantic import SecretStr
from pyoaev.credential import (
    AwsAccessKeySecret,
    AwsAssumeRoleSecret,
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
                    "--subscription-id",
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
                    "--project-id",
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
        lease = self._credential_leases.materialize(resolved)
        try:
            arguments = _reference_arguments(provider, resolved, lease.credential)
            environment: list[tuple[str, EnvironmentValue]] = [
                (name, SecretStr(value))
                for name, value in sorted(lease.credential.env.items())
            ]
            if (
                isinstance(provider, AwsReferenceProviderInput)
                and provider.aws_endpoint_url is not None
            ):
                environment.append(("AWS_ENDPOINT_URL", provider.aws_endpoint_url))
        except BaseException:
            lease.cleanup()
            raise
        return ProviderInvocation(
            arguments=arguments,
            environment=tuple(environment),
            credential_leases=(lease,),
        )


def _reference_arguments(
    provider: CredentialReferenceProviderInput,
    resolved: ResolvedSecret,
    credential: MaterializedCredential,
) -> tuple[str, ...]:
    """Pick the Prowler provider flags from the resolved secret type.

    Region, subscription, and project come from the secret when it carries
    them; the form values are only used when the secret omits them.
    """
    if isinstance(provider, AwsReferenceProviderInput) and isinstance(
        resolved, AwsAccessKeySecret | AwsAssumeRoleSecret
    ):
        # The assume-role profile is selected through AWS_PROFILE.
        region = resolved.aws_default_region or provider.aws_region
        return ("aws", "--region", region)
    if isinstance(provider, AzureReferenceProviderInput) and isinstance(
        resolved, AzureServicePrincipalSecret | AzureManagedIdentitySecret
    ):
        authentication = (
            "--sp-env-auth"
            if isinstance(resolved, AzureServicePrincipalSecret)
            else "--managed-identity-auth"
        )
        subscription = resolved.azure_subscription_id or provider.azure_subscription_id
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
        project = resolved.gcp_project_id or provider.gcp_project_id
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
