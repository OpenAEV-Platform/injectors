"""Translate frozen provider inputs into Prowler 5.36 CLI invocations."""

from pydantic import SecretStr

from prowler.models.provider_inputs import (
    AwsProviderInput,
    AzureProviderInput,
    GcpProviderInput,
    KubernetesProviderInput,
    ProviderInput,
)

from .contracts import CredentialFileFactoryPort, ProviderInvocation

_OCSF_OUTPUT_ARGUMENTS = ("-M", "json-ocsf")


class ProviderInvocationAdapter:
    """Build credential-safe provider arguments and exact environments."""

    def __init__(self, credential_files: CredentialFileFactoryPort) -> None:
        self._credential_files = credential_files

    def adapt(self, provider: ProviderInput) -> ProviderInvocation:
        """Return the invocation for one validated provider input."""
        if isinstance(provider, AwsProviderInput):
            environment = [
                ("AWS_ACCESS_KEY_ID", SecretStr(provider.aws_access_key_id)),
                ("AWS_SECRET_ACCESS_KEY", provider.aws_secret_access_key),
            ]
            if provider.aws_session_token is not None:
                environment.append(("AWS_SESSION_TOKEN", provider.aws_session_token))
            return ProviderInvocation(
                arguments=(
                    "aws",
                    "--region",
                    provider.aws_region,
                    *_OCSF_OUTPUT_ARGUMENTS,
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
                    *_OCSF_OUTPUT_ARGUMENTS,
                ),
                environment=(
                    ("AZURE_TENANT_ID", SecretStr(provider.azure_tenant_id)),
                    ("AZURE_CLIENT_ID", SecretStr(provider.azure_client_id)),
                    ("AZURE_CLIENT_SECRET", provider.azure_client_secret),
                ),
            )
        if isinstance(provider, GcpProviderInput):
            path = self._credential_files.create(provider.gcp_service_account_json)
            return ProviderInvocation(
                arguments=(
                    "gcp",
                    "--credentials-file",
                    str(path),
                    "--project-id",
                    provider.gcp_project_id,
                    *_OCSF_OUTPUT_ARGUMENTS,
                ),
                environment=(),
                temporary_files=(path,),
            )
        if isinstance(provider, KubernetesProviderInput):
            path = self._credential_files.create(provider.kubernetes_kubeconfig)
            return ProviderInvocation(
                arguments=(
                    "kubernetes",
                    "--kubeconfig-file",
                    str(path),
                    "--kube-context",
                    provider.kubernetes_context,
                    *_OCSF_OUTPUT_ARGUMENTS,
                ),
                environment=(),
                temporary_files=(path,),
            )
        raise TypeError("provider must be a supported provider input")
