"""Composition root and quick-access API for synchronous Prowler clients."""

from collections.abc import Sequence
from dataclasses import dataclass

from prowler._core.cli_engine import CliEngineFactory, CommandResult
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import ProviderInput

from .client import ProwlerClient
from .contracts import CliEngineFactoryPort, CredentialLeaseFactoryPort
from .credentials import TemporaryCredentialLeaseFactory
from .provider_adapter import ProviderInvocationAdapter


@dataclass(frozen=True)
class ProwlerClientFactory:
    """Create clients from safe defaults or explicitly injected test ports."""

    engine_factory: CliEngineFactoryPort = CliEngineFactory()
    credential_lease_factory: CredentialLeaseFactoryPort = (
        TemporaryCredentialLeaseFactory()
    )

    def create(self, config: ProwlerConfig, provider: ProviderInput) -> ProwlerClient:
        """Create a client without executing Prowler."""
        return ProwlerClient(
            config=config,
            provider=provider,
            engine=self.engine_factory.create(),
            provider_adapter=ProviderInvocationAdapter(
                self.credential_lease_factory,
                aws_endpoint_url=config.aws_endpoint_url,
            ),
        )

    def run(
        self,
        config: ProwlerConfig,
        provider: ProviderInput,
        *,
        check_filters: Sequence[str] = (),
    ) -> CommandResult:
        """Create a client and synchronously run one assessment."""
        return self.create(config, provider).run(check_filters)
