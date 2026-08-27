"""Synchronous Prowler client over the safe CLI engine."""

from collections.abc import Sequence
from threading import Lock

from prowler._core.cli_engine import (
    CommandResult,
    OutputSpecification,
    ValidatedCommandRequest,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import ProviderInput

from .contracts import CliEnginePort
from .credentials import CredentialCleanupError
from .provider_adapter import ProviderInvocationAdapter

# A full multi-provider assessment may legitimately run for a substantial period.
DEFAULT_TIMEOUT_SECONDS = 3_600.0
# Bound captured stdout/stderr while allowing a substantial raw OCSF result.
DEFAULT_MAXIMUM_ACCEPTED_OUTPUT_BYTES = 100 * 1024 * 1024


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
    ) -> None:
        self._config = config.model_copy(deep=True)
        self._provider: ProviderInput | None = provider.model_copy(deep=True)
        self._engine = engine
        self._provider_adapter = provider_adapter
        self._consumption_lock = Lock()

    def run(self, check_filters: Sequence[str] = ()) -> CommandResult:
        """Run one assessment and return the exact CLI result unchanged."""
        with self._consumption_lock:
            provider = self._provider
            if provider is None:
                raise ProwlerClientConsumedError(
                    "this Prowler client has already been consumed"
                )
            self._provider = None

        invocation = None
        try:
            filters = tuple(check_filters)
            if any(not isinstance(item, str) or not item.strip() for item in filters):
                raise ValueError("check filters must be nonblank strings")

            invocation = self._provider_adapter.adapt(provider)
            primary_error: BaseException | None = None
            try:
                filter_arguments = ("-c", *filters) if filters else ()
                request = ValidatedCommandRequest(
                    executable=str(self._config.executable_path),
                    arguments=(*invocation.arguments, *filter_arguments),
                    environment=invocation.environment,
                    working_directory=None,
                    input_bytes=b"",
                    output=OutputSpecification(parser="raw"),
                    timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
                    maximum_accepted_output_bytes=DEFAULT_MAXIMUM_ACCEPTED_OUTPUT_BYTES,
                )
                try:
                    return self._engine.run(request)
                finally:
                    del request
            except BaseException as error:
                primary_error = error
                raise
            finally:
                cleanup_failed = False
                for lease in invocation.credential_leases:
                    try:
                        lease.cleanup()
                    except BaseException:
                        cleanup_failed = True
                if cleanup_failed:
                    if primary_error is None:
                        raise CredentialCleanupError() from None
                    primary_error.add_note("temporary credential cleanup also failed")
        finally:
            del provider
            if invocation is not None:
                del invocation
