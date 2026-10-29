"""Shared test isolation for the Prowler injector suite."""

from collections.abc import Iterator

import pytest

from prowler._core.prowler_client import client
from prowler.contracts import DEFAULT_PROWLER_CONTRACTS


@pytest.fixture(autouse=True)
def _no_host_system_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the Windows host variables out of the exact environment assertions.

    The client adds ``SYSTEMROOT`` on Windows only, so that Prowler can start;
    the tests assert the exact environment handed over, on every platform.
    """
    monkeypatch.setattr(client, "_WINDOWS_SYSTEM_VARIABLES", ())
    monkeypatch.setattr(client, "_WINDOWS_FIXED_VARIABLES", ())


@pytest.fixture(autouse=True)
def _restore_default_contract_client_factories() -> Iterator[None]:
    """Undo per-test client factory replacements on the shared contract registry.

    Tests install fake client factories on contracts resolved from the
    process-wide DEFAULT_PROWLER_CONTRACTS registry; restoring them after each
    test keeps later tests independent of execution order.
    """
    contracts = list(DEFAULT_PROWLER_CONTRACTS._by_id.values())
    factories = [contract._client_factory for contract in contracts]
    yield
    for contract, factory in zip(contracts, factories):
        contract._client_factory = factory
