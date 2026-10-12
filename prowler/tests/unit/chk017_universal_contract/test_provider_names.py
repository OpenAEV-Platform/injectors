"""Credential provider names stay separate from the universal route identity."""

from typing import get_args

from prowler.contracts import ProviderName, RouteProviderName
from prowler.contracts.provider_fields import build_provider_fields


def test_every_credential_provider_name_builds_its_fields() -> None:
    """Accept only names that have credential fields."""
    for provider in get_args(ProviderName):
        assert build_provider_fields(provider)


def test_route_provider_names_add_only_the_universal_meta_provider() -> None:
    """Keep the universal 'all' meta-provider out of credential provider names."""
    assert "all" not in get_args(ProviderName)
    assert set(get_args(RouteProviderName)) == {*get_args(ProviderName), "all"}
