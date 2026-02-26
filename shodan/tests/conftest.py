"""Conftest file for Pytest fixtures."""

from unittest.mock import Mock, patch

from pytest import fixture

from shodan.injector.openaev_shodan import ShodanInjector
from shodan.services.client_api import ShodanClientAPI


@fixture(autouse=True)
def disable_config_yml():
    """Force environment variable configuration only, override yaml/dotenv loading."""

    def fake_settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        from pydantic_settings import EnvSettingsSource

        return (
            EnvSettingsSource(
                settings_cls,
                env_ignore_empty=True,
            ),
        )

    patcher = patch(
        "shodan.models.configs.config_loader.ConfigLoader.settings_customise_sources",
        new=classmethod(fake_settings_customise_sources),
    )
    patcher.start()

    yield patcher

    patcher.stop()


@fixture
def shodan_client_api() -> ShodanClientAPI:
    """Provide a ShodanClientAPI with mocked config and helper."""
    mock_config = Mock()
    mock_config.shodan.base_url = "https://api.shodan.io"
    mock_config.shodan.api_key.get_secret_value.return_value = "test-api-key"
    mock_config.shodan.api_retry = 1
    mock_config.shodan.api_backoff.total_seconds.return_value = 1
    mock_config.shodan.api_leaky_bucket_rate = 10
    mock_config.shodan.api_leaky_bucket_capacity = 10

    mock_helper = Mock()

    return ShodanClientAPI(config=mock_config, helper=mock_helper)


@fixture
def shodan_injector() -> ShodanInjector:
    """Provide a ShodanInjector with mocked config and helper."""
    mock_config = Mock()
    mock_config.shodan.base_url = "https://api.shodan.io"
    mock_config.shodan.api_key.get_secret_value.return_value = "test-api-key"
    mock_config.shodan.api_retry = 1
    mock_config.shodan.api_backoff.total_seconds.return_value = 1
    mock_config.shodan.api_leaky_bucket_rate = 10
    mock_config.shodan.api_leaky_bucket_capacity = 10

    mock_helper = Mock()

    return ShodanInjector(config=mock_config, helper=mock_helper)
