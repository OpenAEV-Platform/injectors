"""Conftest file for Pytest fixtures."""

from unittest.mock import Mock, patch

from email_smtp.injector.openaev_email_smtp import EmailSmtpInjector
from pytest import fixture


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
        "email_smtp.models.configs.config_loader.ConfigLoader.settings_customise_sources",
        new=classmethod(fake_settings_customise_sources),
    )
    patcher.start()

    yield patcher

    patcher.stop()


@fixture
def email_smtp_injector() -> EmailSmtpInjector:
    """Provide an EmailSmtpInjector with mocked config and helper."""
    mock_config = Mock()
    mock_helper = Mock()

    return EmailSmtpInjector(config=mock_config, helper=mock_helper)
