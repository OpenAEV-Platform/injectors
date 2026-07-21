"""Conftest file for Pytest fixtures."""

from unittest.mock import Mock, patch

from email_smtp.injector.openaev_email_smtp import EmailSmtpInjector
from email_smtp.services.signature_service import EmailSignatureService
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
    """Provide an EmailSmtpInjector with mocked config, helper, and signature service."""
    mock_config = Mock()
    mock_config.injector.hash_algorithm = "sha256"
    mock_helper = Mock()

    with patch(
        "email_smtp.injector.openaev_email_smtp.SignatureManager"
    ) as mock_sm_cls:
        mock_sm = mock_sm_cls.return_value
        injector = EmailSmtpInjector(config=mock_config, helper=mock_helper)

    # The signature service wraps the mocked SignatureManager
    assert isinstance(injector.signature_service, EmailSignatureService)
    assert injector.signature_service._sm is mock_sm

    return injector
