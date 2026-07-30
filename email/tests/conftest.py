"""Conftest file for Pytest fixtures."""

from unittest.mock import Mock, patch

from openaev_email.injector.openaev_email import EmailInjector
from openaev_email.services.signature_service import EmailSignatureService
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
        "openaev_email.models.configs.config_loader.ConfigLoader.settings_customise_sources",
        new=classmethod(fake_settings_customise_sources),
    )
    patcher.start()

    yield patcher

    patcher.stop()


@fixture
def email_injector() -> EmailInjector:
    """Provide an EmailInjector with mocked config, helper, and signature service."""
    mock_config = Mock()
    mock_config.email.hash_algorithm = "sha256"
    mock_helper = Mock()

    with patch("openaev_email.injector.openaev_email.SignatureManager") as mock_sm_cls:
        mock_sm = mock_sm_cls.return_value
        injector = EmailInjector(config=mock_config, helper=mock_helper)

    # The signature service wraps the mocked SignatureManager
    assert isinstance(injector.signature_service, EmailSignatureService)
    assert injector.signature_service._sm is mock_sm

    return injector
