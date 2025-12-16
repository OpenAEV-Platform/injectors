"""Base class for global config models."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class _SettingsLoader(BaseSettings):
    """Base class for global config models.

    Provides common configuration settings and prevents attributes from being
    modified after initialization by using frozen=True in the model config.
    """

    model_config = SettingsConfigDict(
        frozen=True,
        extra="allow",
        env_nested_delimiter="_",
        env_nested_max_split=1,
        validate_default=True,
        enable_decoding=False,
    )
