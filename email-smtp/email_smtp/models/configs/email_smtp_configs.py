"""Configuration for Email-SMTP injector."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigLoaderEmailSmtp(BaseSettings):
    """Email-SMTP specific configurations."""

    model_config = SettingsConfigDict(extra="ignore")

    hash_algorithm: Literal["sha256", "sha1", "md5"] = Field(
        default="sha256",
        description=(
            "Hash algorithm used for signature generation "
            "(URL hashes, attachment hashes). Options: sha256, sha1, md5."
        ),
    )
