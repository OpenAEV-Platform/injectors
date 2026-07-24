from typing import Literal

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector, Configuration


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Email (SMTP)",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="email_smtp/img/icon-email.png",
        description="Path to the icon file",
    )
    type: str = Field(
        default="openaev_email_smtp",
        description="Type of the injector.",
    )
    log_level: Literal["debug", "info", "warning", "error", "critical"] = Field(
        default="info",
        description=(
            "Determines the verbosity of the logs. "
            "Options: debug, info, warning, error, or critical."
        ),
    )
    hash_algorithm: Literal["sha256", "sha1", "md5"] = Field(
        default="sha256",
        description=(
            "Hash algorithm used for signature generation "
            "(URL hashes, attachment hashes). Options: sha256, sha1, md5."
        ),
    )

    def to_daemon_config(self) -> Configuration:
        return Configuration(  # ty: ignore[missing-argument]
            config_base_model=self,  # ty: ignore[invalid-argument-type]
        )
