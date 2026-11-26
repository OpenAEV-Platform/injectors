"""Configuration of the Nmap injector (deployment level)."""

from typing import Optional

from pydantic import Field, NonNegativeInt, PositiveInt, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Built-in safe defaults applied when an inject leaves the field empty.
DEFAULT_HOST_TIMEOUT_SECONDS = 300
DEFAULT_MAX_RETRIES = 2


class ConfigLoaderNmap(BaseSettings):
    """Nmap configurations."""

    model_config = SettingsConfigDict(extra="ignore")

    default_host_timeout_seconds: NonNegativeInt = Field(
        default=DEFAULT_HOST_TIMEOUT_SECONDS,
        le=86400,
        description=(
            "--host-timeout applied when an inject leaves 'Give up on a host after' "
            "empty, in seconds: nmap gives up on a host that has not finished after "
            "this time. An explicit value on the inject (0 included) wins. 0 here "
            "means no default (nmap's own: unbounded)."
        ),
    )

    default_max_retries: NonNegativeInt = Field(
        default=DEFAULT_MAX_RETRIES,
        le=10,
        description=(
            "--max-retries applied when an inject leaves 'Max retries per port' "
            "empty. An explicit value on the inject (0 included) wins."
        ),
    )

    scan_timeout: Optional[PositiveInt] = Field(
        default=None,
        description=(
            "Hard ceiling in seconds for a whole Nmap run. When exceeded, nmap is "
            "terminated, the hosts it finished are reported, the others are marked "
            "not scanned (scan time limit reached) and the inject ends WARNING "
            "(ERROR when no host was scanned). Unset (default): derived from the "
            "platform's inject execution threshold (runtime setting "
            "inject_execution_threshold_minutes) minus 60 s, or 540 s when the "
            "platform does not expose it. An inject may set its own ceiling with "
            "the scan_timeout_seconds field. Any ceiling is capped below the "
            "platform threshold, past which the platform no longer accepts the "
            "results."
        ),
    )

    @field_validator(
        "default_host_timeout_seconds",
        "default_max_retries",
        "scan_timeout",
        mode="before",
    )
    @classmethod
    def empty_is_unset(cls, value, info):
        # docker-compose passes NMAP_X=${NMAP_X}: an unset variable arrives as ""
        # and means "keep the built-in default".
        if isinstance(value, str) and not value.strip():
            return cls.model_fields[info.field_name].default
        return value
