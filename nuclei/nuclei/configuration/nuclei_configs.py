"""Configuration for Nuclei injector."""

from typing import Literal

from pydantic import Field, PositiveInt, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigLoaderNuclei(BaseSettings):
    """Nuclei configurations"""

    model_config = SettingsConfigDict(extra="ignore")

    scan_strategy: Literal["auto", "host-spray", "template-spray"] = Field(
        default="host-spray",
        description=(
            "Strategy to use while scanning (auto, host-spray, template-spray). "
            "Nuclei Flags: -ss, -scan-strategy"
        ),
    )

    templates_parallelism: PositiveInt = Field(
        default=5,
        description=(
            "Maximum number of templates to be executed in parallel. "
            "Nuclei Flags: -c, -concurrency"
        ),
    )

    hosts_parallelism_per_template: PositiveInt = Field(
        default=5,
        description=(
            "Maximum number of hosts to be analyzed in parallel per template. "
            "Nuclei Flags: -bs, -bulk-size"
        ),
    )

    max_requests_per_second: PositiveInt = Field(
        default=50,
        description=(
            "Maximum number of requests to send per second. "
            "Nuclei Flags: -rl, -rate-limit"
        ),
    )

    timeout: PositiveInt = Field(
        default=10,
        description=(
            "Time to wait in seconds before timeout. " "Nuclei Flags: -timeout"
        ),
    )

    retries: PositiveInt = Field(
        default=1,
        description=(
            "Number of times to retry a failed request. " "Nuclei Flags: -retries"
        ),
    )

    max_host_error: PositiveInt = Field(
        default=30,
        description=(
            "Max errors for a host before skipping from scan. "
            "Nuclei Flags: -mhe, -max-host-error"
        ),
    )

    response_size_read: PositiveInt = Field(
        default=1048576,
        description=(
            "Max response size to read in bytes. "
            "Nuclei Flags: -rsr, -response-size-read"
        ),
    )

    response_size_save: PositiveInt = Field(
        default=1048576,
        description=(
            "Max response size to save in bytes. "
            "Nuclei Flags: -rss, -response-size-save"
        ),
    )

    exclude_type: list[
        Literal[
            "dns",
            "file",
            "http",
            "headless",
            "tcp",
            "workflow",
            "ssl",
            "websocket",
            "whois",
            "code",
            "javascript",
        ]
    ] = Field(
        default_factory=lambda: ["headless"],
        description=(
            "Templates to exclude based on protocol type (comma-separated). "
            "Nuclei Flags: -ept, -exclude-type"
        ),
    )

    exclude_severity: list[
        Literal[
            "info",
            "low",
            "medium",
            "high",
            "critical",
            "unknown",
        ]
    ] = Field(
        default_factory=list,
        description=(
            "Templates to exclude based on severity (comma-separated). "
            "Nuclei Flags: -es, -exclude-severity"
        ),
    )

    @field_validator("exclude_type", "exclude_severity", mode="before")
    @classmethod
    def parser_csv_to_list(cls, value):
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value
