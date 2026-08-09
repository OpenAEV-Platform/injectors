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

    scan_timeout: PositiveInt = Field(
        default=540,
        description=(
            "Hard ceiling in seconds for a whole Nuclei scan. When exceeded, the "
            "scan process is terminated and the inject is reported as a timeout "
            "error instead of hanging forever (Nuclei's own -timeout is "
            "per-request and never bounds the total run). Keep it below the "
            "platform's inject.execution.threshold.minutes (default 10 min) so "
            "the injector reports the timeout before the platform marks the "
            "inject stale. Not a Nuclei flag."
        ),
    )

    template_update_timeout: PositiveInt = Field(
        default=300,
        description=(
            "Hard ceiling in seconds for a Nuclei template refresh ("
            "'nuclei -update-templates'), applied at startup and on each periodic "
            "refresh. The refresh holds the writer side of the templates lock, so "
            "a hung update would otherwise block every scan (and startup) forever; "
            "when it fires, the refresh is terminated and degrades to best-effort "
            "(the templates already on disk are used). Not a Nuclei flag."
        ),
    )

    max_concurrent_scans: PositiveInt = Field(
        default=5,
        description=(
            "Maximum number of Nuclei scans this injector runs at the same time. "
            "The consumer spawns one thread (and one Nuclei subprocess) per "
            "inject, so under a burst of injects an unbounded number of scans "
            "could run at once and exhaust CPU / memory / sockets. This bounds "
            "that: extra injects wait for a slot. Not a Nuclei flag."
        ),
    )

    disable_interactsh: bool = Field(
        default=False,
        description=(
            "Disable Nuclei's interactsh (out-of-band / OOB) interaction "
            "polling. Some templates use OOB checks against ProjectDiscovery's "
            "public interactsh servers; in a locked-down network those servers "
            "are unreachable and the affected templates stall for the whole poll "
            "window, making scans intermittently slow or time out. Enable this "
            "in restricted networks (OOB-only findings are then skipped). "
            "Nuclei Flags: -ni, -no-interactsh"
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
