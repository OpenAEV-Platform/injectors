"""Configuration for the Strix injector."""

from typing import Literal, Optional

from pydantic import Field, PositiveFloat, PositiveInt
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigLoaderStrix(BaseSettings):
    """Strix configurations."""

    model_config = SettingsConfigDict(extra="ignore")

    # -- LLM provider --------------------------------------------------------
    llm_model: str = Field(
        default="openai/gpt-4.1",
        description=(
            "LiteLLM-style model identifier Strix reasons with, e.g. "
            "'openai/gpt-4.1', 'anthropic/claude-sonnet-4', or an "
            "'ollama/<model>' identifier for a local model. Exported to Strix as "
            "STRIX_LLM."
        ),
    )
    llm_api_key: str = Field(
        default="",
        description=(
            "API key for the configured LLM provider. Exported to Strix as "
            "LLM_API_KEY. Leave empty for a local provider that needs no key."
        ),
    )
    llm_api_base: Optional[str] = Field(
        default=None,
        description=(
            "Optional base URL of an OpenAI-compatible endpoint (e.g. a local "
            "Ollama or vLLM server: 'http://host:11434'). Exported to Strix as "
            "LLM_API_BASE when set."
        ),
    )
    perplexity_api_key: Optional[str] = Field(
        default=None,
        description=(
            "Optional Perplexity API key enabling Strix's search capability. "
            "Exported as PERPLEXITY_API_KEY when set."
        ),
    )

    # -- Scan behavior -------------------------------------------------------
    scan_mode: Literal["quick", "standard", "deep"] = Field(
        default="deep",
        description=(
            "Strix scan depth (quick / standard / deep). 'deep' is the most "
            "thorough but the longest; keep the run bounded with max_turns / "
            "max_budget_usd / scan_timeout below. Strix flag: -m, --scan-mode"
        ),
    )
    max_turns: PositiveInt = Field(
        default=60,
        description=(
            "Maximum turns per Strix agent before it is force-stopped. Bounds "
            "the run length independently of wall-clock time. Strix flag: "
            "--max-turns"
        ),
    )
    max_budget_usd: Optional[PositiveFloat] = Field(
        default=None,
        description=(
            "Optional maximum LLM cost in USD for a single assessment. The scan "
            "stops cleanly when reached. Recommended in 'deep' mode. Strix flag: "
            "--max-budget"
        ),
    )

    # -- Injector-level guards (not Strix flags) -----------------------------
    scan_timeout: int = Field(
        default=0,
        ge=0,
        description=(
            "Optional injector-side wall-clock ceiling in seconds for a whole "
            "Strix assessment. 0 (the default) DISABLES it: an autonomous pentest "
            "agent should stop on its own conditions (finish_scan) or its agentic "
            "budget (--max-turns / --max-budget), not an arbitrary timer. When set "
            "> 0, the process is terminated after that many seconds. If you enable "
            "it, keep it below the platform's inject.execution.threshold.minutes so "
            "the injector reports before the platform marks the inject stale. Not a "
            "Strix flag."
        ),
    )
    max_concurrent_scans: PositiveInt = Field(
        default=2,
        description=(
            "Maximum number of Strix assessments this injector runs at the same "
            "time. Strix is resource-heavy (it drives a sandbox container and an "
            "LLM), so this defaults low; extra injects wait for a slot. Not a "
            "Strix flag."
        ),
    )
    runs_root: str = Field(
        default="/tmp/strix_runs_root",
        description=(
            "Working directory root under which each inject gets an isolated "
            "run directory (Strix writes its results to <cwd>/strix_runs/<run>). "
            "Not a Strix flag."
        ),
    )
    docker_host: Optional[str] = Field(
        default=None,
        description=(
            "Optional DOCKER_HOST value Strix uses to reach the Docker daemon "
            "that hosts its sandbox container. Leave unset to use the mounted "
            "default socket (/var/run/docker.sock)."
        ),
    )
