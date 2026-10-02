"""build_env: per-inject LLM overrides take precedence; key is never overridable."""

from dataclasses import dataclass
from typing import Optional

from strix.helpers.strix_process import StrixProcess


@dataclass
class _Cfg:
    llm_model: str = "anthropic/claude-sonnet-4-5"
    llm_api_key: str = "test-injector-default-key"
    llm_api_base: Optional[str] = None
    perplexity_api_key: Optional[str] = None
    docker_host: Optional[str] = None


def test_defaults_used_when_no_override():
    env = StrixProcess.build_env(_Cfg())
    assert env["STRIX_LLM"] == "anthropic/claude-sonnet-4-5"
    assert env["LLM_API_KEY"] == "test-injector-default-key"
    assert "LLM_API_BASE" not in env
    assert env["STRIX_NON_INTERACTIVE"] == "1"


def test_per_inject_model_and_base_override():
    env = StrixProcess.build_env(
        _Cfg(),
        {"llm_model": "anthropic/claude-opus-4-1", "llm_api_base": "https://gw.example/v1"},
    )
    assert env["STRIX_LLM"] == "anthropic/claude-opus-4-1"
    assert env["LLM_API_BASE"] == "https://gw.example/v1"
    # Key is NOT overridable per inject -> always the injector default.
    assert env["LLM_API_KEY"] == "test-injector-default-key"


def test_empty_overrides_fall_back():
    env = StrixProcess.build_env(_Cfg(), {"llm_model": None, "llm_api_base": None})
    assert env["STRIX_LLM"] == "anthropic/claude-sonnet-4-5"
