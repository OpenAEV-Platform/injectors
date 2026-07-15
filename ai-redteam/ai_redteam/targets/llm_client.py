"""Thin multi-provider client used by the native engine to send a single-turn prompt to an AI target
and return the model's text response. The per-inject canary marker is always sent as a request
header so an in-line AI gateway / LLM firewall can log it and a defense collector can correlate.
"""

import json

import requests
from ai_redteam import marker as marker_mod


class LLMResponse:
    def __init__(self, text: str, status_code: int, raw):
        self.text = text or ""
        self.status_code = status_code
        self.raw = raw


def _headers(target, marker, extra=None):
    headers = {"Content-Type": "application/json"}
    headers.update(marker_mod.request_header(marker))
    if extra:
        headers.update(extra)
    return headers


def _openai_compatible(target, prompt, marker, timeout, logger=None):
    base = (target.endpoint or "https://api.openai.com/v1").rstrip("/")
    url = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
    messages = []
    if target.system_prompt:
        messages.append({"role": "system", "content": target.system_prompt})
    messages.append({"role": "user", "content": prompt})
    body = {
        "model": target.model or "gpt-4o-mini",
        "messages": messages,
        "temperature": float(target.configuration.get("temperature", 0.7)),
        "max_tokens": int(target.configuration.get("max_tokens", 512)),
    }
    extra = {}
    if target.api_key:
        if target.provider == "AZURE_OPENAI":
            extra["api-key"] = target.api_key
        else:
            extra["Authorization"] = f"Bearer {target.api_key}"
    resp = _post(url, target, marker, body, extra, timeout, logger)
    data = _safe_json(resp)
    text = ""
    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        text = resp.text
    return LLMResponse(text, resp.status_code, data)


def _anthropic(target, prompt, marker, timeout, logger=None):
    base = (target.endpoint or "https://api.anthropic.com").rstrip("/")
    url = base if base.endswith("/messages") else f"{base}/v1/messages"
    extra = {"anthropic-version": "2023-06-01"}
    if target.api_key:
        extra["x-api-key"] = target.api_key
    body = {
        "model": target.model or "claude-3-5-sonnet-latest",
        "max_tokens": int(target.configuration.get("max_tokens", 512)),
        "messages": [{"role": "user", "content": prompt}],
    }
    if target.system_prompt:
        body["system"] = target.system_prompt
    resp = _post(url, target, marker, body, extra, timeout, logger)
    data = _safe_json(resp)
    text = ""
    try:
        text = "".join(block.get("text", "") for block in data.get("content", []))
    except AttributeError:
        text = resp.text
    return LLMResponse(text, resp.status_code, data)


def _ollama(target, prompt, marker, timeout, logger=None):
    base = (target.endpoint or "http://localhost:11434").rstrip("/")
    url = f"{base}/api/chat"
    messages = []
    if target.system_prompt:
        messages.append({"role": "system", "content": target.system_prompt})
    messages.append({"role": "user", "content": prompt})
    body = {"model": target.model or "llama3", "messages": messages, "stream": False}
    resp = _post(url, target, marker, body, None, timeout, logger)
    data = _safe_json(resp)
    text = ""
    try:
        text = data["message"]["content"]
    except (KeyError, TypeError):
        text = resp.text
    return LLMResponse(text, resp.status_code, data)


def _huggingface(target, prompt, marker, timeout, logger=None):
    url = (target.endpoint or "").rstrip("/")
    if not url:
        raise ValueError(
            "HUGGINGFACE target requires an endpoint URL (the inference endpoint)."
        )
    extra = {}
    if target.api_key:
        extra["Authorization"] = f"Bearer {target.api_key}"
    body = {"inputs": prompt}
    resp = _post(url, target, marker, body, extra, timeout, logger)
    data = _safe_json(resp)
    text = ""
    try:
        if isinstance(data, list) and data:
            text = data[0].get("generated_text", "")
        elif isinstance(data, dict):
            text = data.get("generated_text", resp.text)
    except AttributeError:
        text = resp.text
    return LLMResponse(text, resp.status_code, data)


def _custom_http(target, prompt, marker, timeout, logger=None):
    """Generic POST for CUSTOM_HTTP / AGENT_HTTP / MCP_SERVER targets. The request body and the
    response field to read can be customized through the target configuration."""
    url = (target.endpoint or "").rstrip("/")
    if not url:
        raise ValueError(
            f"{target.provider} target requires an endpoint URL to send the request to."
        )
    extra = {}
    if target.api_key:
        header_name = target.configuration.get("auth_header", "Authorization")
        prefix = target.configuration.get("auth_prefix", "Bearer ")
        extra[header_name] = f"{prefix}{target.api_key}"
    input_field = target.configuration.get("input_field", "input")
    body = dict(target.configuration.get("body_template", {}))
    body[input_field] = prompt
    body.setdefault("marker", marker)
    resp = _post(url, target, marker, body, extra, timeout, logger)
    data = _safe_json(resp)
    text = ""
    if isinstance(data, dict):
        for field in (
            target.configuration.get("output_field"),
            "output",
            "response",
            "content",
            "text",
            "message",
        ):
            if field and field in data and isinstance(data[field], str):
                text = data[field]
                break
        if not text:
            text = json.dumps(data)
    else:
        text = resp.text
    return LLMResponse(text, resp.status_code, data)


_SENSITIVE_HEADERS = {"authorization", "api-key", "x-api-key"}


def _redact_headers(headers):
    redacted = {}
    for name, value in (headers or {}).items():
        if name.lower() in _SENSITIVE_HEADERS and value:
            redacted[name] = "***redacted***"
        else:
            redacted[name] = value
    return redacted


def _post(url, target, marker, body, extra, timeout, logger=None):
    headers = _headers(target, marker, extra)
    if logger:
        logger.info(
            f"[llm_client] POST {url} (provider={target.provider}, "
            f"timeout={timeout}s) headers={_redact_headers(headers)} "
            f"body={json.dumps(body)[:2000]}"
        )
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=timeout)
    except requests.exceptions.Timeout as exc:
        if logger:
            logger.error(f"[llm_client] POST {url} timed out after {timeout}s: {exc}")
        raise
    except requests.exceptions.RequestException as exc:
        if logger:
            logger.error(f"[llm_client] POST {url} failed: {exc}")
        raise
    if logger:
        logger.info(
            f"[llm_client] Response {resp.status_code} from {url} "
            f"(elapsed={resp.elapsed.total_seconds():.2f}s, "
            f"body_len={len(resp.text or '')}): {(resp.text or '')[:2000]}"
        )
    return resp


def _xtm_one(target, prompt, marker, timeout, logger=None):
    """XTM One agent call via the Platform Chat API.

    XTM One in ``xtm_one`` platform mode does NOT expose the OpenAI-compatible
    ``/v1/chat/completions`` proxy, so agents are reached through the platform
    chat endpoint ``POST /api/v1/platform/chat/messages`` with a body of
    ``{"agent_slug": ..., "content": ..., "stream": false}`` and an
    ``Authorization: Bearer <fcp- key>`` header. This mirrors how OpenCTI talks
    to XTM One agents (see ``httpChatbotProxy.ts::postAgentMessage``).
    """
    base = (target.endpoint or "").rstrip("/")
    if not base:
        raise ValueError(
            "XTM_ONE target requires an endpoint URL (the XTM One base URL)."
        )
    path = "/api/v1/platform/chat/messages"
    if base.endswith(path):
        url = base
    else:
        # Tolerate an endpoint that still carries a trailing ``/v1`` (legacy
        # OpenAI-compatible targets) by stripping it before appending the path.
        if base.endswith("/v1"):
            base = base[: -len("/v1")].rstrip("/")
        url = f"{base}{path}"

    slug = (target.configuration.get("xtm_one_slug") or "").strip()
    if not slug:
        model = (target.model or "").strip()
        slug = model[len("agent:") :].strip() if model.startswith("agent:") else model
    if not slug:
        raise ValueError(
            "XTM_ONE target requires an agent slug: set the target model to the "
            "agent slug (or 'agent:<slug>'), or provide 'xtm_one_slug' in the "
            "target configuration."
        )

    extra = {}
    if target.api_key:
        extra["Authorization"] = f"Bearer {target.api_key}"
    body = {"agent_slug": slug, "content": prompt, "stream": False}
    resp = _post(url, target, marker, body, extra, timeout, logger)
    data = _safe_json(resp)
    text = ""
    if isinstance(data, dict):
        text = data.get("content") or ""
        if not text and data.get("detail"):
            detail = data["detail"]
            text = detail if isinstance(detail, str) else json.dumps(detail)
    if not text:
        text = resp.text
    return LLMResponse(text, resp.status_code, data)


def _safe_json(resp):
    try:
        return resp.json()
    except ValueError:
        return {"_raw": resp.text}


_DISPATCH = {
    "OPENAI_COMPATIBLE": _openai_compatible,
    "AZURE_OPENAI": _openai_compatible,
    "AWS_BEDROCK": _openai_compatible,
    "GOOGLE_VERTEX": _openai_compatible,
    "ANTHROPIC": _anthropic,
    "OLLAMA": _ollama,
    "HUGGINGFACE": _huggingface,
    "CUSTOM_HTTP": _custom_http,
    "AGENT_HTTP": _custom_http,
    "MCP_SERVER": _custom_http,
    "XTM_ONE": _xtm_one,
}


def send_prompt(target, prompt, marker, timeout=60, logger=None) -> LLMResponse:
    handler = _DISPATCH.get(target.provider, _openai_compatible)
    return handler(target, prompt, marker, timeout, logger=logger)
