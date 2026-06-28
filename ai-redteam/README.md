# OpenAEV AI Red Team Injector

Runs adversarial exposure validation against **LLM models and AI agents** and reports the outcome
(plus findings and a correlation marker) back to OpenAEV. Techniques are mapped to **MITRE ATLAS**
(`AML.Txxxx`) and **OWASP** (LLM 2025 / Agentic 2026), so AI injects flow through Atomic Testing,
Scenarios and the ATLAS coverage matrix exactly like endpoint techniques.

## Engines

- **native** - single-turn adversarial prompts via a built-in multi-provider client, with heuristic
  success detection (canary leakage / refusal / keywords). No heavy dependency.
- **garak** - NVIDIA [Garak](https://github.com/NVIDIA/garak) broad probe scanner (120+ probes).
- **pyrit** - Microsoft [PyRIT](https://github.com/Azure/PyRIT) multi-turn orchestration
  (Crescendo / TAP / PAIR). Degrades to a built-in escalation loop if PyRIT is not installed.
- **promptfoo** - [Promptfoo](https://promptfoo.dev) red-team plugins/strategies with
  assertion-based pass/fail.

The native and PyRIT (internal) engines work out of the box. To enable Garak and Promptfoo, build
the image with `--build-arg INSTALL_OSS_ENGINES=true`.

## Native attack pack (mapped to ATLAS / OWASP)

- Direct prompt injection - `AML.T0051.000` / LLM01
- Indirect prompt injection - `AML.T0051.001` / LLM01
- Jailbreak - `AML.T0054` / LLM01
- System prompt leakage - `AML.T0056` / LLM07
- Sensitive data exfiltration - `AML.T0057` / LLM02
- Excessive agency / tool abuse - `AML.T0053` / LLM06 / ASI02
- MCP tool poisoning - `AML.T0108` / ASI04 / ASI06
- Unbounded consumption / cost harvesting - `AML.T0034` / LLM10

## Targets

An inject selects a target either by referencing an **AI Target** asset id (contract field
`ai_target`) - fetched from the platform - or by providing the connection inline
(`target_provider`, `target_endpoint`, `target_model`, `target_api_key_variable`, `system_prompt`).

Supported providers: OpenAI-compatible, Anthropic, Azure OpenAI, AWS Bedrock, Google Vertex,
HuggingFace, Ollama, custom HTTP, MCP server, agent HTTP.

## Security: credentials

Secrets are **never** stored by the platform. Each AI Target carries only the *name* of the
environment variable (`api_key_variable`); the injector resolves the actual secret from its own
process environment at execution time (e.g. `OPENAI_API_KEY`).

## Correlation with AI defenses

Every request carries a per-inject canary marker (`X-OAEV-Inject-Marker` header + in-prompt token).
An in-line LLM firewall / guardrail logs the marker, and the AI defense collectors then fill the
DETECTION / PREVENTION expectations by matching it - closing the attack + defense loop.

## Run (dev)

```bash
poetry install --extras dev
export OPENAI_API_KEY=sk-...
poetry run python -m ai_redteam.openaev_ai_redteam
```

> As with the other connectors in this repository, the icon
> (`ai_redteam/img/icon-ai-redteam.png`) is provided at build/deploy time.
