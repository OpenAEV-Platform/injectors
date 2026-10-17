# OpenAEV Strix Injector

The Strix injector lets OpenAEV drive [Strix](https://github.com/usestrix/strix) — open-source autonomous
AI penetration-testing agents (Apache-2.0) — as part of attack scenarios. Point an inject at authorized
targets and Strix runs the assessment on its own, validating findings with proofs-of-concept, then reports
the results back to OpenAEV as structured outputs.

> **Authorized use only.** Strix actively exploits its targets. Only run it against systems you are
> explicitly authorized to test, from a dedicated host. This injector wires the tool into OpenAEV's
> scoping, logging and expectation model; it does not relax any of Strix's own safeguards.

## Table of Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
- [Inject contracts](#inject-contracts)
- [Results in OpenAEV](#results-in-openaev)
- [Behavior and limits](#behavior-and-limits)
- [Debugging](#debugging)

## How it works

OpenAEV (Breach and Attack Simulation) dispatches an inject to the injector, which builds a bounded
`strix --non-interactive` command, runs it in an isolated per-inject working directory, then parses the
run's `vulnerabilities.json` and `penetration_test_report.md` and returns them to the platform. The
injector also registers **Strix** as a `VULNERABILITY_SCANNER` security platform so vulnerability
verdicts are attributed to it.

Strix runs its own **sandbox container** via Docker. The injector container therefore needs access to a
Docker daemon (the host socket is mounted in `docker-compose.yml`) and ships the Docker CLI plus the
`strix-agent` package.

## Requirements

- A reachable OpenAEV instance and an admin API token.
- A Docker daemon the injector can reach (host socket mounted).
- An LLM provider reachable by Strix: a cloud model (`STRIX_LLM_MODEL` + `STRIX_LLM_API_KEY`) or a local
  OpenAI-compatible endpoint (`STRIX_LLM_API_BASE`, e.g. an Ollama server).

## Configuration variables

### OpenAEV
| Variable | Config (`config.yml`) | Required | Description |
|---|---|---|---|
| `OPENAEV_URL` | `openaev.url` | Yes | Base URL of the OpenAEV server. |
| `OPENAEV_TOKEN` | `openaev.token` | Yes | Admin API token. |
| `OPENAEV_TENANT_ID` | `openaev.tenant_id` | EE only | Tenant id (multi-tenancy). |

### Injector
| Variable | Config | Default | Description |
|---|---|---|---|
| `INJECTOR_ID` | `injector.id` | — | Unique UUIDv4 for this injector instance. |
| `INJECTOR_NAME` | `injector.name` | `Strix` | Injector display name. |
| `INJECTOR_LOG_LEVEL` | `injector.log_level` | `error` | `debug` / `info` / `warning` / `error`. |

### Strix
| Variable | Config (`strix.*`) | Default | Description |
|---|---|---|---|
| `STRIX_LLM_MODEL` | `llm_model` | `openai/gpt-4.1` | LiteLLM model id Strix reasons with (→ `STRIX_LLM`). |
| `STRIX_LLM_API_KEY` | `llm_api_key` | — | Provider API key (→ `LLM_API_KEY`). |
| `STRIX_LLM_API_BASE` | `llm_api_base` | — | OpenAI-compatible endpoint for a local model (→ `LLM_API_BASE`). |
| `STRIX_PERPLEXITY_API_KEY` | `perplexity_api_key` | — | Enables Strix search (→ `PERPLEXITY_API_KEY`). |
| `STRIX_SCAN_MODE` | `scan_mode` | `deep` | `quick` / `standard` / `deep`. |
| `STRIX_MAX_TURNS` | `max_turns` | `60` | Max turns per agent (bounds a deep run). |
| `STRIX_MAX_BUDGET_USD` | `max_budget_usd` | — | Max LLM cost per assessment; recommended in deep mode. |
| `STRIX_SCAN_TIMEOUT` | `scan_timeout` | `540` | Hard ceiling (s) for a whole assessment. Keep below the platform inject execution threshold (default 10 min). |
| `STRIX_MAX_CONCURRENT_SCANS` | `max_concurrent_scans` | `2` | Concurrent assessments; extra injects wait for a slot. |

## Deployment

### Docker

```bash
cp .env.sample .env   # then edit it
docker compose up -d
```

The compose file mounts `/var/run/docker.sock`. This grants the container control of the host Docker
daemon — run it only on a trusted, dedicated host.

### Manual

```bash
poetry install
# provide config.yml or environment variables, plus a reachable Docker daemon and `strix` on PATH
poetry run python -m strix.openaev_strix
```

## Inject contracts

| Contract | Targets | Use |
|---|---|---|
| **Autonomous Assessment (Network / Web / API)** | Assets, asset groups, or manual URLs/domains/IPs | DAST-style assessment of running services. |
| **Autonomous Assessment (Code repository)** | A git repository URL or a path mounted in the sandbox | Reads the code during the assessment (e.g. to reason about code-informed testing). |

Both contracts expose an optional **scan mode** override, a **custom instructions** field (focus areas,
scope notes, authorized test credentials) and the standard expectations.

## Results in OpenAEV

- `cve` — findings carrying a CVE, grouped by CVE id and mapped to assets (visible Findings).
- `others` — non-CVE findings as `Title [SEVERITY] @ target` (visible Findings).
- `action_output` — the executive `penetration_test_report.md` (not a Finding; usable as a chaining filter).
- Detection / prevention / vulnerability **expectation signatures** (network contract).

## Behavior and limits

- A per-inject working directory isolates each run's `strix_runs/<run>/` output.
- `scan_timeout` terminates a run that overruns and reports a terminal timeout error, so an inject never
  hangs; keep it under the platform's stale-inject threshold.
- `deep` mode is the default and the most thorough; pair it with `max_turns` / `max_budget_usd` so a run
  stays bounded.

## Debugging

Set `INJECTOR_LOG_LEVEL=debug`. The raw Strix command is not logged at info level because instructions
may carry credentials; target count and scan mode are logged instead.

## Per-inject LLM configuration (contract fields)

Both contracts expose two optional fields on the inject form:

- **LLM model** (`llm_model`) — a LiteLLM model id (e.g. `anthropic/claude-sonnet-4-5`) overriding the injector default for that inject.
- **LLM API base URL** (`llm_api_base`) — optional OpenAI-compatible endpoint; empty = provider default.

Empty fields fall back to `STRIX_LLM_MODEL` / `STRIX_LLM_API_BASE`. The **API key is intentionally not an inject field** — pyoaev has no masked/secret field type, so a token entered there would be stored and displayed in plaintext. It stays in `STRIX_LLM_API_KEY`; per-inject/per-tenant secrets should use a proper secret store.

## Testing against a locally-hosted target (Docker / Colima)

Strix runs each assessment from a **sandbox container it spawns itself** (a sibling
container, via the mounted Docker socket). The inject target must therefore be reachable
**from a freshly spawned container**, not just from the host. When the target is a service
published on the Docker host, address it by the **Docker host address** rather than a LAN IP
or a target container IP:

- default bridge gateway (e.g. `http://172.17.0.1:<port>`), or
- the host gateway the runtime maps (`host-gateway`); under Colima that resolves to the
  VM host address, so a target published on the host is reachable there.

`host.docker.internal` is **not** injected into the Strix sandbox, so it won't resolve inside it.

Long assessments (`deep`) can outlast the platform's `inject.execution.threshold.minutes`
(default 10). Raise that threshold for deep runs, and keep `STRIX_SCAN_TIMEOUT=0` so the agent
stops on its own conditions rather than a wall clock.
