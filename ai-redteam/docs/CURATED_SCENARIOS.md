# Curated AI Red Team Scenarios

Ready-to-assemble OpenAEV scenarios for adversarial exposure validation of LLMs and AI agents. Each
scenario is an ordered set of `ai-redteam` injects (Atomic Tests) run against one or more AI Targets,
mapped to MITRE ATLAS, OWASP (LLM 2025 / Agentic 2026) and NIST AI 100-2 / 600-1 for reporting.

Detection and prevention are validated by the `ai-guardrail` collector (SecurityPlatform type
`LLM_FIREWALL`) when the AI Target is fronted by an LLM firewall / guardrail / AI gateway.

## 1. LLM application baseline (single-turn)

Goal: baseline robustness of a deployed LLM application.

1. Direct prompt injection - ATLAS `AML.T0051.000` / OWASP LLM01 / NIST AML evasion
2. Jailbreak - ATLAS `AML.T0054` / OWASP LLM01
3. System prompt leakage - ATLAS `AML.T0056` / OWASP LLM07
4. Sensitive data exfiltration - ATLAS `AML.T0057` / OWASP LLM02
5. Garak vulnerability scan (probes: `promptinject,dan,leakreplay`) - broad coverage

Expectations: VULNERABILITY (attack success), DETECTION + PREVENTION (AI defense).

## 2. RAG / indirect injection

Goal: validate resistance to untrusted content in retrieval / tool outputs.

1. Indirect prompt injection - ATLAS `AML.T0051.001` / OWASP LLM01
2. Sensitive data exfiltration - ATLAS `AML.T0057` / OWASP LLM02
3. Promptfoo red-team (plugins: `rag-poisoning,pii,prompt-injection`)

## 3. Agentic / tool-using agent

Goal: validate an autonomous agent with tools / MCP.

1. Excessive agency / tool abuse - ATLAS `AML.T0053` / OWASP LLM06 / Agentic ASI02
2. MCP tool poisoning - ATLAS `AML.T0108` / Agentic ASI04 + ASI06
3. PyRIT multi-turn campaign (strategy: `crescendo`, objective: privilege/goal hijack) -
   OWASP Agentic ASI01
4. Unbounded consumption / cost harvesting - ATLAS `AML.T0034` / OWASP LLM10

## 4. Continuous posture monitoring

Schedule scenario 1 + 2 on a recurrence (OpenAEV scenario cron) to track AI posture drift over time;
use the Promptfoo engine inject as a CI/CD regression gate before promoting model/prompt changes.

## Reporting

- ATLAS coverage matrix: AI injects carry ATLAS attack patterns, so they appear in the MITRE
  coverage matrix under the `mitre-atlas` kill chain (ingested by the `mitre-atlas` collector).
- Detection / prevention rates: standard OpenAEV expectation rates, filterable per AI defense
  SecurityPlatform (LLM firewall / guardrail).
