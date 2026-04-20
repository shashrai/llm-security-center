# LLM Shield — Architecture

## Overview

LLM Shield is a **security control plane** that sits between your applications and any LLM backend. Every request passes through four sequential security layers before reaching the model. The gateway is OpenAI API-compatible — applications point their existing SDK at the gateway URL and get all security controls with zero code changes.

```
┌─────────────────────────────────────────────────────────────────┐
│                       Application Layer                         │
│   Any app using OpenAI SDK, LangChain, LlamaIndex, direct HTTP  │
└────────────────────────────┬────────────────────────────────────┘
                             │  POST /v1/chat/completions
                             │  Authorization: Bearer <app_id>:<key>
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    LLM Shield Gateway (FastAPI)                  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 1 — Policy Engine (OPA)                           │   │
│  │  • Evaluates app_id + model against Rego policies        │   │
│  │  • DENY → 403 with reason + remediation hint             │   │
│  │  • ALLOW → proceed to Layer 2                            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             │                                    │
│  ┌──────────────────────────▼───────────────────────────────┐   │
│  │  Layer 2 — PII Scanner                                   │   │
│  │  • Regex: SSN, cards, emails, phones, IBANs, API keys    │   │
│  │  • NLP (spaCy): names, orgs, locations                   │   │
│  │  • Tokenise detected values → <REDACTED:TYPE>            │   │
│  │  • Log entity types only (data minimisation)             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             │                                    │
│  ┌──────────────────────────▼───────────────────────────────┐   │
│  │  Layer 3 — Injection Detector                            │   │
│  │  • 14 pattern categories (instruction overrides,         │   │
│  │    prompt extraction, role escalation, RAG injection,    │   │
│  │    encoding obfuscation, zero-width chars)               │   │
│  │  • HIGH  → auto-block, 400 response                      │   │
│  │  • MEDIUM → flag + enhanced logging, allow               │   │
│  │  • LOW   → pass through                                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             │                                    │
│  ┌──────────────────────────▼───────────────────────────────┐   │
│  │  Layer 4 — Audit Vault (async SQLite)                    │   │
│  │  • Written on every request (allowed + blocked)          │   │
│  │  • Immutable append-only log                             │   │
│  │  • Queryable via /v1/audit/* REST endpoints              │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             │                                    │
└─────────────────────────────┼───────────────────────────────────┘
                              │  Sanitised, policy-cleared request
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        LLM Backend                               │
│   OpenAI  /  Azure OpenAI  /  Anthropic  /  Ollama  /  Mock     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Defence-in-depth mapping

The three-layer model mirrors how cloud infrastructure security is structured:

| Cloud analogy | LLM Shield layer | Control type |
|---|---|---|
| Hashicorp Sentinel (IaC) | OPA policy engine | **Preventative** — blocks before execution |
| Azure Policy (post-deploy) | PII scanner + injection detector | **Detective** — identifies violations in-flight |
| Remediation pipeline | Audit vault + dashboard | **Corrective** — enables investigation and tuning |

---

## Component design

### Policy Engine (`policy_engine.py`)

The policy engine uses OPA as a standalone decision engine — the gateway calls OPA's REST API synchronously for every request. OPA evaluates the request against Rego policies and returns an allow/deny decision in under 5ms.

**Fallback behaviour:** If OPA is unreachable (startup race, network issue), the gateway falls back to a local in-process policy table. This ensures requests are never unintentionally allowed due to infrastructure failure — the fallback table uses the same deny-by-default model.

**Policy structure (Rego):**
```
input.app_id + input.model → app_registry lookup → allow/deny + reason
```

### PII Scanner (`pii_scanner.py`)

Two-pass pipeline:

1. **Regex pass** — 15 patterns covering structured PII (O(n) per pattern, very fast). Patterns compiled at startup and reused across requests. Typical latency: < 1ms for a 1000-token prompt.

2. **NLP pass** — spaCy `en_core_web_sm` NER model detects unstructured PII (person names, organisations, locations). Typical latency: 5–15ms per request. Can be disabled via `use_nlp=False` for latency-critical deployments.

**Overlap resolution:** When regex and NLP detections overlap at the same text span, the higher-confidence detection wins.

**Tokenisation vs deletion:** Detected values are replaced with typed tokens (`<REDACTED:SSN>`) rather than deleted. This preserves prompt structure and intent — the model understands it is processing a financial record even with values redacted. Deletion can cause malformed prompts that confuse the model.

### Injection Detector (`injection_detector.py`)

Pattern-based scoring with 14 pattern categories, each weighted by empirical risk level. Score is capped at 1.0 to prevent multiple low-weight matches from creating false HIGH classifications.

**Risk-tier rationale:**

MEDIUM signals are allowed through because:
- False-positive rate for MEDIUM patterns is non-trivial (e.g., "hypothetically" appears in legitimate research questions)
- Blocking at MEDIUM pushes teams toward direct API access outside any control plane
- MEDIUM events are logged with full detail — the signal accumulates for threshold tuning over time

The blocking threshold (HIGH: score ≥ 0.75) was chosen to catch known commodity jailbreak patterns while keeping false-positive rate below 1% on typical enterprise prompt traffic.

### Audit Vault (`audit.py`)

Async SQLite via `aiosqlite`. Design decisions:

- **Never raises** — audit write failures are logged but not propagated to the caller. A broken audit system must not cause production AI requests to fail.
- **Entity type only** — PII detection logs record the entity type (`SSN`, `CREDIT_CARD`) and confidence score, never the original value. The audit log must not itself become a regulated data asset.
- **Append-only semantics** — no UPDATE or DELETE operations exist in the codebase. The database file should be treated as immutable for compliance purposes.

---

## Scaling considerations

For production deployments handling high request volume:

| Component | Scaling approach |
|---|---|
| Gateway | Stateless — run multiple replicas behind a load balancer |
| OPA | Run as a separate cluster; use OPA bundle API to push policies |
| Audit vault | Replace SQLite with PostgreSQL (`asyncpg`) for concurrent writes |
| PII scanner | Pre-warm spaCy model; share the `nlp` object across request workers |

---

## NIST AI RMF mapping

| NIST AI RMF function | LLM Shield control |
|---|---|
| **Govern** | OPA policy framework defines organisational policies on model access, data handling, and use-case classification |
| **Map** | App registry creates an inventory of all AI-consuming applications and their approved model/tier combinations |
| **Measure** | Audit vault provides quantitative risk indicators: block rate, PII detection frequency, injection attempt rate |
| **Manage** | Automated blocking (HIGH injection, policy DENY) operationalises risk response; audit enables forensic investigation |

---

## OWASP LLM Top 10 coverage

| OWASP LLM vulnerability | LLM Shield control |
|---|---|
| LLM01 — Prompt Injection | Injection detector (Layers 3) |
| LLM02 — Insecure Output Handling | Audit logging of model outputs (roadmap) |
| LLM06 — Sensitive Information Disclosure | PII scanner (Layer 2) |
| LLM08 — Excessive Agency | Policy engine limits which apps/models can be used (Layer 1) |
| LLM09 — Overreliance | Audit trail supports human oversight |
