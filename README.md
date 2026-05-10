# 🛡 LLM Shield

**An open-source AI security gateway — OpenAI-compatible proxy with policy enforcement, PII protection, prompt injection detection, and immutable audit logging.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green.svg)](https://fastapi.tiangolo.com)
[![OPA](https://img.shields.io/badge/OPA-Policy%20Engine-blueviolet.svg)](https://openpolicyagent.org)
[![Docker](https://img.shields.io/badge/docker-compose-blue.svg)](docker-compose.yml)

---

## The problem

When you give teams access to AI models in a regulated environment, you open a new, largely unmonitored data channel — one that existing security controls were not designed for:

- Developers can accidentally include **PII, PCI, or confidential data** in prompts
- Any team can call any model with **no access control**
- There is **no audit trail** for regulatory compliance
- **Prompt injection** attacks in RAG workflows can hijack model behaviour
- Without easy governance, teams work around controls (**shadow AI**)

LLM Shield solves this with a **drop-in security control plane** that sits between your applications and any LLM backend.

---

## How it works

```
Your App  →  LLM Shield Gateway  →  Your LLM (OpenAI / Anthropic / local)
              │
              ├── Layer 1: OPA Policy Engine      (who can call what model?)
              ├── Layer 2: PII Scanner            (detect & tokenise sensitive data)
              ├── Layer 3: Injection Detector     (block adversarial prompts)
              └── Layer 4: Audit Vault            (immutable compliance log)
```

LLM Shield is **OpenAI API-compatible** — point your existing `openai` SDK at the gateway and get security controls with zero application changes.

```python
from openai import OpenAI

# Before: direct to OpenAI
client = OpenAI(api_key="sk-...")

# After: through LLM Shield (zero other changes)
client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="my-app:my-key",
)
```

---

## Security layers

### Layer 1 — Policy enforcement (OPA)
Every request is evaluated against Rego policies defining which applications can access which models, under what use-case and data classification tiers. Uses **Open Policy Agent** — the same engine used for cloud infrastructure governance.

```
demo-app    → gpt-mock      ✓  ALLOW (internal tier)
finance-app → gpt-mock      ✓  ALLOW (regulated tier)
demo-app    → gpt-4-turbo   ✗  DENY  (elevated model requires regulated clearance)
unknown-app → any-model     ✗  DENY  (not registered — secure by default)
```

### Layer 2 — PII detection & sanitisation
Scans prompt payloads for sensitive entities before they reach the model. Uses a layered approach:
- **Regex patterns** — SSN, credit card, phone, email, IBAN, API keys, IPs
- **NLP (spaCy)** — names, organisations, locations in unstructured text
- **Tokenisation** — detected values replaced with typed tokens (`<REDACTED:SSN>`)
- **Data minimisation** — audit logs record entity *type*, never entity *value*

### Layer 3 — Prompt injection detection
Analyses prompts for adversarial patterns with risk-tiered response:

| Risk level | Examples | Response |
|---|---|---|
| **HIGH** | "Ignore all previous instructions", jailbreak modes, system prompt extraction | Auto-block, 400 response |
| **MEDIUM** | Hypothetical framing, sudo/admin language | Allow + enhanced audit logging |
| **LOW** | No signals | Pass through |

### Layer 4 — Audit vault
Every interaction — allowed or blocked — is written to an immutable SQLite audit log:
- Application identity, model, timestamp
- Policy decision and denial reason
- PII entity types detected (not values)
- Injection risk level and matched pattern names
- End-to-end latency

Queryable via REST API for real-time compliance reporting.

---

## Quick start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- Python 3.11+ (for running demo scripts)

### 1. Clone and start

```bash
git clone https://github.com/YOUR_USERNAME/llm-security-center.git
cd llm-security-center
docker-compose up --build
```

Wait for all three services to report healthy (about 60 seconds on first build).

### 2. Verify gateway is running

```bash
curl http://localhost:8000/health
# {"status":"healthy","service":"llm-security-center","version":"1.0.0"}
```

### 3. Run the interactive demo

```bash
cd examples
pip install httpx
python demo.py
```

The demo runs 7 scenarios showing each security layer in action.

### 4. Run a single scenario

```bash
# Test PII detection
python demo.py --scenario pii

# Test injection blocking
python demo.py --scenario injection-high

# Test policy enforcement
python demo.py --scenario policy

# View audit summary
python demo.py --scenario audit
```

### 5. Use with your own application

```bash
# Send a request directly with curl
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer demo-app:my-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-mock",
    "messages": [{"role": "user", "content": "Hello, how are you?"}]
  }'
```

---

## Using with a real LLM

By default LLM Shield runs against a local mock LLM. To connect to a real model:

### OpenAI
```bash
# In docker-compose.yml, update gateway environment:
LLM_BACKEND_URL: "https://api.openai.com"

# Or use environment override:
LLM_BACKEND_URL=https://api.openai.com docker-compose up
```

Your application's API key is passed through to the backend — LLM Shield reads the `Authorization` header as `Bearer <app_id>:<your_openai_key>`.

### Azure OpenAI
```bash
LLM_BACKEND_URL=https://YOUR_RESOURCE.openai.azure.com docker-compose up
```

### Local models (Ollama)
```bash
# Start Ollama separately, then:
LLM_BACKEND_URL=http://host.docker.internal:11434 docker-compose up
```

---

## Configuring policies

### Add a new application

Edit `policies/ai_access.rego`:

```rego
app_registry := {
    # Add your app here
    "my-new-app": {
        "allowed_models": ["gpt-4", "gpt-3.5-turbo"],
        "use_case_tier": "internal",
        "data_tier": "internal",
        "owner": "my-team",
    },
    # ... existing entries
}
```

OPA hot-reloads policies from the mounted volume — no restart needed.

### Use-case tiers

| Tier | Description | Allowed model types |
|---|---|---|
| `internal` | Internal tooling, no customer data | Standard models |
| `regulated` | Regulated workflows, financial data | Standard + elevated models |
| `customer-facing` | Direct customer interactions | Standard models only |

### Data tiers

| Tier | Description |
|---|---|
| `public` | Non-sensitive, publicly available data |
| `internal` | Internal business information |
| `confidential` | Sensitive business data, PII |
| `restricted` | Regulated data, PCI, PII in production |

---

## API reference

### `POST /v1/chat/completions`
OpenAI-compatible chat completions endpoint. All security controls applied.

**Headers**
```
Authorization: Bearer <app_id>:<api_key>
Content-Type: application/json
```

**Response includes `shield` metadata**
```json
{
  "choices": [...],
  "shield": {
    "policy_decision": "ALLOW",
    "pii_entities_redacted": 2,
    "injection_risk_level": "LOW",
    "latency_ms": 45
  }
}
```

### `GET /v1/audit/events?limit=50&app_id=my-app`
Query recent audit events.

### `GET /v1/audit/summary`
Aggregated security metrics across all interactions.

### `GET /v1/policies`
List currently loaded AI access policies.

### `GET /health`
Gateway health check.

---

## Project structure

```
llm-security-center/
├── gateway/
│   ├── main.py              # FastAPI application, request pipeline
│   ├── pii_scanner.py       # PII detection and tokenisation
│   ├── injection_detector.py # Prompt injection pattern analysis
│   ├── policy_engine.py     # OPA client + fallback policies
│   ├── audit.py             # Async SQLite audit vault
│   ├── Dockerfile
│   └── requirements.txt
├── mock_llm/
│   ├── main.py              # OpenAI-compatible mock backend
│   └── Dockerfile
├── policies/
│   └── ai_access.rego       # OPA Rego access control policies
├── examples/
│   └── demo.py              # Interactive scenario demo runner
├── docs/
│   └── architecture.md      # Detailed architecture documentation
├── docker-compose.yml
└── README.md
```

---

## Architecture decisions

**Why OPA?** OPA provides a vendor-neutral, declarative policy engine that separates policy from code. The same engine can govern cloud infrastructure (Terraform), Kubernetes admission, and now AI access — giving you a single policy lifecycle for your entire environment.

**Why not block at MEDIUM injection risk?** False positives in injection detection push teams toward shadow AI — direct API integrations outside any control plane. A risk-tiered response (log MEDIUM, block HIGH) maximises coverage without creating the friction that causes workarounds.

**Why tokenise rather than delete PII?** Tokenisation preserves the semantic structure of the prompt (the model still understands it is dealing with a financial account) while removing the actual sensitive values. Deletion can break prompt coherence and cause confusing model responses.

**Why log entity type, not entity value?** The audit log must serve forensic purposes without itself becoming a secondary PII store. Recording that a `CREDIT_CARD` was detected is sufficient to demonstrate the control fired — recording the actual card number would create another regulated data asset.

---

## Roadmap

- [ ] Output scanning (PII in model responses)
- [ ] Rate limiting per application
- [ ] Prometheus metrics endpoint
- [ ] Streaming response support
- [ ] OWASP LLM Top 10 mapping for each control
- [ ] Policy bundle hot-reload via OPA management API
- [ ] Web UI for audit dashboard
- [ ] NIST AI RMF control mapping documentation

---

## Contributing

Contributions welcome. Please open an issue before submitting a PR for significant changes.

Areas particularly welcome: additional injection patterns, new PII entity types, LLM backend adapters, and documentation improvements.

---

## Disclaimer

LLM Shield is a defence-in-depth security layer. No system guarantees 100% detection of adversarial inputs — prompt injection in particular remains an open research problem. This project significantly reduces your attack surface and provides an audit trail for regulatory purposes. It should be deployed as part of a broader security architecture, not as a sole control.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built to demonstrate practical AI security governance patterns for enterprise environments.*
