# Connecting a Real LLM

By default LLM Shield runs against a local mock LLM — no API key required.
This guide shows how to connect a real model once you have verified the
security controls are working.

## OpenAI

```bash
# Option 1: environment variable override
LLM_BACKEND_URL=https://api.openai.com docker-compose up

# Option 2: edit docker-compose.yml
# Under gateway > environment > LLM_BACKEND_URL: "https://api.openai.com"
```

In your application, use your OpenAI API key as the second part of the
Bearer token:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="my-app-id:sk-your-openai-key",
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarise our Q3 results."}],
)
```

LLM Shield forwards the key to OpenAI and returns the response — with
security controls applied transparently.

## Azure OpenAI

```bash
LLM_BACKEND_URL=https://YOUR_RESOURCE.openai.azure.com docker-compose up
```

Your application uses the standard Azure OpenAI SDK pointed at the gateway.

## Anthropic Claude

The gateway forwards OpenAI-format requests. For Anthropic's native API
format, a thin adapter is needed (see `docs/adapters/` — roadmap item).
The simplest current approach is to use an OpenAI-compatible Anthropic
proxy in front of the Anthropic API.

## Local models (Ollama)

```bash
# Start Ollama with your preferred model
ollama pull llama3

# Point the gateway at it
LLM_BACKEND_URL=http://host.docker.internal:11434 docker-compose up
```

Use `host.docker.internal` to reach a process on your host machine from
inside the Docker network.

## Verifying the connection

After changing the backend, run the safe scenario to confirm end-to-end:

```bash
python examples/demo.py --scenario safe
```

A successful response includes the `shield` metadata block plus a real
model response in `choices[0].message.content`.

## Registering your application in policy

Before sending requests from a new application, add it to the policy registry.

**For development (local fallback policy):**

Edit `gateway/policy_engine.py`, `FALLBACK_POLICIES`:

```python
FALLBACK_POLICIES = {
    "your-app-id": {
        "allowed_models": ["gpt-4o", "gpt-3.5-turbo"],
        "use_case_tier": "internal",
        "data_tier": "internal",
    },
    # ...
}
```

**For production (OPA):**

Edit `policies/ai_access.rego`, `app_registry`:

```rego
app_registry := {
    "your-app-id": {
        "allowed_models": ["gpt-4o"],
        "use_case_tier": "internal",
        "data_tier": "internal",
        "owner": "your-team",
    },
    # ...
}
```

OPA hot-reloads from the mounted volume — no restart needed.

Then send requests with your app ID in the Authorization header:

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer your-app-id:your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}'
```
