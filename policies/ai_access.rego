# LLM Shield — AI Access Control Policy
# Rego policy evaluated by OPA for every AI model request.
#
# Policy model:
#   Every application (identified by app_id) must be explicitly
#   registered in the app_registry with:
#     - allowed_models:    list of permitted model identifiers
#     - use_case_tier:     "internal" | "regulated" | "customer-facing"
#     - data_tier:         "public" | "internal" | "confidential" | "restricted"
#
# Requests are DENIED by default — no app entry = no access.
# This is the same secure-by-default principle as cloud IAM.

package llmshield.ai_access

import future.keywords.in

# ── Application registry ───────────────────────────────────────────────────────
# In production: load this from an external data bundle or OPA data API
# rather than hardcoding. See: https://www.openpolicyagent.org/docs/latest/management-bundles/

app_registry := {
    "demo-app": {
        "allowed_models": ["gpt-mock", "llama-mock"],
        "use_case_tier": "internal",
        "data_tier": "public",
        "owner": "platform-team",
    },
    "finance-app": {
        "allowed_models": ["gpt-mock"],
        "use_case_tier": "regulated",
        "data_tier": "confidential",
        "owner": "finance-team",
    },
    "analytics-app": {
        "allowed_models": ["gpt-mock", "llama-mock"],
        "use_case_tier": "internal",
        "data_tier": "internal",
        "owner": "data-team",
    },
    "customer-portal": {
        "allowed_models": ["gpt-mock"],
        "use_case_tier": "customer-facing",
        "data_tier": "restricted",
        "owner": "product-team",
    },
}

# Models that require explicit "regulated" or "restricted" clearance
elevated_models := {"gpt-4-turbo", "claude-opus", "gemini-ultra"}

# ── Main allow decision ────────────────────────────────────────────────────────

default allow := false

allow {
    # App must exist in registry
    app := app_registry[input.app_id]

    # Model must be in app's allowed list
    input.model in app.allowed_models

    # Elevated models require elevated tier clearance
    not requires_elevated_clearance_denied
}

# Elevated model check
requires_elevated_clearance_denied {
    input.model in elevated_models
    app := app_registry[input.app_id]
    not app.use_case_tier in {"regulated", "restricted"}
}

# ── Denial reasons (surfaced in API error response) ────────────────────────────

deny_reason := reason {
    not app_registry[input.app_id]
    reason := sprintf(
        "Application '%v' is not registered in the AI access policy. Contact your security team.",
        [input.app_id]
    )
}

deny_reason := reason {
    app := app_registry[input.app_id]
    not input.model in app.allowed_models
    reason := sprintf(
        "Model '%v' is not in the authorised list for application '%v'. Allowed models: %v",
        [input.model, input.app_id, app.allowed_models]
    )
}

deny_reason := reason {
    input.model in elevated_models
    app := app_registry[input.app_id]
    not app.use_case_tier in {"regulated", "restricted"}
    reason := sprintf(
        "Model '%v' requires 'regulated' or 'restricted' use-case clearance. Application '%v' has tier: '%v'",
        [input.model, input.app_id, app.use_case_tier]
    )
}

# ── Metadata for observability ─────────────────────────────────────────────────

app_metadata := meta {
    app := app_registry[input.app_id]
    meta := {
        "use_case_tier": app.use_case_tier,
        "data_tier": app.data_tier,
        "owner": app.owner,
    }
}
