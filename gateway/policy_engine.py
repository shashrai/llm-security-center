"""
Policy Engine — OPA (Open Policy Agent) client for AI access control.
Author:Shashankitrai@gmail.com

Evaluates every AI request against Rego policies that define:
  - Which applications can access which models
  - Use-case classification requirements
  - Data handling tier constraints
  - Time-of-day / rate limit policies

Falls back to a local in-process policy table when OPA is unavailable
(useful for development without a running OPA instance).
"""

import json
import logging
import httpx
from typing import Optional

logger = logging.getLogger(__name__)

# ── Built-in fallback policy table (used when OPA is bypassed / unavailable) ──
# Format: app_id → { allowed_models, use_case_tier, data_tier }
FALLBACK_POLICIES: dict = {
    "demo-app": {
        "allowed_models": ["gpt-mock", "llama-mock", "*"],
        "use_case_tier": "internal",
        "data_tier": "public",
    },
    "finance-app": {
        "allowed_models": ["gpt-mock"],
        "use_case_tier": "regulated",
        "data_tier": "confidential",
    },
    "blocked-app": {
        "allowed_models": [],
        "use_case_tier": "none",
        "data_tier": "none",
    },
}

# Models that require elevated permissions
RESTRICTED_MODELS = {"gpt-4-turbo", "claude-opus", "gemini-ultra"}

# Default policy for unknown apps — deny by default (secure by default)
DEFAULT_POLICY = {
    "allowed_models": [],
    "use_case_tier": "unknown",
    "data_tier": "none",
}


class PolicyEngine:
    def __init__(self, opa_url: str, bypass: bool = False):
        self.opa_url = opa_url.rstrip("/")
        self.bypass = bypass
        self._policy_cache: dict = {}

    async def evaluate(self, app_id: str, model: str, request_context: dict) -> dict:
        """
        Evaluate whether an app is authorised to call a model.

        Returns:
            {
                "allowed": bool,
                "decision": str,
                "reason": str,
                "policy_id": str,
                "remediation": str (optional)
            }
        """
        if self.bypass:
            return self._fallback_evaluate(app_id, model, request_context)

        try:
            return await self._opa_evaluate(app_id, model, request_context)
        except Exception as e:
            logger.warning(f"OPA unreachable ({e}), falling back to local policy table")
            return self._fallback_evaluate(app_id, model, request_context)

    async def _opa_evaluate(self, app_id: str, model: str, request_context: dict) -> dict:
        input_doc = {
            "input": {
                "app_id": app_id,
                "model": model,
                "context": request_context,
            }
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{self.opa_url}/v1/data/llmshield/ai_access/allow",
                json=input_doc,
            )
            response.raise_for_status()
            result = response.json()

        allowed = result.get("result", False)
        if allowed:
            return {
                "allowed": True,
                "decision": "ALLOW",
                "reason": "Policy authorised",
                "policy_id": "ai_access/allow",
            }
        else:
            # Fetch denial reason
            try:
                deny_response = await client.post(
                    f"{self.opa_url}/v1/data/llmshield/ai_access/deny_reason",
                    json=input_doc,
                )
                deny_data = deny_response.json()
                reason = deny_data.get("result", "Policy denied — no reason provided")
            except Exception:
                reason = "Policy denied"

            return {
                "allowed": False,
                "decision": "DENY",
                "reason": reason,
                "policy_id": "ai_access/allow",
                "remediation": "Request model access via your security team or the policy self-service portal.",
            }

    def _fallback_evaluate(self, app_id: str, model: str, request_context: dict) -> dict:
        policy = FALLBACK_POLICIES.get(app_id, DEFAULT_POLICY)
        allowed_models = policy.get("allowed_models", [])

        # Wildcard allows all models
        if "*" in allowed_models:
            return {
                "allowed": True,
                "decision": "ALLOW",
                "reason": f"App '{app_id}' has wildcard model access (fallback policy)",
                "policy_id": "fallback/wildcard",
            }

        if not allowed_models:
            return {
                "allowed": False,
                "decision": "DENY",
                "reason": f"App '{app_id}' has no authorised models in policy",
                "policy_id": "fallback/no_access",
                "remediation": "Contact your administrator to configure AI model access for your application.",
            }

        if model not in allowed_models:
            return {
                "allowed": False,
                "decision": "DENY",
                "reason": f"Model '{model}' is not in the authorised list for app '{app_id}'",
                "policy_id": "fallback/model_not_allowed",
                "remediation": f"Authorised models for your app: {', '.join(allowed_models)}",
            }

        return {
            "allowed": True,
            "decision": "ALLOW",
            "reason": f"App '{app_id}' is authorised to access model '{model}'",
            "policy_id": "fallback/model_allowed",
        }

    async def list_policies(self) -> dict:
        """Return all configured policies for observability."""
        return {
            "fallback_policies": FALLBACK_POLICIES,
            "opa_url": self.opa_url,
            "opa_active": not self.bypass,
        }
