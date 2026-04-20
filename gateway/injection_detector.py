"""
Prompt Injection Detector
Author:Shashankitrai@gmail.com

Analyses prompt text for adversarial injection patterns using a
multi-signal scoring approach:

  - Instruction override patterns   (jailbreaks, role resets)
  - System prompt extraction attempts
  - Role escalation / persona hijacking
  - Indirect injection markers (for RAG workflows)
  - Encoding obfuscation attempts

Risk levels:
  HIGH   (score >= 0.75) → auto-block
  MEDIUM (score >= 0.40) → flag + enhanced logging, allow
  LOW    (score <  0.40) → pass through

Design rationale: we deliberately DO NOT block at MEDIUM to avoid
false-positive friction that drives shadow AI workarounds. Logs give
us the signal to tune the blocking threshold over time.
"""

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class InjectionPattern:
    name: str
    pattern: str
    weight: float          # 0.0–1.0 contribution to risk score
    risk_tier: str         # "HIGH", "MEDIUM", "LOW"
    description: str


# ── Pattern library ───────────────────────────────────────────────────────────
INJECTION_PATTERNS: list[InjectionPattern] = [

    # ── Direct instruction overrides ─────────────────────────────────────────
    InjectionPattern(
        name="ignore_instructions",
        pattern=r"\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|rules?|guidelines?|constraints?|prompt)\b",
        weight=0.90,
        risk_tier="HIGH",
        description="Direct attempt to override system instructions",
    ),
    InjectionPattern(
        name="new_instructions",
        pattern=r"\b(?:your\s+new\s+(?:instructions?|task|role|directive)|from\s+now\s+on\s+you\s+(?:will|must|shall)|new\s+system\s+prompt)\b",
        weight=0.85,
        risk_tier="HIGH",
        description="Attempt to inject replacement instructions",
    ),
    InjectionPattern(
        name="developer_mode",
        pattern=r"\b(?:developer\s+mode|DAN\s+mode|jailbreak\s+mode|unrestricted\s+mode|god\s+mode|no\s+restrictions?\s+mode)\b",
        weight=0.95,
        risk_tier="HIGH",
        description="Known jailbreak mode activation attempts",
    ),

    # ── System prompt extraction ──────────────────────────────────────────────
    InjectionPattern(
        name="extract_system_prompt",
        pattern=r"\b(?:repeat|print|show|reveal|output|display|tell\s+me|what\s+(?:is|was|are))\s+(?:your\s+)?(?:system\s+prompt|instructions?|initial\s+prompt|original\s+prompt|full\s+prompt)\b",
        weight=0.85,
        risk_tier="HIGH",
        description="Attempt to extract system prompt content",
    ),
    InjectionPattern(
        name="prompt_leak",
        pattern=r"\b(?:what\s+were\s+you\s+told|what\s+(?:are|were)\s+your\s+(?:exact\s+)?instructions?|summarise\s+your\s+(?:system\s+)?prompt)\b",
        weight=0.80,
        risk_tier="HIGH",
        description="Indirect system prompt leakage attempt",
    ),

    # ── Role escalation / persona hijacking ───────────────────────────────────
    InjectionPattern(
        name="role_escalation",
        pattern=r"\byou\s+(?:are\s+now|will\s+now\s+be|must\s+act\s+as|should\s+pretend\s+to\s+be)\s+(?:a\s+)?(?:different|new|another|evil|unrestricted|uncensored)\b",
        weight=0.80,
        risk_tier="HIGH",
        description="Attempt to replace model persona",
    ),
    InjectionPattern(
        name="act_as",
        pattern=r"\bact\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a\s+)?(?:hacker|malicious|evil|uncensored|unrestricted|human\s+without\s+restrictions?)\b",
        weight=0.85,
        risk_tier="HIGH",
        description="Persona hijacking to bypass restrictions",
    ),

    # ── Indirect injection (RAG / document injection) ─────────────────────────
    InjectionPattern(
        name="indirect_injection_marker",
        pattern=r"(?:\[INST\]|\[SYSTEM\]|\[OVERRIDE\]|<\|system\|>|<\|user\|>|\{\{JAILBREAK\}\}|<!-- inject)",
        weight=0.90,
        risk_tier="HIGH",
        description="Known indirect injection delimiters used in RAG attacks",
    ),
    InjectionPattern(
        name="hidden_instruction",
        pattern=r"(?:<!--.*?(?:ignore|override|inject).*?-->|/\*.*?(?:ignore|system|override).*?\*/)",
        weight=0.75,
        risk_tier="HIGH",
        description="HTML/code comment used to hide instructions",
    ),

    # ── Encoding obfuscation ──────────────────────────────────────────────────
    InjectionPattern(
        name="base64_instruction",
        pattern=r"\b(?:decode|base64|rot13|cipher)\s+(?:this|the\s+following|below)\b",
        weight=0.65,
        risk_tier="MEDIUM",
        description="Possible encoding obfuscation to bypass detection",
    ),
    InjectionPattern(
        name="unicode_smuggling",
        pattern=r"[\u200b\u200c\u200d\u2060\ufeff]",  # zero-width characters
        weight=0.80,
        risk_tier="HIGH",
        description="Zero-width Unicode characters used for instruction smuggling",
    ),

    # ── Moderate risk signals ─────────────────────────────────────────────────
    InjectionPattern(
        name="hypothetical_framing",
        pattern=r"\b(?:hypothetically|in\s+a\s+fictional\s+world|for\s+a\s+story|imagine\s+you\s+(?:have\s+no|could\s+bypass))\b",
        weight=0.40,
        risk_tier="MEDIUM",
        description="Hypothetical framing to lower model guardrails",
    ),
    InjectionPattern(
        name="sudo_admin",
        pattern=r"\b(?:sudo|admin\s+mode|root\s+access|as\s+(?:an?\s+)?(?:admin|administrator|superuser|root))\b",
        weight=0.50,
        risk_tier="MEDIUM",
        description="Admin/privilege escalation language",
    ),
    InjectionPattern(
        name="training_data_reference",
        pattern=r"\b(?:you\s+were\s+trained|your\s+training\s+data|update\s+your\s+(?:training|weights|parameters))\b",
        weight=0.45,
        risk_tier="MEDIUM",
        description="References to model training — potential manipulation",
    ),
]

# Pre-compile all patterns
for p in INJECTION_PATTERNS:
    p._compiled = re.compile(p.pattern, re.IGNORECASE | re.DOTALL)


def analyse(text: str) -> dict:
    """
    Analyse text for prompt injection signals.

    Returns:
        {
            "risk_level": "LOW" | "MEDIUM" | "HIGH",
            "score": float (0.0–1.0),
            "matched_patterns": [str],
            "details": [{"pattern": str, "weight": float, "tier": str}]
        }
    """
    if not text or not text.strip():
        return {"risk_level": "LOW", "score": 0.0, "matched_patterns": [], "details": []}

    matched = []
    total_score = 0.0

    for p in INJECTION_PATTERNS:
        if p._compiled.search(text):
            matched.append(p)
            total_score += p.weight

    if not matched:
        return {"risk_level": "LOW", "score": 0.0, "matched_patterns": [], "details": []}

    # Cap score at 1.0 — multiple signals don't push beyond max
    capped_score = min(total_score, 1.0)

    # Any single HIGH-tier pattern above its weight threshold is immediately HIGH
    has_high_pattern = any(p.risk_tier == "HIGH" for p in matched)

    if capped_score >= 0.75 or (has_high_pattern and capped_score >= 0.55):
        risk_level = "HIGH"
    elif capped_score >= 0.40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if matched:
        logger.info(
            f"Injection detection: level={risk_level} score={capped_score:.2f} "
            f"patterns={[p.name for p in matched]}"
        )

    return {
        "risk_level": risk_level,
        "score": round(capped_score, 3),
        "matched_patterns": [p.name for p in matched],
        "details": [
            {"pattern": p.name, "weight": p.weight, "tier": p.risk_tier, "description": p.description}
            for p in matched
        ],
    }


class InjectionDetector:
    """Class wrapper for use in dependency injection."""
    def analyse(self, text: str) -> dict:
        return analyse(text)
