"""
Author:Shashankitrai@gmail.com
LLM Shield — AI Security Gateway
OpenAI-compatible proxy that enforces policy, PII protection,
injection detection, and audit logging on every AI request.
"""

import os
import time
import json
import httpx
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from pii_scanner import PIIScanner
from injection_detector import InjectionDetector
from policy_engine import PolicyEngine
from audit import AuditVault

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
LLM_BACKEND_URL = os.getenv("LLM_BACKEND_URL", "http://mock-llm:8001")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
AUDIT_DB = os.getenv("AUDIT_DB_PATH", "/data/audit.db")
BYPASS_OPA = os.getenv("BYPASS_OPA", "false").lower() == "true"

# ── App lifecycle ─────────────────────────────────────────────────────────────
pii_scanner: PIIScanner = None
injection_detector: InjectionDetector = None
policy_engine: PolicyEngine = None
audit_vault: AuditVault = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global pii_scanner, injection_detector, policy_engine, audit_vault
    logger.info("🛡  LLM Shield starting up...")
    pii_scanner = PIIScanner()
    injection_detector = InjectionDetector()
    policy_engine = PolicyEngine(opa_url=OPA_URL, bypass=BYPASS_OPA)
    audit_vault = AuditVault(db_path=AUDIT_DB)
    await audit_vault.init()
    logger.info("✅ All security components initialised")
    yield
    logger.info("LLM Shield shutting down")

app = FastAPI(
    title="LLM Shield",
    description="AI Security Gateway — OpenAI-compatible proxy with policy enforcement, PII protection, and audit logging",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request model (OpenAI-compatible) ─────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1000
    stream: Optional[bool] = False

# ── Auth helper ───────────────────────────────────────────────────────────────
def extract_app_identity(request: Request) -> dict:
    """
    Extract application identity from the Authorization header.
    Format: Bearer <app_id>:<api_key>
    Falls back to 'unknown-app' if not provided (useful for demos).
    """
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        parts = token.split(":", 1)
        if len(parts) == 2:
            return {"app_id": parts[0], "api_key": parts[1]}
        return {"app_id": token, "api_key": ""}
    return {"app_id": "demo-app", "api_key": "demo"}

# ── Main chat completions endpoint ────────────────────────────────────────────
@app.post("/v1/chat/completions")
async def chat_completions(request: Request, body: ChatCompletionRequest):
    start_time = time.time()
    identity = extract_app_identity(request)
    app_id = identity["app_id"]

    audit_event = {
        "app_id": app_id,
        "model": body.model,
        "timestamp": time.time(),
        "policy_decision": None,
        "pii_detections": [],
        "injection_risk": None,
        "blocked": False,
        "block_reason": None,
        "latency_ms": None,
    }

    try:
        # ── LAYER 1: Policy authorisation ─────────────────────────────────────
        logger.info(f"[{app_id}] Policy check → model={body.model}")
        policy_result = await policy_engine.evaluate(
            app_id=app_id,
            model=body.model,
            request_context={"message_count": len(body.messages)},
        )
        audit_event["policy_decision"] = policy_result["decision"]

        if not policy_result["allowed"]:
            audit_event["blocked"] = True
            audit_event["block_reason"] = f"policy_deny: {policy_result['reason']}"
            await audit_vault.write(audit_event)
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "policy_violation",
                    "message": policy_result["reason"],
                    "policy": policy_result.get("policy_id"),
                    "remediation": policy_result.get("remediation", "Contact your security team to request model access."),
                },
            )

        # ── LAYER 2: PII scanning & sanitisation ─────────────────────────────
        logger.info(f"[{app_id}] PII scan starting")
        sanitised_messages = []
        all_detections = []

        for msg in body.messages:
            if msg.role in ("user", "system"):
                scan_result = pii_scanner.scan_and_sanitise(msg.content)
                sanitised_messages.append(
                    ChatMessage(role=msg.role, content=scan_result["sanitised_text"])
                )
                all_detections.extend(scan_result["detections"])
            else:
                sanitised_messages.append(msg)

        audit_event["pii_detections"] = [
            {"entity_type": d["entity_type"], "score": d["score"]}
            for d in all_detections
        ]

        if all_detections:
            logger.warning(
                f"[{app_id}] PII detected and sanitised: "
                + ", ".join(set(d["entity_type"] for d in all_detections))
            )

        # ── LAYER 3: Prompt injection detection ───────────────────────────────
        logger.info(f"[{app_id}] Injection detection starting")
        user_messages = [m.content for m in sanitised_messages if m.role == "user"]
        combined_user_input = " ".join(user_messages)

        injection_result = injection_detector.analyse(combined_user_input)
        audit_event["injection_risk"] = {
            "level": injection_result["risk_level"],
            "score": injection_result["score"],
            "patterns": injection_result["matched_patterns"],
        }

        if injection_result["risk_level"] == "HIGH":
            audit_event["blocked"] = True
            audit_event["block_reason"] = f"injection_blocked: {injection_result['matched_patterns']}"
            await audit_vault.write(audit_event)
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "prompt_injection_detected",
                    "message": "Your request was blocked due to detected prompt injection patterns.",
                    "risk_level": "HIGH",
                    "patterns": injection_result["matched_patterns"],
                },
            )

        if injection_result["risk_level"] == "MEDIUM":
            logger.warning(
                f"[{app_id}] Medium injection risk — forwarding with enhanced logging. "
                f"Patterns: {injection_result['matched_patterns']}"
            )

        # ── LAYER 4: Forward to LLM backend ───────────────────────────────────
        logger.info(f"[{app_id}] Forwarding sanitised request to LLM backend")
        payload = {
            "model": body.model,
            "messages": [{"role": m.role, "content": m.content} for m in sanitised_messages],
            "temperature": body.temperature,
            "max_tokens": body.max_tokens,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{LLM_BACKEND_URL}/v1/chat/completions",
                json=payload,
            )
            response.raise_for_status()
            llm_response = response.json()

        # ── Enrich response with shield metadata ──────────────────────────────
        latency_ms = round((time.time() - start_time) * 1000)
        audit_event["latency_ms"] = latency_ms
        await audit_vault.write(audit_event)

        llm_response["shield"] = {
            "policy_decision": policy_result["decision"],
            "pii_entities_redacted": len(all_detections),
            "injection_risk_level": injection_result["risk_level"],
            "latency_ms": latency_ms,
        }

        return JSONResponse(content=llm_response)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{app_id}] Unexpected error: {e}", exc_info=True)
        audit_event["blocked"] = True
        audit_event["block_reason"] = f"internal_error: {str(e)}"
        try:
            await audit_vault.write(audit_event)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail={"error": "internal_error", "message": str(e)})


# ── Health & observability endpoints ─────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "llm-shield", "version": "1.0.0"}

@app.get("/v1/audit/events")
async def get_audit_events(limit: int = 50, app_id: Optional[str] = None):
    """Retrieve recent audit events — useful for compliance reporting."""
    events = await audit_vault.query(limit=limit, app_id=app_id)
    return {"events": events, "count": len(events)}

@app.get("/v1/audit/summary")
async def get_audit_summary():
    """Aggregated security metrics across all AI interactions."""
    return await audit_vault.summary()

@app.get("/v1/policies")
async def list_policies():
    """List currently loaded AI access policies."""
    return await policy_engine.list_policies()
