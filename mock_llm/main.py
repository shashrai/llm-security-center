"""
Author:Shashankitrai@gmail.com

Mock LLM — OpenAI-compatible mock backend for offline testing.

Allows the full LLM Shield pipeline to run locally without an API key.
Returns contextually aware responses to help demonstrate security scenarios.
"""

import time
import uuid
import re
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Mock LLM", description="OpenAI-compatible mock for LLM Shield testing")

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1000

# Simple response heuristics based on user message content
def generate_response(messages: list[ChatMessage], model: str) -> str:
    user_msgs = [m.content for m in messages if m.role == "user"]
    last_user_msg = user_msgs[-1] if user_msgs else ""
    lower = last_user_msg.lower()

    # Detect redacted PII tokens in prompt (shows sanitisation worked)
    if "<REDACTED:" in last_user_msg:
        return (
            "I notice some information in your message has been redacted for privacy protection. "
            "I can still help with your request — could you provide the information you need "
            "assistance with in a way that doesn't include sensitive personal data? "
            f"[Responded by Mock LLM model: {model}]"
        )

    # General knowledge questions
    if any(kw in lower for kw in ["what is", "explain", "how does", "tell me about"]):
        topic = re.sub(r"(what is|explain|how does|tell me about)\s+", "", lower).strip("?").strip()
        return (
            f"Here is a helpful explanation about {topic}. "
            f"This is a simulated response from the Mock LLM ({model}). "
            "In a real deployment, this would be replaced by an actual language model response. "
            "The key thing demonstrated here is that your prompt passed through all LLM Shield "
            "security layers — policy check, PII scan, and injection detection — before reaching this point."
        )

    # Help/support queries
    if any(kw in lower for kw in ["help", "assist", "support", "how can"]):
        return (
            f"I'm happy to help! This response comes from Mock LLM ({model}). "
            "Your message successfully passed through the LLM Shield security gateway, "
            "which means it was policy-authorised, scanned for PII, and checked for injection patterns. "
            "How can I assist you today?"
        )

    # Default response
    return (
        f"Thank you for your message. This is a response from Mock LLM (model: {model}). "
        "Your request was processed through the LLM Shield security control plane. "
        "All security checks passed: policy authorisation ✓, PII scan ✓, injection detection ✓. "
        "In production, swap the LLM_BACKEND_URL to point at your actual LLM endpoint."
    )

@app.post("/v1/chat/completions")
async def chat_completions(body: ChatRequest):
    response_text = generate_response(body.messages, body.model)
    completion_id = f"chatcmpl-mock-{uuid.uuid4().hex[:8]}"

    return {
        "id": completion_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": response_text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": sum(len(m.content.split()) for m in body.messages),
            "completion_tokens": len(response_text.split()),
            "total_tokens": sum(len(m.content.split()) for m in body.messages) + len(response_text.split()),
        },
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "mock-llm"}
