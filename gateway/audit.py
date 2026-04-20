"""
Audit Vault — immutable append-only audit log for all AI interactions.
Author:Shashankitrai@gmail.com
Every request through LLM Shield is recorded:
  - Application identity
  - Model called
  - Timestamp
  - Policy decision (ALLOW / DENY)
  - PII entity types detected (NOT values — data minimisation)
  - Injection risk level and matched pattern names
  - Whether the request was blocked and why
  - End-to-end latency

The vault is queryable via the /v1/audit/events API endpoint,
enabling real-time compliance reporting without manual log trawling.
"""

import json
import time
import logging
import aiosqlite
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id          TEXT    NOT NULL,
    model           TEXT    NOT NULL,
    timestamp       REAL    NOT NULL,
    policy_decision TEXT,
    pii_detections  TEXT,       -- JSON array of {entity_type, score}
    injection_risk  TEXT,       -- JSON object {level, score, patterns}
    blocked         INTEGER NOT NULL DEFAULT 0,
    block_reason    TEXT,
    latency_ms      INTEGER,
    created_at      TEXT    DEFAULT (datetime('now'))
);
"""

CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_audit_app_id ON audit_events(app_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_blocked ON audit_events(blocked);
"""


class AuditVault:
    def __init__(self, db_path: str = "/data/audit.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(CREATE_TABLE)
            for stmt in CREATE_INDEX.strip().split(";"):
                if stmt.strip():
                    await db.execute(stmt)
            await db.commit()
        logger.info(f"✅ Audit vault initialised at {self.db_path}")

    async def write(self, event: dict):
        """Append an audit event. Never raises — audit failures are logged but not propagated."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """
                    INSERT INTO audit_events
                        (app_id, model, timestamp, policy_decision,
                         pii_detections, injection_risk, blocked, block_reason, latency_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.get("app_id", "unknown"),
                        event.get("model", "unknown"),
                        event.get("timestamp", time.time()),
                        event.get("policy_decision"),
                        json.dumps(event.get("pii_detections", [])),
                        json.dumps(event.get("injection_risk")),
                        1 if event.get("blocked") else 0,
                        event.get("block_reason"),
                        event.get("latency_ms"),
                    ),
                )
                await db.commit()
        except Exception as e:
            logger.error(f"Audit write failed: {e}")

    async def query(self, limit: int = 50, app_id: Optional[str] = None) -> list[dict]:
        """Query recent audit events."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if app_id:
                cursor = await db.execute(
                    "SELECT * FROM audit_events WHERE app_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (app_id, limit),
                )
            else:
                cursor = await db.execute(
                    "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                )
            rows = await cursor.fetchall()

        events = []
        for row in rows:
            e = dict(row)
            e["pii_detections"] = json.loads(e["pii_detections"] or "[]")
            e["injection_risk"] = json.loads(e["injection_risk"] or "null")
            e["blocked"] = bool(e["blocked"])
            events.append(e)
        return events

    async def summary(self) -> dict:
        """Return aggregated security metrics."""
        async with aiosqlite.connect(self.db_path) as db:
            total = (await (await db.execute("SELECT COUNT(*) FROM audit_events")).fetchone())[0]
            blocked = (await (await db.execute("SELECT COUNT(*) FROM audit_events WHERE blocked = 1")).fetchone())[0]
            pii_events = (await (await db.execute(
                "SELECT COUNT(*) FROM audit_events WHERE pii_detections != '[]'"
            )).fetchone())[0]
            high_injection = (await (await db.execute(
                "SELECT COUNT(*) FROM audit_events WHERE injection_risk LIKE '%\"HIGH\"%'"
            )).fetchone())[0]
            top_apps = await (await db.execute(
                "SELECT app_id, COUNT(*) as calls FROM audit_events GROUP BY app_id ORDER BY calls DESC LIMIT 10"
            )).fetchall()

        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "block_rate_pct": round((blocked / total * 100) if total else 0, 1),
            "requests_with_pii": pii_events,
            "high_injection_attempts": high_injection,
            "top_applications": [{"app_id": r[0], "calls": r[1]} for r in top_apps],
        }
