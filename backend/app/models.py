"""Persistent audit and approval records."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, unique=True, max_length=64)
    event_type: str = Field(index=True, max_length=64)
    decision_id: Optional[str] = Field(default=None, index=True, max_length=64)
    source: str = Field(default="api", index=True, max_length=64)
    action: str = Field(default="evaluate", max_length=64)
    decision: str = Field(default="allow", index=True, max_length=16)
    risk_score: int = Field(default=0, index=True)
    policy: str = Field(default="default", max_length=64)
    payload_json: str = "{}"
    provenance_json: str = "[]"
    matched_rules_json: str = "[]"
    created_at: datetime = Field(default_factory=utc_now, index=True)


class Approval(SQLModel, table=True):
    approval_id: str = Field(primary_key=True, max_length=64)
    decision_id: str = Field(index=True, max_length=64)
    status: str = Field(default="pending", index=True, max_length=16)
    reason: str = ""
    requested_by: str = Field(default="aegis-gate", max_length=128)
    resolved_by: Optional[str] = Field(default=None, max_length=128)
    resolution_note: Optional[str] = None
    requested_at: datetime = Field(default_factory=utc_now, index=True)
    resolved_at: Optional[datetime] = None
    context_json: str = "{}"


class OutboxMessage(SQLModel, table=True):
    outbox_id: str = Field(primary_key=True, max_length=64)
    session_id: str = Field(index=True, max_length=128)
    recipient: str = Field(max_length=320)
    subject: str = Field(default="", max_length=500)
    body: str = ""
    status: str = Field(default="queued", index=True, max_length=32)
    tool: str = Field(default="send_email", max_length=64)
    created_at: datetime = Field(default_factory=utc_now, index=True)


class BenchmarkRun(SQLModel, table=True):
    run_id: str = Field(primary_key=True, max_length=64)
    metrics_json: str = "{}"
    created_at: datetime = Field(default_factory=utc_now, index=True)
