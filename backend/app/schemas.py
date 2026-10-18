"""Public request and response models."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class InboundRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str = Field(default="api", min_length=1, max_length=64)
    payload: Any = None
    content: Any = None
    text: Optional[str] = Field(default=None, max_length=100_000)
    metadata: dict[str, Any] = Field(default_factory=dict)
    policy: str = Field(default="default", min_length=1, max_length=64)
    requested_action: str = Field(default="evaluate", min_length=1, max_length=64)

    @field_validator("metadata")
    @classmethod
    def metadata_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 64:
            raise ValueError("metadata may contain at most 64 keys")
        return value


class RuleMatchResponse(BaseModel):
    rule_id: str
    category: str
    severity: str
    action: str
    reason: str
    evidence: str
    taints: list[str]
    span: list[int] = Field(default_factory=lambda: [0, 0])


class LLMResponse(BaseModel):
    available: bool
    provider: str
    label: str = "unavailable"
    confidence: float = 0.0
    reason: str = ""


class EvaluationResponse(BaseModel):
    event_id: str
    decision_id: str
    decision: str
    risk_score: int
    policy: str
    reasons: list[str]
    matched_rules: list[RuleMatchResponse]
    taints: list[str]
    provenance: list[dict[str, Any]]
    normalized: dict[str, Any]
    llm: LLMResponse
    requires_approval: bool
    approval_id: Optional[str] = None
    created_at: datetime


class ApprovalActionRequest(BaseModel):
    resolved_by: str = Field(default="operator", min_length=1, max_length=128)
    note: str = Field(default="", max_length=1000)


class AgentRunRequest(InboundRequest):
    # Legacy tool-call shape. New scenario fields are optional so old clients keep working.
    tool: str = Field(default="summarize", min_length=1, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    approval_id: Optional[str] = Field(default=None, max_length=64)
    task: Optional[str] = Field(default=None, max_length=10_000)
    fixture_id: Optional[str] = Field(default=None, max_length=128)
    mode: Literal["protected", "unprotected"] = "protected"
    session_id: Optional[str] = Field(default=None, max_length=128)


class AgentRunResponse(BaseModel):
    status: str
    tool: str
    result: Any = None
    decision: EvaluationResponse
    error: Optional[str] = None


class ErrorResponse(BaseModel):
    detail: str


class ScanRequest(BaseModel):
    content: Any
    source_type: str = Field(default="api", min_length=1, max_length=64)
    source_id: Optional[str] = Field(default=None, max_length=256)
    session_id: Optional[str] = Field(default=None, max_length=128)


class ScanSignal(BaseModel):
    id: str
    category: str
    weight: int = Field(ge=0, le=100)
    span: list[int] = Field(default_factory=lambda: [0, 0], min_length=2, max_length=2)
    span_start: Optional[int] = None
    span_end: Optional[int] = None
    excerpt: str = ""


class ScanLLMResult(BaseModel):
    is_injection: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    technique: Optional[str] = None
    rationale: str = Field(default="", max_length=200)
    invoked: bool = False
    degraded: bool = False
    tokens_used: int = Field(default=0, ge=0)
    provider: str = "none"


class ScanResult(BaseModel):
    scan_id: str
    content_id: str
    source_type: str = "api"
    source_id: Optional[str] = None
    session_id: Optional[str] = None
    risk: int = Field(ge=0, le=100)
    risk_score: Optional[int] = None
    verdict: Literal["allow", "flag", "block"]
    signals: list[ScanSignal] = Field(default_factory=list)
    llm: ScanLLMResult = Field(default_factory=ScanLLMResult)
    llm_result: Optional[ScanLLMResult] = None
    stage_latency: dict[str, float] = Field(default_factory=dict)
    stage_latencies: dict[str, float] = Field(default_factory=dict)
    latency: dict[str, float] = Field(default_factory=dict)
    tokens_used: int = Field(default=0, ge=0)
    normalized: dict[str, Any] = Field(default_factory=dict)
    normalization: dict[str, Any] = Field(default_factory=dict)
    hidden_signals: list[dict[str, Any]] = Field(default_factory=list)
    hidden_signal_metadata: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ToolCallCheckRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    provenance: list[Any] = Field(default_factory=list, max_length=100)


class ToolDecision(BaseModel):
    action: Literal["allow", "block", "approve"]
    rule_id: str = "policy.default"
    reason: str = ""
    evidence: str = ""
    approval_id: Optional[str] = None
    risk: int = Field(default=0, ge=0, le=100)
    decision_id: str = ""
    alert: Optional[str] = None


class AgentScenarioRequest(BaseModel):
    task: str = Field(default="summarize the fixture", max_length=10_000)
    fixture_id: str = Field(min_length=1, max_length=128)
    mode: Literal["protected", "unprotected"] = "protected"
    session_id: Optional[str] = Field(default=None, max_length=128)


class AgentScenarioResponse(BaseModel):
    session_id: str
    status: str
    mode: str
    fixture_id: str
    scan_result: Optional[ScanResult] = None
    outbox_id: Optional[str] = None
    tool_decision: Optional[ToolDecision] = None
    events: list[str] = Field(default_factory=list)


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approve", "deny"]
    resolved_by: str = Field(default="operator", min_length=1, max_length=128)
    note: str = Field(default="", max_length=1000)
