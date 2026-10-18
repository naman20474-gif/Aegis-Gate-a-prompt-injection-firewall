"""Orchestration for normalize -> rules -> LLM -> score -> policy -> audit."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


from ..events import EventBus
from ..models import Approval, AuditEvent
from ..policy import PolicyEngine
from ..schemas import EvaluationResponse, InboundRequest, LLMResponse, RuleMatchResponse
from .llm import LLMClient
from .normalize import NormalizedInput, _safe_preview, normalize_inbound
from .rules import RuleEngine, RuleMatch
from .scoring import score_risk

logger = logging.getLogger(__name__)


@dataclass
class EvaluationResult:
    response: EvaluationResponse
    normalized_input: NormalizedInput
    matches: list[RuleMatch]


class EvaluationService:
    def __init__(
        self, *, session_factory: Any, policy_engine: PolicyEngine, rule_engine: RuleEngine,
        llm_client: LLMClient, event_bus: EventBus, max_text_chars: int = 100_000,
    ):
        self.session_factory = session_factory
        self.policy_engine = policy_engine
        self.rule_engine = rule_engine
        self.llm_client = llm_client
        self.event_bus = event_bus
        self.max_text_chars = max_text_chars

    def evaluate(
        self, request: InboundRequest | dict[str, Any] | Any, *, persist: bool = True,
        event_type: str = "evaluation", requested_action: str | None = None,
    ) -> EvaluationResult:
        if not isinstance(request, InboundRequest):
            request = InboundRequest.model_validate(request)
        payload = request.payload
        if payload is None:
            payload = {}
        if request.content is not None:
            payload = {"payload": payload, "content": request.content}
        if request.text is not None:
            payload = {"payload": payload, "text": request.text}
        if request.metadata:
            payload = {"payload": payload, "metadata": request.metadata}
        extra = getattr(request, "model_extra", None) or {}
        if extra:
            payload = {"payload": payload, "extra": extra}
        normalized = normalize_inbound(
            payload, source=request.source, max_text_chars=self.max_text_chars,
        )
        matches = self.rule_engine.evaluate(normalized)
        try:
            llm = self.llm_client.analyze(
                normalized.text, provenance=[record.as_dict() for record in normalized.provenance],
            )
        except Exception as exc:  # custom clients must not turn the gateway into an outage.
            logger.warning("llm adapter failed; continuing deterministically", extra={"fields": {"error": type(exc).__name__}})
            llm = LLMResponse(available=False, provider="error-failsafe", reason=type(exc).__name__)
        risk = score_risk(matches, normalized.taints, llm)
        action = requested_action or request.requested_action
        policy_decision = self.policy_engine.evaluate(request.policy, risk, matches, normalized.taints, requested_action=action)
        # A configured LLM is a second opinion: an explicit unsafe label fails closed,
        # while an unavailable/error response never overrides deterministic policy.
        if llm.available and llm.label == "deny" and policy_decision.decision != "deny":
            policy_decision = replace(
                policy_decision, decision="deny", requires_approval=False,
                reasons=tuple(dict.fromkeys((*policy_decision.reasons, "LLM second opinion classified input as deny"))),
            )
        elif llm.available and llm.label == "review" and policy_decision.decision == "allow":
            policy_decision = replace(
                policy_decision, decision="review", requires_approval=True,
                reasons=tuple(dict.fromkeys((*policy_decision.reasons, "LLM second opinion requested review"))),
            )
        event_id = f"evt_{uuid4().hex}"
        decision_id = f"dec_{uuid4().hex}"
        approval_id: str | None = None
        now = datetime.now(timezone.utc)
        if persist and policy_decision.requires_approval:
            approval_id = f"apr_{uuid4().hex}"
            with self.session_factory() as session:  # type: ignore[operator]
                session.add(Approval(
                    approval_id=approval_id, decision_id=decision_id, status="pending",
                    reason="; ".join(policy_decision.reasons), requested_by=request.source,
                    context_json=json.dumps({
                        "policy": request.policy, "risk_score": risk, "action": action,
                        "input_sha256": hashlib.sha256(normalized.text.encode("utf-8")).hexdigest(),
                    }),
                ))
                session.commit()
        response = EvaluationResponse(
            event_id=event_id, decision_id=decision_id, decision=policy_decision.decision, risk_score=risk,
            policy=self.policy_engine.get(request.policy).name, reasons=list(policy_decision.reasons),
            matched_rules=[RuleMatchResponse(**match.as_dict()) for match in matches], taints=normalized.taints,
            provenance=[record.as_dict() for record in normalized.provenance], normalized=normalized.as_dict(),
            llm=llm, requires_approval=policy_decision.requires_approval, approval_id=approval_id, created_at=now,
        )
        if persist:
            self._audit(response, request, normalized, matches)
            self.event_bus.publish(event_type, response.model_dump(mode="json"))
        return EvaluationResult(response=response, normalized_input=normalized, matches=matches)

    def _audit(self, response: EvaluationResponse, request: InboundRequest, normalized: NormalizedInput, matches: list[RuleMatch]) -> None:
        record = AuditEvent(
            event_id=response.event_id, event_type="evaluation", decision_id=response.decision_id,
            source=request.source, action=request.requested_action, decision=response.decision,
            risk_score=response.risk_score, policy=response.policy,
            payload_json=json.dumps(
                {
                    **normalized.as_dict(),
                    "text": _safe_preview(normalized.text, 2_000),
                    "fields": {record.path: record.preview for record in normalized.provenance},
                },
                default=str,
            ),
            provenance_json=json.dumps(response.provenance, default=str),
            matched_rules_json=json.dumps([match.as_dict() for match in matches], default=str),
        )
        with self.session_factory() as session:  # type: ignore[operator]
            session.add(record)
            session.commit()

    def recent_audit(self, *, limit: int = 50, decision: str | None = None) -> list[AuditEvent]:
        from sqlmodel import select

        with self.session_factory() as session:  # type: ignore[operator]
            statement = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(max(1, min(limit, 250)))
            if decision:
                statement = select(AuditEvent).where(AuditEvent.decision == decision).order_by(AuditEvent.created_at.desc()).limit(max(1, min(limit, 250)))
            return list(session.exec(statement).all())
