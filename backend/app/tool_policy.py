"""Session-aware declarative tool policy and fake tool execution."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from sqlmodel import select

from .events import EventBus
from .models import Approval, AuditEvent, OutboxMessage
from .pipeline.normalize import normalize_inbound
from .pipeline.rules import RuleEngine
from .pipeline.scoring import score_risk
from .policy import PolicyEngine
from .scan import SessionStore
from .schemas import ToolCallCheckRequest, ToolDecision
from .agent.tools import read_fixture

logger = logging.getLogger(__name__)
_EMAIL = re.compile(r"^[^@\s]+@(?P<domain>[^@\s]+)$")


class ToolPolicyService:
    def __init__(
        self,
        *,
        session_factory: Any,
        policy_engine: PolicyEngine,
        rule_engine: RuleEngine,
        session_store: SessionStore,
        event_bus: EventBus,
    ) -> None:
        self.session_factory = session_factory
        self.policy_engine = policy_engine
        self.rule_engine = rule_engine
        self.session_store = session_store
        self.event_bus = event_bus

    def policy_document(self) -> dict[str, Any]:
        return self.policy_engine.raw("default")

    def _tool_config(self, tool: str) -> dict[str, Any]:
        document = self.policy_document()
        policies = document.get("tool_policies", {})
        value = policies.get(tool, {}) if isinstance(policies, dict) else {}
        return value if isinstance(value, dict) else {}

    def _global_config(self) -> dict[str, Any]:
        value = self.policy_document().get("global", {})
        return value if isinstance(value, dict) else {}

    def check(self, request: ToolCallCheckRequest | dict[str, Any], *, persist: bool = True) -> ToolDecision:
        if not isinstance(request, ToolCallCheckRequest):
            request = ToolCallCheckRequest.model_validate(request)
        normalized_provenance = [
            item if isinstance(item, dict) else {"content_id": str(item)}
            for item in request.provenance
        ]
        request = request.model_copy(update={"provenance": normalized_provenance})
        decision_id = f"tool_{uuid4().hex}"
        args_text = json.dumps(request.args, ensure_ascii=False, sort_keys=True, default=str)
        normalized = normalize_inbound({"tool": request.tool, "args": request.args}, source="tool")
        matches = self.rule_engine.evaluate(normalized)
        risk = score_risk(matches, normalized.taints)
        untrusted, provenance_risk, content_ids = self.session_store.resolve(request.session_id, request.provenance)
        risk = max(risk, provenance_risk)
        for item in request.provenance:
            verdict = str(item.get("verdict", "")).lower()
            if verdict == "block":
                risk = max(risk, 80)
            elif verdict in {"flag", "review"}:
                # Keep the caller/session risk; the policy threshold is explicit.
                risk = max(risk, int(item.get("risk", item.get("risk_score", 0)) or 0))
        evidence = args_text[:500]
        global_config = self._global_config()
        canary = str(global_config.get("canary_token", "CANARY-7731"))
        if canary and (
            canary in args_text
            or any(canary in json.dumps(item, default=str) for item in request.provenance)
            or self.session_store.contains_token(request.session_id, content_ids, canary)
        ):
            return self._finish(
                request, decision_id, "block", "global.canary_token",
                "Canary token detected: block and raise a critical alert.", canary, risk=100,
                persist=persist, content_ids=content_ids, alert="critical",
            )

        tool = request.tool
        if tool == "send_email":
            config = self._tool_config(tool)
            domains = {str(value).lower() for value in config.get("recipient_domain_allowlist", config.get("recipient_domain_approval_allowlist", [])) or []}
            deny_if = config.get("deny_if", {}) if isinstance(config.get("deny_if", {}), dict) else {}
            deny_risk = int(config.get("deny_untrusted_risk_gte", deny_if.get("risk_gte", 30)))
            recipient = str(request.args.get("recipient", request.args.get("to", "")))
            match = _EMAIL.match(recipient)
            domain = match.group("domain").lower() if match else ""
            if untrusted and risk >= deny_risk:
                return self._finish(
                    request, decision_id, "block", "tool.send_email.untrusted_content",
                    "Untrusted provenance cannot send email at this risk.",
                    f"risk={risk}; content_ids={','.join(content_ids) or 'inline'}", risk=risk,
                    persist=persist, content_ids=content_ids,
                )
            if not domain or domain not in domains:
                return self._finish(
                    request, decision_id, "approve", "tool.send_email.recipient_domain",
                    "Recipient domain requires operator approval.", domain or "missing recipient domain", risk=risk,
                    persist=persist, content_ids=content_ids,
                )
            return self._finish(
                request, decision_id, "allow", "tool.send_email.allowlisted",
                "Email recipient and provenance satisfy the declarative policy.", domain, risk=risk,
                persist=persist, content_ids=content_ids,
            )

        if tool == "read_file":
            path_value = str(request.args.get("path", request.args.get("name", "")))
            config = self._tool_config(tool)
            deny_patterns = [str(value).lower() for value in config.get("deny_secret_patterns", []) or []]
            lowered_path = path_value.lower()
            if any(pattern and pattern in lowered_path for pattern in deny_patterns):
                return self._finish(
                    request, decision_id, "block", "tool.read_file.secrets_or_sandbox",
                    "File access is outside the fixture sandbox or targets a secret.", path_value[:300], risk=100,
                    persist=persist, content_ids=content_ids,
                )
            try:
                # This validates both traversal and symlink escapes without reading the file.
                from .agent.tools import _fixture_path
                _fixture_path(path_value)
            except (ValueError, FileNotFoundError):
                return self._finish(
                    request, decision_id, "block", "tool.read_file.secrets_or_sandbox",
                    "File access is outside the fixture sandbox or targets a secret.", path_value[:300], risk=100,
                    persist=persist, content_ids=content_ids,
                )
            return self._finish(
                request, decision_id, "allow", "tool.read_file.sandbox", "File is inside the fixture sandbox.", path_value,
                risk=risk, persist=persist, content_ids=content_ids,
            )

        if tool == "fetch_page":
            config = self._tool_config(tool)
            limit = int(config.get("rate_limit", config.get("max_per_minute", 10)))
            window = int(config.get("window_seconds", 60))
            allowed, count = self.session_store.consume_fetch_slot(request.session_id, limit, window)
            if not allowed:
                return self._finish(
                    request, decision_id, "block", "tool.fetch_page.rate_limit",
                    f"fetch_page exceeds {limit} calls per {window} seconds.", f"count={count}", risk=100,
                    persist=persist, content_ids=content_ids,
                )
            return self._finish(
                request, decision_id, "allow", "tool.fetch_page.rate_limit", "fetch_page is within the session rate limit.",
                f"count={count}/{limit}", risk=risk, persist=persist, content_ids=content_ids,
            )

        if tool in {"list_fixtures", "summarize", "calculate"}:
            return self._finish(
                request, decision_id, "allow", "tool.safe_allowlist", "Tool is local and allow-listed.", tool,
                risk=risk, persist=persist, content_ids=content_ids,
            )
        return self._finish(
            request, decision_id, "block", "tool.not_allowlisted", "Tool is not in the safe tool allowlist.", tool,
            risk=100, persist=persist, content_ids=content_ids,
        )

    def _finish(
        self,
        request: ToolCallCheckRequest,
        decision_id: str,
        action: str,
        rule_id: str,
        reason: str,
        evidence: str,
        *,
        risk: int,
        persist: bool,
        content_ids: list[str],
        alert: str | None = None,
    ) -> ToolDecision:
        approval_id: str | None = None
        if persist and action == "approve":
            approval_id = f"apr_{uuid4().hex}"
            with self.session_factory() as session:
                session.add(Approval(
                    approval_id=approval_id,
                    decision_id=decision_id,
                    status="pending",
                    reason=reason,
                    requested_by=request.session_id,
                    context_json=json.dumps({
                        "session_id": request.session_id, "tool": request.tool,
                        "args": request.args, "content_ids": content_ids,
                    }, default=str),
                ))
                session.commit()
        if persist:
            with self.session_factory() as session:
                session.add(AuditEvent(
                    event_id=decision_id,
                    event_type="tool_call",
                    decision_id=decision_id,
                    source=request.session_id,
                    action=request.tool,
                    decision=action,
                    risk_score=max(0, min(100, int(risk))),
                    policy="default",
                    payload_json=json.dumps({"tool": request.tool, "args": request.args}, default=str),
                    provenance_json=json.dumps(request.provenance, default=str),
                    matched_rules_json=json.dumps([{
                        "rule_id": rule_id, "reason": reason, "evidence": evidence, "alert": alert,
                    }], default=str),
                ))
                session.commit()
            policy_event = {
                "session_id": request.session_id,
                "decision_id": decision_id,
                "tool": request.tool,
                "action": action,
                "rule_id": rule_id,
                "reason": reason,
                "evidence": evidence,
                "approval_id": approval_id, "alert": alert,
            }
            self.event_bus.publish("policy_decision", policy_event)
            if approval_id:
                self.event_bus.publish("approval_requested", {
                    "session_id": request.session_id, "approval_id": approval_id,
                    "tool": request.tool, "reason": reason,
                })
        return ToolDecision(
            action=action, rule_id=rule_id, reason=reason, evidence=evidence,
            approval_id=approval_id, risk=max(0, min(100, int(risk))), decision_id=decision_id, alert=alert,
        )

    def record_unprotected_execution(self, session_id: str, tool: str, args: dict[str, Any], reason: str) -> str:
        decision_id = f"tool_{uuid4().hex}"
        with self.session_factory() as session:
            session.add(AuditEvent(
                event_id=decision_id, event_type="tool_call", decision_id=decision_id,
                source=session_id, action=tool, decision="allow", risk_score=0, policy="unprotected-demo",
                payload_json=json.dumps({"tool": tool, "args": args}, default=str),
                provenance_json="[]",
                matched_rules_json=json.dumps([{"rule_id": "mode.unprotected", "reason": reason}], default=str),
            ))
            session.commit()
        return decision_id

    def execute_fake(self, session_id: str, tool: str, args: dict[str, Any]) -> Any:
        """Execute only local demo behavior; send_email writes SQLite and never networks."""
        if tool == "send_email":
            outbox_id = f"out_{uuid4().hex}"
            row = OutboxMessage(
                outbox_id=outbox_id,
                session_id=session_id,
                recipient=str(args.get("recipient", args.get("to", ""))),
                subject=str(args.get("subject", "Aegis Gate demo"))[:500],
                body=str(args.get("body", ""))[:50_000],
                status="queued",
            )
            with self.session_factory() as session:
                session.add(row)
                session.commit()
            return {"outbox_id": outbox_id, "status": "queued", "network": False}
        if tool == "read_file":
            return {"content": read_fixture(str(args.get("path", args.get("name", ""))))}
        if tool == "fetch_page":
            fixture_id = str(args.get("fixture_id", args.get("id", "")))
            if fixture_id:
                from .agent.tools import fetch_page
                return fetch_page(fixture_id)
            return {"url": str(args.get("url", "")), "content": "fake local response", "network": False}
        if tool == "summarize":
            from .agent.tools import summarize
            return summarize(str(args.get("text", "")))
        if tool == "calculate":
            from .agent.tools import calculate
            return {"result": calculate(str(args.get("expression", "")))}
        raise ValueError(f"tool {tool!r} is not executable")

    def outbox(self, limit: int = 100) -> list[OutboxMessage]:
        with self.session_factory() as session:
            return list(session.exec(select(OutboxMessage).order_by(OutboxMessage.created_at.desc()).limit(limit)).all())
