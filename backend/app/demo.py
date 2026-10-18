"""Protected/unprotected local agent scenario used by the Aegis Gate demo."""
from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from .agent.tools import list_fixtures, read_fixture
from .events import EventBus
from .scan import ScanService, SessionStore
from .schemas import AgentScenarioRequest, AgentScenarioResponse, ScanRequest, ToolCallCheckRequest, ToolDecision
from .tool_policy import ToolPolicyService


FIXTURE_ALIASES = {
    "prompt_injection": "pages/prompt_injection.txt",
    "poisoned": "pages/prompt_injection.txt",
    "poisoned_prompt": "pages/prompt_injection.txt",
    "poisoned_fixture": "pages/prompt_injection.txt",
    "fixture-poisoned": "pages/prompt_injection.txt",
    "poisoned_email": "files/secret_exfiltration.txt",
    "secret_exfiltration": "files/secret_exfiltration.txt",
    "benign": "files/benign_note.txt",
    "safe": "files/benign_note.txt",
    "dangerous_command": "files/dangerous_command.txt",
    "path_traversal": "files/path_traversal.txt",
    "pii": "files/pii_review.txt",
    "encoded": "pages/encoded_payload.txt",
    "agent_summary": "pages/agent_summary.txt",
}


class DemoScenarioRunner:
    def __init__(self, *, scan_service: ScanService, tool_policy: ToolPolicyService, event_bus: EventBus, session_store: SessionStore):
        self.scan_service = scan_service
        self.tool_policy = tool_policy
        self.event_bus = event_bus
        self.session_store = session_store

    def run(self, request: AgentScenarioRequest) -> AgentScenarioResponse:
        session_id = request.session_id or f"ses_{uuid4().hex}"
        state = self.session_store.create(session_id)
        events: list[str] = []

        fixture_path = self._resolve_fixture(request.fixture_id)
        content = read_fixture(fixture_path)
        self._emit(events, "content_ingested", {
            "content_id": request.fixture_id,
            "source_type": "fixture",
            "source_id": request.fixture_id,
            "size": len(content),
            "preview": content[:500],
        }, session_id)
        scan = self.scan_service.scan(ScanRequest(
            content=content, source_type="fixture", source_id=request.fixture_id, session_id=session_id,
        ), emit_ingest=False)
        # ScanService has emitted scan_result; record it for the response/event summary.
        events.append("scan_result")
        state.last_result = scan.model_dump(mode="json")

        poisoned = scan.verdict != "allow" or "CANARY-7731" in content
        if poisoned:
            email_args = {
                "recipient": "security@example.com",
                "subject": f"Aegis Gate report: {request.task[:120]}",
                "body": f"{request.task}\n\nCANARY-7731\n\n{content}",
            }
            self._emit(events, "tool_proposed", {
                "tool": "send_email", "args": email_args, "provenance": [{
                    "content_id": scan.content_id, "verdict": scan.verdict, "risk": scan.risk,
                    "source_type": "fixture", "trusted": False,
                }],
            }, session_id)
            if request.mode == "unprotected":
                decision = ToolDecision(
                    action="allow", rule_id="mode.unprotected", reason="Unprotected demo bypasses the safety gate.",
                    evidence="local fake outbox only", risk=scan.risk, decision_id=f"tool_{uuid4().hex}",
                )
                self._emit(events, "policy_decision", decision.model_dump(mode="json") | {"tool": "send_email"}, session_id)
                self.tool_policy.record_unprotected_execution(
                    session_id, "send_email", email_args, "Unprotected demo bypasses the safety gate."
                )
                executed = self.tool_policy.execute_fake(session_id, "send_email", email_args)
                self._emit(events, "tool_executed", {"tool": "send_email", **executed}, session_id)
                status = "completed"
                outbox_id = executed.get("outbox_id")
                state.status = status
                self._emit(events, "run_finished", {"status": status, "outbox_id": outbox_id}, session_id)
                return AgentScenarioResponse(
                    session_id=session_id, status=status, mode=request.mode, fixture_id=request.fixture_id,
                    scan_result=scan, outbox_id=outbox_id, tool_decision=decision, events=events,
                )
            decision = self.tool_policy.check(ToolCallCheckRequest(
                session_id=session_id, tool="send_email", args=email_args,
                provenance=[{
                    "content_id": scan.content_id, "verdict": scan.verdict, "risk": scan.risk,
                    "source_type": "fixture", "trusted": False,
                }],
            ))
            # ToolPolicyService emitted policy_decision into the stream.
            events.append("policy_decision")
            if decision.action == "approve" and decision.approval_id:
                # ToolPolicyService has already emitted this exact session event.
                events.append("approval_requested")
                status = "approval_required"
            else:
                status = "blocked" if decision.action == "block" else "approval_required"
            state.status = status
            self._emit(events, "run_finished", {"status": status, "tool": "send_email"}, session_id)
            return AgentScenarioResponse(
                session_id=session_id, status=status, mode=request.mode, fixture_id=request.fixture_id,
                scan_result=scan, tool_decision=decision, events=events,
            )

        # A benign fixture is still routed through the protected local summarize tool.
        proposed = {"tool": "summarize", "args": {"text": content}, "provenance": [{
            "content_id": scan.content_id, "verdict": scan.verdict, "risk": scan.risk, "trusted": True,
        }]}
        self._emit(events, "tool_proposed", proposed, session_id)
        decision = self.tool_policy.check(ToolCallCheckRequest(
            session_id=session_id, tool="summarize", args={"text": content}, provenance=proposed["provenance"],
        ))
        events.append("policy_decision")
        status = "blocked"
        result: dict[str, Any] | None = None
        if decision.action == "allow":
            result = self.tool_policy.execute_fake(session_id, "summarize", {"text": content})
            self._emit(events, "tool_executed", {"tool": "summarize", "result": result}, session_id)
            status = "completed"
        elif decision.action == "approve" and decision.approval_id:
            events.append("approval_requested")
            status = "approval_required"
        state.status = status
        self._emit(events, "run_finished", {"status": status}, session_id)
        return AgentScenarioResponse(
            session_id=session_id, status=status, mode=request.mode, fixture_id=request.fixture_id,
            scan_result=scan, tool_decision=decision, events=events,
        )

    @staticmethod
    def _resolve_fixture(fixture_id: str) -> str:
        value = FIXTURE_ALIASES.get(fixture_id, fixture_id)
        if value in list_fixtures():
            return value
        # Friendly IDs can refer to a file basename while the safe tool still enforces the root.
        candidates = [item for item in list_fixtures() if item.rsplit("/", 1)[-1].rsplit(".", 1)[0] == value]
        if candidates:
            return candidates[0]
        raise ValueError(f"unknown fixture: {fixture_id}")

    def _emit(self, events: list[str], event_type: str, data: dict[str, Any], session_id: str) -> None:
        self.event_bus.publish(event_type, {"session_id": session_id, **data})
        events.append(event_type)

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        state = self.session_store.existing(session_id)
        if state is None:
            return None
        return {
            "session_id": state.session_id,
            "status": state.status,
            "tokens_used": state.tokens_used,
            "content": [item.__dict__ for item in state.content.values()],
            "last_result": state.last_result,
            "created_at": state.created_at.isoformat(),
        }
