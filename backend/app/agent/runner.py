"""Agent request flow: safety evaluation always precedes tool execution."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..pipeline.service import EvaluationService
from ..schemas import AgentRunRequest, AgentRunResponse, InboundRequest
from .tools import SAFE_TOOLS, run_tool


class DemoAgent:
    def __init__(self, service: EvaluationService):
        self.service = service

    def run(self, request: AgentRunRequest) -> AgentRunResponse:
        if request.tool not in SAFE_TOOLS:
            # Feed the attempted tool name through the same inbound rules for an auditable denial.
            evaluation_request = InboundRequest(
                source=request.source, payload={"tool": request.tool, "args": request.args},
                policy=request.policy, requested_action="agent_tool", metadata=request.metadata,
            )
            result = self.service.evaluate(evaluation_request)
            return AgentRunResponse(status="denied", tool=request.tool, decision=result.response, error="tool is not allow-listed")

        payload: dict[str, Any] = {"tool": request.tool, "args": request.args}
        if request.content is not None:
            payload["content"] = request.content
        if request.text is not None:
            payload["text"] = request.text
        evaluation_request = InboundRequest(
            source=request.source, payload=payload,
            policy=request.policy, requested_action="agent_tool", metadata=request.metadata,
        )
        result = self.service.evaluate(evaluation_request)
        decision = result.response
        if decision.decision == "deny":
            return AgentRunResponse(status="denied", tool=request.tool, decision=decision, error="safety policy denied tool execution")
        if decision.decision == "review":
            if not request.approval_id:
                return AgentRunResponse(status="approval_required", tool=request.tool, decision=decision, error="operator approval is required")
            approval = self._get_approval(request.approval_id)
            context = {}
            if approval is not None:
                try:
                    context = json.loads(approval.context_json)
                except (TypeError, json.JSONDecodeError):
                    context = {}
            input_hash = hashlib.sha256(result.normalized_input.text.encode("utf-8")).hexdigest()
            context_matches = (
                context.get("policy") == request.policy
                and context.get("action") == "agent_tool"
                and context.get("input_sha256") == input_hash
            )
            if approval is None or approval.status != "approved" or not context_matches:
                return AgentRunResponse(status="denied", tool=request.tool, decision=decision, error="approval is missing or does not match this request")
        try:
            result_value = run_tool(request.tool, request.args)
        except (ValueError, FileNotFoundError) as exc:
            return AgentRunResponse(status="error", tool=request.tool, decision=decision, error=str(exc))
        return AgentRunResponse(status="completed", tool=request.tool, result=result_value, decision=decision)

    def _get_approval(self, approval_id: str) -> Any:
        from sqlmodel import select
        from ..models import Approval

        with self.service.session_factory() as session:  # type: ignore[operator]
            return session.exec(select(Approval).where(Approval.approval_id == approval_id)).first()
