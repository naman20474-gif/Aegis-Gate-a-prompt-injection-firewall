"""FastAPI application for Aegis Gate and its exact compatibility APIs."""
from __future__ import annotations

import asyncio
import json
import logging
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from sqlmodel import select

from .agent.runner import DemoAgent
from .bench.cases import BENCHMARK_CASES
from .bench.runner import _percentile, run_benchmark
from .config import Settings
from .db import Database
from .demo import DemoScenarioRunner
from .events import EventBus, sse_frame
from .logging import configure_logging, log
from .models import Approval, AuditEvent, BenchmarkRun, OutboxMessage
from .pipeline.llm import LLMClient, build_llm_client
from .pipeline.normalize import InputLimitError
from .pipeline.rules import RuleEngine
from .pipeline.service import EvaluationService
from .policy import PolicyEngine
from .scan import ScanService, SessionStore
from .schemas import (
    AgentRunRequest,
    AgentScenarioRequest,
    ApprovalActionRequest,
    ApprovalDecisionRequest,
    EvaluationResponse,
    InboundRequest,
    ScanRequest,
    ScanResult,
    ToolCallCheckRequest,
    ToolDecision,
)
from .tool_policy import ToolPolicyService

logger = logging.getLogger(__name__)
SESSION_EVENT_TYPES = {
    "content_ingested", "scan_result", "tool_proposed", "policy_decision",
    "approval_requested", "tool_executed", "run_finished",
}


def _approval_dict(approval: Approval) -> dict[str, Any]:
    return approval.model_dump(mode="json")


def _audit_dict(row: AuditEvent) -> dict[str, Any]:
    result = row.model_dump(mode="json")
    for key in ("payload_json", "provenance_json", "matched_rules_json"):
        try:
            result[key.removesuffix("_json")] = json.loads(result[key])
        except (TypeError, json.JSONDecodeError):
            pass
    return result


def create_app(settings: Settings | None = None, *, llm_client: LLMClient | Any | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    configure_logging(settings.log_level)
    database = Database(settings.database_url)
    database.create_all()
    policy_engine = PolicyEngine(settings.policy_dir)
    event_bus = EventBus()
    session_store = SessionStore()
    resolved_llm = build_llm_client(settings, llm_client)
    service = EvaluationService(
        session_factory=database.session,
        policy_engine=policy_engine,
        rule_engine=RuleEngine(),
        llm_client=resolved_llm,
        event_bus=event_bus,
        max_text_chars=settings.max_text_chars,
    )
    scan_service = ScanService(
        session_factory=database.session,
        rule_engine=RuleEngine(),
        llm_client=resolved_llm,
        event_bus=event_bus,
        session_store=session_store,
        max_text_chars=settings.max_text_chars,
        llm_token_cap=settings.llm_token_cap,
        llm_max_tokens=settings.llm_max_tokens,
    )
    tool_policy = ToolPolicyService(
        session_factory=database.session,
        policy_engine=policy_engine,
        rule_engine=RuleEngine(),
        session_store=session_store,
        event_bus=event_bus,
    )
    agent = DemoAgent(service)
    scenario = DemoScenarioRunner(
        scan_service=scan_service, tool_policy=tool_policy,
        event_bus=event_bus, session_store=session_store,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        log(logger, logging.INFO, "aegis gate started", environment=settings.environment)
        yield
        log(logger, logging.INFO, "aegis gate stopped")

    app = FastAPI(
        title="Aegis Gate",
        version="0.2.0",
        description="Inbound safety gateway with deterministic policy enforcement, scan compatibility, and a safe demo agent.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.policy_engine = policy_engine
    app.state.event_bus = event_bus
    app.state.service = service
    app.state.scan_service = scan_service
    app.state.session_store = session_store
    app.state.tool_policy = tool_policy
    app.state.agent = agent
    app.state.scenario = scenario

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_limits(request: Request, call_next):
        content_length = request.headers.get("content-length")
        try:
            if content_length is not None and int(content_length) > settings.max_body_bytes:
                return JSONResponse(status_code=413, content={"detail": "request body is too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid content-length"})
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > settings.max_body_bytes:
                return JSONResponse(status_code=413, content={"detail": "request body is too large"})
        return await call_next(request)

    @app.exception_handler(InputLimitError)
    async def input_limit_handler(request: Request, exc: InputLimitError):
        return JSONResponse(status_code=413, content={"detail": str(exc)})

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    frontend_dist = Path(__file__).resolve().parents[2] / "dist"
    if settings.serve_frontend and (frontend_dist / "assets").is_dir():
        app.mount("/assets", __import__("fastapi.staticfiles", fromlist=["StaticFiles"]).StaticFiles(directory=frontend_dist / "assets"), name="frontend-assets")

    @app.get("/", tags=["system"])
    async def root() -> Any:
        if settings.serve_frontend and (frontend_dist / "index.html").is_file():
            return FileResponse(frontend_dist / "index.html")
        return {"service": "aegis-gate", "version": app.version, "docs": "/docs"}

    @app.get("/health", tags=["system"])
    @app.get("/api/health", tags=["system"])
    @app.get("/api/v1/health", tags=["system"])
    async def health() -> dict[str, Any]:
        return {"status": "ok", "service": "aegis-gate", "llm": resolved_llm.__class__.__name__}

    # Exact scan contract. The legacy evaluator remains below.
    @app.post("/api/scan", response_model=ScanResult, tags=["scan"])
    @app.post("/api/v1/scan", response_model=ScanResult, include_in_schema=False)
    async def scan(request: ScanRequest) -> ScanResult:
        return scan_service.scan(request)

    @app.post("/api/v1/evaluate", response_model=EvaluationResponse, tags=["evaluation"])
    @app.post("/api/evaluate", response_model=EvaluationResponse, include_in_schema=False)
    @app.post("/api/v1/inbound", response_model=EvaluationResponse, include_in_schema=False)
    @app.post("/api/v1/check", response_model=EvaluationResponse, include_in_schema=False)
    async def evaluate(request: InboundRequest) -> EvaluationResponse:
        return service.evaluate(request).response

    @app.post("/api/tool-call/check", response_model=ToolDecision, tags=["tools"])
    @app.post("/api/v1/tool-call/check", response_model=ToolDecision, include_in_schema=False)
    async def tool_call_check(request: ToolCallCheckRequest) -> ToolDecision:
        return tool_policy.check(request)

    @app.get("/api/audit", tags=["audit"])
    @app.get("/api/v1/audit", include_in_schema=False)
    async def audit(
        limit: int = Query(default=50, ge=1, le=250),
        decision: str | None = None,
        verdict: str | None = None,
    ) -> dict[str, Any]:
        rows = service.recent_audit(limit=limit, decision=verdict or decision)
        return {"items": [_audit_dict(row) for row in rows], "count": len(rows)}

    @app.get("/api/audit/{event_id}", tags=["audit"])
    @app.get("/api/v1/audit/{event_id}", include_in_schema=False)
    async def audit_event(event_id: str) -> dict[str, Any]:
        with database.session() as session:
            row = session.exec(select(AuditEvent).where(AuditEvent.event_id == event_id)).first()
        if row is None:
            raise HTTPException(status_code=404, detail="audit event not found")
        return _audit_dict(row)

    @app.get("/api/approvals", tags=["approvals"])
    @app.get("/api/v1/approvals", include_in_schema=False)
    async def approvals(status: str | None = None, limit: int = Query(default=50, ge=1, le=250)) -> dict[str, Any]:
        with database.session() as session:
            statement = select(Approval).order_by(Approval.requested_at.desc()).limit(limit)
            if status:
                statement = select(Approval).where(Approval.status == status).order_by(Approval.requested_at.desc()).limit(limit)
            rows = list(session.exec(statement).all())
        return {"items": [_approval_dict(row) for row in rows], "count": len(rows)}

    @app.get("/api/approvals/{approval_id}", tags=["approvals"])
    @app.get("/api/v1/approvals/{approval_id}", include_in_schema=False)
    async def approval(approval_id: str) -> dict[str, Any]:
        with database.session() as session:
            row = session.get(Approval, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail="approval not found")
        return _approval_dict(row)

    async def resolve_approval(approval_id: str, action: str, body: ApprovalActionRequest) -> dict[str, Any]:
        with database.session() as session:
            row = session.get(Approval, approval_id)
            if row is None:
                raise HTTPException(status_code=404, detail="approval not found")
            if row.status != "pending":
                return _approval_dict(row)
            row.status = action
            row.resolved_by = body.resolved_by
            row.resolution_note = body.note
            row.resolved_at = datetime.now(timezone.utc)
            session.add(row)
            session.commit()
            session.refresh(row)
        event_bus.publish("approval", _approval_dict(row) | {"session_id": _approval_session(row)})
        return _approval_dict(row)

    @app.post("/api/approvals/{approval_id}", tags=["approvals"])
    async def decide_approval(approval_id: str, body: ApprovalDecisionRequest) -> dict[str, Any]:
        action = "approved" if body.decision == "approve" else "rejected"
        return await resolve_approval(
            approval_id,
            action,
            ApprovalActionRequest(resolved_by=body.resolved_by, note=body.note),
        )

    @app.post("/api/approvals/{approval_id}/approve", tags=["approvals"])
    @app.post("/api/v1/approvals/{approval_id}/approve", include_in_schema=False)
    async def approve(approval_id: str, body: ApprovalActionRequest | None = None) -> dict[str, Any]:
        return await resolve_approval(approval_id, "approved", body or ApprovalActionRequest())

    @app.post("/api/approvals/{approval_id}/reject", tags=["approvals"])
    @app.post("/api/v1/approvals/{approval_id}/reject", include_in_schema=False)
    async def reject(approval_id: str, body: ApprovalActionRequest | None = None) -> dict[str, Any]:
        return await resolve_approval(approval_id, "rejected", body or ApprovalActionRequest())

    @app.post("/api/agent/run", tags=["agent"])
    @app.post("/api/v1/agent/run", include_in_schema=False)
    async def run_agent(request: AgentRunRequest):
        if request.fixture_id or request.task is not None:
            return scenario.run(AgentScenarioRequest(
                task=request.task or "summarize the fixture",
                fixture_id=request.fixture_id or "agent_summary",
                mode=request.mode,
                session_id=request.session_id,
            ))
        return agent.run(request)

    @app.get("/api/agent/session/{session_id}", tags=["agent"])
    async def agent_session(session_id: str) -> dict[str, Any]:
        value = scenario.get_session(session_id)
        if value is None:
            raise HTTPException(status_code=404, detail="session not found")
        return value

    @app.get("/api/v1/agent/tools", tags=["agent"])
    async def agent_tools() -> dict[str, Any]:
        from .agent.tools import TOOL_NAMES, list_fixtures
        return {"tools": list(TOOL_NAMES), "fixtures": list_fixtures()}

    @app.get("/api/outbox", tags=["agent"])
    async def outbox(limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
        rows = tool_policy.outbox(limit)
        return {"items": [row.model_dump(mode="json") for row in rows], "count": len(rows)}

    @app.get("/api/outbox/{outbox_id}", tags=["agent"])
    async def outbox_item(outbox_id: str) -> dict[str, Any]:
        with database.session() as session:
            row = session.get(OutboxMessage, outbox_id)
        if row is None:
            raise HTTPException(status_code=404, detail="outbox message not found")
        return row.model_dump(mode="json")

    @app.get("/api/stats", tags=["stats"])
    @app.get("/api/v1/stats", include_in_schema=False)
    async def stats() -> dict[str, Any]:
        with database.session() as session:
            audits = list(session.exec(select(AuditEvent)).all())
            approvals_rows = list(session.exec(select(Approval)).all())
        scans = scan_service.latest(10_000)
        latencies = [float(item.stage_latency.get("total_ms", 0.0)) for item in scans]
        blocked_count = sum(item.verdict == "block" for item in scans) + sum(
            row.event_type == "tool_call" and row.decision == "block" for row in audits
        )
        allow_count = sum(item.verdict == "allow" for item in scans)
        tokens_used = sum(item.tokens_used for item in scans)
        decisions = Counter(row.decision for row in audits)
        policies = Counter(row.policy for row in audits)
        return {
            "evaluations": len(audits), "decisions": dict(decisions), "policies": dict(policies),
            "risk": {"average": round(sum(row.risk_score for row in audits) / len(audits), 2) if audits else 0,
                      "max": max((row.risk_score for row in audits), default=0)},
            "approvals": dict(Counter(row.status for row in approvals_rows)),
            "approvals_pending": sum(row.status == "pending" for row in approvals_rows),
            "blocked_count": blocked_count,
            "scan_blocked_count": sum(item.verdict == "block" for item in scans),
            "allow_rate": round(allow_count / len(scans), 4) if scans else 0.0,
            "p50_latency_ms": _percentile(latencies, 50),
            "p95_latency_ms": _percentile(latencies, 95),
            "p50_latency": _percentile(latencies, 50),
            "p95_latency": _percentile(latencies, 95),
            "tokens_used": tokens_used,
            "events_buffered": len(event_bus.recent(250)),
        }

    @app.get("/api/policies", tags=["policies"])
    @app.get("/api/v1/policies", include_in_schema=False)
    async def policies() -> dict[str, Any]:
        raw_default = policy_engine.raw("default")
        return {
            **raw_default,
            "policies": [policy_engine.describe(name) for name in policy_engine.names()],
            "default": raw_default,
        }

    @app.put("/api/policies", tags=["policies"])
    @app.put("/api/v1/policies", include_in_schema=False)
    async def update_policies(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            value = policy_engine.update("default", payload)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"updated": True, "policy": value, "policies": policy_engine.names()}

    @app.get("/api/policies/{name}", tags=["policies"])
    @app.get("/api/v1/policies/{name}", include_in_schema=False)
    async def policy(name: str) -> dict[str, Any]:
        if name not in policy_engine.names():
            raise HTTPException(status_code=404, detail="policy not found")
        if name == "default":
            return {**policy_engine.describe(name), **policy_engine.raw(name)}
        return policy_engine.describe(name)

    @app.post("/api/v1/policies/reload", tags=["policies"])
    @app.post("/api/policies/reload", include_in_schema=False)
    async def reload_policies() -> dict[str, Any]:
        policy_engine.reload()
        return {"reloaded": True, "policies": policy_engine.names()}

    @app.get("/api/bench/cases", tags=["benchmark"])
    @app.get("/api/v1/benchmark", include_in_schema=False)
    @app.get("/api/benchmark", include_in_schema=False)
    async def benchmark_cases() -> dict[str, Any]:
        cases = [
            {"case_id": case.case_id, "category": case.category, "text": case.text,
             "expected_verdict": case.expected_verdict, "expected": case.expected, "is_injection": case.is_injection}
            for case in BENCHMARK_CASES
        ]
        return {"total": len(cases), "injection_cases": sum(case["is_injection"] for case in cases), "cases": cases}

    def persist_benchmark() -> dict[str, Any]:
        result = run_benchmark(scan_service=scan_service)
        run_id = f"bench_{uuid4().hex}"
        created = datetime.now(timezone.utc)
        with database.session() as session:
            session.add(BenchmarkRun(run_id=run_id, metrics_json=json.dumps(result["metrics"], default=str), created_at=created))
            session.commit()
        return {"run_id": run_id, "created_at": created.isoformat(), **result}

    @app.post("/api/bench/run", tags=["benchmark"])
    async def bench_run() -> dict[str, Any]:
        return persist_benchmark()

    @app.get("/api/bench/latest", tags=["benchmark"])
    async def bench_latest() -> dict[str, Any]:
        with database.session() as session:
            row = session.exec(select(BenchmarkRun).order_by(BenchmarkRun.created_at.desc())).first()
        if row is None:
            return {"run_id": None, "metrics": None}
        try:
            metrics = json.loads(row.metrics_json)
        except json.JSONDecodeError:
            metrics = {}
        return {"run_id": row.run_id, "created_at": row.created_at, "metrics": metrics}

    @app.post("/api/v1/benchmark/run", tags=["benchmark"])
    @app.post("/api/benchmark/run", include_in_schema=False)
    async def benchmark_run() -> dict[str, Any]:
        # Preserve the old endpoint's return shape while using the new exact 60-case set.
        return run_benchmark(scan_service=scan_service)

    @app.get("/api/stream/{session_id}", tags=["events"])
    async def session_stream(
        session_id: str,
        request: Request,
        limit: int = Query(default=100, ge=1, le=250),
        follow: bool = False,
    ):
        initial = event_bus.recent(limit=limit, session_id=session_id, event_types=SESSION_EVENT_TYPES)

        async def stream():
            for event in initial:
                yield sse_frame(event)
            if not follow:
                return
            queue = await event_bus.subscribe(session_id=session_id)
            try:
                while True:
                    if await request.is_disconnected():
                        return
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"
                        return
                    if event.get("type") in SESSION_EVENT_TYPES:
                        yield sse_frame(event)
            finally:
                event_bus.unsubscribe(queue)

        return StreamingResponse(
            stream(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/v1/events", tags=["events"])
    @app.get("/api/events", include_in_schema=False)
    @app.get("/api/events/stream", include_in_schema=False)
    async def events(
        request: Request,
        limit: int = Query(default=50, ge=1, le=250),
        after: str | None = None,
        once: bool = False,
    ):
        initial = event_bus.recent(limit=limit, after=after)

        async def stream():
            for event in initial:
                yield sse_frame(event)
            if once:
                return
            queue = await event_bus.subscribe()
            try:
                while True:
                    if await request.is_disconnected():
                        return
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"
                        return
                    yield sse_frame(event)
            finally:
                event_bus.unsubscribe(queue)

        return StreamingResponse(
            stream(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/v1/events/recent", tags=["events"])
    async def recent_events(limit: int = Query(default=50, ge=1, le=250)) -> dict[str, Any]:
        return {"events": event_bus.recent(limit=limit)}

    return app


def _approval_session(approval: Approval) -> str | None:
    try:
        value = json.loads(approval.context_json)
        return value.get("session_id") if isinstance(value, dict) else None
    except (TypeError, json.JSONDecodeError):
        return None


app = create_app()
