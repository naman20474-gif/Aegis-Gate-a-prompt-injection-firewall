"""Aegis Gate scan contract, session taint memory, and scan metrics."""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .events import EventBus
from .models import AuditEvent
from .pipeline.llm import LLMClient
from .pipeline.normalize import NormalizedInput, normalize_inbound
from .pipeline.rules import RuleEngine, RuleMatch
from .pipeline.scoring import score_risk
from .schemas import ScanLLMResult, ScanRequest, ScanResult, ScanSignal

logger = logging.getLogger(__name__)


CATEGORY_MAP = {
    "prompt_injection": "instruction_override",
    "role_hijack": "role_hijack",
    "secret_exfiltration": "exfiltration",
    "dangerous_command": "tool_coercion",
    "unsafe_tool": "tool_coercion",
    "hidden_content": "hidden_content",
    "obfuscated_content": "obfuscation",
    "delimiter_spoofing": "delimiter_spoofing",
    "social_engineering": "urgency_authority",
    "sensitive_personal_data": "urgency_authority",
}


@dataclass
class ContentState:
    content_id: str
    verdict: str
    risk: int
    source_type: str
    source_id: str | None
    trusted: bool
    contains_canary: bool = False
    seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SessionState:
    session_id: str
    content: dict[str, ContentState] = field(default_factory=dict)
    tokens_used: int = 0
    fetch_times: deque[float] = field(default_factory=deque)
    status: str = "created"
    last_result: dict[str, Any] | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SessionStore:
    """In-memory session context used for provenance taint and deterministic demos."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.RLock()

    def create(self, session_id: str | None = None) -> SessionState:
        session_id = session_id or f"ses_{uuid4().hex}"
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                state = SessionState(session_id=session_id)
                self._sessions[session_id] = state
            return state

    def get(self, session_id: str) -> SessionState:
        return self.create(session_id)

    def existing(self, session_id: str) -> SessionState | None:
        with self._lock:
            return self._sessions.get(session_id)

    def remember(self, session_id: str, content: ContentState) -> SessionState:
        state = self.create(session_id)
        with self._lock:
            state.content[content.content_id] = content
            state.status = "content_ingested"
        return state

    def resolve(self, session_id: str, provenance: list[dict[str, Any]]) -> tuple[bool, int, list[str]]:
        state = self.get(session_id)
        untrusted = False
        risk = 0
        ids: list[str] = []
        with self._lock:
            for item in provenance:
                content_id = str(item.get("content_id", item.get("id", item.get("source_id", ""))))
                if content_id:
                    ids.append(content_id)
                known = state.content.get(content_id)
                verdict = str(item.get("verdict", "")).lower()
                trusted_value = item.get("trusted")
                is_untrusted = (
                    known is not None and not known.trusted
                    or trusted_value is False
                    or verdict in {"flag", "block", "review", "deny"}
                    or str(item.get("source_type", "")).lower() in {"external", "webhook", "untrusted"}
                )
                untrusted = untrusted or is_untrusted
                risk = max(risk, int(item.get("risk", item.get("risk_score", 0)) or 0))
                if known is not None:
                    risk = max(risk, known.risk)
                    untrusted = untrusted or not known.trusted or known.verdict != "allow"
            return untrusted, min(100, risk), ids

    def contains_token(self, session_id: str, content_ids: list[str], token: str) -> bool:
        state = self.get(session_id)
        with self._lock:
            return any(state.content.get(content_id) is not None and state.content[content_id].contains_canary for content_id in content_ids)

    def consume_fetch_slot(self, session_id: str, limit: int = 10, window_seconds: int = 60) -> tuple[bool, int]:
        state = self.get(session_id)
        now = time.monotonic()
        with self._lock:
            while state.fetch_times and now - state.fetch_times[0] >= window_seconds:
                state.fetch_times.popleft()
            count = len(state.fetch_times)
            if count >= limit:
                return False, count
            state.fetch_times.append(now)
            return True, count + 1

    def all_states(self) -> list[SessionState]:
        with self._lock:
            return list(self._sessions.values())


class ScanService:
    def __init__(
        self,
        *,
        session_factory: Any,
        rule_engine: RuleEngine,
        llm_client: Any,
        event_bus: EventBus,
        session_store: SessionStore,
        max_text_chars: int = 100_000,
        llm_token_cap: int = 4096,
        llm_max_tokens: int = 256,
    ) -> None:
        self.session_factory = session_factory
        self.rule_engine = rule_engine
        self.llm_client = llm_client
        self.event_bus = event_bus
        self.session_store = session_store
        self.max_text_chars = max_text_chars
        self.llm_token_cap = llm_token_cap
        self.llm_max_tokens = llm_max_tokens
        self.records: list[ScanResult] = []
        self._lock = threading.RLock()

    def scan(
        self, request: ScanRequest | dict[str, Any], *, persist: bool = True, emit_ingest: bool = True,
    ) -> ScanResult:
        if not isinstance(request, ScanRequest):
            request = ScanRequest.model_validate(request)
        started = time.perf_counter()
        content_id = request.source_id or f"cnt_{uuid4().hex}"
        source = request.source_type
        source_id = request.source_id
        if request.session_id and emit_ingest:
            self.event_bus.publish("content_ingested", {
                "session_id": request.session_id, "content_id": content_id,
                "source_type": source, "source_id": source_id,
                "size": len(str(request.content)), "preview": str(request.content)[:500],
            })
        normalize_started = time.perf_counter()
        normalized = normalize_inbound(request.content, source=source, max_text_chars=self.max_text_chars)
        normalize_ms = _ms(normalize_started)
        rules_started = time.perf_counter()
        matches = self.rule_engine.evaluate(normalized)
        rules_ms = _ms(rules_started)
        raw_risk = score_risk(matches, normalized.taints)
        llm_result = self._default_llm()
        llm_ms = 0.0
        state: SessionState | None = self.session_store.get(request.session_id) if request.session_id else None
        if 25 <= raw_risk <= 70:
            llm_started = time.perf_counter()
            remaining = self.llm_token_cap - (state.tokens_used if state else 0)
            llm_result = self._classify(normalized.text, remaining)
            llm_ms = _ms(llm_started)
            used = int(llm_result.get("tokens_used", 0) or 0)
            if state is not None:
                state.tokens_used += min(used, max(0, remaining))
        score_started = time.perf_counter()
        risk = raw_risk
        if llm_result.get("invoked") and not llm_result.get("degraded"):
            if llm_result.get("is_injection"):
                risk = min(100, risk + round(20 * float(llm_result.get("confidence", 0))))
            elif float(llm_result.get("confidence", 0)) >= 0.8:
                risk = max(0, risk - 5)
        if any(match.action == "deny" for match in matches) or risk >= 75:
            verdict = "block"
        elif any(match.action == "review" for match in matches) or risk >= 30:
            verdict = "flag"
        else:
            verdict = "allow"
        score_ms = _ms(score_started)
        signals = [self._signal(match) for match in matches]
        for hidden in normalized.hidden_signals:
            signals.append(
                ScanSignal(
                    id=str(hidden.get("id", "hidden.content")),
                    category=str(hidden.get("category", "hidden_content")),
                    weight=25,
                    span=[int(v) for v in hidden.get("span", [0, 0])],
                    span_start=int(hidden.get("span", [0, 0])[0]), span_end=int(hidden.get("span", [0, 0])[1]),
                    excerpt=str(hidden.get("excerpt", ""))[:500],
                )
            )
        # Preserve signal order while avoiding duplicate IDs from a rule plus metadata.
        signal_map: dict[str, ScanSignal] = {}
        for signal in signals:
            signal_map.setdefault(signal.id, signal)
        signals = list(signal_map.values())
        total_ms = round(_ms(started), 3)
        stage_latency = {
            "normalize_ms": round(normalize_ms, 3),
            "rules_ms": round(rules_ms, 3),
            "llm_ms": round(llm_ms, 3),
            "score_ms": round(score_ms, 3),
            "total_ms": total_ms,
            "normalization": round(normalize_ms, 3),
            "rules": round(rules_ms, 3),
            "llm": round(llm_ms, 3),
            "scoring": round(score_ms, 3),
            "total": total_ms,
        }
        normalized_payload = normalized.as_dict()
        normalized_payload.update({"content_id": content_id, "source_type": source, "source_id": source_id})
        result = ScanResult(
            scan_id=f"scan_{uuid4().hex}",
            content_id=content_id,
            source_type=source,
            source_id=source_id,
            session_id=request.session_id,
            risk=max(0, min(100, int(risk))),
            risk_score=max(0, min(100, int(risk))),
            verdict=verdict,
            signals=signals,
            llm=ScanLLMResult.model_validate(llm_result),
            llm_result=ScanLLMResult.model_validate(llm_result),
            stage_latency=stage_latency,
            stage_latencies=stage_latency,
            latency=stage_latency,
            tokens_used=int(llm_result.get("tokens_used", 0) or 0),
            normalized=normalized_payload,
            normalization=normalized_payload,
            hidden_signals=normalized.hidden_signals,
            hidden_signal_metadata=normalized.hidden_signals,
            metadata={**normalized.metadata, "source_type": source, "source_id": source_id},
            provenance=[record.as_dict() for record in normalized.provenance],
            created_at=datetime.now(timezone.utc),
        )
        if request.session_id:
            self.session_store.remember(
                request.session_id,
                ContentState(
                    content_id=result.content_id,
                    verdict=result.verdict,
                    risk=result.risk,
                    source_type=source,
                    source_id=source_id,
                    trusted=result.verdict == "allow",
                    contains_canary="CANARY-7731" in normalized.text,
                ),
            )
        if persist:
            with self._lock:
                self.records.append(result)
        if persist:
            self._persist(result, request, normalized, matches)
            event_data = result.model_dump(mode="json")
            if request.session_id:
                event_data["session_id"] = request.session_id
            self.event_bus.publish("scan_result", event_data)
        return result

    def _default_llm(self) -> dict[str, Any]:
        return {
            "is_injection": False,
            "confidence": 0.0,
            "technique": None,
            "rationale": "not invoked; deterministic score was outside ambiguous range or LLM is offline",
            "invoked": False,
            "degraded": False,
            "tokens_used": 0,
            "provider": "none",
        }

    def _classify(self, text: str, remaining: int) -> dict[str, Any]:
        if remaining <= 0:
            result = self._default_llm()
            result.update({"degraded": True, "rationale": "session token cap exhausted", "provider": "none"})
            return result
        try:
            if hasattr(self.llm_client, "classify"):
                result = self.llm_client.classify(
                    text,
                    max_tokens=min(self.llm_max_tokens, remaining),
                    token_budget=remaining,
                )
            else:
                legacy = self.llm_client.analyze(text, provenance=[])
                result = {
                    "is_injection": legacy.label in {"deny", "malicious", "unsafe"},
                    "confidence": legacy.confidence,
                    "technique": legacy.label,
                    "rationale": legacy.reason[:200],
                    "invoked": legacy.available,
                    "degraded": not legacy.available,
                    "tokens_used": 0,
                    "provider": legacy.provider,
                }
            if not isinstance(result, dict):
                raise ValueError("LLM classifier must return a dict")
            result = {
                "is_injection": bool(result.get("is_injection", False)),
                "confidence": max(0.0, min(1.0, float(result.get("confidence", 0.0)))),
                "technique": str(result["technique"])[:80] if result.get("technique") is not None else None,
                "rationale": str(result.get("rationale", ""))[:200],
                "invoked": bool(result.get("invoked", True)),
                "degraded": bool(result.get("degraded", False)),
                "tokens_used": max(0, min(int(result.get("tokens_used", 0) or 0), min(self.llm_max_tokens, remaining))),
                "provider": str(result.get("provider", "none")),
            }
            if result["provider"] == "none" and not result["invoked"]:
                result["degraded"] = False
            return result
        except Exception as exc:
            logger.warning("scan llm classifier failed", extra={"fields": {"error": type(exc).__name__}})
            result = self._default_llm()
            result.update({"invoked": True, "degraded": True, "rationale": f"failsafe: {type(exc).__name__}"[:200]})
            return result

    @staticmethod
    def _signal(match: RuleMatch) -> ScanSignal:
        return ScanSignal(
            id=match.rule_id,
            category=CATEGORY_MAP.get(match.category, match.category),
            weight=max(0, min(100, match.weight)),
            span=[int(match.span[0]), int(match.span[1])],
            span_start=int(match.span[0]), span_end=int(match.span[1]),
            excerpt=match.evidence[:500],
        )

    def _persist(self, result: ScanResult, request: ScanRequest, normalized: NormalizedInput, matches: list[RuleMatch]) -> None:
        record = AuditEvent(
            event_id=result.scan_id,
            event_type="scan",
            decision_id=result.scan_id,
            source=request.source_type,
            action="scan",
            decision=result.verdict,
            risk_score=result.risk,
            policy="default",
            payload_json=json.dumps(result.model_dump(mode="json"), default=str),
            provenance_json=json.dumps([record.as_dict() for record in normalized.provenance], default=str),
            matched_rules_json=json.dumps([match.as_dict() for match in matches], default=str),
        )
        with self.session_factory() as session:
            session.add(record)
            session.commit()

    def latest(self, limit: int = 100) -> list[ScanResult]:
        with self._lock:
            return list(self.records[-max(1, min(limit, 1000)):])


def _ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000
