"""Offline benchmark runner and metrics."""
from __future__ import annotations

import json
import statistics
from typing import Any

from ..config import Settings
from ..db import Database
from ..events import EventBus
from ..pipeline.llm import NullLLMClient
from ..pipeline.rules import RuleEngine
from ..pipeline.service import EvaluationService
from ..policy import PolicyEngine
from ..scan import ScanService, SessionStore
from ..schemas import InboundRequest, ScanRequest
from .cases import BENCHMARK_CASES


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile / 100) * (len(ordered) - 1))))
    return round(float(ordered[index]), 3)


def _metrics(rows: list[dict[str, Any]], latencies: list[float], tokens: list[int]) -> dict[str, Any]:
    positives = [row for row in rows if row["is_injection"]]
    negatives = [row for row in rows if not row["is_injection"]]
    tp = sum(row["predicted_unsafe"] for row in positives)
    fn = len(positives) - tp
    fp = sum(row["predicted_unsafe"] for row in negatives)
    tn = len(negatives) - fp
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / len(negatives) if negatives else 0.0
    categories: dict[str, dict[str, int]] = {}
    for row in positives:
        category = row["category"]
        value = categories.setdefault(category, {"total": 0, "detected": 0})
        value["total"] += 1
        value["detected"] += int(row["predicted_unsafe"])
    per_category = {category: round(value["detected"] / value["total"], 4) for category, value in categories.items()}
    return {
        "total": len(rows), "injection_cases": len(positives), "safe_cases": len(negatives),
        "true_positive": tp, "true_negative": tn, "false_positive": fp, "false_negative": fn,
        "precision": round(precision, 4), "recall": round(recall, 4), "fpr": round(fpr, 4),
        "false_positive_rate": round(fpr, 4),
        "per_category_recall": per_category,
        "p50_latency_ms": _percentile(latencies, 50), "p95_latency_ms": _percentile(latencies, 95),
        "p50_latency": _percentile(latencies, 50), "p95_latency": _percentile(latencies, 95),
        "tokens_per_scan": round(sum(tokens) / len(tokens), 3) if tokens else 0.0,
        "tokens_used": sum(tokens),
    }


def run_benchmark(
    service: EvaluationService | None = None,
    *,
    scan_service: ScanService | None = None,
) -> dict[str, Any]:
    if scan_service is None:
        if service is None:
            settings = Settings.from_env(database_url="sqlite://")
            database = Database(settings.database_url)
            database.create_all()
            scan_service = ScanService(
                session_factory=database.session,
                rule_engine=RuleEngine(),
                llm_client=NullLLMClient(),
                event_bus=EventBus(),
                session_store=SessionStore(),
                max_text_chars=settings.max_text_chars,
                llm_token_cap=settings.llm_token_cap,
                llm_max_tokens=settings.llm_max_tokens,
            )
        else:
            scan_service = ScanService(
                session_factory=service.session_factory,
                rule_engine=service.rule_engine,
                llm_client=NullLLMClient(),
                event_bus=service.event_bus,
                session_store=SessionStore(),
                max_text_chars=service.max_text_chars,
            )
    rows: list[dict[str, Any]] = []
    latencies: list[float] = []
    tokens: list[int] = []
    for case in BENCHMARK_CASES:
        result = scan_service.scan(ScanRequest(content=case.text, source_type="benchmark"), persist=False)
        predicted_unsafe = int(result.verdict != "allow")
        expected_unsafe = int(case.is_injection)
        rows.append({
            "case_id": case.case_id, "category": case.category, "expected": case.expected_verdict,
            "actual": result.verdict, "expected_decision": case.expected, "actual_decision": {
                "allow": "allow", "flag": "review", "block": "deny",
            }[result.verdict], "is_injection": case.is_injection,
            "predicted_unsafe": predicted_unsafe, "passed": predicted_unsafe == expected_unsafe,
            "risk": result.risk, "tokens_used": result.tokens_used,
        })
        latencies.append(result.stage_latency.get("total_ms", 0.0))
        tokens.append(result.tokens_used)
    rules_only = _metrics(rows, latencies, tokens)
    # The offline default has no LLM invocation, so this is an honest same-path baseline.
    rules_plus_llm = dict(rules_only)
    return {
        "total": len(BENCHMARK_CASES),
        "passed": sum(int(row["passed"]) for row in rows),
        "accuracy": round(sum(int(row["passed"]) for row in rows) / len(rows), 4),
        "metrics": {
            **rules_only,
            "rules_only": rules_only,
            "rules_plus_llm": rules_plus_llm,
        },
        "results": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), indent=2, sort_keys=True))
