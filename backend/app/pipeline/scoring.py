"""Risk scoring independent of policy action."""
from __future__ import annotations

from typing import Any, Iterable

from .rules import RuleMatch


def score_risk(
    matches: Iterable[RuleMatch],
    taints: Iterable[str] = (),
    llm: Any | None = None,
) -> int:
    matches = list(matches)
    score = 0
    # The strongest match contributes most; multiple independent signals add bounded context.
    for index, match in enumerate(sorted(matches, key=lambda item: item.weight, reverse=True)):
        score += match.weight if index == 0 else max(5, match.weight // 3)
    taint_bonus = {
        "secret_candidate": 12, "instruction_like": 10, "path_traversal": 15,
        "execution_like": 8, "encoded_content": 6, "personal_data": 6, "unsafe_tool": 15,
    }
    score += sum(taint_bonus.get(taint, 0) for taint in dict.fromkeys(taints))
    if llm is not None and getattr(llm, "available", False):
        confidence = max(0.0, min(1.0, float(getattr(llm, "confidence", 0.0))))
        label = str(getattr(llm, "label", "")).lower()
        if label in {"deny", "malicious", "unsafe", "high_risk"}:
            score += round(20 * confidence)
        elif label in {"review", "suspicious", "uncertain"}:
            score += round(10 * confidence)
        elif label in {"allow", "benign", "safe"}:
            score -= round(8 * confidence)
    return max(0, min(100, score))
