"""Small public provenance/taint primitives used by integrations and tests."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class TaintRecord:
    content_id: str
    verdict: str
    trusted: bool = False


@dataclass
class TaintState:
    """Monotonic session taint: once untrusted content is recorded it remains known."""

    records: dict[str, TaintRecord] = field(default_factory=dict)

    def remember(self, content_id: str, verdict: str, *, trusted: bool = False) -> TaintRecord:
        record = TaintRecord(content_id=content_id, verdict=verdict, trusted=trusted)
        self.records[content_id] = record
        return record

    def is_untrusted(self, provenance: Iterable[str | dict[str, object]]) -> bool:
        for item in provenance:
            content_id = str(item if isinstance(item, str) else item.get("content_id", item.get("id", "")))
            known = self.records.get(content_id)
            if known is not None and not known.trusted:
                return True
            if isinstance(item, dict) and (
                item.get("trusted") is False or str(item.get("verdict", "")).lower() in {"flag", "block", "review", "deny"}
            ):
                return True
        return False


__all__ = ["TaintRecord", "TaintState"]
