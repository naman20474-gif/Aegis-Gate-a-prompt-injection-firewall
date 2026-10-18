"""Small in-process event bus used by the SSE endpoint."""
from __future__ import annotations

import asyncio
import json
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any


class EventBus:
    def __init__(self, max_events: int = 250):
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = threading.Lock()

    def publish(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        event = {
            "id": str(data.get("event_id") or data.get("decision_id") or data.get("scan_id") or len(self._events) + 1),
            "type": event_type, "session_id": data.get("session_id"),
            "created_at": datetime.now(timezone.utc).isoformat(), "data": data,
        }
        with self._lock:
            self._events.append(event)
            subscribers = list(self._subscribers)
        for queue in subscribers:
            wanted_session = getattr(queue, "_aegis_session_id", None)
            if wanted_session is not None and wanted_session != event.get("session_id") and wanted_session != data.get("session_id"):
                continue
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except asyncio.QueueEmpty:
                    pass
        return event

    def recent(
        self, limit: int = 50, after: str | None = None,
        session_id: str | None = None, event_types: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self._events)
        if session_id is not None:
            events = [event for event in events if event.get("session_id") == session_id or event.get("data", {}).get("session_id") == session_id]
        if event_types is not None:
            events = [event for event in events if event.get("type") in event_types]
        if after:
            for index, event in enumerate(events):
                if event["id"] == after:
                    events = events[index + 1:]
                    break
        return events[-max(1, min(limit, 250)):]

    async def subscribe(self, session_id: str | None = None) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        # Store the filter on the queue without changing the public queue type.
        queue._aegis_session_id = session_id  # type: ignore[attr-defined]
        with self._lock:
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.discard(queue)


def sse_frame(event: dict[str, Any]) -> str:
    return f"id: {event['id']}\nevent: {event['type']}\ndata: {json.dumps(event['data'], default=str, sort_keys=True)}\n\n"
