"""Canonicalization, hidden-content inspection, and provenance tracking."""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable


class InputLimitError(ValueError):
    """Raised when an inbound request exceeds the configured text limit."""


@dataclass(frozen=True)
class ProvenanceRecord:
    path: str
    source: str
    kind: str
    preview: str
    sha256: str
    taints: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "source": self.source,
            "kind": self.kind,
            "preview": self.preview,
            "sha256": self.sha256,
            "taints": list(self.taints),
        }


@dataclass
class NormalizedInput:
    text: str
    payload: Any
    source: str
    fields: dict[str, Any] = field(default_factory=dict)
    provenance: list[ProvenanceRecord] = field(default_factory=list)
    taints: list[str] = field(default_factory=list)
    hidden_signals: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self, *, include_payload: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {
            "text": self.text,
            "source": self.source,
            "fields": self.fields,
            "taints": self.taints,
            "provenance_count": len(self.provenance),
            "hidden_signals": self.hidden_signals,
            "metadata": self.metadata,
        }
        if include_payload:
            result["payload"] = self.payload
        return result


_TEXT_KEYS = {
    "text", "content", "body", "message", "prompt", "input", "query", "instruction",
    "description", "title", "value", "name", "command", "expression", "path", "tool",
}
_SECRET_HINTS = re.compile(
    r"(?:api[_ -]?key|secret|password|passwd|private[_ -]?key|bearer\s+[a-z0-9._-]+|token)",
    re.I,
)
_URL = re.compile(r"https?://[^\s]+", re.I)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{41,}={0,2}(?![A-Za-z0-9+/])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{41,}(?![0-9A-Fa-f])")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\ufeff")
_BIDI = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_TAG = re.compile(r"</?[A-Za-z][^>]*>", re.S)
_COMMENT = re.compile(r"<!--(?P<body>.*?)-->", re.S)
_HIDDEN_ELEMENT = re.compile(
    r"<(?P<tag>[a-z][\w:-]*)\b(?P<attrs>[^>]*)>(?P<body>.*?)</(?P=tag)\s*>",
    re.I | re.S,
)
_HIDDEN_ATTR = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px)?|"
    r"(?:width|height)\s*:\s*0(?:px)?|(?:width|height)\s*=\s*[\"']?0[\"']?|color\s*:\s*(?:#fff(?:fff)?|white)\s*;?\s*"
    r"background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white)|aria-hidden\s*=\s*[\"']?true)",
    re.I,
)


def _clean(value: str) -> str:
    """Legacy-compatible text cleanup used by callers and tests."""
    return _inspect_text(value)[0]


def _json_scalar(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, (bool, int, float)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(value)


def _walk(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield child_path, child
            yield from _walk(child, child_path)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            yield child_path, child
            yield from _walk(child, child_path)


def _taints_for(path: str, text: str, source: str) -> tuple[str, ...]:
    lowered = f"{path} {text}".lower()
    taints = ["external_input"]
    if source not in {"internal", "fixture", "benchmark"}:
        taints.append("untrusted_source")
    if _SECRET_HINTS.search(text):
        taints.append("secret_candidate")
    if any(word in lowered for word in ("ssn", "social security", "credit card", "medical record", "date of birth")):
        taints.append("personal_data")
    if _URL.search(text):
        taints.append("external_link")
    if _BASE64.search(text) or _HEX.search(text) or "base64" in lowered or "encoded" in lowered:
        taints.append("encoded_content")
    if re.search(r"(?:^|[^a-z0-9])\.\.(?:[/\\]|$)|(?:^|[/\\])(?:etc[/\\]passwd|root[/\\]\.ssh)", lowered):
        taints.append("path_traversal")
    if re.search(r"(?:rm\s+-rf|curl\s+[^|]+\|\s*(?:ba)?sh|powershell|cmd(?:\.exe)?|os\.system|subprocess\.)", lowered):
        taints.append("execution_like")
    if re.search(
        r"(?:tool|function)\s*[:=]\s*(?:shell|exec|http|browser|network|delete|write_file)|"
        r"\b(?:shell|exec|run_command|http_request|browser_automation)\b",
        lowered,
    ):
        taints.append("unsafe_tool")
    if any(marker in lowered for marker in (
        "ignore previous", "system prompt", "jailbreak", "disregard instructions", "unrestricted agent",
    )):
        taints.append("instruction_like")
    return tuple(dict.fromkeys(taints))


def _safe_preview(text: str, limit: int = 240) -> str:
    # Keep audit records useful without copying a whole inbound secret.
    preview = text[:limit]
    preview = re.sub(
        r"(?i)(api[_ -]?key|password|secret|token|private[_ -]?key)\s*[:=]\s*\S+",
        r"\1=[redacted]",
        preview,
    )
    if _SECRET_HINTS.search(preview):
        preview = _SECRET_HINTS.sub("[sensitive]", preview)
    return preview


def _decode_segments(text: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Decode long base64/hex candidates as data only; never execute decoded values."""
    additions: list[str] = []
    signals: list[dict[str, Any]] = []
    for encoding, pattern in (("base64", _BASE64), ("hex", _HEX)):
        for match in pattern.finditer(text):
            candidate = match.group(0)
            decoded: str | None = None
            try:
                raw = base64.b64decode(candidate, validate=True) if encoding == "base64" else bytes.fromhex(candidate)
                value = raw.decode("utf-8")
                if value and all(character.isprintable() or character in "\r\n\t" for character in value):
                    decoded = value
            except (ValueError, UnicodeDecodeError, binascii.Error):
                decoded = None
            signal: dict[str, Any] = {
                "id": f"normalization.{encoding}",
                "category": "obfuscation",
                "type": encoding,
                "span": [match.start(), match.end()],
                "excerpt": _safe_preview(candidate, 120),
                "decoded": decoded is not None,
            }
            if decoded is not None:
                signal["decoded_preview"] = _safe_preview(decoded, 300)
                additions.append(f"[decoded {encoding}: {decoded[:2000]}]")
            signals.append(signal)
    return additions, signals


def _inspect_text(value: str) -> tuple[str, dict[str, Any]]:
    """Return visible canonical text plus non-executable hidden/encoding metadata."""
    original = unicodedata.normalize("NFKC", value)
    metadata: dict[str, Any] = {
        "nfkc_changed": original != value,
        "zero_width_count": sum(character in _ZERO_WIDTH for character in original),
        "bidi_control_count": sum(character in _BIDI for character in original),
        "control_count": len(_CONTROL.findall(original)),
        "html_stripped_count": 0,
        "hidden_signals": [],
        "decoded_segments": [],
    }
    working = "".join(character for character in original if character not in _ZERO_WIDTH and character not in _BIDI)
    working = _CONTROL.sub("", working)
    hidden_texts: list[str] = []
    for comment in _COMMENT.finditer(working):
        body = html.unescape(_TAG.sub(" ", comment.group("body"))).strip()
        metadata["hidden_signals"].append({
            "id": "hidden.html_comment", "category": "hidden_content", "type": "html_comment",
            "span": [comment.start(), comment.end()], "excerpt": _safe_preview(body, 240),
        })
        if body:
            hidden_texts.append(body)
    for element in _HIDDEN_ELEMENT.finditer(working):
        attrs = element.group("attrs")
        if _HIDDEN_ATTR.search(attrs):
            body = html.unescape(_TAG.sub(" ", element.group("body"))).strip()
            style_match = _HIDDEN_ATTR.search(attrs)
            kind = (style_match.group(0) if style_match else "hidden").replace(" ", "_").replace(":", "_")[:40]
            metadata["hidden_signals"].append({
                "id": f"hidden.{kind}", "category": "hidden_content", "type": kind,
                "span": [element.start(), element.end()], "excerpt": _safe_preview(body or element.group(0), 240),
            })
            if body:
                hidden_texts.append(body)
    # A standalone hidden attribute may not have a matching closing tag.
    for tag in re.finditer(r"<[^>]*?(?:aria-hidden\s*=\s*[\"']?true|display\s*:\s*none)[^>]*>", working, re.I):
        if not any(signal["span"][0] == tag.start() for signal in metadata["hidden_signals"]):
            metadata["hidden_signals"].append({
                "id": "hidden.html_attribute", "category": "hidden_content", "type": "hidden_attribute",
                "span": [tag.start(), tag.end()], "excerpt": _safe_preview(tag.group(0), 240),
            })
    without_comments = _COMMENT.sub(" ", working)
    without_tags = _TAG.sub(" ", without_comments)
    metadata["html_stripped_count"] = len(_TAG.findall(working))
    visible = html.unescape(without_tags)
    decoded_additions, decoded_signals = _decode_segments(visible)
    metadata["decoded_segments"] = decoded_signals
    if hidden_texts:
        visible = f"{visible} [hidden content: {' | '.join(hidden_texts)}]"
    if decoded_additions:
        visible = f"{visible} {' '.join(decoded_additions)}"
    visible = re.sub(r"[ \t]+", " ", visible)
    return visible.strip(), metadata


def normalize_inbound(
    payload: Any,
    *,
    source: str = "api",
    max_text_chars: int = 100_000,
    metadata: dict[str, Any] | None = None,
) -> NormalizedInput:
    """Normalize arbitrary JSON-ish input while retaining field-level provenance."""
    source = _clean(source)[:64] or "api"
    fragments: list[str] = []
    records: list[ProvenanceRecord] = []
    fields: dict[str, Any] = {}
    hidden_signals: list[dict[str, Any]] = []
    aggregate_metadata: dict[str, Any] = {
        "nfkc_changed": False,
        "zero_width_count": 0,
        "bidi_control_count": 0,
        "control_count": 0,
        "html_stripped_count": 0,
        "decoded_segments": [],
    }

    if isinstance(payload, str):
        candidates = [("$.text", payload)]
    else:
        candidates = [
            (path, value)
            for path, value in _walk(payload)
            if isinstance(value, (str, int, float, bool)) or value is None
        ]
        if not candidates:
            candidates = [("$", payload)]

    for path, value in candidates:
        raw_text = _json_scalar(value)
        if not raw_text:
            continue
        text, info = _inspect_text(raw_text)
        if not text:
            continue
        aggregate_metadata["nfkc_changed"] = aggregate_metadata["nfkc_changed"] or bool(info.get("nfkc_changed", False))
        for key in ("zero_width_count", "bidi_control_count", "control_count", "html_stripped_count"):
            aggregate_metadata[key] += int(info.get(key, 0))
        hidden_signals.extend(info.get("hidden_signals", []))
        aggregate_metadata["decoded_segments"].extend(info.get("decoded_segments", []))
        lowered_path = path.rsplit(".", 1)[-1].lower()
        if isinstance(value, (str, int, float, bool)) or lowered_path in _TEXT_KEYS:
            fragment = f"{path}: {text}" if path != "$.text" else text
            fragments.append(fragment)
            taints = _taints_for(path, f"{raw_text} {text}", source)
            record = ProvenanceRecord(
                path=path,
                source=source,
                kind=type(value).__name__,
                preview=_safe_preview(text),
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                taints=taints,
            )
            records.append(record)
            fields[path] = text if len(text) <= 500 else text[:500] + "…"

    if metadata:
        for key, value in metadata.items():
            raw_text = _json_scalar(value)
            if not raw_text:
                continue
            text, info = _inspect_text(raw_text)
            if not text:
                continue
            path = f"$.metadata.{key}"
            fragments.append(f"{path}: {text}")
            records.append(ProvenanceRecord(
                path=path,
                source=source,
                kind=type(value).__name__,
                preview=_safe_preview(text),
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                taints=_taints_for(path, f"{raw_text} {text}", source),
            ))
            hidden_signals.extend(info.get("hidden_signals", []))
            aggregate_metadata["decoded_segments"].extend(info.get("decoded_segments", []))
            aggregate_metadata["nfkc_changed"] = aggregate_metadata["nfkc_changed"] or bool(info.get("nfkc_changed", False))
            for key_name in ("zero_width_count", "bidi_control_count", "control_count", "html_stripped_count"):
                aggregate_metadata[key_name] += int(info.get(key_name, 0))

    canonical = "\n".join(dict.fromkeys(fragments))
    if len(canonical) > max_text_chars:
        raise InputLimitError(f"normalized input exceeds {max_text_chars} characters")
    # Shift each local hidden span into the canonical representation approximately. The
    # metadata remains useful even when a payload has multiple fields.
    if hidden_signals:
        for signal in hidden_signals:
            signal.setdefault("global_span", signal.get("span"))
    taints = list(dict.fromkeys(taint for record in records for taint in record.taints))
    if hidden_signals:
        taints.append("hidden_content")
    if aggregate_metadata["decoded_segments"]:
        taints.append("encoded_content")
    taints = list(dict.fromkeys(taints))
    if not records:
        taints = ["external_input"]
    aggregate_metadata["hidden_signal_count"] = len(hidden_signals)
    aggregate_metadata["zero_width_detected"] = aggregate_metadata["zero_width_count"] > 0
    aggregate_metadata["bidi_control_detected"] = aggregate_metadata["bidi_control_count"] > 0
    return NormalizedInput(
        text=canonical,
        payload=payload,
        source=source,
        fields=fields,
        provenance=records,
        taints=taints,
        hidden_signals=hidden_signals,
        metadata=aggregate_metadata,
    )


def decode_base64_candidate(value: str) -> str | None:
    """Best-effort helper used by diagnostics; never executes content."""
    try:
        raw = base64.b64decode(value, validate=True)
        decoded = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    return decoded if decoded.isprintable() else None
