"""Deterministic inbound safety rules."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from .normalize import NormalizedInput


@dataclass(frozen=True)
class Signal:
    """Stable public signal shape exposed by the fast rules stage."""

    id: str
    category: str
    weight: int
    span: tuple[int, int]
    excerpt: str


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    category: str
    severity: str
    action: str
    reason: str
    evidence: str
    taints: tuple[str, ...] = ()
    span: tuple[int, int] = (0, 0)

    @property
    def weight(self) -> int:
        return {"low": 10, "medium": 24, "high": 44, "critical": 68}.get(self.severity, 10)

    def as_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id, "category": self.category, "severity": self.severity,
            "action": self.action, "reason": self.reason, "evidence": self.evidence,
            "taints": list(self.taints), "span": list(self.span),
        }

    def as_signal(self) -> Signal:
        return Signal(
            id=self.rule_id,
            category=self.category,
            weight=max(0, min(100, self.weight)),
            span=self.span,
            excerpt=self.evidence[:500],
        )


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    category: str
    severity: str
    action: str
    reason: str
    patterns: tuple[Pattern[str], ...]
    taints: tuple[str, ...] = ()


def _rx(*patterns: str) -> tuple[Pattern[str], ...]:
    return tuple(re.compile(pattern, re.I | re.M) for pattern in patterns)


DEFAULT_RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        "injection.role_hijack", "role_hijack", "high", "deny",
        "The input attempts to impersonate a privileged role or replace the agent identity.",
        _rx(
            r"(?:you are now|act as|pretend to be|role[- ]?play)\s+(?:the\s+)?(?:system|developer|admin|administrator|root|unrestricted|different\s+assistant)",
            r"(?:become|switch to)\s+(?:an?\s+)?(?:admin|system|developer)\s+mode",
            r"\bdeveloper\s+mode\b",
        ),
        ("instruction_like",),
    ),
    RuleDefinition(
        "injection.delimiter_spoofing", "delimiter_spoofing", "high", "deny",
        "The input spoofs a system/developer message delimiter.",
        _rx(r"<\|(?:system|developer|assistant)\|>", r"(?:^|\n)\s*#{2,}\s*(?:system|developer|assistant)\b", r"\[(?:SYSTEM|DEVELOPER|ASSISTANT)\]", r"\bsystem\s*:", r"</?document>"),
        ("instruction_like",),
    ),
    RuleDefinition(
        "injection.ignore_instructions", "instruction_override", "high", "deny",
        "The input attempts to override higher-priority instructions.",
        _rx(r"ignore\s+(?:all\s+)?previous\s+instructions?", r"disregard\s+(?:the\s+)?(?:system|developer|safety)\s+(?:prompt|instructions?)", r"(?:new|follow\s+these)\s+instructions?\s*:", r"jailbreak", r"do\s+anything\s+now", r"reveal\s+(?:the\s+)?system\s+prompt", r"unrestricted\s+(?:agent|mode)", r"(?:system\s+administrator|override\s+(?:the\s+)?safety\s+prompt)", r"forget\s+(?:the\s+)?developer\s+(?:message|instructions?)"),
        ("instruction_like",),
    ),
    RuleDefinition(
        "exfiltration.secrets", "exfiltration", "critical", "deny",
        "The input requests credentials or directs secrets outside the safe boundary.",
        _rx(r"(?:send|post|upload|forward|email|leak)\b.{0,100}\b(?:api[_ -]?key|secret|password|token|private[_ -]?key)", r"(?:api[_ -]?key|secret|password|token|private[_ -]?key).{0,100}\b(?:send|post|upload|forward|email|leak)\b", r"\b(?:send|post|upload|forward|email|reveal)\b.{0,120}(?:https?://|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", r"(?:api[_ -]?key|password|secret|token)\s*[:=]\s*\S+", r"BEGIN (?:RSA |OPENSSH )?PRIVATE KEY", r"sk-[A-Za-z0-9]{12,}"),
        ("secret_candidate",),
    ),
    RuleDefinition(
        "execution.dangerous_command", "dangerous_command", "high", "review",
        "The input contains a shell or code execution pattern outside the demo tool boundary.",
        _rx(r"rm\s+-rf\b", r"(?:curl|wget)\s+[^\n|]+\|\s*(?:ba)?sh", r"(?:powershell|cmd(?:\.exe)?|/bin/(?:ba)?sh)\b", r"(?:os\.system|subprocess\.(?:run|Popen|call)|eval\s*\()"),
        ("execution_like",),
    ),
    RuleDefinition(
        "filesystem.traversal", "path_traversal", "high", "deny",
        "The input attempts to leave the fixture or workspace boundary.",
        _rx(r"(?:^|[^A-Za-z0-9])\.\.(?:[\\/]|$)", r"(?:^|[\\/])etc[\\/]passwd", r"(?:^|[\\/])root[\\/]\.ssh", r"file://"),
        ("path_traversal",),
    ),
    RuleDefinition(
        "tools.unsafe_name", "tool_coercion", "high", "deny",
        "Only the allow-listed local demo tools may be invoked.",
        _rx(r"(?:tool|function)\s*[:=]\s*(?:shell|exec|http|browser|network|delete|write_file)\b", r"\b(?:shell|exec|run_command|http_request|browser_automation)\b", r"\b(?:send_email|read_file|fetch_page)\s*\("),
        ("unsafe_tool",),
    ),
    RuleDefinition(
        "privacy.pii", "sensitive_personal_data", "medium", "review",
        "The input appears to contain sensitive personal data.",
        _rx(r"\b\d{3}-\d{2}-\d{4}\b", r"\b(?:4\d{3}|5[1-5]\d{2})(?:[ -]?\d{4}){3}\b", r"(?:date of birth|social security|credit card|medical record)"),
        ("personal_data",),
    ),
    RuleDefinition(
        "encoding.obfuscated_payload", "obfuscation", "medium", "review",
        "The input contains an encoded or intentionally obscured payload.",
        _rx(r"base64\s*(?:-d|decode)", r"\bdecode\b.{0,20}\bbase64\b", r"\bencoded\b", r"(?:encoded|decode this).{0,30}[A-Za-z0-9+/]{24,}={0,2}", r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/])"),
        ("encoded_content",),
    ),
    RuleDefinition(
        "content.hidden_markup", "hidden_content", "medium", "review",
        "The input contains content hidden from a normal visual rendering.",
        _rx(r"\[hidden content:"),
        ("hidden_content",),
    ),
    RuleDefinition(
        "content.social_engineering", "urgency_authority", "low", "review",
        "The input uses urgency or authority pressure that merits review.",
        _rx(r"urgent(?:ly)?\b.{0,80}\b(?:secret|password|credential|transfer|do\s+this\s+first)", r"(?:ceo|admin|security)\s+(?:asked|requires|orders?|says)", r"\bIMPORTANT\s*:", r"\bdo\s+this\s+first\b"),
        ("social_engineering",),
    ),
)


class RuleEngine:
    def __init__(self, rules: tuple[RuleDefinition, ...] | None = None):
        self.rules = rules or DEFAULT_RULES

    @staticmethod
    def _evidence(text: str, match: re.Match[str] | None) -> str:
        if match is None:
            return "matched taint"
        start = max(0, match.start() - 40)
        end = min(len(text), match.end() + 80)
        evidence = text[start:end].replace("\n", " ").strip()
        return re.sub(r"(?i)(api[_ -]?key|password|secret|token)\s*[:=]\s*\S+", r"\1=[redacted]", evidence)

    def evaluate(self, normalized: NormalizedInput) -> list[RuleMatch]:
        text = normalized.text
        matches: list[RuleMatch] = []
        for rule in self.rules:
            found = None
            for pattern in rule.patterns:
                found = pattern.search(text)
                if found:
                    break
            taints = tuple(dict.fromkeys((*rule.taints, *[t for t in normalized.taints if t in rule.taints])))
            if found:
                matches.append(RuleMatch(
                    rule_id=rule.rule_id, category=rule.category, severity=rule.severity,
                    action=rule.action, reason=rule.reason, evidence=self._evidence(text, found), taints=taints,
                    span=(found.start(), found.end()),
                ))
        if normalized.hidden_signals and not any(match.rule_id == "content.hidden_markup" for match in matches):
            signal = normalized.hidden_signals[0]
            span_value = signal.get("span", [0, 0])
            matches.append(RuleMatch(
                rule_id="content.hidden_markup", category="hidden_content", severity="medium", action="review",
                reason="The input contains content hidden from a normal visual rendering.",
                evidence=str(signal.get("excerpt", "hidden content")), taints=("hidden_content",),
                span=(int(span_value[0]), int(span_value[1])),
            ))
        obfuscation_metadata = normalized.metadata
        if (
            int(obfuscation_metadata.get("zero_width_count", 0)) > 0
            or int(obfuscation_metadata.get("bidi_control_count", 0)) > 0
            or obfuscation_metadata.get("decoded_segments")
        ) and not any(match.category == "obfuscation" for match in matches):
            matches.append(RuleMatch(
                rule_id="encoding.control_or_encoded_payload",
                category="obfuscation", severity="medium", action="review",
                reason="The input contains characters or segments commonly used to hide instructions.",
                evidence="zero-width/bidi controls or encoded segment detected",
                taints=("encoded_content",), span=(0, min(len(text), 1)),
            ))
        return matches

    def signals(self, normalized: NormalizedInput) -> list[Signal]:
        """Return the compact public signal list required by the scan contract."""
        return [match.as_signal() for match in self.evaluate(normalized)]
