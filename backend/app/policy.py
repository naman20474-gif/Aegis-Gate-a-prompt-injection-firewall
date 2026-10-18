"""YAML policy loader and taint-aware decision engine."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .pipeline.rules import RuleMatch

logger = logging.getLogger(__name__)
_ALLOWED_ACTIONS = {"allow", "review", "deny"}


@dataclass(frozen=True)
class Policy:
    name: str
    description: str
    review_threshold: int = 45
    deny_threshold: int = 75
    blocked_taints: tuple[str, ...] = ()
    approval_taints: tuple[str, ...] = ()
    rule_actions: dict[str, str] = field(default_factory=dict)
    protected_actions: tuple[str, ...] = ("agent_tool", "execute_tool")

    def __post_init__(self) -> None:
        if not 0 <= self.review_threshold <= 100 or not 0 <= self.deny_threshold <= 100:
            raise ValueError("policy thresholds must be between 0 and 100")
        if self.review_threshold > self.deny_threshold:
            raise ValueError("review threshold cannot exceed deny threshold")
        if any(action not in _ALLOWED_ACTIONS for action in self.rule_actions.values()):
            raise ValueError("rule actions must be allow, review, or deny")


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reasons: tuple[str, ...]
    requires_approval: bool


class PolicyEngine:
    def __init__(self, policy_dir: str | Path | None = None):
        self.policy_dir = Path(policy_dir) if policy_dir else Path(__file__).resolve().parents[1] / "policies"
        self._policies: dict[str, Policy] = {}
        self.reload()

    @staticmethod
    def _parse(name: str, data: dict[str, Any]) -> Policy:
        thresholds = data.get("thresholds", {}) or {}
        if not isinstance(thresholds, dict):
            thresholds = {}
        raw_actions = data.get("rule_actions")
        if raw_actions is None:
            raw_actions = data.get("rules", {})
        actions: dict[str, Any] = {}
        if isinstance(raw_actions, dict):
            actions = raw_actions
        elif isinstance(raw_actions, list):
            for item in raw_actions:
                if isinstance(item, dict):
                    rule_id = item.get("rule_id", item.get("id", item.get("name")))
                    action = item.get("action", item.get("decision", item.get("effect")))
                    if rule_id is not None and action is not None:
                        actions[str(rule_id)] = action
        normalized_actions = {}
        for key, value in actions.items():
            if isinstance(value, dict):
                value = value.get("action", value.get("decision", value.get("effect", "review")))
            normalized_actions[str(key)] = str(value).lower()
        return Policy(
            name=str(data.get("name", name)),
            description=str(data.get("description", "")),
            review_threshold=int(thresholds.get("review", data.get("review_threshold", 45))),
            deny_threshold=int(thresholds.get("deny", data.get("deny_threshold", 75))),
            blocked_taints=tuple(str(value) for value in data.get("blocked_taints", data.get("deny_taints", [])) or []),
            approval_taints=tuple(str(value) for value in data.get("approval_taints", data.get("review_taints", [])) or []),
            rule_actions=normalized_actions,
            protected_actions=tuple(str(value) for value in data.get("protected_actions", ["agent_tool", "execute_tool"]) or []),
        )

    def reload(self) -> None:
        policies: dict[str, Policy] = {}
        if self.policy_dir.exists():
            for path in sorted((*self.policy_dir.glob("*.yml"), *self.policy_dir.glob("*.yaml"))):
                try:
                    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                    if not isinstance(data, dict):
                        raise ValueError("root must be a mapping")
                    policy = self._parse(path.stem, data)
                    policies[policy.name] = policy
                except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
                    logger.error("policy load failed", extra={"fields": {"path": str(path), "error": str(exc)}})
        if "default" not in policies:
            policies["default"] = Policy(name="default", description="Built-in fail-closed default")
        self._policies = policies

    def names(self) -> list[str]:
        return sorted(self._policies)

    def get(self, name: str = "default") -> Policy:
        return self._policies.get(name, self._policies["default"])

    def raw(self, name: str = "default") -> dict[str, Any]:
        """Return the safe-loaded YAML mapping for declarative integrations."""
        path = self.policy_dir / f"{name}.yaml"
        if not path.exists():
            path = self.policy_dir / f"{name}.yml"
        if not path.exists():
            return self.describe(name)
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            return value if isinstance(value, dict) else self.describe(name)
        except (OSError, yaml.YAMLError):
            return self.describe(name)

    def update(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        """Validate and atomically replace one YAML-like policy mapping."""
        if not name or "/" in name or "\\" in name or name != "default":
            raise ValueError("only the default policy is editable")
        if not isinstance(data, dict):
            raise ValueError("policy must be an object")
        current = self.raw("default")
        merged = dict(current)
        for key, value in data.items():
            if key == "rules" and "rule_actions" not in data:
                # Accept the concise YAML-like update shape while retaining the canonical key on disk.
                merged["rule_actions"] = value
                continue
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                nested = dict(merged[key])
                nested.update(value)
                merged[key] = nested
            else:
                merged[key] = value
        # Parse before writing; this rejects invalid thresholds/actions and custom tags are
        # never accepted because safe_load is used on the serialized representation.
        serialized = yaml.safe_dump(merged, sort_keys=False)
        parsed = yaml.safe_load(serialized)
        if not isinstance(parsed, dict):
            raise ValueError("policy must be a mapping")
        self._parse(name, parsed)
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        path = self.policy_dir / "default.yaml"
        temporary = path.with_suffix(".yaml.tmp")
        temporary.write_text(serialized, encoding="utf-8")
        temporary.replace(path)
        self.reload()
        return self.raw("default")

    def describe(self, name: str = "default") -> dict[str, Any]:
        policy = self.get(name)
        return {
            "name": policy.name, "description": policy.description,
            "thresholds": {"review": policy.review_threshold, "deny": policy.deny_threshold},
            "blocked_taints": list(policy.blocked_taints), "approval_taints": list(policy.approval_taints),
            "rule_actions": policy.rule_actions, "protected_actions": list(policy.protected_actions),
        }

    def evaluate(
        self, policy_name: str, risk_score: int, matches: list[RuleMatch], taints: list[str],
        *, requested_action: str = "evaluate",
    ) -> PolicyDecision:
        policy = self.get(policy_name)
        reasons: list[str] = []
        decision = "allow"
        for match in matches:
            action = policy.rule_actions.get(match.rule_id, match.action)
            if action == "deny":
                decision = "deny"
            elif action == "review" and decision != "deny":
                decision = "review"
            reasons.append(f"{match.rule_id}: {match.reason}")
        blocked = sorted(set(policy.blocked_taints).intersection(taints))
        if blocked:
            decision = "deny"
            reasons.append("blocked taint(s): " + ", ".join(blocked))
        approval_taints = sorted(set(policy.approval_taints).intersection(taints))
        if approval_taints and decision == "allow":
            decision = "review"
            reasons.append("approval-required taint(s): " + ", ".join(approval_taints))
        if risk_score >= policy.deny_threshold:
            decision = "deny"
            reasons.append(f"risk score {risk_score} meets deny threshold {policy.deny_threshold}")
        elif risk_score >= policy.review_threshold and decision == "allow":
            decision = "review"
            reasons.append(f"risk score {risk_score} meets review threshold {policy.review_threshold}")
        if requested_action in policy.protected_actions and decision == "allow" and risk_score >= policy.review_threshold:
            decision = "review"
            reasons.append(f"protected action {requested_action} requires approval at this risk")
        requires_approval = decision == "review"
        if not reasons:
            reasons.append("no safety rule matched")
        return PolicyDecision(decision=decision, reasons=tuple(dict.fromkeys(reasons)), requires_approval=requires_approval)
