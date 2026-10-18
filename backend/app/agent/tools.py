"""Allow-listed, deterministic demo tools; no shell or network access."""
from __future__ import annotations

import ast
import operator
from pathlib import Path
from typing import Any

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "fixtures"
SAFE_TOOLS = ("list_fixtures", "read_fixture", "summarize", "calculate")
DEMO_TOOLS = ("fetch_page", "read_file", "send_email")
TOOL_NAMES = SAFE_TOOLS + DEMO_TOOLS


def _fixture_path(name: str) -> Path:
    if not name or len(name) > 128:
        raise ValueError("fixture name is required")
    candidate = (FIXTURE_ROOT / name).resolve()
    if candidate != FIXTURE_ROOT and FIXTURE_ROOT not in candidate.parents:
        raise ValueError("fixture path escapes the fixture directory")
    if not candidate.is_file():
        raise FileNotFoundError(name)
    return candidate


def list_fixtures() -> list[str]:
    return sorted(path.relative_to(FIXTURE_ROOT).as_posix() for path in FIXTURE_ROOT.rglob("*") if path.is_file())


def read_fixture(name: str) -> str:
    return _fixture_path(name).read_text(encoding="utf-8")[:20_000]


def summarize(text: str) -> dict[str, Any]:
    text = str(text).strip()
    words = text.split()
    sentences = [part.strip() for part in text.replace("!", ".").replace("?", ".").split(".") if part.strip()]
    return {
        "summary": (sentences[0][:300] if sentences else ""),
        "word_count": len(words),
        "character_count": len(text),
    }


_BIN_OPS: dict[type[ast.operator], Any] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS: dict[type[ast.unaryop], Any] = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _calculate(node: ast.AST) -> float | int:
    if isinstance(node, ast.Expression):
        return _calculate(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        if abs(node.value) > 1_000_000:
            raise ValueError("number too large")
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        left, right = _calculate(node.left), _calculate(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > 8:
            raise ValueError("exponent too large")
        return _BIN_OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_calculate(node.operand))
    raise ValueError("only numeric arithmetic is allowed")


def calculate(expression: str) -> float | int:
    if len(str(expression)) > 200:
        raise ValueError("expression too long")
    try:
        tree = ast.parse(str(expression), mode="eval")
        result = _calculate(tree)
    except (SyntaxError, TypeError, ZeroDivisionError, OverflowError) as exc:
        raise ValueError("invalid arithmetic expression") from exc
    if isinstance(result, (int, float)) and abs(result) <= 1_000_000_000:
        return result
    raise ValueError("calculation result out of range")


def fetch_page(fixture_id: str) -> dict[str, Any]:
    """Read a page fixture without making a network request."""
    return {"fixture_id": fixture_id, "content": read_fixture(fixture_id), "network": False}


def run_tool(name: str, args: dict[str, Any] | None = None) -> Any:
    args = args or {}
    if name == "list_fixtures":
        return list_fixtures()
    if name in {"read_fixture", "read_file"}:
        return read_fixture(str(args.get("name", args.get("path", ""))))
    if name == "fetch_page":
        return fetch_page(str(args.get("fixture_id", args.get("id", args.get("name", "")))))
    if name == "summarize":
        return summarize(str(args.get("text", "")))
    if name == "calculate":
        return {"result": calculate(str(args.get("expression", "")))}
    raise ValueError(f"tool {name!r} is not allow-listed")
