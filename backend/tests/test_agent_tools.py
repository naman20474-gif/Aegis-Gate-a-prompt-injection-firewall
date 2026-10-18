from __future__ import annotations

import pytest

from backend.app.agent.tools import SAFE_TOOLS, calculate, list_fixtures, read_fixture, run_tool, summarize


def test_safe_tool_allowlist_is_explicit():
    assert SAFE_TOOLS == ("list_fixtures", "read_fixture", "summarize", "calculate")


def test_eight_local_fixtures_exist():
    assert len(list_fixtures()) == 8


def test_fixture_read_is_bounded_and_local():
    text = read_fixture("files/benign_note.txt")
    assert "ordinary project" in text
    with pytest.raises(ValueError):
        read_fixture("../pyproject.toml")


def test_missing_fixture_is_reported():
    with pytest.raises(FileNotFoundError):
        read_fixture("files/nope.txt")


def test_summarize_is_deterministic():
    assert summarize("One sentence. Second sentence!") == {
        "summary": "One sentence", "word_count": 4, "character_count": 30
    }


@pytest.mark.parametrize(("expression", "expected"), [("2 + 3 * 4", 14), ("10 / 2", 5), ("2 ** 3", 8), ("-4", -4)])
def test_calculate_allows_bounded_arithmetic(expression, expected):
    assert calculate(expression) == expected


@pytest.mark.parametrize("expression", ["__import__('os')", "open('x')", "2 ** 99", "1 / 0"])
def test_calculate_rejects_code_or_unbounded_work(expression):
    with pytest.raises(ValueError):
        calculate(expression)


def test_run_tool_dispatches_without_shell():
    assert run_tool("calculate", {"expression": "6 * 7"}) == {"result": 42}
    with pytest.raises(ValueError):
        run_tool("shell", {"command": "id"})
