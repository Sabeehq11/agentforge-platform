"""The protocols accept a conforming message and stop. No agent class exists."""

from __future__ import annotations

import ast
from pathlib import Path

from agentforge.agents.interfaces import Documentation, Harness, Judge, Orchestrator, RedTeam
from agentforge.contracts.validate import validate

from tests.fixtures import attack_result, campaign_request, confirmed_exploit, verdict

ROOT = Path(__file__).resolve().parents[1]


class _Red:
    def propose(self, request: object) -> dict[str, object]:
        validate("campaign_request", request)
        return attack_result()


class _Judge:
    def judge(self, result: object) -> dict[str, object]:
        validate("attack_result", result)
        return verdict()


class _Doc:
    def draft(self, exploit: object) -> str:
        validate("confirmed_exploit", exploit)
        return "draft-1"


class _Harness:
    def accept(self, found: object) -> None:
        validate("verdict", found)
        return None


class _Orch:
    def next_request(self, correlation_id: str) -> dict[str, object]:
        message = campaign_request()
        message["correlation_id"] = correlation_id
        validate("campaign_request", message)
        return message


def test_a_conforming_message_passes_each_protocol() -> None:
    red: RedTeam = _Red()
    judge: Judge = _Judge()
    doc: Documentation = _Doc()
    harness: Harness = _Harness()
    orch: Orchestrator = _Orch()

    produced = red.propose(campaign_request())
    judged = judge.judge(produced)  # type: ignore[arg-type]
    assert harness.accept(judged) is None  # type: ignore[arg-type]
    assert doc.draft(confirmed_exploit()) == "draft-1"
    assert orch.next_request("corr-9")["correlation_id"] == "corr-9"


def test_no_agent_module_imports_a_client_or_opens_a_socket() -> None:
    banned = ("socket", "httpx", "urllib", "requests", "openai", "anthropic")
    for path in (ROOT / "src" / "agentforge" / "agents").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        imported += [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module]
        assert not any(name.split(".")[0] in banned for name in imported if name)
