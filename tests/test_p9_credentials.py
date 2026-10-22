"""Agent modules do not read target or provider secrets. Isolation is in-process, not a YAML note."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_NAMES = (
    "OPENROUTER_API_KEY",
    "COPILOT_FIXTURE_PASSWORD",
    "MODULE_SIGNING_SECRET",
    "OAUTH_TOKEN",
    "ACCESS_TOKEN",
)
AGENT_FILES = (
    "red_team.py",
    "red_team_generator.py",
    "judge.py",
    "documentation.py",
    "model_output.py",
)


def test_agent_modules_do_not_read_secrets() -> None:
    root = ROOT / "src" / "agentforge" / "agents"
    for name in AGENT_FILES:
        text = (root / name).read_text(encoding="utf-8")
        for secret in SECRET_NAMES:
            assert secret not in text, f"{name} reads {secret}"


def test_signing_secret_and_oauth_are_unread() -> None:
    root = ROOT / "src" / "agentforge"
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "os.environ" not in text or "MODULE_SIGNING_SECRET" not in text
        assert 'os.environ.get("MODULE_SIGNING_SECRET"' not in text
        assert 'os.environ["MODULE_SIGNING_SECRET"]' not in text
        assert "OAUTH_TOKEN" not in text


def test_session_login_is_the_only_password_reader() -> None:
    readers = []
    root = ROOT / "src" / "agentforge"
    for path in root.rglob("*.py"):
        if "COPILOT_FIXTURE_PASSWORD" in path.read_text(encoding="utf-8"):
            readers.append(path.name)
    assert readers == ["session.py"]


def test_live_scripts_do_not_build_login_request() -> None:
    for name in ("live_agent.py", "live_campaign.py"):
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "LoginRequest" not in text
        assert "LIVE_ENABLED = True" not in text


def test_provider_key_is_read_only_by_openrouter() -> None:
    readers = []
    root = ROOT / "src" / "agentforge"
    for path in root.rglob("*.py"):
        if "OPENROUTER_API_KEY" in path.read_text(encoding="utf-8"):
            readers.append(path.relative_to(root).as_posix())
    assert set(readers) <= {"agents/openrouter.py", "agents/openrouter_redteam.py", "agents/probe.py"}
