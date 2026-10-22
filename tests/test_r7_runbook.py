"""The R7 deploy and rollback runbooks describe one isolated approach and never run the pin's stock scripts.

These read the runbook text only. They cannot show that the commands work, because nothing is run.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = (ROOT / "Docs/runbooks/r7-deploy.md").read_text()
ROLLBACK = (ROOT / "Docs/runbooks/r7-rollback.md").read_text()
BOTH = DEPLOY + "\n" + ROLLBACK
FLAT_DEPLOY = " ".join(DEPLOY.split())
FLAT_ROLLBACK = " ".join(ROLLBACK.split())


def _section(text: str, start: str, end: str) -> str:
    return text[text.index(start) : text.index(end)]


def test_there_is_no_option_one_and_no_stop_the_existing_stack_path() -> None:
    lowered = FLAT_DEPLOY.lower()
    for phrase in ("option 1", "you choose at gate a", "restart your old stack", "only stack on ports 8300"):
        assert phrase not in lowered, phrase
    assert not re.search(r"stop the existing stack", lowered)
    assert "start it again" not in FLAT_ROLLBACK.lower().replace("so there is nothing to start again", "")


def test_stock_scripts_are_prohibited_and_never_invoked() -> None:
    assert "Do not run `scripts/copilot/tunnel.sh` in any form" in FLAT_DEPLOY
    assert "Do not run `scripts/copilot/security_gate.sh` either" in FLAT_DEPLOY
    invocation = re.compile(r"(\./|bash |sh )\S*(tunnel|security_gate)\.sh|tunnel\.sh (up|down|status)")
    for line in BOTH.splitlines():
        if invocation.search(line):
            assert re.search(r"\b(do not|never|not)\b", line, re.IGNORECASE), line
    assert "Do not use `scripts/copilot/tunnel.sh down`" in FLAT_ROLLBACK
    # the hardening steps are read from the pin's text, not executed
    assert "git -C CHECKOUT show HEAD:scripts/copilot/tunnel.sh" in FLAT_DEPLOY


def test_every_compose_command_names_a_unique_project() -> None:
    assert "must not be `development-easy-light`" in FLAT_DEPLOY
    commands = re.findall(r"docker compose (\S+)", BOTH)
    assert commands, "the runbooks should show compose commands"
    for first in commands:
        assert first in {"-p", "`"}, first  # "`" is the prose sentence that forbids a bare `docker compose`
    assert "never with `-v`" in FLAT_ROLLBACK
    assert not re.search(r"docker compose[^\n]*\s-v\b", BOTH)


def test_isolated_volumes_ports_and_network_are_checked_before_start() -> None:
    before_start = _section(DEPLOY, "### Isolation checks, before anything starts", "### Existing-stack canary")
    for expected in (
        "Every named volume is prefixed `P_`",
        "No volume is declared `external`",
        "Every bind-mount source is under `CHECKOUT`",
        "Every published port is bound to `127.0.0.1`",
        "None of 8300, 9300, 8320, 8310 or 8400 appears",
        "The network is `P_default`",
        "`development-easy-light_default`",
    ):
        assert expected in " ".join(before_start.split()), expected
    assert "not 8300, 9300, 8320, 8310 or 8400" in FLAT_DEPLOY
    assert "config" in before_start and " up " not in before_start


def test_agent_gets_its_own_port_and_the_new_network() -> None:
    override = _section(DEPLOY, "```yaml", "Replace `AGENT_HOST_PORT`")
    assert "ports: !override" in override
    assert '"127.0.0.1:AGENT_HOST_PORT:8400"' in override
    assert "name: P_default" in override
    assert "8400" not in override.replace(":8400", "")  # the old host port is never published
    assert "WORK/agent-override.yml" in DEPLOY and "outside `CHECKOUT`" in FLAT_DEPLOY
    assert "-p P-agent" in DEPLOY
    assert "agent attaches to `P_default` and not to `development-easy-light_default`" in FLAT_DEPLOY


def test_security_checks_target_the_new_stack_not_hardcoded_old_ports() -> None:
    section = _section(DEPLOY, "Security checks, hand-run against the new stack", "## 3. Open the window")
    flat = " ".join(section.split())
    assert "P-mysql-1" in flat and "P-openemr-1" in flat
    assert "https://localhost:WT_HTTPS_PORT/" in flat and "Do not use port 9300" in flat
    stripped = flat.replace("Do not use port 9300", "")
    for old in ("localhost:9300", ":8320", ":8310", ":8400", "development-easy-light-"):
        assert old not in stripped, old
    for check in (
        "oauth_password_grant",
        "portal_onsite_two_enable",
        "rest_portal_api",
        "api_log_option",
        "Secure",
        "secret_scan.py",
        "check-ignore",
    ):
        assert check in flat or check in DEPLOY, check
    assert "label=com.docker.compose.project=P " in flat and "`P-agent`" in flat


def test_the_tunnel_is_started_by_hand_against_the_new_port() -> None:
    assert "cloudflared tunnel --no-autoupdate --no-tls-verify --url https://localhost:WT_HTTPS_PORT" in FLAT_DEPLOY
    assert "never with `tunnel.sh up`" in FLAT_DEPLOY
    assert "not 9300" in FLAT_DEPLOY


def test_pinned_checkout_is_protected_and_rechecked() -> None:
    assert "git clone --no-hardlinks" in FLAT_DEPLOY
    assert "checkout --detach 9f036541cf95e896db065e0c652afb75627b03c2" in FLAT_DEPLOY
    assert "ca0f7d5e5a705e57fb1f2161411c2a0680e64933" in FLAT_DEPLOY
    assert "`git -C CHECKOUT status --porcelain --untracked-files=all` prints nothing" in FLAT_DEPLOY
    assert "immediately before the first container starts" in FLAT_DEPLOY
    assert "do not run `git checkout`, `git stash` or `git reset` in it" in FLAT_DEPLOY
    assert "mounts `CHECKOUT` into the OpenEMR container read-write" in FLAT_DEPLOY
    close = _section(DEPLOY, "## 5. Close the window", "## 6. Abort")
    assert "Re-check the pinned checkout" in close and "tracked file" in close
    assert "Leave `CHECKOUT` as it is" in FLAT_ROLLBACK


def test_existing_stack_canary_is_taken_before_and_compared_after() -> None:
    for name in ("containers-before.txt", "volumes-before.txt", "networks-before.txt"):
        assert DEPLOY.index(name) < DEPLOY.index("## 2. Start the isolated stack"), name
    close = _section(DEPLOY, "## 5. Close the window", "## 6. Abort")
    assert "Compare the canary" in close
    for name in ("containers-before.txt", "volumes-before.txt", "networks-before.txt"):
        assert name in DEPLOY[DEPLOY.index("## 5. Close the window") :] or "WORK/*-before.txt" in close
    assert "canary" in ROLLBACK.lower()


def test_the_runbook_is_labelled_untested_and_approves_no_other_gate() -> None:
    assert "untested" in DEPLOY and "never run" in DEPLOY
    assert "does not approve the allowlist commit (Gate B)" in FLAT_DEPLOY
