"""The R7 deploy and rollback runbooks describe one isolated approach and never run the pin's stock scripts.

These read the runbook text only. They cannot show that the commands work, because nothing is run.
"""

from __future__ import annotations

import os
import re
import subprocess
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


# --- the canary, run for real against a fake `docker` --------------------------------------------------------------
# The canary script is taken from the runbook text, so the test cannot drift from what the operator would paste. `docker` is a
# small shell shim that serves canned state from files. Nothing here touches a real Docker daemon.
PROJECT = "copilot-p"
FAKE_DOCKER = r"""#!/usr/bin/env bash
f="$FAKE"
case "$1 $2" in
  "ps -aq") [ -s "$f/containers.txt" ] && echo ids || true ;;
  "inspect --format") cat "$f/containers.txt" ;;
  "volume ls") cat "$f/volumes.txt" ;;
  "network ls") cat "$f/networks.txt" ;;
  "volume inspect") [ -f "$f/vol/$5.labels" ] && cat "$f/vol/$5.labels" || exit 1 ;;
  "ps -a") v="${4#volume=}"; [ -f "$f/vol/$v.users" ] && cat "$f/vol/$v.users" || true ;;
  *) echo "fake docker: unexpected call: $*" >&2; exit 99 ;;
esac
"""
OLD_CONTAINERS = [
    "idA /web img1 running 2026-10-20T01:00:00Z 0 {}",
    "idB /db img2 running 2026-10-20T01:00:00Z 0 {}",
]
OUR_CONTAINER = f"idZ /{PROJECT}-openemr-1 img3 running 2026-10-22T01:00:00Z 0 {{}}"
ANON = "a" * 64


def _canary_script() -> str:
    match = re.search(r"cat > \"\$WORK/canary.sh\" <<'SH'\n(.*?)\nSH\n", DEPLOY, re.S)
    assert match, "canary.sh heredoc not found in the deploy runbook"
    return match.group(1) + "\n"


class FakeHost:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.fake = tmp / "fake"
        self.work = tmp / "work"
        (self.fake / "vol").mkdir(parents=True)
        self.work.mkdir()
        (tmp / "bin").mkdir()
        shim = tmp / "bin" / "docker"
        shim.write_text(FAKE_DOCKER)
        shim.chmod(0o755)
        script = self.work / "canary.sh"
        script.write_text(_canary_script())
        script.chmod(0o755)

    def state(
        self,
        containers: list[str],
        volumes: list[str],
        networks: list[str],
        meta: dict[str, tuple[str, list[str]]] | None = None,
    ) -> None:
        (self.fake / "containers.txt").write_text("".join(c + "\n" for c in containers))
        (self.fake / "volumes.txt").write_text("".join(v + "\n" for v in volumes))
        (self.fake / "networks.txt").write_text("".join(n + "\n" for n in networks))
        for old in (self.fake / "vol").iterdir():
            old.unlink()
        for name, (labels, users) in (meta or {}).items():
            (self.fake / "vol" / f"{name}.labels").write_text(labels)
            (self.fake / "vol" / f"{name}.users").write_text("".join(u + "\n" for u in users))

    def run(self, mode: str, label: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.tmp / 'bin'}:{os.environ['PATH']}",
            "P": PROJECT,
            "WORK": str(self.work),
            "FAKE": str(self.fake),
        }
        return subprocess.run(
            ["bash", str(self.work / "canary.sh"), mode, label], env=env, capture_output=True, text=True, check=False
        )


BASE_VOLUMES = ["old_data", "other_project_data"]
BASE_NETWORKS = ["n1 bridge", "n2 old_default"]
OUR_VOLUMES = [f"{PROJECT}_databasevolume", f"{PROJECT}_sitesvolume", f"{PROJECT}-agent_agent_data"]
OUR_NETWORK = f"n9 {PROJECT}_default"
ANON_LABEL = "com.docker.volume.anonymous \n"


def _after_stage(
    tmp: Path,
    *,
    extra_volumes: list[str],
    meta: dict[str, tuple[str, list[str]]],
    containers: list[str] | None = None,
    base_volumes: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    host = FakeHost(tmp)
    before_volumes = base_volumes if base_volumes is not None else BASE_VOLUMES
    host.state(OLD_CONTAINERS, before_volumes, BASE_NETWORKS)
    assert host.run("snap", "before").returncode == 0
    assert (host.work / "volumes-before.txt").read_text().split() == sorted(before_volumes)
    host.state(
        containers if containers is not None else [*OLD_CONTAINERS, OUR_CONTAINER],
        before_volumes + OUR_VOLUMES + extra_volumes,
        [*BASE_NETWORKS, OUR_NETWORK],
        meta,
    )
    return host.run("diff", "after")


def test_the_runbook_canary_does_not_use_xargs_and_names_its_snapshots() -> None:
    script = _canary_script()
    assert "xargs" not in script
    for name in ("containers-$1.txt", "volumes-$1.txt", "networks-$1.txt"):
        assert name in script


def test_canary_is_ok_when_only_this_projects_objects_are_added(tmp_path: Path) -> None:
    result = _after_stage(tmp_path, extra_volumes=[], meta={})
    assert result.returncode == 0 and "CANARY OK" in result.stdout, result.stdout + result.stderr


def test_an_anonymous_volume_used_only_by_this_project_is_ignored_and_named(tmp_path: Path) -> None:
    meta = {ANON: (ANON_LABEL, [f"{PROJECT}-openemr-1 {PROJECT}"])}
    result = _after_stage(tmp_path, extra_volumes=[ANON], meta=meta)
    assert result.returncode == 0 and "CANARY OK" in result.stdout, result.stdout + result.stderr
    assert "ignoring anonymous volume aaaaaaaaaaaa" in result.stderr and f"{PROJECT}-openemr-1" in result.stderr


def test_an_anonymous_volume_used_by_this_projects_agent_project_is_also_ignored(tmp_path: Path) -> None:
    meta = {ANON: (ANON_LABEL, [f"{PROJECT}-agent-agent-1 {PROJECT}-agent"])}
    assert _after_stage(tmp_path, extra_volumes=[ANON], meta=meta).returncode == 0


def test_an_unrelated_anonymous_volume_still_fails_the_canary(tmp_path: Path) -> None:
    meta = {ANON: (ANON_LABEL, ["someone-else-1 someone-else"])}
    result = _after_stage(tmp_path, extra_volumes=[ANON], meta=meta)
    assert result.returncode == 1 and "CANARY CHANGED" in result.stdout, result.stdout
    assert ANON in result.stdout and "ignoring" not in result.stderr


def test_an_anonymous_volume_shared_with_another_project_still_fails(tmp_path: Path) -> None:
    meta = {ANON: (ANON_LABEL, [f"{PROJECT}-openemr-1 {PROJECT}", "web other-project"])}
    result = _after_stage(tmp_path, extra_volumes=[ANON], meta=meta)
    assert result.returncode == 1 and ANON in result.stdout


def test_an_anonymous_volume_that_nothing_mounts_still_fails(tmp_path: Path) -> None:
    result = _after_stage(tmp_path, extra_volumes=[ANON], meta={ANON: (ANON_LABEL, [])})
    assert result.returncode == 1 and ANON in result.stdout


def test_a_name_prefix_without_the_project_label_does_not_prove_ownership(tmp_path: Path) -> None:
    meta = {ANON: (ANON_LABEL, [f"{PROJECT}-lookalike-1 not-our-project"])}
    assert _after_stage(tmp_path, extra_volumes=[ANON], meta=meta).returncode == 1


def test_a_new_named_volume_without_the_prefix_still_fails_even_if_we_mount_it(tmp_path: Path) -> None:
    meta = {"stray_named": ("\n", [f"{PROJECT}-openemr-1 {PROJECT}"])}
    result = _after_stage(tmp_path, extra_volumes=["stray_named"], meta=meta)
    assert result.returncode == 1 and "stray_named" in result.stdout


def test_an_anonymous_volume_that_existed_before_is_never_ignored(tmp_path: Path) -> None:
    # It is in the "before" snapshot, so it stays in the comparison. Removing it is a change even if we now mount it.
    meta = {ANON: (ANON_LABEL, [f"{PROJECT}-openemr-1 {PROJECT}"])}
    result = _after_stage(
        tmp_path, extra_volumes=[], meta=meta, base_volumes=[*BASE_VOLUMES, ANON]
    )
    assert result.returncode == 0, "an unchanged old volume is not a change"
    host = FakeHost(tmp_path / "removed")
    host.state(OLD_CONTAINERS, [*BASE_VOLUMES, ANON], BASE_NETWORKS)
    assert host.run("snap", "before").returncode == 0
    host.state([*OLD_CONTAINERS, OUR_CONTAINER], [*BASE_VOLUMES, *OUR_VOLUMES], [*BASE_NETWORKS, OUR_NETWORK])
    removed = host.run("diff", "after")
    assert removed.returncode == 1 and ANON in removed.stdout


def test_a_restarted_existing_container_still_fails_the_canary(tmp_path: Path) -> None:
    restarted = [OLD_CONTAINERS[0].replace("2026-10-20T01:00:00Z", "2026-10-22T02:00:00Z"), OLD_CONTAINERS[1], OUR_CONTAINER]
    result = _after_stage(tmp_path, extra_volumes=[], meta={}, containers=restarted)
    assert result.returncode == 1 and "idA" in result.stdout


def test_the_status_text_is_not_part_of_the_comparison() -> None:
    script = _canary_script()
    assert "State.Status" in script and "{{.Status}}" not in script
