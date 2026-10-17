
# P0 plan adapted for this repo

## Sources and checks

- This file is the P0 plan adapted for this repository. It is based on the approved P0 plan (revision 2, an earlier planning draft that was not committed). Decisions A to G and Q2 from that plan are unchanged. The adaptations made here are the repo strategy (independent repo, target reached only over HTTP), the target-repo path labels, and deferring target reachability to P3.
- Read-only checks of the Co-Pilot repo over raw GitHub at the pinned SHA (no clone):
  - `deploy_w2.sh` keeps the agent on `127.0.0.1:8400` and fails if `/health` is reachable through the tunnel. So "`/ready` at the public URL" cannot pass.
  - `chat.php` takes authority only from the PHP session plus CSRF.
  - `authz_fixture.php` seeds `copilot_doc_a`, `copilot_doc_b`, `copilot_nurse`, `copilot_front`. The password comes from `COPILOT_FIXTURE_PASSWORD`.
  - `week2-agentforge` is still `9f03654`. Fork `main` is merge commit `efb66b5` with an identical tree (`ca0f7d5e5a70`). TARGET_FREEZE.md records both.

## Changes because the work happens here

- This repo is the independent repo for strategy B. It has `main` with no commits and `origin` set to `Sabeehq11/agentforge-platform`. The GitHub repository already exists. The earlier unauthenticated API 404 is an access issue (GitHub returns 404 for private repos to anonymous callers), not evidence it is missing. A read-only `git ls-remote origin` using the stored credentials succeeded with exit 0 and no refs, which fits an existing, empty, accessible repo. Push access is not yet tested and stays unverified until you push.
- The create-sibling-repo step and the outside-workspace approval are gone.
- The planning docs are already in `Docs/` (capital D). The copy step is dropped. Their sha256 is recorded before any edit:
  - ROADMAP `edf1a6fb...`
  - PROGRESS `3dbb09cc...`
  - DECISIONS `69b95b50...`
- Keep the `Docs/` casing. The link check is case-sensitive because CI runs on Linux.
- ADRs go in `Docs/adr/`. Other records go in `Docs/`.
- The target repo is never written. The old "target git status unchanged" check becomes "no file outside this repo was written".
- Edit ROADMAP and DECISIONS: label `agent/`, `evals/` and `docs/week2/` as target-repo paths, fix the `docs/week3/ROADMAP.md` reference in D-002, replace the P0 `/ready` verification line with "reachability UNVERIFIED, deferred to P3 (no target request in P0)", and mark section 2.5 decided.
- `.gitignore` covers `.DS_Store` (currently untracked), `.env`, `*.db`, `data/`, transcripts, `__pycache__`, `.coverage`, `.venv`.

## Deliverables

### Repo basics
- `README.md`: "P0, nothing attacks anything yet", planned versus runnable.
- `pyproject.toml` with Python `>=3.12,<3.13`, package at `src/agentforge/`.
- `requirements-dev.txt`: ruff 0.11.12, mypy 1.15.0, bandit 1.8.3, pytest-cov 6.1.1 (same pins as the target's `ci-requirements.txt`), plus pinned pytest and PyYAML.

### ADRs in `Docs/adr/` (index and template; each names 2+ rejected alternatives)
- 001 repo strategy B (A and C rejected).
- 002 target access through the public module login as a synthetic identity. Rejected: signed direct agent calls and the agent through the tunnel.
- 003 persisted SQLite state machine (LangGraph and a queue rejected, with reopen triggers).
- 004 per-role models in `config/models.yaml`. Red Team and Judge must be different families. No paid probe in P0.
- 005 SQLite state store.
- 006 own SQLite traces with correlation IDs and per-agent cost. Langfuse deferred.
- 007 quick tunnel with manual reviewed URL edits, provisional until Q2 is answered.

### Records
- `Docs/BUILD_VS_CONFIGURE.md`: Burp Suite, OWASP ZAP, Semgrep, Garak, plus promptfoo, PyRIT and deterministic replay/fuzz tooling. Covers what each does, where it falls short, and whether custom code is justified per role. Tool claims are marked "unverified" until checked against each tool's own docs.
- `Docs/TARGET_FREEZE.md`: SHA `9f03654` and fork-main `efb66b5` (same tree), the dirty-tree caveat (the running stack may have been built from uncommitted files), provisional URL, changes made to reach a testable state, synthetic-data statement, fixture usernames only.
- `Docs/DEFENSE_PACKET.md` (draft): mermaid agent diagram, planned message list, trust boundaries, failure modes.

### Safety skeleton (`src/agentforge/safety/`, stdlib plus PyYAML, no network code)
- `allowlist.py`: exact scheme, host, port, path prefix. Empty or missing file denies all. Redirects are checked as new URLs. Userinfo tricks are rejected.
- `budget.py`: per-run, per-day and attack-count caps. Approval token bound to exact numbers (`measure.py` pattern). `reserve()` raises before overspend. `kill()` blocks all later calls.
- `spend_limits.py`: attestation gate. It reads `config/spend_limits.yaml`, refuses when the record is missing or stale, and queries no provider.
- `chokepoint.py`: allowlist, then budget, then spend-limit gate, then an injected transport. `LIVE_ENABLED = False`, so no real transport exists in P0.
- Config: `allowlist.yaml` (no hosts), `budget.yaml`, `spend_limits.yaml` (empty), `models.yaml` (no keys).
- Not in P0: fingerprint code, login code, payloads, any agent.

### Tests
- Allowlist: default deny, wrong scheme/host/port/path, `https://allowed@evil/`, off-list redirect.
- Budget: over-cap, token mismatch, kill switch.
- Spend limits: missing and stale attestation.
- Chokepoint: gate order, transport never called on any failure, sockets patched to fail.
- Models config: same-family Red Team and Judge rejected.

### CI (`.github/workflows/ci.yml`, `.github/CODEOWNERS` for `config/`, workflows, `safety/`)
- Triggers: push and pull_request on `main`. `permissions: contents: read`. No secrets. No live or paid calls.
- Python 3.12 on ubuntu-24.04, pinned tools.
- Jobs: ruff (E9, F63, F7, F82); mypy; pytest with a coverage floor; Bandit; secret scan (adapted copy of the target's `secret_scan.py`, with its agent `.env` and OpenEMR skip lists removed; history scan kept); case-sensitive internal markdown link check; workflow guard that forbids `pull_request_target`.
- P0 mapping: markdown/link check is the P0 PRD-listed job. Bandit and mypy are earlier than the ROADMAP's P9, which is harmless.
- CODEOWNERS only takes effect once branch protection requires it. That is a repo setting and cannot be set from code.

## P0 verification (evidence goes into `Docs/PROGRESS.md`)

1. `pytest` passes on Python 3.12, including the no-socket test.
2. Weakening the allowlist locally makes tests fail (then reverted).
3. Every ADR lists at least 2 rejected alternatives (scripted check).
4. Original doc sha256 values recorded before edits.
5. A planted fake key fails the secret scan (temp file, removed).
6. Local run of every CI command passes. GitHub Actions is unverified until you push, and PROGRESS says so.
7. Target reachability is **UNVERIFIED** in P0. P0 makes zero requests to the target, including the public OpenEMR login-page GET. That check moves to the first checkpoint that has the allowlist entry and the chokepoint transport (P3, before the first live run). PROGRESS.md and ROADMAP.md say so, and TARGET_FREEZE.md records the URL as unconfirmed.
8. No file outside this repo was written, and nothing is committed or pushed.
9. The P0 code and tests contain no code path that contacts the target. This is covered by the no-socket tests, `LIVE_ENABLED = False`, and an empty `config/allowlist.yaml`.

## Genuine blockers and inputs

- **Python 3.12 is not installed** (only 3.10.13; no uv or pyenv shim). Local tests need `brew install python@3.12` or equivalent. Until then the code is written but local verification is UNVERIFIED. CI uses 3.12 either way.
- **GitHub remote access.** The repo exists. Anonymous API calls return 404, and `git ls-remote origin` works with stored credentials. Before the first push, confirm your credentials can write (and that the repo is private or public as intended). CI is unverified until the first push runs it. This does not block P0 implementation.
- **Tunnel URL.** Not needed in P0. P0 makes no target requests. The URL is recorded as provisional and unconfirmed, and it is needed at the later reachability check.
- **Synthetic identity.** Confirm the fixture user exists on the deployed stack and that its password stays in a git-ignored `.env`.
- **Provider-side spend limits (Q13).** P0 builds the gate. Setting the limits is yours and must precede any live run.

Non-blocking: send staff questions Q2, Q4, Q5 and Q6 now. They gate later checkpoints, not P0.

## Out of scope for P0

Live requests, paid calls, agents, JSON Schema contracts, attack cases, the threat model, commits, pushes.