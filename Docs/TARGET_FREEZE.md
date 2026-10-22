# Target freeze

Records the exact target version and what is known about its state. PRD Stage 1 asks for the version and every change
made to bring the target into a testable state. No request was made to the target to produce this file (P0 makes
zero target requests).

## Target

| Item | Value | Source |
|---|---|---|
| Repository | `Sabeehq11/openemr-base-clean` (user fork, not upstream `Gauntlet-HQ`) | Handoff |
| Pinned branch | `week2-agentforge` | Handoff |
| Pinned commit | `9f036541cf95e896db065e0c652afb75627b03c2` | Read-only GitHub API, 2026-10-17 |
| Fork `main` | `efb66b5a8f295a26d3006a710abba28947e8db4c` (merge of PR #1) | Read-only GitHub API, 2026-10-17 |
| Tree equality | Both commits have tree `ca0f7d5e5a70...`, so pinning `9f03654` is content-equivalent to fork `main` at that time | Read-only GitHub API |
| Tag | None added. `w1-baseline` pre-exists in the target. No commit, tag or push was made in the target repo | This record |
| Target components | FastAPI Co-Pilot agent, OpenEMR module `oe-module-copilot` | Handoff |

Fork `main` may move later. If it does, this record must be updated by a new dated entry, not edited silently.

## Deployed URL

**Provisional and unconfirmed.** The target is exposed through a Cloudflare quick tunnel whose hostname changes on
each start (ADR-007, Q2). No URL is recorded here. A URL is added only when you supply the current one, and then
only through a reviewed change to `config/allowlist.yaml`.

**Reachability: UNVERIFIED.** P0 makes zero requests to the target, so nothing was probed. The check is deferred to
P3, after the allowlist entry and the chokepoint transport exist.

## What is publicly reachable

From the target's `scripts/copilot/deploy_w2.sh` at the pinned SHA: the tunnel serves OpenEMR only. The agent
(`127.0.0.1:8400`) is private by design, and the script fails if `/health` answers through the tunnel. The roadmap
line "target `/ready` answers at the recorded URL" therefore cannot be met and was replaced (ROADMAP P0). The
attack path is the public module login (ADR-002).

## Caveat: the running stack may differ from the pinned SHA

At the Project 2 close the target working tree held four uncommitted files: `docs/week2/DEMO_SCRIPT.md`,
`evals/results/gate-latest.md`, `evals/results/w2-golden-latest.json` and `evals/results/w2-golden-latest.md`.
They are docs and eval outputs, not agent code, but it is **unverified** whether the running stack was built from
the pinned commit or from the dirty tree. They are left alone (D-009). A replay result is only tied to the SHA
once the build is confirmed.

## Changes made to bring the target to a testable state

None by this repository. Nothing in the target repo was edited, committed, tagged or pushed for Week 3. Operational
state from the handoff that affects testing, all unconfirmed for the current deployment:

- OpenEMR `config.local.php` (git-ignored) may route the module to the real-model agent (`agent-real`, port 8402)
  or to the original stub agent. Routing is not assumed.
- The real-model agent uses `anthropic/claude-sonnet-4.5` via OpenRouter on a shared key. Spend is paid on the
  target's key (about 0.05 USD per chat, PERFORMANCE.md).
- Five weak stock OpenEMR accounts were disabled in Project 2.

## Synthetic data

The target holds synthetic demo patients only (for example patient 100 Maria Alvarez, patient 101). This is
assumption A-001 and is **unverified** for the current deployment. Some historical lab values are anomalous on
purpose. Platform fixtures and stored transcripts must be synthetic, and transcripts that quote target output are
scanned before storage (ROADMAP 2.2).

## Synthetic test identity

Fixture usernames seeded by `scripts/copilot/authz_fixture.php`: `copilot_doc_a`, `copilot_doc_b`, `copilot_nurse`,
`copilot_front`. Their password is set at seed time from `COPILOT_FIXTURE_PASSWORD`. It must live only in a
git-ignored `.env` and is never written in this repo. Which identity the platform uses, and whether it exists on the
deployed stack, is unconfirmed (A-004). The earlier handoff notes `copilot_doc_a` is denied access to patient 101,
which is owned by `copilot_doc_b`.

## Integrity of the planning docs

SHA-256 of the planning documents before any P0 edit (recorded 2026-10-17):

```
edf1a6fb1c25039905fc20d499b9b65d9bde6f449db139e2d0b4fa5b0f23a8d9  Docs/ROADMAP.md
3dbb09cc243172692d7b0a38a9f1175559921bcef29c59e1e87914365e5a91fc  Docs/PROGRESS.md
69b95b503b884f8675abe98bb4c838ce090c0c02137675fc84b0c26bc62430b7  Docs/DECISIONS.md
```

The copies in this repo then diverge on purpose (see PROGRESS.md log).

## Correction, 2026-10-21 (R7-R8 Build, offline)

The "Caveat: the running stack may differ from the pinned SHA" section above lists four uncommitted files. That count
was stale. A read-only `git status --porcelain` of the local target working tree on 2026-10-21 shows **22 paths**
differing from HEAD `9f036541cf95e896db065e0c652afb75627b03c2`: 15 modified tracked files and 7 untracked paths.

- Modified, agent and module code: `agent/app/chat.py`, the module's `public/chat.php`, `src/ModuleConfig.php` and
  `config.local.php.example`.
- Untracked, new module files: `public/stub_preflight.php`, `src/StubRouteGuard.php` and `src/StubRoutePreflight.php`.
- Untracked, tests and docs: `agent/tests/test_chat_latency_unit.py`, `docs/week3/`, and two isolated PHP tests under
  `tests/Tests/Isolated/Modules/Copilot/`.
- Modified, tests, docs and eval outputs: the remaining 11 paths.

Consequence: the existing local stack, if built from this tree, is **not** the pin. HEAD matches the pin, but HEAD alone
does not describe what runs. This repository made none of those changes and did not touch the target repo.

Decision for the public deployment: deploy from a **clean checkout of exactly `9f03654`** (a separate clean clone, not a `git worktree` of the existing repo, with its own
compose project), leaving the existing tree and its volumes alone. The expected values for that build are in
[`config/target_pin.yaml`](../config/target_pin.yaml): the commit and tree sha, the sha256 of the four module assets, and
three paths that must be absent. The four assets are identical in the dirty tree and at the pin, so they cannot tell the
two apart. The absent paths can. The agent code is private, so no outside check proves a clean pin. The pin outcome is
recorded as `consistent_with_pin`, `difference` or `unverified`, never "verified".

No deployment, URL, allowlist entry or target request exists as a result of this entry.
