# R7 and R8 rollback runbook

Status: written, never run. Use it for a Gate A stage you ran (Stage 1, the isolated localhost-only deployment, or Stage 2, public
exposure), or to confirm the platform is back to its Build state. In code blocks, `$P`, `$CHECKOUT` and `$WORK` are the values from the
deploy runbook.

## Abort conditions

An off-list host or redirect, an identity or pin `difference`, a 429 or 503, a provider 403, spend above a cap, anything
resembling real patient data, an unexplained access-log entry, a changed tunnel hostname, a failing check, a changed existing-stack
canary, or a secret in any output (a password, a key, or the upstream token from the deploy runbook's blocker B3).

## Build (offline)

Revert the working-tree changes. No external state exists. No deployment, request, provider call or key use took place.

## Target, Stage 2 (public exposure): close the exposure first

1. Stop the `cloudflared` process you started by hand, using the process ID you noted. Do not use `scripts/copilot/tunnel.sh down`.
   Confirm it is gone with `ps -p <pid>`, and that the hostname no longer answers. A hostname is never reused.
2. Rotate the generated secrets in `WORK` even if nothing looked wrong: the database root and admin passwords, the fixture password
   and the signing and audit values. Do it by deleting the isolated stack's own volumes (Stage 1, step 2) and starting a fresh stack for
   any later window. Never rotate anything on your existing stack.
3. Keep the access logs. Do not delete a log that holds an unexplained entry.
4. Then continue with the Stage 1 steps below.

## Target, Stage 1 (isolated localhost-only stack)

1. Stop only your own projects, always with an explicit project name and the same `-f` files as the deploy runbook:
   `docker compose -p P-agent -f ... stop`, then `docker compose -p P --env-file WORK/stack.env -f ... stop`. Use `down` only with the same `-p`,
   and never with `-v`.
2. To delete the new volumes, name each volume that begins `P_` or `P-agent_` and appears in neither `WORK/volumes-before.txt` nor your existing
   stack's list. The OpenEMR container also owns two anonymous volumes (its `/etc/letsencrypt` and `/etc/ssl`). Delete one only after
   `docker ps -a --filter volume=<name>` shows that only your containers mount it. Never delete a volume you did not create for `P`, and
   never run a prune command.
3. Check the existing-stack canary: `"$WORK/canary.sh" diff rollback`. It must print `CANARY OK`. It compares container IDs, images,
   state, start times, restart counts and port bindings, and the volume and network lists, with the `WORK/*-before.txt` snapshots. It does
   not compare the `Status` text, which changes on its own. It skips an anonymous volume only when that volume is new and every container
   that mounts it belongs to your two projects (see the canary section of the deploy runbook). If anything differs, report it and do not
   start or stop anything to fix it.
4. Leave `CHECKOUT` as it is until you have read `git status` in it. Do not run `git checkout`, `git reset` or `git clean` there, or
   anywhere in your existing OpenEMR repo.
5. Check for leaked secrets before you delete `WORK`: `git -C "$CHECKOUT" status --ignored --porcelain --untracked-files=all` shows only the
   expected ignored files, and nothing under `Docs/` or `config/` in this repository holds a secret (`python scripts/secret_scan.py`).
   If the upstream token appears in any file, note, log or attestation, remove it, record that it leaked, and tell the upstream owner.
   Do not test the token.
6. Delete `WORK/stack.env`, `WORK/app-secrets.env` and `CHECKOUT/agent/.env` once the stage is over. Keep the canary snapshots and
   `WORK/stage1-result.txt` as the record.

The existing local stack is never stopped by the deploy runbook, so there is nothing to start again. If you did stop it, you went
outside the runbook: say so in the outcome notes.

## Platform (after any gate)

- `git diff --stat -- src/agentforge/safety/chokepoint.py` prints nothing, and the file still reads `LIVE_ENABLED = False` and
  `PROVIDER_ENABLED = False`. Gate K1 is unavailable, so neither should ever have changed.
- Revert the allowlist commit (Gate B). `config/allowlist.yaml` returns to the single `127.0.0.1:8300` entry.
- Remove any attestation from `config/spend_limits.yaml` (back to `attestations: []`), if Gate F was done.
- Remove `Docs/attestations/*.yaml` records you filled in only if they were wrong. Otherwise keep them as the record, with the outcome
  written beside them.
- Keep a copy of `data/agentforge.sqlite3` made before the first operational step. Do not restore it unless you must.
- Settle an open reservation at $0 with `Ledger.settle_orphan` only if you confirm that no request was sent. A reservation that
  may have been sent stays reserved, counted in full, until evidence says otherwise (see `Docs/prerequisites/P-U.md`).
- Run `python scripts/preflight_live.py`. After a rollback it should return NO-GO again.

## Provider

The key owner lowers or revokes the limit, or rotates the key if exposure is suspected. The platform cannot do either.

## Records

Write the outcome in `Docs/TARGET_FREEZE.md` and `Docs/PROGRESS.md` as it happened, with the date. Keep stopped-run files.
Traceability rows stay `gap` or `partial`.
