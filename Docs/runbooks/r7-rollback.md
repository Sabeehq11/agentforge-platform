# R7 and R8 rollback runbook

Status: written, never run. Use it for a deploy window you ran under Gate A, or to confirm the platform is back to its Build state.

## Abort conditions

An off-list host or redirect, an identity or pin `difference`, a 429 or 503, a provider 403, spend above a cap, anything
resembling real patient data, an unexplained access-log entry, a changed tunnel hostname, or a failing check.

## Build (offline)

Revert the working-tree changes. No external state exists. No deployment, request, provider call or key use took place.

## Target (the machine you ran the window on)

1. Stop the `cloudflared` process you started by hand, using the process ID you noted. Do not use `scripts/copilot/tunnel.sh down`.
2. Stop only your own projects, always with an explicit project name: `docker compose -p P-agent -f ... stop`, then
   `docker compose -p P -f ... stop`, using the same `-f` files as the deploy runbook. Use `down` only with the same `-p`, and never with
   `-v`. To delete the new volumes, name each volume that begins `P_` or `P-agent_` and has been checked against the deploy runbook's
   canary snapshot. Never delete a volume you did not create for `P`.
3. Check the existing-stack canary against the `WORK/*-before.txt` snapshots from the deploy runbook. Container IDs, statuses and
   volumes of `development-easy-light` must be unchanged. If anything differs, report it and do not start or stop anything to fix it.
4. Rotate the fixture password, even if nothing looked wrong. Discard the hostname. A new window gets a new hostname.
5. Keep the access logs. Do not delete a log that holds an unexplained entry.
6. Leave `CHECKOUT` as it is until you have read `git status` in it. Do not run `git checkout`, `git reset` or `git clean` there, or
   anywhere in your existing OpenEMR repo.

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
