# R7 deploy runbook (operator-run, Gate A)

Status: written, never run. Nothing in this file was executed by the platform or by the assistant. It exists so that you,
the operator, can run a deploy window yourself after you approve Gate A. The platform has no deploy code and Build ran none.

Approving Gate A approves one named time window. It does not approve the allowlist commit (Gate B), a `LIVE_ENABLED` change
(Gate K1, unavailable), a provider call, or any spend. A new tunnel hostname is a new window.

## 0. How this window is deployed: one isolated stack, run by hand

There is one approved way to deploy, and it never touches your existing local OpenEMR stack. The pin's scripts are read for
their steps only, and are never run:

- Do not run `scripts/copilot/tunnel.sh` in any form. It hardcodes the compose file `docker/development-easy-light/docker-compose.yml`,
  the container names `development-easy-light-openemr-1` and `development-easy-light-mysql-1`, and the tunnel target
  `https://localhost:9300`. Its `harden` step runs `docker exec` on those names, so it would rotate your existing stack's database
  root and admin passwords.
- Do not run `scripts/copilot/security_gate.sh` either. It hardcodes ports 8320, 8310 and 8400, checks the cookie at
  `https://localhost:9300`, and lists every container on the host. Section 2 gives the same checks, aimed at the new stack.
- Do not stop, restart, rebuild or recreate your existing stack, and do not use its project name, its volumes, its network or its ports.
  The existing stack must be indistinguishable before and after the window (the canary in section 1).

What you do instead, in outline: a clean checkout of exactly the pin, outside every other repo; the pin's compose files run under
your own unique project name, with your own ports; the agent run under its own project name on the new stack's network; and a
`cloudflared` process you start yourself. Every command below was read from the pin's text and is untested. If a command behaves
differently from what is written here, stop. Do not improvise on a stack that is about to be exposed.

Names used below. Choose them once, at Gate A, and write them in the approval request:

- `P`: the compose project name, for example `copilot-r7-20261022`. It must not be `development-easy-light`, and no container,
  volume or network on the host may already use it as a prefix.
- `CHECKOUT`: the absolute path of the new checkout, for example `~/r7/openemr-9f03654`.
- `WORK`: a directory outside `CHECKOUT`, outside the existing OpenEMR repo and outside this repository. It holds the secrets file,
  the agent override file and the canary snapshots.
- Four free host ports, not 8300, 9300, 8320, 8310 or 8400, for example `WT_HTTP_PORT=18300`, `WT_HTTPS_PORT=19300`,
  `WT_MYSQL_PORT=18320`, `WT_PMA_PORT=18310`, plus `AGENT_HOST_PORT=18400`. Check each is free with
  `lsof -nP -iTCP:<port> -sTCP:LISTEN`, which must print nothing.

Gate A is not requestable until `P`, `CHECKOUT`, `WORK` and the five ports are named. This finding is not resolved by Build.

## 1. Before the window

- [ ] Gate A approved in writing, with start and end times (UTC).
- [ ] Repository visibility checked, so a committed hostname is not published by accident (needed at Gate B).
- [ ] Synthetic data only. You confirm A-001 for this database and name the seed script. The pin ships
      `scripts/copilot/seed_demo_patients.py`.
- [ ] Route is the original stub agent: `LLM_PROVIDER=stub` in the agent's `.env`, and no `OPENROUTER_API_KEY` value in it.
      Target model spend is $0 in this window.
- [ ] `config/allowlist.yaml`, `config/spend_limits.yaml` and both kill switches are unchanged.
- [ ] Secrets: generate a new database root password, a new admin password and a new fixture password. Write them to
      `WORK/secrets.env` with mode 600. Never print them, never reuse a local one, never put them in this repository or in `CHECKOUT`.

### Pinned checkout (never the existing tree)

The existing dirty tree is not touched, switched or reset. Do not deploy from it, and do not run `git checkout`, `git stash` or
`git reset` in it. Make the clean checkout somewhere else:

1. `git clone --no-hardlinks <existing OpenEMR repo path> CHECKOUT`. This only reads the existing repo. Prefer it to
   `git worktree add`, which writes into the existing repo's `.git`.
2. `git -C CHECKOUT checkout --detach 9f036541cf95e896db065e0c652afb75627b03c2`.
3. `git -C CHECKOUT rev-parse HEAD` prints `9f036541cf95e896db065e0c652afb75627b03c2`.
4. `git -C CHECKOUT rev-parse 'HEAD^{tree}'` prints `ca0f7d5e5a705e57fb1f2161411c2a0680e64933`.
5. `git -C CHECKOUT status --porcelain --untracked-files=all` prints nothing. Do this immediately before the first container
   starts. This is the value for `git_status_porcelain_empty` in the attestation.
6. Do not run `composer`, `npm`, `pip` or any build step inside `CHECKOUT`. The compose file keeps dependencies in named volumes.

The pin's compose file mounts `CHECKOUT` into the OpenEMR container read-write (the `htdocs` mount is `:rw`), so a running
container can change files in it. Section 5 re-checks the checkout after the window. Treat a changed tracked file as "the running
code was not the pin", not as noise.

### Isolation checks, before anything starts

Write the agent override file from section 2 first, then render both projects without starting them:

- `docker compose -p P -f CHECKOUT/docker/development-easy-light/docker-compose.yml -f CHECKOUT/deploy/tunnel/docker-compose.override.yml config`,
  with `OPENEMR_DIR=CHECKOUT` and the five port values exported in the shell.
- `docker compose -p P-agent -f CHECKOUT/agent/docker-compose.yml -f WORK/agent-override.yml config`.

In the rendered output, confirm all of these, and stop if any fails:

- [ ] The project name is `P` (and `P-agent`), not `development-easy-light`.
- [ ] Every named volume is prefixed `P_` (and `P-agent_agent_data`). Docker creates a volume for each project name separately, so none can be
      one of your existing stack's volumes. No volume is declared `external`.
- [ ] Every bind-mount source is under `CHECKOUT`. None is the existing tree.
- [ ] Every published port is bound to `127.0.0.1` and is one of your five new ports. None of 8300, 9300, 8320, 8310 or 8400 appears.
- [ ] The network is `P_default`. The agent attaches to `P_default` and not to `development-easy-light_default`. That is what makes
      the agent's `https://openemr` mean the new OpenEMR and not the existing one.

### Existing-stack canary

Before anything starts, save a snapshot outside the repository:

- `docker ps -a --format '{{.ID}} {{.Names}} {{.Status}}' | sort > WORK/containers-before.txt`
- `docker volume ls --format '{{.Name}}' | sort > WORK/volumes-before.txt`
- `docker network ls --format '{{.Name}}' | sort > WORK/networks-before.txt`

The existing stack's container IDs and volumes must be unchanged after the window. Section 5 compares them.

## 2. Start the isolated stack, then harden it before exposure

Everything here runs against project `P` only. Give each command `-p P` and the explicit `-f` files. Never run `docker compose`
for the pin without `-p P`, because the default project name would be your existing stack's.

Agent override, written once to `WORK/agent-override.yml` (outside `CHECKOUT`, so the checkout stays the pin):

```yaml
services:
  agent:
    ports: !override
      - "127.0.0.1:AGENT_HOST_PORT:8400"
networks:
  oe:
    name: P_default
```

Replace `AGENT_HOST_PORT` and `P` with your values. The base file publishes the agent on `127.0.0.1:8400`, which is your existing
agent's port, so the override replaces that list instead of adding to it. `external: true` stays from the base file, so the network
must exist first: start the stack, then the agent.

Order:

1. Export `DB_ROOT_PASS` and the admin password from `WORK/secrets.env` without echoing them. The overlay reads `DB_ROOT_PASS`, so
   the database root is not the default from first boot of the fresh `P_databasevolume`.
2. Start: `docker compose -p P -f ... -f ... up -d`, with the five ports and `OPENEMR_DIR=CHECKOUT` exported. The containers are
   named `P-openemr-1` and `P-mysql-1`. Wait until OpenEMR is healthy.
3. Create `CHECKOUT/agent/.env` from `agent/.env.example`, with `LLM_PROVIDER=stub`, no provider key and your new fixture password. It is
   git-ignored at the pin. Check that with `git -C CHECKOUT check-ignore agent/.env`. Do the same for the module's `config.local.php`.
   The module's `agent_base_url` is `http://agent:8400`, a name on the network, so it needs no port. Do not point it at a host port.
4. Start the agent: `docker compose -p P-agent -f CHECKOUT/agent/docker-compose.yml -f WORK/agent-override.yml up -d --build`.
5. Apply the steps `tunnel.sh harden` performs, by hand and against `P-mysql-1` and `P-openemr-1` only: set the admin password to the
   new value, and set the globals below. Read the exact statements from `scripts/copilot/tunnel.sh` at the pin
   (`git -C CHECKOUT show HEAD:scripts/copilot/tunnel.sh`) and reproduce them with the container names replaced. List each step you did in
   the attestation notes.

Security checks, hand-run against the new stack. These replace `security_gate.sh`. Each must hold before the tunnel starts, and any failure
means no tunnel:

- [ ] The database root password is not the default: a login to `P-mysql-1` with the old default fails, and the new one works.
- [ ] The admin password is not `pass`, and a login as admin with `pass` fails.
- [ ] No active OpenEMR account has a default or guessable password. Run the pin's audit logic through `docker exec` into `P-openemr-1`.
- [ ] Only `127.0.0.1` port bindings exist for the new project. Run
      `docker ps --filter label=com.docker.compose.project=P --format '{{.Names}} {{.Ports}}'` and then the same with `P-agent`. Neither
      may show a `0.0.0.0` or `::` binding. Check each project separately: two filters on the same label are ORed, not ANDed.
- [ ] The globals are right, read by SQL in `P-mysql-1`: `oauth_password_grant`, `portal_onsite_two_enable` and `rest_portal_api` are 0,
      and `api_log_option` is 1.
- [ ] Session cookies carry the Secure flag: `curl -ksI https://localhost:WT_HTTPS_PORT/` on your new HTTPS port shows `Secure` on each `Set-Cookie`.
      Do not use port 9300.
- [ ] `python3 CHECKOUT/scripts/copilot/secret_scan.py` finds nothing, and `agent/.env` and `config.local.php` are git-ignored and untracked.
- [ ] The agent is not reachable through the tunnel. `/health` is off the platform allowlist, so the platform cannot test this. It is
      your own check, recorded as `agent_private_check`.

## 3. Open the window

- [ ] Read the access log and note its position (the "before" review).
- [ ] Start the tunnel by hand, never with `tunnel.sh up`:
      `cloudflared tunnel --no-autoupdate --no-tls-verify --url https://localhost:WT_HTTPS_PORT`, with your new HTTPS port. Note the
      process ID, because you stop it yourself later. Record the hostname you were given. Never reuse `deploy/tunnel/url.txt` from an older run.
- [ ] Confirm the tunnel target is your new port and not 9300, from the command line you ran.
- [ ] Do not paste the hostname into this repo yet. That is Gate B.

## 4. Observe from outside (recorded by you)

You fetch these yourself, with a browser or `curl`, one request each. The platform does not.

- The sha256 of the four module assets under `interface/modules/custom_modules/oe-module-copilot/` (listed in
  `config/target_pin.yaml`).
- The HTTP status of the three negative-control paths in the same file. They are absent at the pin, so 404 is the expected answer.
  A served file is a pin `difference`.

Record the pin outcome as `consistent_with_pin`, `difference` or `unverified`. It is never "verified": the agent code is private,
and the four assets are identical in the dirty tree, so only the negative controls can tell the two apart.

Identity is recorded as operator-observed. The platform sends no request in R7, because Gate K1 is unavailable.

## 5. Close the window

- [ ] Read the access log again (the "after" review). An entry you cannot explain means stop, rotate the fixture credential and
      close the tunnel. Do not continue to Gate B.
- [ ] Stop the tunnel (see the rollback runbook).
- [ ] Re-check the pinned checkout: `git -C CHECKOUT rev-parse HEAD` is still the pin, and
      `git -C CHECKOUT status --porcelain --untracked-files=all`. A modified or deleted tracked file means the running code was not the
      pin: stop, record a pin `difference`, and do not go on to Gate B. Untracked files are runtime output. List them in the notes.
- [ ] Compare the canary: `docker ps -a --format '{{.ID}} {{.Names}} {{.Status}}' | sort`, `docker volume ls --format '{{.Name}}' | sort`
      and `docker network ls --format '{{.Name}}' | sort`, against the `WORK/*-before.txt` files. The only differences allowed are
      containers, volumes and networks prefixed `P_`, `P-` or `P-agent`. Any change to a `development-easy-light` container ID, status or volume
      is a stop. Report it and do not restart anything to hide it.
- [ ] Fill in `Docs/attestations/deploy-attestation.yaml` from `deploy-attestation.template.yaml`, and
      `log-access-inventory.md` from its template. Hashes and labels only. No password, token, key, cookie or header.
- [ ] Run `python scripts/preflight_live.py`. It reads local files only. A pass is necessary, not an approval.

## 6. Abort now, without finishing the window

An off-list host, a pin `difference`, an unexplained access-log entry, a changed hostname, anything resembling real patient data,
a failing security check, a changed existing-stack canary, a modified tracked file in the checkout, or any step that would need `tunnel.sh`,
`security_gate.sh`, or the project name `development-easy-light`. Follow `r7-rollback.md`.
