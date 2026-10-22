# R7 deploy runbook (operator-run, Gate A in two stages)

Status: written, never run. Nothing in this file was executed by the platform or by the assistant. It exists so that you,
the operator, can run the stages yourself after you approve them. The platform has no deploy code and Build ran none.

Gate A has two stages. Each needs its own written approval, and the first does not imply the second.

- **Stage 1, isolated localhost-only deployment.** A separate OpenEMR stack that listens on `127.0.0.1` only. There is no tunnel
  and no public hostname. Nothing here needs an AI chat to work: the agent is optional, runs the stub route with no provider key,
  and the module's chat path is left unconfigured. Stage 1 passes on isolation, credential and leakage checks alone.
- **Stage 2, public exposure.** A named time window in which you start a tunnel to the Stage 1 stack. It is requested only after
  Stage 1 passed, and only with every blocker in section 3 closed or accepted in writing.

Approving either stage does not approve the allowlist commit (Gate B), a `LIVE_ENABLED` change (Gate K1, unavailable), a provider
call, or any spend. A new tunnel hostname is a new Stage 2 window.

In code blocks, `$P`, `$CHECKOUT`, `$WORK` and the `$WT_*` variables are the values you choose in section 0. In prose they appear as
`P`, `CHECKOUT`, `WORK` and `WT_*`.

## 0. How this is deployed: one isolated stack, run by hand

There is one approved way to deploy, and it never touches your existing local OpenEMR stack. The pin's scripts are read for
their steps only, and are never run:

- Do not run `scripts/copilot/tunnel.sh` in any form. It hardcodes the compose file `docker/development-easy-light/docker-compose.yml`,
  the container names `development-easy-light-openemr-1` and `development-easy-light-mysql-1`, and the tunnel target
  `https://localhost:9300`. Its `harden` step runs `docker exec` on those names, so it would rotate your existing stack's database
  root and admin passwords.
- Do not run `scripts/copilot/security_gate.sh` either. It hardcodes ports 8320, 8310 and 8400, checks the cookie at
  `https://localhost:9300`, and lists every container on the host. Section 2 gives the same checks, aimed at the new stack.
- Do not stop, restart, rebuild or recreate your existing stack, and do not use its project name, its volumes, its network or its ports.
  The existing stack must be indistinguishable before and after each stage (the canary in section 1).

What you do instead, in outline: a clean checkout of exactly the pin, outside every other repo; the pin's compose files run under
your own unique project name, with your own ports; the agent run under its own project name on the new stack's network; and, in
Stage 2 only, a `cloudflared` process you start yourself. Every command below was read from the pin's text and is untested. If a
command behaves differently from what is written here, stop. Do not improvise on a stack that is about to be exposed.

Rule for every command in this runbook: no secret value appears on a command line. Secrets are read from files in `WORK` (mode 600),
through `--env-file`, and inside containers through their own environment. If you add a command that puts a secret on a command line,
you broke the rule.

Names used below. Choose them once, and write them in the Stage 1 approval request:

- `P`: the compose project name, for example `copilot-r7-20261022`. It must not be `development-easy-light`, and no container,
  volume or network on the host may already use it as a prefix.
- `CHECKOUT`: the absolute path of the new checkout, for example `~/r7/openemr-9f03654`.
- `WORK`: a directory outside `CHECKOUT`, outside the existing OpenEMR repo and outside this repository. It holds the secret files,
  the agent override file, the verifier and the canary snapshots.
- Four free host ports, not 8300, 9300, 8320, 8310 or 8400, for example `WT_HTTP_PORT=18300`, `WT_HTTPS_PORT=19300`,
  `WT_MYSQL_PORT=18320`, `WT_PMA_PORT=18310`, plus `AGENT_HOST_PORT=18400`. Check each is free with
  `lsof -nP -iTCP:<port> -sTCP:LISTEN`, which must print nothing.

```bash
export PIN=9f036541cf95e896db065e0c652afb75627b03c2
export TREE=ca0f7d5e5a705e57fb1f2161411c2a0680e64933
export SRC="<path of your existing OpenEMR repo, read only>"
export P=copilot-r7-20261022
export CHECKOUT="$HOME/r7/openemr-9f03654"
export WORK="$HOME/r7/work-$P"
export WT_HTTP_PORT=18300 WT_HTTPS_PORT=19300 WT_MYSQL_PORT=18320 WT_PMA_PORT=18310 AGENT_HOST_PORT=18400
mkdir -p "$HOME/r7" && mkdir -m 700 "$WORK"
docker ps -a --filter "label=com.docker.compose.project=$P"      # must print only the header line
```

Gate A, Stage 1 is not requestable until `P`, `CHECKOUT`, `WORK` and the five ports are named. This finding is not resolved by Build.

What was read from the pin, so you can check the render against it. The render in section 1 is the real test.

- The overlay's `ports: !override` replaces the stock port lists, so MariaDB, phpMyAdmin and OpenEMR publish on `127.0.0.1` only.
  The stock file publishes on all interfaces.
- The overlay mounts `../../deploy/tunnel/security.conf`. Compose resolves it against the first `-f` file's directory, which is
  `CHECKOUT/docker/development-easy-light`, so it lands inside `CHECKOUT`.
- The stock file declares twelve plain named volumes and no `external` volume or network. Compose prefixes each with the project name.
- The agent file publishes `127.0.0.1:8400` and joins the external network `development-easy-light_default`, both of which belong to
  your existing stack. Without the override in section 2, the agent's `https://openemr` would reach the existing OpenEMR.
- The overlay reads `DB_ROOT_PASS` with the fallback `root`. A missing variable is silent, so section 2 checks for it.

## 1. Before Stage 1

- [ ] Gate A, Stage 1 approved in writing, with start and end times (UTC). It names `P`, `CHECKOUT`, `WORK` and the five ports.
- [ ] You accept the outbound downloads of a first boot and a first agent build: container images, composer, npm, pip and apt.
- [ ] Synthetic data only. You confirm A-001 for this database and name the seed script. The pin ships
      `scripts/copilot/seed_demo_patients.py`.
- [ ] No provider key is used anywhere. Target model spend is $0.
- [ ] `config/allowlist.yaml`, `config/spend_limits.yaml` and both kill switches are unchanged, and the platform runs nothing during the stage.
- [ ] Repository visibility checked, so a committed hostname is not published by accident (needed at Gate B).

### Pinned checkout (never the existing tree)

The existing dirty tree is not touched, switched or reset. Do not deploy from it, and do not run `git checkout`, `git stash` or
`git reset` in it. Make the clean checkout somewhere else:

1. `git clone --no-hardlinks <existing OpenEMR repo path> CHECKOUT`. This only reads the existing repo. Prefer it to
   `git worktree add`, which writes into the existing repo's `.git`. Then `git -C CHECKOUT remote set-url --push origin DISABLED`.
2. `git -C CHECKOUT checkout --detach 9f036541cf95e896db065e0c652afb75627b03c2`.
3. `git -C CHECKOUT rev-parse HEAD` prints `9f036541cf95e896db065e0c652afb75627b03c2`.
4. `git -C CHECKOUT rev-parse 'HEAD^{tree}'` prints `ca0f7d5e5a705e57fb1f2161411c2a0680e64933`.
5. `git -C CHECKOUT status --porcelain --untracked-files=all` prints nothing. Do this immediately before the first container
   starts. This is the value for `git_status_porcelain_empty` in the attestation.
6. Do not run `composer`, `npm`, `pip` or any build step inside `CHECKOUT`. The compose file keeps dependencies in named volumes.

The pin's compose file mounts `CHECKOUT` into the OpenEMR container read-write (the `htdocs` mount is `:rw`), so a running
container can change files in it. Section 5 re-checks the checkout after each stage. Treat a changed tracked file as "the running
code was not the pin", not as noise.

### Secret and override files

```bash
umask 077
rand() { openssl rand -base64 33 | tr -d '/+=\n' | cut -c1-24; }
printf 'OPENEMR_DIR=%s\nWT_HTTP_PORT=%s\nWT_HTTPS_PORT=%s\nWT_MYSQL_PORT=%s\nWT_PMA_PORT=%s\n' "$CHECKOUT" "$WT_HTTP_PORT" "$WT_HTTPS_PORT" "$WT_MYSQL_PORT" "$WT_PMA_PORT" > "$WORK/ports.env"
{ cat "$WORK/ports.env"; echo "DB_ROOT_PASS=$(rand)"; } > "$WORK/stack.env"
printf 'OE_ADMIN_PASS=%s\nCOPILOT_FIXTURE_PASSWORD=%s\nMODULE_SIGNING_SECRET=%s\nAUDIT_HMAC_KEY=%s\n' "$(rand)" "$(rand)" "$(rand)" "$(rand)" > "$WORK/app-secrets.env"
grep -q '^DB_ROOT_PASS=.\{20,\}$' "$WORK/stack.env" && echo "DB_ROOT_PASS present"
# Placeholder for the agent's env_file. Compose refuses to render the agent without it. It is empty, so it holds no secret.
# It is git-ignored at the pin, so it does not change `git status`. Section 2 fills it in only after the render checks.
: > "$CHECKOUT/agent/.env" && git -C "$CHECKOUT" check-ignore agent/.env
```

`ports.env` holds no secret and is the only file used to render the configuration. `stack.env` is used only to start, stop and
inspect the stack, so the database root password reaches every compose command and the silent `root` fallback never applies.
The placeholder `agent/.env` must exist, and must still be empty, when the agent is rendered. Rendering with the filled-in file would
copy its secrets into `WORK/ag.json`. If `check-ignore` prints nothing, stop.

### Isolation checks, before anything starts

Write the agent override file (section 2, "Agent override") and create the empty placeholder `agent/.env` (above) first, then render
both projects without starting them. Send the output to files in `WORK`. Do not print it, because the upstream compose file carries a
committed token (blocker B3), which `WORK/oe.json` will contain. Keep that file at mode 600, and delete it when the stage is over.

- `docker compose -p P --env-file WORK/ports.env -f CHECKOUT/docker/development-easy-light/docker-compose.yml -f CHECKOUT/deploy/tunnel/docker-compose.override.yml config --format json`, saved to `WORK/oe.json`.
- `docker compose -p P-agent -f CHECKOUT/agent/docker-compose.yml -f WORK/agent-override.yml config --format json`, saved to `WORK/ag.json`.

```bash
OE_R=(docker compose -p "$P" --env-file "$WORK/ports.env" -f "$CHECKOUT/docker/development-easy-light/docker-compose.yml" -f "$CHECKOUT/deploy/tunnel/docker-compose.override.yml")
AG=(docker compose -p "$P-agent" -f "$CHECKOUT/agent/docker-compose.yml" -f "$WORK/agent-override.yml")
"${OE_R[@]}" config --format json > "$WORK/oe.json"
"${AG[@]}" config --format json > "$WORK/ag.json"
cat > "$WORK/check_iso.py" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1])); co, proj, ports, net = sys.argv[2], sys.argv[3], set(sys.argv[4].split()), sys.argv[5]
bad = []
if cfg["name"] != proj: bad.append("project name")
for k, v in cfg.get("volumes", {}).items():
    if v.get("external") or not v["name"].startswith(proj + "_"): bad.append("volume " + k)
for k, v in cfg.get("networks", {}).items():
    if v["name"] != net: bad.append("network " + k)
for s, svc in cfg["services"].items():
    for m in svc.get("volumes", []):
        if m["type"] == "bind" and not m["source"].startswith(co): bad.append("bind %s %s" % (s, m["source"]))
    for pt in svc.get("ports", []):
        if pt.get("host_ip") != "127.0.0.1" or str(pt["published"]) not in ports: bad.append("port %s %s" % (s, pt))
print("ISOLATION FAIL: " + "; ".join(bad) if bad else "ISOLATION OK")
sys.exit(1 if bad else 0)
PY
python3 "$WORK/check_iso.py" "$WORK/oe.json" "$CHECKOUT" "$P" "$WT_HTTP_PORT $WT_HTTPS_PORT $WT_MYSQL_PORT $WT_PMA_PORT" "${P}_default"
python3 "$WORK/check_iso.py" "$WORK/ag.json" "$CHECKOUT" "$P-agent" "$AGENT_HOST_PORT" "${P}_default"
```

Both lines must print `ISOLATION OK`. That one script is what makes the checks below true, and you confirm all of these:

- [ ] The project name is `P` (and `P-agent`), not `development-easy-light`.
- [ ] Every named volume is prefixed `P_` (and `P-agent_agent_data`). Docker creates a volume for each project name separately, so none can be
      one of your existing stack's volumes. No volume is declared `external`.
- [ ] Every bind-mount source is under `CHECKOUT`. None is the existing tree.
- [ ] Every published port is bound to `127.0.0.1` and is one of your five new ports. None of 8300, 9300, 8320, 8310 or 8400 appears.
- [ ] The network is `P_default`. The agent attaches to `P_default` and not to `development-easy-light_default`. That is what makes
      the agent's `https://openemr` mean the new OpenEMR and not the existing one.

### Existing-stack canary

The canary proves your existing stack did not change. Do not compare the `Status` column of `docker ps`. It reads "Up 3 days" and
changes by itself, so it raises false alarms and hides real ones. Compare, for every container, the ID, image ID, state, `StartedAt`
time, restart count and port bindings, which only change when something restarts, recreates or rebinds a container. The script uses
fixed `--format` fields and never prints `Env`.

Volumes need one more rule. The OpenEMR image declares volumes that the compose file does not name (`/etc/letsencrypt` and `/etc/ssl`),
so Docker creates anonymous volumes with random 64-character names and no project prefix when the container is created. The canary
ignores an unprefixed volume only when all of these are proven, one volume at a time:

- it is not in the "before" snapshot (a volume that existed before the stage always stays in the comparison);
- it carries the `com.docker.volume.anonymous` label;
- at least one container mounts it, and every container that mounts it has the compose project label `P` or `P-agent`.

Anything else is a change and fails the canary: a named volume without the prefix, an anonymous volume that any other container
mounts (even together with one of ours), and an anonymous volume that nothing mounts, because ownership cannot be shown. Each ignored
volume is named on stderr with its mounters, so you can see what was skipped.

```bash
cat > "$WORK/canary.sh" <<'SH'
#!/usr/bin/env bash
# canary.sh snap LABEL   record the host's containers, volumes and networks
# canary.sh diff LABEL   record again, then compare with the "before" record, ignoring only this project's own objects
set -euo pipefail
: "${P:?}" "${WORK:?}"
mode="$1"; label="$2"
snap() {
  : > "$WORK/containers-$1.txt"
  ids=$(docker ps -aq)
  if [ -n "$ids" ]; then
    docker inspect --format '{{.Id}} {{.Name}} {{.Image}} {{.State.Status}} {{.State.StartedAt}} {{.RestartCount}} {{json .NetworkSettings.Ports}}' $ids | sort > "$WORK/containers-$1.txt"
  fi
  docker volume ls -q | sort > "$WORK/volumes-$1.txt"
  docker network ls --format '{{.ID}} {{.Name}}' | sort > "$WORK/networks-$1.txt"
}
# Volumes of this snapshot that still count as the existing stack's: everything except this project's own volumes and anonymous
# volumes proven to belong only to this project.
foreign_volumes() {
  local v users
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    case "$v" in "${P}_"*|"${P}-agent_"*) continue ;; esac
    if ! grep -qxF -- "$v" "$WORK/volumes-before.txt" \
       && docker volume inspect -f '{{range $k,$x := .Labels}}{{$k}} {{end}}' "$v" 2>/dev/null | grep -qw 'com.docker.volume.anonymous'; then
      users=$(docker ps -a --filter "volume=$v" --format '{{.Names}} {{.Label "com.docker.compose.project"}}')
      if [ -n "$users" ] && ! printf '%s\n' "$users" | awk -v p="$P" '!($2 == p || $2 == p "-agent") { bad = 1 } END { exit !bad }'; then
        echo "note: ignoring anonymous volume ${v:0:12} used only by this project: $(printf '%s' "$users" | cut -d' ' -f1 | tr '\n' ' ')" >&2
        continue
      fi
    fi
    printf '%s\n' "$v"
  done < "$WORK/volumes-$1.txt"
}
case "$mode" in
  snap) snap "$label" ;;
  diff)
    snap "$label"; rc=0
    diff "$WORK/containers-before.txt" <(grep -v " /${P}-" "$WORK/containers-$label.txt") || rc=1
    diff "$WORK/volumes-before.txt" <(foreign_volumes "$label" | sort) || rc=1
    diff "$WORK/networks-before.txt" <(grep -v " ${P}_default\$" "$WORK/networks-$label.txt") || rc=1
    if [ "$rc" = 0 ]; then echo "CANARY OK: existing stack unchanged"; else echo "CANARY CHANGED: stop and report"; exit 1; fi ;;
esac
SH
chmod 700 "$WORK/canary.sh"
"$WORK/canary.sh" snap before
```

Before anything starts, `canary.sh snap before` writes `WORK/containers-before.txt`, `WORK/volumes-before.txt` and
`WORK/networks-before.txt`. Run `"$WORK/canary.sh" diff <label>` at the end of Stage 1 and again in section 5. It must print
`CANARY OK`. A changed line is a stop: report it and do not restart anything to hide it.

## 2. Start the isolated stack (Stage 1), then harden it

Everything here runs against project `P` only. Give each command `-p P` and the explicit `-f` files. Never run `docker compose`
for the pin without `-p P`, because the default project name would be your existing stack's.

Agent override. Save it as `WORK/agent-override.template.yml` (outside `CHECKOUT`, so the checkout stays the pin):

```yaml
services:
  agent:
    ports: !override
      - "127.0.0.1:AGENT_HOST_PORT:8400"
networks:
  oe:
    name: P_default
```

Replace `AGENT_HOST_PORT` and `P` with your values, writing the result to `WORK/agent-override.yml`:
`sed -e "s/AGENT_HOST_PORT/$AGENT_HOST_PORT/" -e "s/P_default/${P}_default/" "$WORK/agent-override.template.yml" > "$WORK/agent-override.yml"`.
The base file publishes the agent on `127.0.0.1:8400`, which is your existing agent's port, so the override replaces that list instead of
adding to it. `external: true` stays from the base file, so the network must exist first: start the stack, then the agent.

Order:

1. Run the isolation checks in section 1 and take the canary. Stop on any failure.
2. Start only the database and OpenEMR, never phpMyAdmin:
   `docker compose -p P --env-file WORK/stack.env -f CHECKOUT/docker/development-easy-light/docker-compose.yml -f CHECKOUT/deploy/tunnel/docker-compose.override.yml up -d mysql openemr`.
   The containers are named `P-openemr-1` and `P-mysql-1`. Then wait for health with the bounded script below. The first boot builds
   `vendor` and `node_modules` into empty volumes and takes about five minutes. If the script exits non-zero, stop: do not retry the
   start, do not continue to step 3, and follow `r7-rollback.md`.
3. Seed synthetic data, create the fixture users, rotate the admin password and set the globals. The commands below read every
   secret inside the container.
4. Optional, and not needed for any Stage 1 check: fill in the placeholder `CHECKOUT/agent/.env` from section 1, using `agent/.env.example`
   with `LLM_PROVIDER=stub`, an empty `OPENROUTER_API_KEY`, an empty `DASHBOARD_TOKEN`, `W2_ENABLED=false` and your generated signing and
   audit values. It is git-ignored at the pin. Check that with `git -C CHECKOUT check-ignore agent/.env`. Do this only after the
   render checks passed. Then
   `docker compose -p P-agent -f CHECKOUT/agent/docker-compose.yml -f WORK/agent-override.yml up -d --build`.
   Do not create the module's `config.local.php`, register an OAuth client or activate the module in R7. Chat is not needed, and
   its failure is not a Stage 1 failure. How the module behaves without that file was not tested.
5. The steps `tunnel.sh harden` performs are done by hand below, against `P-mysql-1` and `P-openemr-1` only. They were read from the pin
   with `git -C CHECKOUT show HEAD:scripts/copilot/tunnel.sh`. List each step you did in the attestation notes.

Bounded health wait. It polls every 15 seconds for at most 80 tries (20 minutes), fails at once if the container is missing or is no
longer running, and exits non-zero on timeout. It never loops forever.

```bash
cat > "$WORK/wait_healthy.sh" <<'SH'
#!/usr/bin/env bash
# wait_healthy.sh CONTAINER [MAX_TRIES] [SLEEP_SECONDS]   exit 0 only when the container reports healthy
set -u
c="$1"; max="${2:-80}"; nap="${3:-15}"; s=missing; r=missing
for i in $(seq 1 "$max"); do
  r=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null | tr -d '[:space:]'); [ -n "$r" ] || r=missing
  s=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null | tr -d '[:space:]'); [ -n "$s" ] || s=missing
  [ "$s" = healthy ] && { echo "$c is healthy after $i checks"; exit 0; }
  case "$r" in running|restarting) ;; *) echo "FAIL: $c is $r (health $s). Stop and follow the rollback runbook." >&2; exit 1 ;; esac
  sleep "$nap"
done
echo "FAIL: $c not healthy after $max checks of ${nap}s (state $r, health $s). Stop and follow the rollback runbook." >&2
exit 1
SH
chmod 700 "$WORK/wait_healthy.sh"
"$WORK/wait_healthy.sh" "$P-openemr-1" 80 15 || echo "STOP: OpenEMR did not become healthy"
```

```bash
OEU=(docker compose -p "$P" --env-file "$WORK/stack.env" -f "$CHECKOUT/docker/development-easy-light/docker-compose.yml" -f "$CHECKOUT/deploy/tunnel/docker-compose.override.yml")
export PYTHONDONTWRITEBYTECODE=1
q() { docker exec "$P-mysql-1" sh -c 'mariadb -uroot -p"$MYSQL_ROOT_PASSWORD" openemr -N -e "$1"' _ "$1"; }
python3 "$CHECKOUT/scripts/copilot/seed_demo_patients.py" | docker exec -i "$P-mysql-1" sh -c 'mariadb -uroot -p"$MYSQL_ROOT_PASSWORD" openemr'
docker exec -u apache --env-file "$WORK/app-secrets.env" "$P-openemr-1" php /var/www/localhost/htdocs/openemr/scripts/copilot/authz_fixture.php > /dev/null
docker exec -u apache --env-file "$WORK/app-secrets.env" "$P-openemr-1" php -r '
  $_GET["site"]="default"; $ignoreAuth=true;
  require "/var/www/localhost/htdocs/openemr/interface/globals.php";
  $h=(new OpenEMR\Common\Auth\AuthHash("auth"))->passwordHash(getenv("OE_ADMIN_PASS"));
  sqlStatement("UPDATE users_secure SET password=?, last_update_password=NOW(), login_fail_counter=0 WHERE username=?", [$h,"admin"]);
  echo "admin password rotated\n";'
q "UPDATE globals SET gl_value=0 WHERE gl_name IN ('oauth_password_grant','portal_onsite_two_enable','rest_portal_api'); UPDATE globals SET gl_value=1 WHERE gl_name='api_log_option';"
```

Security checks, hand-run against the new stack. These replace `security_gate.sh`. Each must hold at the end of Stage 1 and again
immediately before any tunnel starts, and any failure means no tunnel:

- [ ] `DB_ROOT_PASS` is in `WORK/stack.env`. The database root password is not the default: a login to `P-mysql-1` with the old default
      fails, and the new one works.
- [ ] The admin password is not `pass`, and a login as admin with `pass` fails.
- [ ] No active OpenEMR account has a default or guessable password. Run the pin's audit logic through `docker exec` into `P-openemr-1`,
      as the `apache` user. It must exit 0.
- [ ] Only `127.0.0.1` port bindings exist for the new project. Run
      `docker ps --filter label=com.docker.compose.project=P --format '{{.Names}} {{.Ports}}'` and then the same with `P-agent`. Neither
      may show a `0.0.0.0` or `::` binding. Check each project separately: two filters on the same label are ORed, not ANDed.
- [ ] The globals are right, read by SQL in `P-mysql-1`: `oauth_password_grant`, `portal_onsite_two_enable` and `rest_portal_api` are 0,
      and `api_log_option` is 1. An empty result is a failure.
- [ ] Session cookies carry the Secure flag: `curl -ksI https://localhost:WT_HTTPS_PORT/` on your new HTTPS port shows `Secure` on each `Set-Cookie`,
      and shows at least one `Set-Cookie`. The pin's gate passes with none. Do not use port 9300.
- [ ] `python3 CHECKOUT/scripts/copilot/secret_scan.py` finds nothing, and `agent/.env` and `config.local.php` are git-ignored and untracked.
      The pin's gate also requires that no `.env` or `config.local.php` was ever committed.
- [ ] Neither `agent/.env` nor the module's `config.local.php` is served: both return 403 or 404 on your new HTTPS port (blocker B4).
- [ ] The agent, if running, is attached to `P_default` only, and `openemr` resolves from inside the agent to the new OpenEMR's address
      (the commands below).
- [ ] The agent is not reachable through the tunnel. `/health` is off the platform allowlist, so the platform cannot test this. It is
      your own check, recorded as `agent_private_check`.

```bash
DB="$P-mysql-1"; OEC="$P-openemr-1"; AGC="$P-agent-agent-1"
! docker exec "$DB" mariadb -uroot -proot -e 'select 1' 2>/dev/null && echo "PASS root is not the default"
h=$(q "select password from users_secure where username='admin'"); docker exec "$OEC" php -r 'exit(password_verify("pass",$argv[1])?1:0);' "$h" && echo "PASS admin is not 'pass'"
docker exec -u apache "$OEC" php /var/www/localhost/htdocs/openemr/scripts/copilot/fixture_accounts_audit.php; echo "audit exit $? (0 is a pass)"
for pr in "$P" "$P-agent"; do docker ps --filter "label=com.docker.compose.project=$pr" --format '{{.Names}} {{.Ports}}'; done | grep -E '0\.0\.0\.0|\[::\]|:::|:(8300|9300|8310|8320|8400)->' && echo "FAIL bindings" || echo "PASS bindings"
q "select gl_name, gl_value from globals where gl_name in ('oauth_password_grant','portal_onsite_two_enable','rest_portal_api','api_log_option')"   # 0, 0, 0 and 1
c=$(curl -sk -D - -o /dev/null "https://localhost:$WT_HTTPS_PORT/interface/login/login.php?site=default" | grep -i '^set-cookie'); [ -n "$c" ] && [ "$(printf '%s\n' "$c" | grep -vic '; secure')" = 0 ] && echo "PASS secure cookies"
for u in agent/.env interface/modules/custom_modules/oe-module-copilot/config.local.php; do curl -sk -o /dev/null -w "$u %{http_code}\n" "https://localhost:$WT_HTTPS_PORT/$u"; done
(cd "$CHECKOUT" && python3 scripts/copilot/secret_scan.py && [ -z "$(git log --all --name-only --pretty=format: | grep -E '(^|/)(\.env|config\.local\.php)$')" ] && echo "PASS secret scan and history")
docker exec "$AGC" python -c "import socket;print(socket.gethostbyname('openemr'))"
docker inspect -f '{{(index .NetworkSettings.Networks "'"$P"'_default").IPAddress}}' "$OEC"      # the same address as the line above
docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$AGC" "$OEC"   # only P_default, on both lines
```

End of Stage 1:

- [ ] `"$WORK/canary.sh" diff after-stage1` prints `CANARY OK`.
- [ ] Section 5's checkout re-check is clean.
- [ ] Write `WORK/stage1-result.txt` with the PASS lines, the pin commit and tree, and the image IDs of the new containers
      (`docker inspect` with `--format '{{.Name}} {{.Image}}'` only). Labels and hashes only.
- [ ] Stop the stack, or leave it running on loopback. Either way nothing is exposed. If you leave it running, repeat the checks and the canary
      before Stage 2.

Stage 1 ends here. Nothing below runs without the Stage 2 approval.

## 3. Open the window (Stage 2, public exposure)

Stage 2 exposes the whole OpenEMR application, not a chosen path, to anyone who has the tunnel hostname. Do not start it while any
blocker below is open. A blocker is closed by the stated evidence, or by your written acceptance naming it, in the Stage 2 request.

### Blockers

**B1. Dev-mode exposure.** The pin's stock file turns on `EASY_DEV_MODE`, `EASY_DEV_MODE_NEW`, `DEVELOPER_TOOLS`, `XDEBUG_ON` and
`XDEBUG_PROFILER_ON`, and enables the REST, FHIR and system-scope APIs (`rest_api`, `rest_fhir_api`, `rest_system_scopes_api`). The
overlay turns off only `oauth_password_grant`, `portal_onsite_two_enable` and `rest_portal_api`, and sets `api_log_option`.

- Evidence: print only those named keys from the rendered file, with
  `python3 -c 'import json;e=json.load(open("'"$WORK"'/oe.json"))["services"]["openemr"]["environment"];[print(k,e.get(k)) for k in ("EASY_DEV_MODE","DEVELOPER_TOOLS","XDEBUG_ON","XDEBUG_PROFILER_ON","OPENEMR_SETTING_rest_api","OPENEMR_SETTING_rest_fhir_api","OPENEMR_SETTING_rest_system_scopes_api")]'`.
  Never print the whole environment.
- Clears by one of: your written acceptance of each setting as it stands, or an extra override file kept in `WORK` (never in
  `CHECKOUT`) that lowers `XDEBUG_ON`, `XDEBUG_PROFILER_ON` and `DEVELOPER_TOOLS`. The second path changes the pin's configuration, may
  break the first boot, and was not tested. If you use it, re-run every check in sections 1 and 2 and record it as a deviation.
- Also required: `git -C CHECKOUT grep -n 'phpinfo(' -- ':!tests' ':!vendor'` lists no page you can reach over HTTPS without logging in. A
  page that prints the environment would print the token in B3.

**B2. Default credentials.** The stock file sets `OE_PASS=pass`, `MYSQL_PASS=openemr` and a database root of `root`. The overlay replaces
the root value only through `DB_ROOT_PASS`, and falls back to `root` silently.

- Evidence: every credential check in section 2 passes, including the audit exit 0 and the `DB_ROOT_PASS` check, and the fixture users
  were created with the generated password.
- The `openemr` database user keeps the password `openemr`. The pin's flow does not rotate it, and it is the account OpenEMR uses to reach
  the database. Clears by one of: your written acceptance that it is reachable only on the compose network and on
  `127.0.0.1:WT_MYSQL_PORT`, or an extra override in `WORK` that stops publishing the MariaDB host port (untested, and the isolation
  check must still print `ISOLATION OK`). The environment of `P-openemr-1` also still holds `OE_PASS=pass`, which is an install-time value.
  It is a default credential in `docker inspect` output, so never print that container's environment.

**B3. The committed upstream token.** The pinned compose file carries a `GITHUB_COMPOSER_TOKEN` value, in three encodings, in the OpenEMR
container's environment. Its history shows it arrived with the upstream import, not from you. Treat it as a live credential
anyway.

- Rules: never print, copy or log it. Do not paste rendered configuration, `docker inspect` output of the OpenEMR container, container
  logs or an environment dump anywhere. Do not test the token or call any API with it. Keep it out of this repository, the attestation and every note.
- Evidence: `git -C CHECKOUT log --format='%h %an %ad %s' --date=short -S'GITHUB_COMPOSER_TOKEN:' -- docker/development-easy-light/docker-compose.yml`
  prints only commit metadata. Record that it is the upstream author. Run the pin's `secret_scan.py` and record whether it flags the token. If it does,
  the section 2 secret scan check fails and the blocker stays open until you decide in writing.
- Clears by your written acceptance that the token sits in the container environment of an exposed stack, with the provenance you recorded
  and the B1 environment-page check done. The pinned file is not edited, so it cannot be removed here. Tell the upstream owner if you believe it is private.

**B4. Secret leakage.** The whole checkout is the OpenEMR web root, so `agent/.env` and the module's `config.local.php` sit where Apache can
serve them. Only the `.htaccess` rewrite rules in `agent/` and in the module stop that, and the pin's gate never requests them.

- Evidence: both paths return 403 or 404 on the new HTTPS port, at the end of Stage 1 and again immediately before the tunnel.
- Evidence: `git -C CHECKOUT status --ignored --porcelain --untracked-files=all` shows only the two expected ignored files, plus runtime output you
  can name. Any other secret-looking file in `CHECKOUT` is a stop.
- Evidence: the secret files exist only in `WORK` (mode 600) and those two ignored files. No `deploy/tunnel/.env` was created. No secret
  was on a command line, in a pasted output, in `WORK/*.json`, or in the attestation notes.
- Clears when all of that holds. This blocker cannot be cleared by acceptance alone.

### Stage 2 start

- [ ] Gate A, Stage 2 approved in writing, with start and end times (UTC), naming the accepted blockers and whether the agent runs.
- [ ] Stage 1 passed. Re-run every check in section 2, `"$WORK/canary.sh" diff before-stage2`, and the checkout re-check in section 5. All pass.
- [ ] If the agent is not running, say so in the attestation notes. Record `route: stub` only for a stub configuration that actually exists in
      `agent/.env`. Ask before attesting otherwise.
- [ ] Read the access log and note its position (the "before" review).
- [ ] Start the tunnel by hand, never with `tunnel.sh up`:
      `cloudflared tunnel --no-autoupdate --no-tls-verify --url https://localhost:WT_HTTPS_PORT`, with your new HTTPS port. Note the
      process ID, because you stop it yourself later. Record the hostname you were given. Never reuse `deploy/tunnel/url.txt` from an older run.
- [ ] Confirm the tunnel target is your new port and not 9300, from the command line you ran.
- [ ] Do not paste the hostname into this repo yet. That is Gate B.

## 4. Observe from outside (Stage 2, recorded by you)

You fetch these yourself, with a browser or `curl`, one request each. The platform does not.

- The sha256 of the four module assets under `interface/modules/custom_modules/oe-module-copilot/` (listed in
  `config/target_pin.yaml`).
- The HTTP status of the three negative-control paths in the same file. They are absent at the pin, so 404 is the expected answer.
  A served file is a pin `difference`.

Record the pin outcome as `consistent_with_pin`, `difference` or `unverified`. It is never "verified": the agent code is private,
and the four assets are identical in the dirty tree, so only the negative controls can tell the two apart.

Identity is recorded as operator-observed. The platform sends no request in R7, because Gate K1 is unavailable.

## 5. Close the window (after Stage 2, and the same checks at the end of Stage 1)

- [ ] Read the access log again (the "after" review). An entry you cannot explain means stop, rotate every secret in `WORK` and
      close the tunnel. Do not continue to Gate B. After Stage 1 only, skip this line and the next.
- [ ] Stop the tunnel (see the rollback runbook).
- [ ] Re-check the pinned checkout: `git -C CHECKOUT rev-parse HEAD` is still the pin, and
      `git -C CHECKOUT status --porcelain --untracked-files=all`. A modified or deleted tracked file means the running code was not the
      pin: stop, record a pin `difference`, and do not go on to Gate B. Untracked files are runtime output. List them in the notes.
- [ ] Compare the canary: `"$WORK/canary.sh" diff after`, against the `WORK/*-before.txt` files. It prints `CANARY OK` only if every existing
      container keeps its ID, image, state, start time, restart count and port bindings, and the volume and network lists differ only by objects
      prefixed `P_`, `P-` or `P-agent`. Any change to a `development-easy-light` container or volume is a stop. Report it and do not restart
      anything to hide it.
- [ ] Fill in `Docs/attestations/deploy-attestation.yaml` from `deploy-attestation.template.yaml`, and
      `log-access-inventory.md` from its template. Hashes and labels only. No password, token, key, cookie or header.
- [ ] Run `python scripts/preflight_live.py`. It reads local files only. A pass is necessary, not an approval.

## 6. Abort now, without finishing the stage

An off-list host, a pin `difference`, an unexplained access-log entry, a changed hostname, anything resembling real patient data,
a failing security check, an open blocker at Stage 2, a changed existing-stack canary, a modified tracked file in the checkout, a secret in any output,
or any step that would need `tunnel.sh`, `security_gate.sh`, or the project name `development-easy-light`. Follow `r7-rollback.md`.
