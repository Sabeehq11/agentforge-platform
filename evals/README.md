# Seed attack suite

P3 seed cases. They are not an agent and they are not `AttackResult`. Contracts in `contracts/v1/` are unchanged.

Dry-run is the default. It does not open a socket. A case that needs a target response is `not_run`, not `pass`.
The attack-count case is the only local grader that can pass without a target, because it checks the platform cap,
not the target.

`LIVE_ENABLED` in `src/agentforge/safety/chokepoint.py` is the kill switch. An environment variable cannot turn it
on. `results/campaign-latest.json` holds three graded `pass` rows (`seed-tm-ex-3`, `seed-tm-ds-1`, `seed-tm-pi-1`)
from the deployed local target. None is a public-URL result. The public-URL repeat belongs to the R10 checkpoint, and
no file here names a public URL.

The two CareTeam authorization candidates in `THREAT_MODEL.md` are not cases here. The public module does not accept
a caller-supplied FHIR bundle, and this suite does not add a signing-secret path.

## Cases, the p.11 gate and offline outcomes

There are 19 cases. Every case must pass the PRD p.11 validity gate in `scripts/check_evals.py`: its exercise tag
holds, its trigger source can be located, its grader returns `pass` for a synthetic safe body and `fail` for a
synthetic weakened body, an empty body is `error`, and its turns are PHI-clean. The gate has one rule set for every
case. It checks case metadata and synthetic bodies. It is not a finding about the target.

`offline/responses.json` holds the synthetic safe and weakened body for each case. `scripts/run_offline_cases.py`
grades them and writes `results/offline-latest.json`. `--check` regenerates the file and fails if it was edited by
hand. Those rows are labeled `basis: offline_replay`, `live: false`, `target_result: false`. They show the case and
grader discriminate. They are not target behavior and are kept apart from `campaign-latest.json`.

`seed-tm-ds-rate` is the A04 Co-Pilot rate-limit case. `seed-tm-ds-4` and `seed-tm-ds-audit` are platform controls and are not Co-Pilot coverage. `seed-tm-ds-a03`, `seed-tm-ds-a06`, `seed-tm-ds-a09`, `seed-tm-ds-a10` and `seed-tm-ds-llm05` map those IDs to stored rows in `evals/results/local-owasp-final.json`. They do not rerun the checks. A09 is platform-only evidence. A06, A09 and LLM05 keep their stored fail grades as findings.

`seed-tm-tm-1` (LLM08) is a response-claim proxy. A `pass` means the answer text did not contain the claim token. A
`fail` means it did. Neither shows whether a tool call happened. `seed-tm-ex-1-output` (LLM02) uses the offline-only
`active_markup` grader, which is not on the live chat path, so a live run is `not_run`.

## OWASP coverage ledger

`owasp_coverage.json` records, per PRD-named OWASP item, what the suite exercises and what it does not. It closes no
PRD requirement. A04 and A09 are unverified Co-Pilot properties. LLM02, LLM06 and LLM08 are partially
exercised. A01 is `offline_only`: it has cases and synthetic replay pairs and no target outcome. A07 and LLM01 are
`exercised`, which means a stored outcome from the local fixture target exists, not one from the public URL. A06 and LLM05 are platform scans of
this repository, not of the target. A03 and A10 are interpretations. Each row names the half it cannot observe and
the gate that could: R10 for the chat-observable repeat on the public target, or one of the unresolved requirements
U1 to U5, which no roadmap checkpoint has taken into scope. None of R10 or U1 to U5 has run.
