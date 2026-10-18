# Seed attack suite

P3 seed cases. They are not an agent and they are not `AttackResult`. Contracts in `contracts/v1/` are unchanged.

Dry-run is the default. It does not open a socket. A case that needs a target response is `not_run`, not `pass`.
The attack-count case is the only local grader that can pass without a target, because it checks the platform cap,
not the target.

`LIVE_ENABLED` in `src/agentforge/safety/chokepoint.py` is the kill switch. An environment variable cannot turn it
on. This directory does not contain a live result. H-3 is unmet until an approved run stores graded `pass` or `fail`
results for TM-PI, TM-EX and TM-DS.

The two CareTeam authorization candidates in `THREAT_MODEL.md` are not cases here. The public module does not accept
a caller-supplied FHIR bundle, and this suite does not add a signing-secret path.
