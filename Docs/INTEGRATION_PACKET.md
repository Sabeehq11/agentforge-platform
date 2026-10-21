# Contract conformance test

This packet is the Q4 fallback. It is a contract conformance test. It is not peer integration (D-008).

The project is being completed independently and remotely. No cohort peer was assigned. X-3 and X-4 are externally unavailable and are excluded from independent-project completion scope. They stay unmet against the original PRD. This packet does not close them.

## Both sides

`tests/test_contracts.py` validates the same bytes on both sides. The producer and the consumer do not import each other's builders. The producer is in this repo (`tests/fixtures.py`). That is a stand-in, not a peer.

## Schema diff

`scripts/check_schema_diff.py` exits 1 on a breaking v1 change that does not leave `contracts/v1/`. The CI step is `.github/workflows/ci.yml`, "Schema diff (a breaking v1 change without a version bump fails)". No failing diff is invented here.

## Dependency map

This is our own agent map, taken from `ARCHITECTURE.md`. It is not a cross-team map. No edge was added.

- Orchestrator sends a campaign request to Red Team.
- Red Team returns an attack result to the executor.
- The executor reaches the target only through the chokepoint.
- The executor records a transcript for the Judge.
- The Judge returns a verdict to the harness and a confirmed exploit to Documentation.
- Documentation writes a draft. A human gate precedes publication.

## End-to-end trace

Stub only. `tests/test_p7_trace.py` lists Orchestrator, Red Team, Judge, and Documentation under one correlation id. This does not close M-1. M-1 stays partial until a live run.

## Interface diffs

None.

## Contract-correction ADRs

None. No ADR was added for this packet.

## Inherited component

No peer component was inherited. The in-repo stub consumes the published v1 schema in `contracts/v1/`. That schema is not another student's component, so it does not satisfy the lab.
