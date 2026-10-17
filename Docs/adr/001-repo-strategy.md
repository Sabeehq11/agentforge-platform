# ADR-001: Repo strategy: independent repo, target pinned by SHA, HTTP only

- Status: accepted
- Date: 2026-10-17
- Related questions: Q1 (see ROADMAP section 2.5)

## Context

The Week 3 PRD asks for an "Independent code repo". The Co-Pilot (Weeks 1 and 2) lives in
`Sabeehq11/openemr-base-clean`. The platform must reach it only over HTTP (D-007) and must not import target
internals. Criteria: PRD independence, black-box boundary, CI reuse, history preservation, cost of coordinating
changes across repos.

## Options considered

### Chosen: B. New repo, target pinned by commit SHA
- Meets "independent". The target version is traceable through a recorded SHA. No source-level coupling is needed
  because the platform only speaks HTTP. The SHA is recorded in `Docs/TARGET_FREEZE.md`; no tag, commit or push is made
  in the target repo.

### Rejected: A. Same repo, new top-level package
- Might not satisfy "independent code repo". Blurs the trust boundary, because the platform could import target
  internals. Would put platform CI and secrets in a repo that also holds the target.

### Rejected: C. New repo, target by URL only (no pin)
- Cleanest black-box boundary, but gives no traceable target version, so replays and regression results could not be
  tied to a build. B keeps the same boundary and adds the pin.

### Rejected: B with a git submodule of the target
- Submodule friction, and it invites source-level coupling. A recorded SHA gives traceability without that risk.

## Decision

Option B. This repository is the platform. The target is an external HTTP service pinned by SHA.

## Consequences and risks

- Target contracts or fixtures needed by tests are copied or described here, not imported.
- Target changes need a separate record (TARGET_FREEZE.md and later the regression trigger).
- The PRD wording is not confirmed by staff for B specifically; B is the strictest reading of "independent".

## Verification that the decision holds

- No file in this repo imports from the target repo (`agent/`). Checked by review and by the absence of the target
  source in the tree.
- The safety chokepoint is the only path to the target (ADR-002, `src/agentforge/safety/chokepoint.py`).
