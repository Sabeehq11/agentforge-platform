# ADR-004: Models: per-role configuration, distinct families for Red Team and Judge

- Status: accepted
- Date: 2026-10-17
- Related questions: Q10, Q13

## Context

The PRD requires the Judge to be independent of attack generation. It also warns that commercial frontier models may
refuse offensive tasks and can be expensive. Which providers refuse which attacks has not been measured, and P0 may
not spend money.

## Options considered

### Chosen: model per role is configuration
- `config/models.yaml` holds provider, model and family per role. No role is hard-wired to a vendor. A check
  (`src/agentforge/models_config.py`) refuses a configuration where Red Team and Judge share a family. The real
  assignment is made in P4 after an approved, capped probe.

### Rejected: one frontier model for every role
- Breaks Judge independence, concentrates cost, and risks refusals on the Red Team role.

### Rejected: pick a Red Team model now from reputation
- Refusal behavior is unmeasured. Choosing without a probe would be a guess. A probe costs money and needs approval.

### Rejected: hard-code vendors in source
- Makes later swaps a code change. Configuration keeps the change reviewable and small.

## Decision

Per-role configuration with a same-family check. `config/models.yaml` ships with placeholders and no keys.

## Consequences and risks

- Two provider accounts and keys are needed in practice. This is unconfirmed.
- "Family" is a label we assign, so the check is only as honest as the labels. P4 verifies them.

## Verification that the decision holds

- `tests/test_models_config.py` rejects same-family Red Team and Judge.
- P4: measured refusal rates and Judge precision and recall on a labeled set.
