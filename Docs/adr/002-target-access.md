# ADR-002: Target access: public OpenEMR module as a synthetic identity

- Status: accepted
- Date: 2026-10-17
- Related questions: A-004 (synthetic identity), Q2

## Context

Read-only inspection of the target at the pinned SHA shows:

- `scripts/copilot/deploy_w2.sh` publishes the agent on `127.0.0.1:8400` only and fails if `/health` answers
  through the tunnel. The agent is private by design.
- `interface/modules/custom_modules/oe-module-copilot/public/chat.php` takes authority only from the PHP session
  (logged-in user, open patient) plus a CSRF token, then signs and forwards the request to the agent.
- Direct signed agent calls need `MODULE_SIGNING_SECRET` and a user OAuth token (`agent/app/signing.py`).
- `scripts/copilot/authz_fixture.php` seeds the synthetic users `copilot_doc_a`, `copilot_doc_b`, `copilot_nurse`,
  `copilot_front`. The password comes from the `COPILOT_FIXTURE_PASSWORD` env var at seed time.

## Options considered

### Chosen: attack through the public OpenEMR module, logged in as a synthetic fixture user
- It is the path a real external attacker or user has. It needs no target secret, and the target's own signing,
  authorization and verifier layers stay in scope for testing.

### Rejected: signed direct calls to the agent (`/v1/chat`, `/v1/w2/*`)
- Needs the shared signing secret and an OAuth token, which a black-box platform should not hold. Only works
  locally. Would bypass the OpenEMR session and CSRF layer and so test a different surface than users reach.

### Rejected: reaching the agent through the tunnel
- The agent is deliberately private and the deploy script fails if it becomes reachable. Opening it would weaken
  the target.

## Decision

The platform attacks through the public OpenEMR module with a synthetic test identity whose password lives only in a
git-ignored `.env`. P0 builds no login code and makes no request. Which fixture user and whether it exists on the
deployed stack are unconfirmed (A-004).

## Consequences and risks

- Needs a live OpenEMR login flow, CSRF handling and patient selection (P3).
- Scope limit: this tests the module plus agent path, not the agent API in isolation.
- Reachability and the identity's existence are UNVERIFIED until P3.

## Verification that the decision holds

- P3: allowlist entry, a read-only reachability check and a login as the synthetic user, all through the chokepoint.
