# ADR-007: Target URL: quick tunnel with reviewed manual edits

- Status: accepted (provisional until Q2 is answered)
- Date: 2026-10-17
- Related questions: Q2, Q3

## Context

The target is exposed through a Cloudflare quick tunnel whose hostname changes on every start. The PRD requires a
publicly accessible deployed target with every checkpoint. The platform allowlist is default deny and version
controlled, so each new hostname is a deliberate edit.

## Options considered

### Chosen: keep the quick tunnel, edit `config/allowlist.yaml` by reviewed change for each new URL
- No new hosting (D-005). Keeps the allowlist a deliberate control. Provisional until staff say whether a rotating URL
  counts as deployed.

### Rejected: a named tunnel with a stable hostname
- Probably the best fix for stability and needs no new hosting, but it changes the target's deployment and needs
  the target owner to set it up. Revisit when Q2 is answered.

### Rejected: the untested VPS path in the target's `deploy/`
- New infrastructure and an untested path, against D-005.

### Rejected: wildcard or pattern allowlist entries for `*.trycloudflare.com`
- Would let the platform attack any quick tunnel, which breaks the target-allowlist control.

## Decision

Quick tunnel with manual reviewed allowlist edits. In P0 `config/allowlist.yaml` has no hosts, and the recorded URL
is unconfirmed.

## Consequences and risks

- Every restart of the tunnel needs an allowlist edit, and the submitted URL may be stale at review time.
- The URL in `deploy/tunnel/url.txt` of the target repo may be stale. It is not used in P0.

## Verification that the decision holds

- P3: reachability checked through the chokepoint after the allowlist entry is reviewed. UNVERIFIED in P0.
