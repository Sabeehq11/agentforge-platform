# Model probe

Status: measured on 2026-10-19 for `red_team` and `judge` only. `orchestrator` and `documentation` stay `TBD`.

## Measured run (2026-10-19, after the key limit was raised)

`scripts/probe_models.py` ran once under `PROVIDER_ENABLED=True` (restored to `False` straight after), the
`openrouter` operator approval, and the shared ledger. One capped call per candidate, `$0.01` reserved each.

| Role | Model | Family | Outcome | Provider-reported USD |
|---|---|---|---|---|
| judge | `anthropic/claude-sonnet-4.5` | anthropic | completed (valid single-label reply) | `$0.000291` |
| red_team | `openai/gpt-4.1-mini` | openai | refused | `$0.0000228` |

- Rules Judge precision and recall on the labeled set were 1.0 and 1.0, scored by the fixture `RulesJudge` with
  `fixture_only=True`, so that scoring made no provider call. `provider_precision` in the probe report is `null` by design.
- `config/models.yaml` now sets `red_team` and `judge` from these rows. `evals/judge/probe/candidates.json` holds the
  measured outcome and USD. Neither value is a fixture.
- One call per family is a single sample. It is not a refusal rate.

### Why the first two attempts after the limit raise failed

1. **Diagnosis, not a provider rejection.** The first post-raise call returned HTTP 200 with `usage.cost`
   `$0.000975`. The reply was a 262-character explanation, not one label, and the client raised the generic
   `unusable response`. That one call was billed and recorded as `diag-judge-112a52e0c6ee`.
2. **Fixes applied before the measured run:** an explicit single-word system instruction and `max_tokens` 16 on every
   Judge request, a `refused`/`completed` label set for the red-team probe, provider cost recorded when a 200 reply
   has an invalid label, and distinct failure classes (`OpenRouterHttpError`, `OpenRouterResponseError`,
   `OpenRouterLabelError`). A probe row now names its failure as `http_<status>`, `invalid_label` or `invalid_response`.
3. Two further runs stopped locally before the measured one: `ProbeError` because no `RulesJudge` was supplied, then
   `judge model is not configured` because `RulesJudge` read the `TBD` models file. The second one billed
   `$0.000291`. The measured run is the third.

Earlier stopped reports are kept as `evals/results/probe-report.stopped-20261019T222023Z.json` and
`evals/results/judge-drift.stopped-20261019T190700Z.json`.

## Earlier attempt (2026-10-19, before the limit raise)

Stopped by a provider-side refusal. Not measured. Kept as history.

## Attempted run (2026-10-19)

- `PROVIDER_ENABLED` was set `True` only for this command and restored to `False` immediately after, on both
  the success and the failure path.
- The run was authorized by the local operator-approval scope `openrouter` in
  `config/operator_approval.yaml` (`max_usd: 5.0`), not by a fabricated dashboard attestation.
- `scripts/probe_models.py` reserved `$0.01` against the shared ledger for the first candidate (`judge`,
  `anthropic/claude-sonnet-4.5`), then called the real OpenRouter endpoint.
- The call failed with a provider refusal, confirmed by a direct diagnostic request (status `403`): the
  shared OpenRouter key has already exceeded its own total spend limit (`$250.20` of `$250.00` used,
  "does not reset", per the provider's own error body). This is a hard, external, key-owner-side limit. It is
  not a local budget, allowlist, or approval failure, and this operator cannot raise it.
- The ledger reservation was released, not incurred: `evals/results/probe-report.json` records
  `"status": "stopped"`, `"calls": 1`, and the error class. `evals/results/judge-drift.json` records the same
  outcome for the provider Judge attempt. No model call was billed.
- `red_team` (`openai/gpt-4.1-mini`) was never attempted, because the loop stops at the first failure.

M-12 and M-4 stay not met. This is the exact "missing OpenRouter key or a provider refusal" case the P4 plan
calls out: it stops M-12 and M-4 only, and does not undo the graded `seed-tm-pi-1` result or the stored agent
finding. Re-running this probe cannot succeed until the key owner raises or replaces the OpenRouter key's
total usage limit. The same-family check in `src/agentforge/models_config.py` remains the only enforcement
in the meantime. A fixture refusal is not a measured refusal rate.
