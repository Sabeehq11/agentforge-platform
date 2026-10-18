# Model probe

Status: not run against a provider.

ADR-004 defers the real model assignment to a budgeted probe. This file records the offline comparison only.
`evals/judge/probe/candidates.json` holds placeholder family labels and fixture responses (`refused` or
`completed`) with a fixture USD amount of 0. No provider was called. No key was read. `config/models.yaml`
is still `TBD`.

M-12 stays not started until an operator runs an approved, capped probe and replaces these fixtures with
measured refusal rates and cost. The same-family check in `src/agentforge/models_config.py` remains the only
enforcement. A fixture refusal is not a measured refusal rate.
