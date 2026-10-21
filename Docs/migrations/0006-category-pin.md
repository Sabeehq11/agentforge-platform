# 0006 Category pin and mutation claims

- Date: 2026-10-21
- Schema: platform store. Additive column `campaigns.category_pinned`. New table `mutation_claims`.
- Version change: store 0005 to 0006. Contracts stay v1.
- Breaking: no. `request_json`, `coverage_metrics`, `signals` and `attack_variants` are not altered.
- What existing rows become: `category_pinned` is 1. An existing campaign stays an explicit category. `mutation_claims` starts empty.
- How to reverse: drop `mutation_claims`, then rebuild `campaigns` without `category_pinned`. Do not drop earlier tables.

`category_pinned` is not a campaign-request field. The published v1 schema still requires `category` to be one of the six enums. A 0 means the stored category is a placeholder and the first attack comes from rank. A 1 means the stored category is the first attack. Resume does not clear the flag.

`mutation_claims` records one loop-accepted mutation per parent signal. The row is written in the same transaction as that mutation's `attack_variants` row. A later judge rejection does not delete it. Variant mode does not write a claim. A direct `persist` call does not claim, so the existing child cap still allows more than one stored child.
