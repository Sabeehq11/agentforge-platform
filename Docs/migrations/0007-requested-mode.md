# 0007 Requested mode

- Date: 2026-10-21
- Schema: platform store. Additive nullable column `campaigns.requested_mode`.
- Version change: store 0006 to 0007. Contracts stay v1.
- Breaking: no. `request_json`, `coverage_metrics`, `signals`, `attack_variants` and `mutation_claims` are not altered.
- What existing rows become: `requested_mode` is NULL. An existing campaign keeps its one-turn novel default.
- How to reverse: rebuild `campaigns` without `requested_mode`. Do not drop earlier tables.

`requested_mode` is not a campaign-request field. The published v1 schema is unchanged. The value `multi_turn` is stored when a dry-run operator asks for multi-turn attacks, and it is read again on resume so a resumed campaign does not fall back to one turn. A Judge partial that is eligible for mutation still takes priority over it. NULL keeps the novel one-turn default.
