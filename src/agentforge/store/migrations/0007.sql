-- R2 requested mode. Additive. No v1 contract change.
-- NULL means the campaign did not ask for a mode, so attacks stay one turn. 'multi_turn' is the request that
-- keeps a campaign on multi-turn attacks, including after a resume.

ALTER TABLE campaigns ADD COLUMN requested_mode TEXT CHECK (requested_mode IS NULL OR requested_mode = 'multi_turn');
