-- Account disable flag. Idempotent.
-- An operator (or an automated abuse response) needs a reversible kill
-- switch that is stronger than revoking sessions: revocation only stops
-- the tokens that exist right now, while `disabled` also refuses every
-- future login — password, magic link, and OAuth alike — and turns live
-- sessions into expired ones on next validation.
-- Deliberately NOT a soft delete: the row, its identities, and its audit
-- trail stay intact so the account can be re-enabled and so forensics
-- keep working.

ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT false;
