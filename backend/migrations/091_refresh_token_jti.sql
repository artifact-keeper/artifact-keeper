-- #1174: Refresh-token reuse/replay detection per RFC 6819 / RFC 9700.
--
-- Each refresh JWT issued by the auth service is recorded here by its `jti`
-- along with a `family_id` shared across the rotation chain. On every
-- `/api/auth/refresh` call (and OCI refresh-grant flow), the auth service:
--
--   1. Looks up the row for the presented `jti`.
--   2. If `consumed_at IS NOT NULL`, the same refresh JWT has already been
--      used once. This is the replay-detection trigger: reject the request
--      AND revoke every other token in the same `family_id` so that whichever
--      side of the race the attacker is on, they lose their next refresh.
--   3. Otherwise mark this row consumed and mint a new refresh JWT with the
--      same `family_id` (rotation) and a fresh `jti`.
--   4. Administrative revocation sets `revoked_at` for every row in the
--      target family.
--
-- The cleanup janitor in scheduler_service.rs drops rows whose underlying
-- JWT has been expired for longer than the grace period.

CREATE TABLE IF NOT EXISTS refresh_token_jti (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

-- Family-revocation lookups (`WHERE family_id = $1`) and per-user audit
-- queries both ride this composite. user_id leads so the index also serves
-- single-user revocation sweeps (e.g. on password change).
CREATE INDEX IF NOT EXISTS refresh_token_jti_user_family_idx
    ON refresh_token_jti (user_id, family_id);

-- Cleanup janitor scans by expires_at.
CREATE INDEX IF NOT EXISTS refresh_token_jti_expires_at_idx
    ON refresh_token_jti (expires_at);
