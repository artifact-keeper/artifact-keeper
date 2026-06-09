-- #1820: Single-use TOTP pending token.
--
-- The short-lived (`5 min`) `totp_pending` JWT issued by `/auth/login` when a
-- user has 2FA enabled was previously stateless and therefore replayable: an
-- attacker holding the user's password could brute-force the 6-digit second
-- factor (or a backup code) against the SAME pending token hundreds of times
-- with no throttling and no consumption.
--
-- Each pending token now carries a `jti`. The first `/auth/totp/verify` call
-- that presents a given `jti` claims it here (INSERT ... ON CONFLICT DO
-- NOTHING). A duplicate `jti` means the token was already used and the verify
-- is rejected, so one login yields exactly one verification attempt window.
-- This also serializes the backup-code TOCTOU race (#1822) at the token layer.
--
-- Rows are cleaned up by the scheduler janitor once `expires_at` is past.

CREATE TABLE IF NOT EXISTS totp_pending_jti (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Cleanup janitor scans by expires_at.
CREATE INDEX IF NOT EXISTS totp_pending_jti_expires_at_idx
    ON totp_pending_jti (expires_at);
