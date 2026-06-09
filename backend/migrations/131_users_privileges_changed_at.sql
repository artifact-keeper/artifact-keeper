-- Track when a user's privileges last changed (#1821).
--
-- Admin demotion (is_admin true -> false) and SSO role-set re-sync are
-- security-relevant: a stale JWT bakes `is_admin` into its claims at mint
-- time, so without a token-invalidating signal a demoted admin keeps admin
-- authority until the access token expires (default 30 min).
--
-- `updated_at` is deliberately excluded from the credential-change watermark
-- (#1190: benign profile edits must not log users out). This dedicated column
-- gives privilege changes their own watermark that IS folded into
-- `fetch_credential_change_watermark`'s GREATEST(...), so demotions are
-- honoured immediately across replicas while profile edits stay non-invalidating.
--
-- Defaults to `created_at`-equivalent NOW() so existing tokens minted before
-- this migration are not retroactively invalidated.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS privileges_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
