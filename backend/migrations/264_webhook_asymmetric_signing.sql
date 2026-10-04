-- Webhooks v2, first slice (#921): asymmetric (Ed25519) webhook signing.
--
-- 1. `webhooks.signing_mode` selects which tokens a webhook's deliveries
--    carry in `X-ArtifactKeeper-Signature`: `hmac` (the existing `v1=`
--    tokens only, and the default, so every existing webhook keeps its exact
--    wire format), `asymmetric` (a `v2=<kid>:<sig>` Ed25519 token only), or
--    `both`.
-- 2. `webhook_signing_keys` holds the instance-wide Ed25519 key. The private
--    half is AES-256-GCM encrypted with AK_WEBHOOK_SECRET_KEY, exactly like
--    `webhooks.secret_encrypted`; the public half is plain so the JWKS
--    endpoint never decrypts. `kid` is the RFC 7638 thumbprint. At most one
--    key is active (`retired_at IS NULL`); `retired_at` in the future is the
--    rotation-overlap window a follow-up will use, and such keys stay in the
--    published JWKS until it passes.
--
-- Online shape: `webhooks` is configuration-sized (not in migration_safety's
-- HOT_TABLES). ADD COLUMN with a constant default is catalogue-only (PG 11+);
-- the CHECK is added NOT VALID (catalogue-only) and validated separately
-- under SHARE UPDATE EXCLUSIVE. The lock timeout makes a rolling upgrade
-- fail fast, leaving nothing applied, instead of queueing behind an old
-- replica's open transaction on `webhooks`; it is re-run on the next start.

SET LOCAL lock_timeout = '5s';

ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS signing_mode TEXT NOT NULL DEFAULT 'hmac';

ALTER TABLE webhooks DROP CONSTRAINT IF EXISTS webhooks_signing_mode_check;
ALTER TABLE webhooks ADD CONSTRAINT webhooks_signing_mode_check
    CHECK (signing_mode IN ('hmac', 'asymmetric', 'both'))
    NOT VALID;
ALTER TABLE webhooks VALIDATE CONSTRAINT webhooks_signing_mode_check;

CREATE TABLE IF NOT EXISTS webhook_signing_keys (
    kid                   TEXT        PRIMARY KEY,
    algorithm             TEXT        NOT NULL DEFAULT 'EdDSA'
        CHECK (algorithm = 'EdDSA'),
    public_key            BYTEA       NOT NULL
        CHECK (octet_length(public_key) = 32),
    private_key_encrypted BYTEA       NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at            TIMESTAMPTZ
);

-- One active key: concurrent first-use creators converge on one row
-- (the loser's INSERT ... ON CONFLICT DO NOTHING is a no-op).
CREATE UNIQUE INDEX IF NOT EXISTS webhook_signing_keys_one_active
    ON webhook_signing_keys ((TRUE))
    WHERE retired_at IS NULL;
