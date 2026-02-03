-- SSO exchange codes: short-lived, single-use codes for the authorization code
-- exchange pattern. Instead of passing raw JWT tokens in URL query parameters,
-- the backend redirects with an opaque code that the frontend POSTs to exchange
-- for tokens over a secure channel.

CREATE TABLE IF NOT EXISTS sso_exchange_codes (
    code VARCHAR(64) PRIMARY KEY,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '60 seconds'
);

CREATE INDEX IF NOT EXISTS idx_sso_exchange_codes_expires ON sso_exchange_codes(expires_at);
