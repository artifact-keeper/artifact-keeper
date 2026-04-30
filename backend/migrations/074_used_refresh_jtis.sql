-- Tracks refresh-token JWT IDs that have already been used to mint a new
-- token pair. Once a refresh token's jti is recorded here, any subsequent
-- attempt to refresh with the same token must be rejected as a replay.
--
-- Rows are reaped periodically by the auth GC task once they pass the
-- refresh-token TTL (jwt_refresh_token_expiry_days), since after that point
-- the token would fail JWT exp validation anyway.

CREATE TABLE used_refresh_jtis (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_used_refresh_jtis_used_at ON used_refresh_jtis (used_at);
CREATE INDEX idx_used_refresh_jtis_user_id ON used_refresh_jtis (user_id);

COMMENT ON TABLE used_refresh_jtis IS
    'Refresh-token JWT IDs that have already been consumed. Used to enforce single-use refresh-token rotation (issue #929).';
COMMENT ON COLUMN used_refresh_jtis.jti IS
    'JWT ID claim from a refresh token that has been redeemed.';
COMMENT ON COLUMN used_refresh_jtis.used_at IS
    'When the refresh token was redeemed. Rows older than the refresh-token TTL are GC-eligible.';
