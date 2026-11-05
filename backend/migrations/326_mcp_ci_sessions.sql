-- #5253 Phase 3: the CI OIDC claims behind a CI-exchanged access token, so
-- an MCP namespace grant can interpolate them (`io.github.{repository_owner}/*`).
-- Keyed by the sha256 of the minted token; rows expire with the token and are
-- pruned on the next exchange. Only bounded, string-valued top-level claims
-- are kept (never the assertion itself).
CREATE TABLE IF NOT EXISTS mcp_ci_sessions (
    token_sha256  TEXT PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    claims        JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mcp_ci_sessions_expires_at
    ON mcp_ci_sessions (expires_at);
