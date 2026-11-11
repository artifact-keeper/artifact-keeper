-- #5253 Phase 3: administrator-initiated MCP namespace proofs.
--
-- An administrator opens a challenge for a reverse-DNS namespace
-- (`com.acme` <-> `acme.com`), the domain owner publishes the token as a DNS
-- TXT record or an HTTPS well-known file, and an administrator asks AK to
-- verify it. A verified proof is recorded evidence; it grants no write
-- (namespace-conditioned permission rules do).
CREATE TABLE IF NOT EXISTS mcp_namespace_proofs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace        TEXT NOT NULL,
    domain           TEXT NOT NULL,
    method           TEXT NOT NULL CHECK (method IN ('dns', 'http')),
    token            TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'verified', 'failed')),
    last_error       TEXT,
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_checked_at  TIMESTAMPTZ,
    verified_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mcp_namespace_proofs_namespace
    ON mcp_namespace_proofs (namespace);
