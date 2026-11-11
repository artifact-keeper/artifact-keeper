-- #5253 (Phase 2/3): MCP server capability snapshots and the introspection
-- job queue.
--
-- A capability snapshot is one observation (or declaration) of what a server
-- version advertises: its tools, resources, prompts and instructions. Every
-- snapshot names where it came from (`source`) and how much it can be trusted
-- (`provenance`, a display label), whether the list was gated by
-- authentication (`auth_state`) and how the attempt ended (`outcome`).
-- History is kept: the newest row per (artifact, source) is the current one,
-- older rows are what the diff endpoint and the `tool_drift` finding compare.
--
-- `content_hash` is the order-independent SHA-256 of the canonical tool,
-- resource and prompt objects plus the instructions; two snapshots with the
-- same hash advertise the same surface.
--
-- The backend only ever STORES these rows. Snapshots observed by talking to a
-- server come from the separate `ak-mcp-introspector` worker, which claims
-- `mcp_introspection_jobs` rows over the HTTP API; nothing in the backend
-- process connects to an MCP server.
--
-- Both tables are new, so their indexes are built while nothing can write to
-- them yet.

CREATE TABLE IF NOT EXISTS mcp_capability_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    server_name TEXT NOT NULL,
    server_version TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN (
        'publisher_declared', 'ci_reported', 'gateway_reported', 'remote_probe', 'sandbox_run'
    )),
    -- Display label, e.g. "declared in server.json", "declared in MCPB
    -- manifest", "reported by CI (alice)", "observed by remote probe".
    provenance TEXT NOT NULL,
    -- Free-form identifier of what produced the snapshot (`generatedBy` of a
    -- report, the bundle file, the remote URL index, the worker id).
    origin TEXT,
    reported_by UUID REFERENCES users(id) ON DELETE SET NULL,
    auth_state TEXT NOT NULL DEFAULT 'none' CHECK (auth_state IN (
        'none', 'auth_required', 'caller_specific', 'unknown'
    )),
    outcome TEXT NOT NULL DEFAULT 'ok' CHECK (outcome IN (
        'ok', 'auth_required', 'rate_limited', 'timeout', 'start_failed', 'needs_config',
        'refused', 'unsupported', 'error'
    )),
    protocol_version TEXT,
    observed_at TIMESTAMPTZ NOT NULL,
    ttl_ms BIGINT,
    cache_scope TEXT,
    tools JSONB NOT NULL DEFAULT '[]'::jsonb,
    resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    prompts JSONB NOT NULL DEFAULT '[]'::jsonb,
    instructions TEXT,
    tools_hash TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    worker_version TEXT,
    -- Source-specific extras: `toolsGenerated` (MCPB), the remote index and
    -- URL, a sandbox behaviour summary, the error of a failed attempt.
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_capability_snapshots_artifact
    ON mcp_capability_snapshots (artifact_id, source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_capability_snapshots_server
    ON mcp_capability_snapshots (repository_id, server_name, created_at DESC);
-- A declaration is recorded once per (artifact, origin, content): re-running
-- the declared-snapshot builder is idempotent.
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_capability_snapshots_declared
    ON mcp_capability_snapshots (artifact_id, COALESCE(origin, ''), content_hash)
    WHERE source = 'publisher_declared';

CREATE TABLE IF NOT EXISTS mcp_introspection_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('remote_probe', 'sandbox_run')),
    -- `remote:<index>` or `package:<index>`: which entry of the server.json.
    target_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'claimed', 'completed', 'failed', 'cancelled'
    )),
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    not_before TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_by TEXT,
    claimed_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    -- SHA-256 of the per-claim token; the worker must present the token to
    -- complete the job, so a lease that expired and was re-claimed cannot be
    -- completed by its first holder.
    claim_token_hash TEXT,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    last_error TEXT,
    snapshot_id UUID REFERENCES mcp_capability_snapshots(id) ON DELETE SET NULL,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- At most one open job per target: enqueueing is idempotent.
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_introspection_jobs_open
    ON mcp_introspection_jobs (artifact_id, kind, target_key)
    WHERE status IN ('pending', 'claimed');
CREATE INDEX IF NOT EXISTS idx_mcp_introspection_jobs_due
    ON mcp_introspection_jobs (kind, not_before)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_mcp_introspection_jobs_artifact
    ON mcp_introspection_jobs (artifact_id, created_at DESC);
