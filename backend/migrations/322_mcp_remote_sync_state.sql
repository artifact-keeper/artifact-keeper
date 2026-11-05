-- Remote MCP registries (#5253): per-repository upstream sync state.
--
-- A Remote `mcp` repository pages its upstream registry's
-- `GET /v0.1/servers?updated_since=...` listing. `updated_since` is the
-- watermark of the last completed pass (the newest upstream `updatedAt` it
-- saw, upstream's clock, never this instance's). A pass that stops early
-- (page budget, upstream error) records where to resume: the cursor and the
-- `updated_since` it was running with, so the next run continues the same
-- pass instead of skipping the rest of it.
CREATE TABLE IF NOT EXISTS mcp_remote_sync_state (
    repository_id     UUID PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    updated_since     TIMESTAMPTZ,
    resume_cursor     TEXT,
    resume_since      TIMESTAMPTZ,
    last_started_at   TIMESTAMPTZ,
    last_finished_at  TIMESTAMPTZ,
    last_succeeded_at TIMESTAMPTZ,
    last_error        TEXT,
    last_summary      JSONB NOT NULL DEFAULT '{}'
);

-- The approval queue of a Remote MCP registry reads its curation rows by
-- status within one repository and format.
CREATE INDEX IF NOT EXISTS idx_curation_pkg_mcp_queue
    ON curation_packages (staging_repo_id, status, package_name)
    WHERE format = 'mcp';
