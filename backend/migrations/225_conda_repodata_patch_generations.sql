-- Issue #4051: record which upstream repodata patch generation was in effect
-- when a Remote conda repo served an index.
--
-- Upstream conda channels rewrite dependency metadata of ALREADY-published
-- packages via repodata patching: the artifact hash never changes, but
-- resolution behavior does. Two solves months apart against the same channel
-- and the same package hashes can produce different environments with no
-- recorded difference to point at. We do not run a patching pipeline of our
-- own (we are not a patch authority); we only RECORD what was in effect when
-- we served an index so a change is visible as a change, not silent.
--
-- One row per distinct patch generation observed per repository/subdir. The
-- generation is content-addressed: the BLAKE2b-256 hex digest of the upstream
-- `{subdir}/patch_instructions.json` bytes as fetched through the proxy at
-- serve time. Content-addressing works across upstreams that do not version
-- their patch documents and makes "same content -> same generation" and
-- "changed content -> new generation" hold by construction.
--
-- Rows are insert-only (INSERT ... ON CONFLICT DO NOTHING): a repeat
-- observation of an already-recorded generation writes nothing, so the hot
-- repodata serve path does not turn into a per-request UPDATE. A generation
-- CHANGE shows up as a new row with a later first_seen_at, which is the audit
-- signal the issue asks for.
--
-- Hosted (local) and virtual repos never write here: there is no upstream
-- patch authority behind them, so there is nothing to attribute.
CREATE TABLE IF NOT EXISTS conda_repodata_patch_generations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    subdir TEXT NOT NULL,
    -- BLAKE2b-256 hex of the upstream patch_instructions.json bytes.
    generation TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT conda_repodata_patch_generations_unique
        UNIQUE (repository_id, subdir, generation)
);

-- Read path: "which generations were in effect for this channel/subdir, and
-- when did each first appear" — ordered newest-first for audit display.
CREATE INDEX IF NOT EXISTS conda_repodata_patch_generations_repo_subdir_idx
    ON conda_repodata_patch_generations (repository_id, subdir, first_seen_at DESC);
