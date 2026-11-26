-- #6526: the conda age gate's sighting ledger for Remote channels.
--
-- A gated remote ages each record from when this server first saw that exact
-- file: the (filename, sha256) pair, so an upstream that swaps the bytes
-- under a published filename makes a new sighting. Rows are insert-once:
-- replicas and concurrent rebuilds race benignly, because whoever inserts
-- first fixes the time, and `first_seen_at` is always the database clock.
--
-- One channel is one (remote, subdir). `baseline_at` is set once, after one
-- complete snapshot of that subdir has been recorded (both `packages` and
-- `packages.conda`, every record), under an advisory lock on the channel.
-- Records of that snapshot (`in_baseline`) are as old as the channel's
-- history allows; later sightings are aged from the sighting. Until the
-- baseline exists the gate refuses to serve the subdir (fail closed), and a
-- restarted build completes it. Repointing the remote or toggling the gate
-- never resets the baseline: re-baselining is an explicit, audited
-- administrator action (`POST .../age-gate/conda/rebaseline`).
-- `upstream_fingerprint` names the upstream the ledger was last read from,
-- so a repoint is detected and logged.
--
-- `prev_fetch_at` is the subdir's previous successful upstream read when the
-- row was inserted: a file first seen now was not there then, so it cannot be
-- older than that read.
--
-- Sized for conda-forge (a few hundred thousand files per subdir): a rebuild
-- writes only files it has not seen before and reads back only sightings
-- inside the gate window (`conda_record_first_seen_recent`, which skips the
-- baseline), so steady-state work is proportional to what changed.
--
-- Expand-only: new tables and their indexes, built empty. The previous
-- release neither reads nor writes them (docs/operations/online-migrations.md).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS conda_first_seen_channels (
    id BIGSERIAL PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    subdir TEXT NOT NULL,
    upstream_fingerprint TEXT NOT NULL,
    -- When the first complete snapshot was recorded; NULL while it is built.
    baseline_at TIMESTAMPTZ,
    -- The last successful upstream read of the subdir.
    last_fetch_at TIMESTAMPTZ,
    -- Bumped whenever ledger rows are deleted (a repoint prune), so every
    -- replica reloads its in-memory set of recorded files.
    ledger_generation BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repository_id, subdir)
);

CREATE TABLE IF NOT EXISTS conda_record_first_seen (
    channel_id BIGINT NOT NULL REFERENCES conda_first_seen_channels(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    -- The record's sha256 as the upstream index lists it ('' when it lists none).
    sha256 TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prev_fetch_at TIMESTAMPTZ,
    in_baseline BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (channel_id, filename, sha256)
);

-- The gate window read: a channel's post-baseline sightings after a cutoff.
-- Partial, so the read never walks the (large) baseline.
CREATE INDEX IF NOT EXISTS conda_record_first_seen_recent
    ON conda_record_first_seen (channel_id, first_seen_at) WHERE NOT in_baseline;

-- The revive rule (#6528): a revived row keeps the time this server first
-- saw the same bytes anywhere.
CREATE INDEX IF NOT EXISTS conda_record_first_seen_sha256
    ON conda_record_first_seen (sha256) WHERE sha256 <> '';
