-- #2358 (RPM curation Phase-3): curated snapshot publish.
--
-- Freezes an approved RPM curation set into a monotonic, immutable
-- `repository_version` that is published as signed, AK-generated repodata and
-- served under `/rpm/{key}/@N/`. Reuses the existing curation sync/authz and the
-- already-shipped RPM signing.
--
-- Reversible: the objects below drop cleanly in reverse order —
--   ALTER TABLE repositories DROP COLUMN IF EXISTS active_publication_id;
--   DROP INDEX IF EXISTS idx_repository_version_packages_filename;
--   DROP TABLE IF EXISTS repository_version_packages;
--   DROP TABLE IF EXISTS repository_versions;
--   ALTER TABLE curation_packages DROP COLUMN IF EXISTS primary_metadata;

-- 1. Retain the STRUCTURED, validated upstream primary.xml metadata on each
--    synced package (#2358 A-hardened). Captured as typed JSONB so a publish
--    re-serializes it canonically under AK's escaping and AK-derived
--    `<location>` -- attacker-influenced upstream markup is never signed
--    verbatim. Rows synced before this column existed stay NULL and must be
--    re-synced before a publish can include them (the publish path fails closed
--    on missing metadata).
ALTER TABLE curation_packages ADD COLUMN IF NOT EXISTS primary_metadata JSONB;

-- 2. A frozen, monotonic snapshot of an approved curation set. The publication
--    columns (published_at + storage keys) are folded in here; they stay NULL
--    until the version is published.
CREATE TABLE IF NOT EXISTS repository_versions (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id         UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    version_number        BIGINT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by            UUID REFERENCES users(id) ON DELETE SET NULL,
    package_count         INTEGER NOT NULL DEFAULT 0,
    -- Publication columns (NULL until published). The stored, immutable blobs
    -- served under `/rpm/{key}/@N/` live beneath `storage_prefix`.
    published_at          TIMESTAMPTZ,
    repomd_storage_key    TEXT,
    storage_prefix        TEXT,
    signature_storage_key TEXT,
    -- Monotonic per repository: version N is allocated as MAX(version_number)+1
    -- inside a serializable transaction, and this constraint is the hard backstop
    -- against two concurrent creates colliding on the same number.
    UNIQUE (repository_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_repository_versions_repo
    ON repository_versions (repository_id, version_number);

-- 3. The membership of each snapshot: which curation packages were frozen into
--    a version. CASCADE on the version so deleting a version drops its rows.
--
--    The package IDENTITY is frozen here, not read back from `curation_packages`
--    at serve time. `curation_packages` is a LIVE table: a routine re-sync
--    upserts the same row (ON CONFLICT DO UPDATE), so a post-publish sync — or a
--    compromised upstream — would otherwise change the checksum/location that an
--    already-published, signed `@N` serves, letting `@N` hand out bytes that
--    contradict its own signed `primary.xml`. These columns are snapshotted from
--    the `curation_packages` row AS IT EXISTS AT SNAPSHOT TIME, from the same
--    state the signed metadata is generated from, so the frozen checksum always
--    equals what the signed `primary.xml` attests.
CREATE TABLE IF NOT EXISTS repository_version_packages (
    version_id          UUID NOT NULL REFERENCES repository_versions(id) ON DELETE CASCADE,
    curation_package_id UUID NOT NULL REFERENCES curation_packages(id) ON DELETE CASCADE,
    -- The FROZEN package identity (never re-read from curation_packages).
    frozen_checksum_sha256 TEXT NOT NULL,
    frozen_upstream_path   TEXT NOT NULL,
    -- The canonical AK NEVRA filename this member is served as under `@N`
    -- (matches the `<location href>` the signed primary.xml emits), so the
    -- serve path resolves a member by the exact name it published.
    frozen_filename        TEXT NOT NULL,
    PRIMARY KEY (version_id, curation_package_id)
);

-- Serve-path lookup: resolve a member of version N by its published filename.
CREATE INDEX IF NOT EXISTS idx_repository_version_packages_filename
    ON repository_version_packages (version_id, frozen_filename);

-- 4. The repository's currently-active publication (the version whose metadata
--    the no-`@N` repodata routes serve). NULL keeps today's live-generation
--    behavior unchanged.
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS active_publication_id UUID REFERENCES repository_versions(id);
