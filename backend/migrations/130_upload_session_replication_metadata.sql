-- Preserve format-specific metadata across peer replication upload sessions.
--
-- Debian/APT repositories need artifact_metadata for Packages/Release index
-- generation and package catalog metadata for the UI/API package rows. Peer
-- replication uses the generic resumable upload API, so store the source
-- metadata on the session and materialize it when the receiver finalizes.

ALTER TABLE upload_sessions
    ADD COLUMN IF NOT EXISTS artifact_metadata_format TEXT,
    ADD COLUMN IF NOT EXISTS artifact_metadata JSONB,
    ADD COLUMN IF NOT EXISTS artifact_metadata_properties JSONB,
    ADD COLUMN IF NOT EXISTS package_description TEXT,
    ADD COLUMN IF NOT EXISTS package_metadata JSONB;
