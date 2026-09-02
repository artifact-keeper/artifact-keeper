-- OCI 1.1 Referrers API subject tracking (artifact-keeper#3108).
--
-- The distribution-spec 1.1 Referrers API
-- (`GET /v2/<name>/referrers/<digest>`) lists every manifest in the
-- repository whose `subject` descriptor points at `<digest>`. Nothing
-- recorded the subject edge at push time, so the endpoint could not be
-- implemented without re-parsing every stored manifest per request.
--
-- One row per (repository, referrer manifest). A manifest has at most one
-- `subject`, so the pair is the natural primary key. The referrers read
-- path needs everything required to build the response descriptor without
-- touching storage: the referrer's own mediaType, its byte size, its
-- artifactType (the manifest's `artifactType`, falling back to
-- `config.mediaType` per spec), and its annotations.
--
-- Rows are written inside `persist_tag_and_refs_in_tx` (the same
-- transaction as the `oci_tags` upsert), so a referrer row can never exist
-- for a manifest whose push failed, and vice versa. Rows are removed by
-- the manifest-DELETE handler once the digest's last tag entry is gone.
-- ON DELETE CASCADE keeps repository deletion clean.

CREATE TABLE oci_manifest_subjects (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    manifest_digest TEXT NOT NULL,
    subject_digest TEXT NOT NULL,
    media_type TEXT NOT NULL,
    artifact_type TEXT,
    size_bytes BIGINT NOT NULL,
    annotations JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, manifest_digest)
);

-- The referrers endpoint's hot path: "all referrers of <subject> in <repo>".
CREATE INDEX idx_oci_manifest_subjects_subject
    ON oci_manifest_subjects(repository_id, subject_digest);
