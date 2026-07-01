-- Composite expression index on artifact_metadata for Maven GAV lookups.
--
-- Maven `maven-metadata.xml` generation runs
--   ... WHERE am.format = 'maven'
--         AND am.metadata->>'groupId'  = $2
--         AND am.metadata->>'artifactId' = $3
-- which currently degrades to a sequential scan over artifact_metadata rows.
-- The existing idx_artifact_metadata_gin uses the default jsonb_ops opclass,
-- which serves @> containment but does NOT serve ->> text-extraction equality.
--
-- A partial composite expression index keyed on the extracted text values
-- makes cold-start queries O(log n) and removes the seq-scan bottleneck that
-- caused Maven builds to take ~4x longer than against Sonatype Nexus
-- (artifact-keeper #2079).
--
-- CREATE INDEX (non-CONCURRENTLY) is intentional: sqlx::migrate wraps each
-- migration file in a transaction and CONCURRENTLY is rejected inside a txn
-- block. The non-concurrent build takes ACCESS EXCLUSIVE on artifact_metadata
-- for the duration of the build, so writes will block until it finishes.
-- Operators with a large artifact_metadata table who cannot accept the lock
-- window can apply the equivalent CONCURRENTLY out of band before running
-- migrations (IF NOT EXISTS then makes this file a clean no-op):
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifact_metadata_maven_gav
--     ON artifact_metadata ((metadata->>'groupId'), (metadata->>'artifactId'))
--     WHERE format = 'maven';
CREATE INDEX IF NOT EXISTS idx_artifact_metadata_maven_gav
    ON artifact_metadata ((metadata->>'groupId'), (metadata->>'artifactId'))
    WHERE format = 'maven';
