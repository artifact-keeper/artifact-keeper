-- #5153: existing acknowledged rows become decisions. Separate from the schema
-- migration so that nothing is locked across this scan of `scan_findings`.
--
-- An existing acknowledged row becomes a decision only when that cannot hide a
-- finding an operator sees as open today. For one (repository, bytes, identity),
-- every row in the artifacts' current scans must be acknowledged:
--
-- * acknowledged only in an older scan, reported open by the current one: the
--   rescan bug reopened it and the operator may have seen that, or may have
--   revoked the newer row, which leaves no trace on the older one. Not migrated.
-- * one engine's row acknowledged, another's open: the decision would now cover
--   both. Not migrated.
-- * acknowledged in a scan the artifact no longer reports it in: there is
--   nothing current to decide about. Not migrated.
--
-- Those stay open, or absent, exactly as they are before the upgrade, and an
-- administrator acknowledges them again. The flags stay on the rows for that.
-- The migrated decision is repository-scoped with no expiry, and keeps the actor,
-- reason and time of the most recent acknowledgement.
--
-- BEGIN backfill
WITH candidates AS (
    SELECT DISTINCT same.id AS artifact_id, same.repository_id, same.checksum_sha256
    FROM (SELECT DISTINCT artifact_id FROM scan_findings WHERE is_acknowledged) acked
    JOIN artifacts a ON a.id = acked.artifact_id AND NOT a.is_deleted
    JOIN artifacts same
      ON same.repository_id = a.repository_id
     AND same.checksum_sha256 = a.checksum_sha256
     AND NOT same.is_deleted
),
current_rows AS (
    SELECT
        c.repository_id,
        c.checksum_sha256,
        sf.finding_class,
        finding_advisory_key(sf.cve_id, sf.title) AS advisory_key,
        finding_component_key(sf.affected_component) AS component_key,
        finding_component_key(sf.affected_version) AS component_version_key,
        finding_severity_rank(sf.severity) AS severity_rank,
        sf.is_acknowledged,
        sf.acknowledged_by,
        sf.acknowledged_reason,
        sf.acknowledged_at
    FROM candidates c
    CROSS JOIN LATERAL artifact_current_scan_ids(c.artifact_id) cs
    JOIN scan_findings sf
      ON sf.scan_result_id = cs.scan_result_id
     AND sf.artifact_id = c.artifact_id
),
decided AS (
    SELECT
        repository_id,
        checksum_sha256,
        finding_class,
        advisory_key,
        component_key,
        component_version_key,
        MAX(severity_rank) AS max_severity_rank,
        (ARRAY_AGG(acknowledged_reason ORDER BY acknowledged_at DESC NULLS LAST))[1] AS reason,
        (ARRAY_AGG(acknowledged_by ORDER BY acknowledged_at DESC NULLS LAST))[1] AS acknowledged_by,
        MAX(acknowledged_at) AS acknowledged_at
    FROM current_rows
    GROUP BY repository_id, checksum_sha256, finding_class, advisory_key,
             component_key, component_version_key
    HAVING BOOL_AND(is_acknowledged)
),
inserted AS (
    SELECT gen_random_uuid() AS id, d.*
    FROM decided d
)
INSERT INTO finding_acknowledgements (
    id, lineage_id, repository_id, checksum_sha256, finding_class, advisory_key,
    component_key, component_version_key, max_severity_rank, reason,
    acknowledged_by, acknowledged_at, created_via
)
SELECT
    id, id, repository_id, checksum_sha256, finding_class, advisory_key,
    component_key, component_version_key, max_severity_rank, reason,
    acknowledged_by, COALESCE(acknowledged_at, NOW()), 'migration'
FROM inserted
ON CONFLICT (
    COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid),
    checksum_sha256,
    finding_class,
    md5(advisory_key),
    md5(component_key),
    md5(component_version_key)
) WHERE revoked_at IS NULL
DO NOTHING;
-- END backfill

