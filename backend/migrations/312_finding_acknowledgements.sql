-- #5153: an acknowledgement is a decision about an advisory in a component of
-- specific bytes, and it outlives any one finding row.
--
-- Until now it was three columns on `scan_findings`, so every path that writes
-- rows for an artifact (a rescan, a dedup copy, a reused placeholder) wrote
-- them unacknowledged, and a promoted copy had no rows at all. The columns are
-- replaced by `finding_acknowledgements`, applied at read time through the
-- `scan_findings_effective` view. Every reader of acknowledged state selects
-- from that view, so a new row, whichever path wrote it, is judged the same
-- way as an old one and an expiry needs no sweep to take effect.
--
-- `scan_findings.is_acknowledged`, `acknowledged_by`, `acknowledged_reason` and
-- `acknowledged_at` are frozen, not dropped: a 1.11 replica still reads them
-- during a rolling upgrade, and a rollback finds the state it left behind.
-- Nothing in this version reads or writes them. Removing them is a follow-up.

-- ---------------------------------------------------------------------------
-- The identity of a finding, in one place
-- ---------------------------------------------------------------------------

-- The same ordering as `open_findings::SEVERITY_RANK_SQL`.
CREATE OR REPLACE FUNCTION finding_severity_rank(severity TEXT)
RETURNS INTEGER
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT CASE LOWER(severity)
        WHEN 'critical' THEN 4
        WHEN 'high' THEN 3
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 1
        ELSE 0
    END
$$;

-- The same key as `open_findings::ADVISORY_KEY_SQL`: the CVE id,
-- case-insensitively, or the title when a scanner reported no id.
CREATE OR REPLACE FUNCTION finding_advisory_key(cve_id TEXT, title TEXT)
RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT COALESCE(NULLIF(UPPER(BTRIM(cve_id)), ''), title)
$$;

-- A component or version as it takes part in the identity. Deliberately exact
-- apart from surrounding whitespace: a scanner that renames a component yields
-- a new identity, which fails closed (the finding is open and is decided again).
CREATE OR REPLACE FUNCTION finding_component_key(value TEXT)
RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT COALESCE(BTRIM(value), '')
$$;

-- ---------------------------------------------------------------------------
-- The decisions
-- ---------------------------------------------------------------------------

CREATE TABLE finding_acknowledgements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Shared by a decision, the copies promotion made of it and the decisions
    -- that superseded it. A revoke applies to the whole lineage.
    lineage_id UUID NOT NULL,
    -- The repository the decision applies in. NULL means every repository, and
    -- only an explicit `all_repositories` request writes it.
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    -- The bytes the operator looked at. Not an artifact id, which a re-upload
    -- changes, and not a coordinate, which different bytes can reuse.
    checksum_sha256 CHAR(64) NOT NULL,
    finding_class TEXT NOT NULL,
    advisory_key TEXT NOT NULL,
    component_key TEXT NOT NULL,
    component_version_key TEXT NOT NULL,
    -- The highest severity the operator accepted, as `finding_severity_rank`.
    -- A re-grade above it is new information, so the finding reopens.
    max_severity_rank SMALLINT NOT NULL,
    reason TEXT,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL: until revoked. Applied at read time.
    expires_at TIMESTAMPTZ,
    -- When the sweep recorded the lapse in the audit log and refreshed the
    -- stored scores. Not an input to any gate.
    expiry_recorded_at TIMESTAMPTZ,
    created_via TEXT NOT NULL
        CHECK (created_via IN ('api', 'promotion', 'migration')),
    -- For `created_via = 'promotion'`: who promoted the artifact. The decision
    -- itself remains that of `acknowledged_by`.
    carried_by UUID REFERENCES users(id) ON DELETE SET NULL,
    -- A revoked row stays as the record of the decision.
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_reason TEXT
        CHECK (revoked_reason IS NULL OR revoked_reason IN ('revoked', 'superseded')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- At most one live decision per identity and scope. The md5s keep the key under
-- the btree row limit: a title-keyed advisory can be long.
CREATE UNIQUE INDEX uq_finding_acknowledgements_live
    ON finding_acknowledgements (
        COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid),
        checksum_sha256,
        finding_class,
        md5(advisory_key),
        md5(component_key),
        md5(component_version_key)
    )
    WHERE revoked_at IS NULL;

-- The read path, for a query about one artifact.
CREATE INDEX idx_finding_acknowledgements_digest
    ON finding_acknowledgements (checksum_sha256)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_finding_acknowledgements_lineage
    ON finding_acknowledgements (lineage_id)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_finding_acknowledgements_unrecorded_expiry
    ON finding_acknowledgements (expires_at)
    WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expiry_recorded_at IS NULL;

-- ---------------------------------------------------------------------------
-- The read side
-- ---------------------------------------------------------------------------

-- `scan_findings` with acknowledged state derived from the live decisions. The
-- legacy columns are deliberately not projected, so this view keeps working
-- when they are dropped.
--
-- The decisions are resolved to artifacts in a subquery rather than per finding
-- row, so the planner can hash join them: a dashboard over every finding pays
-- for the (few) decisions once, and a query for one artifact has its artifact id
-- pushed into the subquery.
--
-- Where a repository decision and an every-repository decision both apply, the
-- narrower one is the decision that speaks, its severity ceiling included.
CREATE VIEW scan_findings_effective AS
SELECT
    sf.id,
    sf.scan_result_id,
    sf.artifact_id,
    sf.severity,
    sf.title,
    sf.description,
    sf.cve_id,
    sf.affected_component,
    sf.affected_version,
    sf.fixed_version,
    sf.source,
    sf.source_url,
    sf.created_at,
    sf.finding_class,
    (ack.id IS NOT NULL) AS is_acknowledged,
    ack.id AS acknowledgement_id,
    ack.acknowledged_by,
    ack.reason AS acknowledged_reason,
    ack.acknowledged_at,
    ack.expires_at AS acknowledgement_expires_at
FROM scan_findings sf
LEFT JOIN (
    SELECT DISTINCT ON (a.id, fa.finding_class, fa.advisory_key, fa.component_key,
                        fa.component_version_key)
        a.id AS artifact_id,
        fa.id,
        fa.finding_class,
        fa.advisory_key,
        fa.component_key,
        fa.component_version_key,
        fa.max_severity_rank,
        fa.acknowledged_by,
        fa.reason,
        fa.acknowledged_at,
        fa.expires_at
    FROM finding_acknowledgements fa
    JOIN artifacts a
      ON a.checksum_sha256 = fa.checksum_sha256
     AND (fa.repository_id = a.repository_id OR fa.repository_id IS NULL)
    WHERE fa.revoked_at IS NULL
      AND (fa.expires_at IS NULL OR fa.expires_at > NOW())
    ORDER BY a.id, fa.finding_class, fa.advisory_key, fa.component_key,
             fa.component_version_key, (fa.repository_id IS NULL), fa.acknowledged_at DESC
) ack
  ON ack.artifact_id = sf.artifact_id
 AND ack.finding_class = sf.finding_class
 AND ack.advisory_key = finding_advisory_key(sf.cve_id, sf.title)
 AND ack.component_key = finding_component_key(sf.affected_component)
 AND ack.component_version_key = finding_component_key(sf.affected_version)
 AND finding_severity_rank(sf.severity) <= ack.max_severity_rank;

-- The scans the download gate grades for one artifact: per scan type, the
-- latest complete scan and every row after it, or all rows when no complete
-- scan exists.
--
-- A completed rescan supersedes what came before it, so history no longer
-- blocks. A row after that baseline still counts whatever its state: findings
-- are written before a scan is marked completed, so a scan that crashed in
-- between has real findings on record, and a completed scan that could not
-- assess the artifact (`partial`, `not_cataloged`) says nothing about what the
-- complete one reported. Both fail closed.
CREATE OR REPLACE FUNCTION artifact_current_scan_ids(p_artifact_id UUID)
RETURNS TABLE (scan_result_id UUID)
LANGUAGE sql STABLE PARALLEL SAFE
AS $$
    WITH baseline AS (
        SELECT DISTINCT ON (scan_type) id, scan_type, created_at
        FROM scan_results
        WHERE artifact_id = p_artifact_id
          AND status = 'completed'
          AND COALESCE(scan_completeness, 'complete') = 'complete'
        ORDER BY scan_type, completed_at DESC NULLS LAST, created_at DESC
    )
    SELECT sr.id
    FROM scan_results sr
    LEFT JOIN baseline b ON b.scan_type = sr.scan_type
    WHERE sr.artifact_id = p_artifact_id
      AND (b.id IS NULL OR sr.id = b.id OR sr.created_at > b.created_at)
$$;

-- ---------------------------------------------------------------------------
-- A copied verdict must not pin its source
-- ---------------------------------------------------------------------------

-- `source_scan_id` is provenance. With no ON DELETE action, a scan that had been
-- copied could not be deleted, so purging the source artifact or deleting its
-- repository failed. A cross-repository dedup copy could already cause that, and
-- promotion now copies the verdict every time, so a staging repository could
-- otherwise never be emptied. The copy keeps its findings and `is_reused`. NOT
-- VALID because the old constraint already enforced every existing row and this
-- must not scan the table under the ACCESS EXCLUSIVE lock.
ALTER TABLE scan_results DROP CONSTRAINT scan_results_source_scan_id_fkey;
ALTER TABLE scan_results
    ADD CONSTRAINT scan_results_source_scan_id_fkey
    FOREIGN KEY (source_scan_id) REFERENCES scan_results(id)
    ON DELETE SET NULL NOT VALID;

-- ---------------------------------------------------------------------------
-- Existing acknowledgements
-- ---------------------------------------------------------------------------

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

COMMENT ON TABLE finding_acknowledgements IS
    'Acknowledgement decisions (#5153), keyed on the bytes, the repository and the '
    'finding identity. Applied at read time through scan_findings_effective.';

COMMENT ON COLUMN scan_findings.is_acknowledged IS
    'FROZEN (#5153): no longer read or written. Acknowledged state comes from '
    'finding_acknowledgements through scan_findings_effective. Kept for rolling '
    'upgrades and rollback; to be dropped in a later release.';
COMMENT ON COLUMN scan_findings.acknowledged_by IS 'FROZEN (#5153): see is_acknowledged.';
COMMENT ON COLUMN scan_findings.acknowledged_reason IS 'FROZEN (#5153): see is_acknowledged.';
COMMENT ON COLUMN scan_findings.acknowledged_at IS 'FROZEN (#5153): see is_acknowledged.';
