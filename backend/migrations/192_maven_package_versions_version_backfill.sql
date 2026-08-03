-- #3064: Backfill `package_versions.version` for Maven/Gradle catalog rows
-- written by the generic/chunked upload paths before the write-path fix.
--
-- Context. #2723 normalized `packages.name` to `groupId:artifactId` on the
-- generic/chunked write paths but left `package_versions.version` holding a
-- naive path segment (e.g. the first groupId component, `com`), so hosted
-- Maven grouped listings -- which join `packages` to `package_versions` --
-- reported components with zero matching versions. The write paths now derive
-- both name and version from the artifact's GAV path; this backfill repairs
-- the rows written in between.
--
-- Derivation. A Maven artifact is stored at the GAV layout
--   <groupId-as-path>/<artifactId>/<version>/<file>
-- (the `artifacts.path` column). For a grouped catalog row
-- `name = groupId:artifactId` the on-disk version directories are the path
-- segments directly under `<groupId-as-path>/<artifactId>/` (the "prefix").
-- A `package_versions` row is broken when NO artifact exists under
-- `prefix || version || '/'` while the package DOES have candidate version
-- directories:
--   * exactly one candidate -> rewrite `version` to it; when a row with that
--     version already exists for the package (UNIQUE(package_id, version)),
--     delete the broken row instead;
--   * multiple candidates  -> the broken row cannot be attributed to a single
--     version, so it is deleted. The catalog is derived data; the row is
--     recreated correctly on the next push.
--
-- Scope + safety.
--   * Restricted to Maven/Gradle repositories and to `packages.name` rows in
--     the grouped `groupId:artifactId` shape (a `:` strictly inside the
--     name). Bare-name legacy rows are migration 177's concern.
--   * Proxy repositories store no hosted `artifacts` rows, so their catalog
--     rows never produce candidates and are left untouched.
--   * `artifacts.version` carries the same naive-segment residue but is
--     cosmetic there and is out of scope.
--   * Forward-only and idempotent: a repaired row matches an existing version
--     directory and is never selected again, so re-running is a no-op.

WITH maven_packages AS (
    SELECT
        p.id,
        p.repository_id,
        REPLACE(split_part(p.name, ':', 1), '.', '/')
            || '/' || split_part(p.name, ':', 2) || '/' AS prefix
    FROM packages p
    JOIN repositories r
      ON r.id = p.repository_id
     AND r.format IN ('maven', 'gradle')
    WHERE POSITION(':' IN p.name) > 1
      AND POSITION(':' IN p.name) < CHAR_LENGTH(p.name)
),
candidates AS (
    SELECT DISTINCT
        mp.id AS package_id,
        split_part(SUBSTRING(a.path FROM CHAR_LENGTH(mp.prefix) + 1), '/', 1) AS version
    FROM maven_packages mp
    JOIN artifacts a
      ON a.repository_id = mp.repository_id
     AND LEFT(a.path, CHAR_LENGTH(mp.prefix)) = mp.prefix
     AND POSITION('/' IN SUBSTRING(a.path FROM CHAR_LENGTH(mp.prefix) + 1)) > 0
),
broken AS (
    SELECT pv.id AS pv_id, pv.package_id
    FROM package_versions pv
    JOIN maven_packages mp
      ON mp.id = pv.package_id
    WHERE EXISTS (
        SELECT 1 FROM candidates c WHERE c.package_id = pv.package_id
    )
    AND NOT EXISTS (
        SELECT 1
        FROM artifacts a
        WHERE a.repository_id = mp.repository_id
          AND LEFT(a.path, CHAR_LENGTH(mp.prefix) + CHAR_LENGTH(pv.version) + 1)
              = mp.prefix || pv.version || '/'
    )
),
resolved AS (
    SELECT
        b.pv_id,
        b.package_id,
        ARRAY(
            SELECT c.version FROM candidates c WHERE c.package_id = b.package_id
        ) AS versions
    FROM broken b
),
rewritten AS (
    UPDATE package_versions pv
    SET version = r.versions[1]
    FROM resolved r
    WHERE pv.id = r.pv_id
      AND ARRAY_LENGTH(r.versions, 1) = 1
      AND NOT EXISTS (
          SELECT 1
          FROM package_versions existing
          WHERE existing.package_id = r.package_id
            AND existing.version = r.versions[1]
            AND existing.id <> r.pv_id
      )
    RETURNING pv.id
)
DELETE FROM package_versions pv
USING resolved r
WHERE pv.id = r.pv_id
  AND NOT EXISTS (SELECT 1 FROM rewritten w WHERE w.id = r.pv_id);
