-- #3064: Backfill `package_versions.version` for Maven/Gradle catalog rows
-- written by the generic/chunked upload paths before the write-path fix.
--
-- Context. #2723 normalized `packages.name` to `groupId:artifactId` on the
-- generic/chunked write paths but left `package_versions.version` holding a
-- naive path segment, so hosted Maven grouped listings -- which join
-- `packages` to `package_versions` -- reported components with zero matching
-- versions. The write paths now derive both name and version from the
-- artifact's GAV path; this backfill repairs the rows written in between.
--
-- Derivation. A Maven artifact is stored at the GAV layout
--   <groupId-as-path>/<artifactId>/<version>/<file>
-- (the `artifacts.path` column). For a grouped catalog row
-- `name = groupId:artifactId` the on-disk version directories are the path
-- segments directly under `<groupId-as-path>/<artifactId>/` (the "prefix").
-- A `package_versions` row is broken when its version is not one of those
-- directories while the package DOES have candidate version directories.
--
-- Repair rule (see the UNIQUE(package_id, version) note below):
--   * exactly one candidate AND exactly one broken row -> rewrite that row;
--   * anything else (several broken rows, or several candidates) -> delete
--     the broken rows. The catalog is derived data and is recreated
--     correctly on the next push, so deleting is safe and is the only
--     option that cannot violate the unique constraint.
--
-- WHY NOT "rewrite every broken row when there is one candidate":
--   `package_versions` carries UNIQUE(package_id, version)
--   (019_builds_packages.sql:52). The UPDATE's guard subquery sees the
--   pre-statement snapshot, so with TWO broken rows and ONE candidate both
--   rows pass the guard and both are rewritten to the same version, raising
--   23505. Migrations run at boot, so that aborts startup and the deployment
--   crash-loops until someone does DB surgery. That shape is organically
--   reachable (a generic-push naive version plus a chunked explicit version
--   on the same GAV), so the rule above rewrites AT MOST ONE row per package
--   and deletes the remainder. Covered by
--   `migration_192_multiple_broken_rows_single_candidate_does_not_violate_unique`.
--
-- Scope + safety.
--   * Restricted to Maven/Gradle repositories and to `packages.name` rows in
--     the grouped `groupId:artifactId` shape (a `:` strictly inside the
--     name). Bare-name legacy rows are migration 177's concern.
--   * Artifacts are attributed to the LONGEST matching package prefix, so a
--     nested coordinate (`com.example:app` vs `com.example.app:foo`) does not
--     harvest the nested package's directories as its own candidate versions
--     and then "repair" a healthy row into a wrong one.
--   * Prefix matching uses LIKE against a literal-escaped prefix so it can be
--     served by the text_pattern_ops index on artifacts(path) (migration 110);
--     `LEFT(path, N) = prefix` is not sargable and degraded to a full scan per
--     broken row on large catalogs, risking the 30-minute startup
--     statement_timeout.
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
      -- Exactly one colon. `split_part(name, ':', 2)` would silently truncate a
      -- multi-colon name ('a:b:c' -> 'b') while the read path splits on the
      -- FIRST colon only (repositories.rs `maven_component_path_prefix`), so the
      -- two would disagree about the artifactId. Such names are not produced by
      -- the Maven write paths; skip rather than guess.
      AND CHAR_LENGTH(p.name) - CHAR_LENGTH(REPLACE(p.name, ':', '')) = 1
),
-- Escape LIKE metacharacters so a prefix containing % or _ stays literal.
maven_prefixes AS (
    SELECT
        mp.id,
        mp.repository_id,
        mp.prefix,
        REPLACE(REPLACE(REPLACE(mp.prefix, '\', '\\'), '%', '\%'), '_', '\_')
            AS prefix_like
    FROM maven_packages mp
),
-- Version directories that actually exist under each package prefix.
-- An artifact is attributed to the LONGEST matching prefix only.
candidates AS (
    SELECT DISTINCT
        mp.id AS package_id,
        split_part(SUBSTRING(a.path FROM CHAR_LENGTH(mp.prefix) + 1), '/', 1) AS version
    FROM maven_prefixes mp
    JOIN artifacts a
      ON a.repository_id = mp.repository_id
     AND a.path LIKE mp.prefix_like || '%'
     AND POSITION('/' IN SUBSTRING(a.path FROM CHAR_LENGTH(mp.prefix) + 1)) > 0
    WHERE NOT EXISTS (
        SELECT 1
        FROM maven_prefixes longer
        WHERE longer.repository_id = mp.repository_id
          AND CHAR_LENGTH(longer.prefix) > CHAR_LENGTH(mp.prefix)
          AND a.path LIKE longer.prefix_like || '%'
    )
      AND split_part(SUBSTRING(a.path FROM CHAR_LENGTH(mp.prefix) + 1), '/', 1) <> ''
),
-- A row is broken iff its version is not one of the package's candidate
-- directories, and the package has at least one candidate. Expressed as an
-- anti-join against `candidates` so `artifacts` is scanned once overall
-- rather than once per broken row.
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
        FROM candidates c
        WHERE c.package_id = pv.package_id
          AND c.version = pv.version
    )
),
counts AS (
    SELECT
        b.package_id,
        COUNT(*) AS broken_count,
        (SELECT COUNT(*) FROM candidates c WHERE c.package_id = b.package_id)
            AS candidate_count,
        MIN(b.pv_id::text) AS keep_pv_id
    FROM broken b
    GROUP BY b.package_id
),
-- Rewrite only when the mapping is unambiguous AND collision-free: exactly
-- one broken row and exactly one candidate for that package.
-- `candidates` is JOINed rather than read through a scalar subquery: the
-- ct.candidate_count = 1 predicate guarantees exactly one matching row, and a
-- scalar subquery here would be evaluated for multi-candidate packages too
-- (Postgres does not promise it is filtered first), raising "more than one row
-- returned by a subquery used as an expression".
rewritten AS (
    UPDATE package_versions pv
    SET version = c.version
    FROM broken b
    JOIN counts ct ON ct.package_id = b.package_id
    JOIN candidates c ON c.package_id = b.package_id
    WHERE pv.id = b.pv_id
      AND ct.broken_count = 1
      AND ct.candidate_count = 1
      AND NOT EXISTS (
          SELECT 1
          FROM package_versions existing
          WHERE existing.package_id = b.package_id
            AND existing.id <> b.pv_id
            AND existing.version = c.version
      )
    RETURNING pv.id
)
DELETE FROM package_versions pv
USING broken b
WHERE pv.id = b.pv_id
  AND NOT EXISTS (SELECT 1 FROM rewritten w WHERE w.id = b.pv_id);
