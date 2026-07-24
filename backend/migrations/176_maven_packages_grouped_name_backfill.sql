-- #2723: Normalize existing Maven/Gradle catalog `packages.name` rows to the
-- grouped `groupId:artifactId` form used by hosted/virtual grouped listings.
--
-- Context. PF-003 (#2520) shipped SQL keyset paging for Docker and remote-Maven
-- grouped listings but deferred hosted/virtual Maven grouping, which still
-- grouped in memory. The write path now records `packages.name =
-- "groupId:artifactId"` for Maven/Gradle artifacts (artifact_service::
-- finalize_upload and the chunked-completion fallback in upload.rs), so hosted/
-- virtual grouped listings can be served straight out of the catalog keyset --
-- but rows written before that change still hold the BARE artifactId (or the
-- filename, for the generic/chunked push path). This backfill rewrites those
-- legacy rows so the catalog keyset lists them under the same grouped key.
--
-- Derivation. A Maven artifact is stored at the GAV layout
--   <groupId-as-path>/<artifactId>/<version>/<file>
-- (the `artifacts.path` column; `storage_key` is the same value under the
-- `maven/` object prefix). Given the catalog row's `name` (the legacy
-- artifactId) and one of its `package_versions.version`, the substring of a
-- matching artifact path before the first `/<name>/<version>/` segment is the
-- group path; converting its `/` separators to `.` yields the groupId. The row
-- is then rewritten to `groupId:artifactId`.
--
-- Scope + safety.
--   * Restricted to Maven/Gradle repositories and to catalog rows joined to a
--     Maven object (`artifacts.storage_key LIKE 'maven/%'`).
--   * Forward-only and idempotent: only rows whose `name` does NOT already
--     contain a `:` are touched, and a normalized `groupId:artifactId` always
--     contains one. A Maven artifactId never contains `:`, so re-running this
--     migration (or running it after the write-path fix has already produced
--     grouped names) is a no-op.
--   * A row with no resolvable group path (no matching artifact / empty group)
--     is left untouched rather than corrupted.

WITH resolved AS (
    SELECT DISTINCT ON (p.id)
        p.id AS package_id,
        LEFT(
            a.path,
            POSITION('/' || p.name || '/' || pv.version || '/' IN a.path) - 1
        ) AS group_path
    FROM packages p
    JOIN repositories r
      ON r.id = p.repository_id
     AND r.format IN ('maven', 'gradle')
    JOIN package_versions pv
      ON pv.package_id = p.id
    JOIN artifacts a
      ON a.repository_id = p.repository_id
     AND a.storage_key LIKE 'maven/%'
     AND POSITION('/' || p.name || '/' || pv.version || '/' IN a.path) > 0
    WHERE p.name NOT LIKE '%:%'
    ORDER BY p.id, a.path
)
UPDATE packages p
SET name = REPLACE(resolved.group_path, '/', '.') || ':' || p.name,
    updated_at = NOW()
FROM resolved
WHERE p.id = resolved.package_id
  AND resolved.group_path <> ''
  AND p.name NOT LIKE '%:%';
