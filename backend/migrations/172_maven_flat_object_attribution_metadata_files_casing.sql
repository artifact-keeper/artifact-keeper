-- Re-run migration 163's metadata-`files[]` backfill with the correct key
-- spelling, qualified by storage backend (#2706).
--
-- Migration 163 category (2) attributed row-less GAV-grouped companion files
-- (`.pom`, `.module`, `-sources.jar`, `-javadoc.jar`) by reading each parent
-- artifact's metadata `files[]` array element as `elem->>'storage_key'`
-- (snake_case). The GAV-grouped upload handler (#418) has ALWAYS serialized
-- those entries with a camelCase `"storageKey"` (matching every other reader of
-- this array: `repositories.rs` reads `sizeBytes`/`extension`, `sbom.rs` reads
-- `storageKey`). The spelling never matched real data, so category (2) inserted
-- ZERO rows and every legacy row-less companion still fails closed with 404 on
-- cloud backends after upgrading to >= 1.5.7 -- the primary `.jar`/`.aar`
-- resolves (live row) while its `.pom`/`.module` 404s, breaking dependency
-- resolution for those GAVs.
--
-- The read-time layer 2 lookup (`OWNER_BY_METADATA_FILES_SQL`) is corrected in
-- the same change to match `COALESCE(f->>'storageKey', f->>'storage_key')`, so
-- companions whose parent row is still live resolve directly. This migration
-- persists the attribution for companions whose parent row was later
-- soft-deleted (where the live-row-only layer 2 no longer matches), and derives
-- their checksum/signature sidecars, exactly as 163 intended.
--
-- Isolation is preserved (#2504/#2574/#2584/#2671):
--   * Cloud repositories only (`storage_backend <> 'filesystem'`) and LIVE
--     parents only (`is_deleted = false`), as in 163.
--   * Single-owner only, qualified by the physical object identity
--     (storage_backend, storage_key): a key referenced by two repositories on
--     the SAME backend stays ambiguous and UNATTRIBUTED, so it fails closed
--     (404 read / 403 write) for both tenants. Two repositories on DIFFERENT
--     backends do not collide (#2671).
--   * `ON CONFLICT (storage_backend, storage_key) DO NOTHING`: never overwrites
--     an existing attribution (a live-row `primary_row`, an earlier claim, or a
--     rollup) -- it only fills in the genuinely-missing metadata-`files[]` rows.
--
-- Replay-safe: pure INSERT ... ON CONFLICT DO NOTHING against the post-168
-- `(storage_backend, storage_key)` primary key; re-running is a no-op.

-- (2') Companion files recorded in a live parent artifact's metadata `files[]`
--      array, keyed on the real camelCase `storageKey` (with a snake_case
--      fallback), qualified by the owning repository's backend.
INSERT INTO maven_flat_object_owner (storage_backend, storage_key, repository_id, source)
SELECT r.storage_backend,
       COALESCE(elem->>'storageKey', elem->>'storage_key') AS storage_key,
       MIN(a.repository_id::text)::uuid,
       'metadata_files'
FROM artifact_metadata am
JOIN artifacts a ON a.id = am.artifact_id
JOIN repositories r ON r.id = a.repository_id
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(am.metadata->'files') = 'array'
         THEN am.metadata->'files'
         ELSE '[]'::jsonb END
) AS elem
WHERE a.is_deleted = false
  AND r.storage_backend <> 'filesystem'
  AND COALESCE(elem->>'storageKey', elem->>'storage_key') LIKE 'maven/%'
GROUP BY r.storage_backend, COALESCE(elem->>'storageKey', elem->>'storage_key')
HAVING COUNT(DISTINCT a.repository_id) = 1
ON CONFLICT (storage_backend, storage_key) DO NOTHING;

-- (3') Derived checksum/signature sidecars for the metadata-`files[]` keys
--      attributed above (or already present): `.sha1`, `.md5`, `.sha256`, `.asc`
--      inherit the base object's owner and backend. Base keys that already carry
--      a sidecar suffix are skipped. Existing sidecars are left untouched.
INSERT INTO maven_flat_object_owner (storage_backend, storage_key, repository_id, source)
SELECT o.storage_backend,
       o.storage_key || s.suffix,
       o.repository_id,
       'derived_checksum'
FROM maven_flat_object_owner o
CROSS JOIN (VALUES ('.sha1'), ('.md5'), ('.sha256'), ('.asc')) AS s(suffix)
WHERE o.source = 'metadata_files'
  AND o.storage_key NOT LIKE '%.sha1'
  AND o.storage_key NOT LIKE '%.md5'
  AND o.storage_key NOT LIKE '%.sha256'
  AND o.storage_key NOT LIKE '%.asc'
ON CONFLICT (storage_backend, storage_key) DO NOTHING;
