-- Repair the `metadata_files` attribution backfill: match the key spelling the
-- upload handler actually writes.
--
-- Migration 163 category (2) attributed row-less GAV-grouped companion files
-- (`.pom`, `.module`, `-sources.jar`, ...) from their parent artifact's
-- metadata `files[]` array -- but matched `elem->>'storage_key'` (snake_case),
-- while the GAV-grouped upload handler has always serialized those entries
-- with camelCase keys (`"storageKey"`, since #418). The backfill therefore
-- inserted NOTHING on real data, and (together with the same spelling in the
-- read-time lookup, fixed in code alongside this migration) every legacy
-- row-less companion failed closed on cloud backends after the storage-read
-- fallback was removed.
--
-- This migration re-runs category (2) and its derived-checksum expansion (3)
-- accepting BOTH spellings, against the current schema (post-168:
-- `storage_backend`-qualified composite primary key). Idempotent and
-- replay-safe: pure INSERT ... ON CONFLICT DO NOTHING; a key already claimed
-- (by a corrected earlier run, a write-time claim, or a hand repair) is left
-- untouched. Same single-owner-per-backend semantics as 163/168: a key whose
-- parents span two repositories on one backend stays unattributed
-- (fail-closed).

-- (2') Companion files recorded in a parent artifact's metadata `files[]`
--      array -- camelCase `storageKey` (what the upload handler writes) with
--      snake_case `storage_key` accepted as a fallback spelling.
INSERT INTO maven_flat_object_owner (storage_key, repository_id, source, storage_backend)
SELECT COALESCE(elem->>'storageKey', elem->>'storage_key') AS storage_key,
       MIN(a.repository_id::text)::uuid,
       'metadata_files',
       r.storage_backend
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

-- (3') Derived checksum sidecars for the newly attributed companion keys:
--      `.sha1`, `.md5`, `.sha256`, `.asc` inherit the base object's owner.
--      Scoped to `metadata_files` rows -- `primary_row` sidecars were already
--      derived correctly by 163.
INSERT INTO maven_flat_object_owner (storage_key, repository_id, source, storage_backend)
SELECT o.storage_key || s.suffix,
       o.repository_id,
       'derived_checksum',
       o.storage_backend
FROM maven_flat_object_owner o
CROSS JOIN (VALUES ('.sha1'), ('.md5'), ('.sha256'), ('.asc')) AS s(suffix)
WHERE o.source = 'metadata_files'
  AND o.storage_key NOT LIKE '%.sha1'
  AND o.storage_key NOT LIKE '%.md5'
  AND o.storage_key NOT LIKE '%.sha256'
  AND o.storage_key NOT LIKE '%.asc'
ON CONFLICT (storage_backend, storage_key) DO NOTHING;
