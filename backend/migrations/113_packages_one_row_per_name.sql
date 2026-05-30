WITH canonical_packages AS (
    SELECT DISTINCT ON (repository_id, name)
        id,
        repository_id,
        name
    FROM packages
    ORDER BY repository_id, name, version DESC, updated_at DESC, created_at DESC, id
),
duplicate_version_rows AS (
    SELECT pv.id
    FROM package_versions pv
    JOIN packages p ON p.id = pv.package_id
    JOIN canonical_packages cp
      ON cp.repository_id = p.repository_id
     AND cp.name = p.name
    JOIN package_versions existing
      ON existing.package_id = cp.id
     AND existing.version = pv.version
    WHERE pv.package_id <> cp.id
)
DELETE FROM package_versions
WHERE id IN (SELECT id FROM duplicate_version_rows);

WITH canonical_packages AS (
    SELECT DISTINCT ON (repository_id, name)
        id,
        repository_id,
        name
    FROM packages
    ORDER BY repository_id, name, version DESC, updated_at DESC, created_at DESC, id
)
UPDATE package_versions pv
SET package_id = cp.id
FROM packages p
JOIN canonical_packages cp
  ON cp.repository_id = p.repository_id
 AND cp.name = p.name
WHERE pv.package_id = p.id
  AND p.id <> cp.id;

WITH canonical_packages AS (
    SELECT DISTINCT ON (repository_id, name)
        id,
        repository_id,
        name
    FROM packages
    ORDER BY repository_id, name, version DESC, updated_at DESC, created_at DESC, id
)
DELETE FROM packages p
USING canonical_packages cp
WHERE p.repository_id = cp.repository_id
  AND p.name = cp.name
  AND p.id <> cp.id;

ALTER TABLE packages
DROP CONSTRAINT IF EXISTS packages_repository_id_name_version_key;

ALTER TABLE packages
ADD CONSTRAINT packages_repository_id_name_key UNIQUE (repository_id, name);
