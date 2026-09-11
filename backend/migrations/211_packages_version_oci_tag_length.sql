-- #3611: the OCI tag grammar allows up to 128 characters, but
-- packages.version and package_versions.version were VARCHAR(100)
-- (019_builds_packages.sql). A valid 101-128 character tag -- CI schemes
-- like v1.2.3-nightly-<date>-<sha>-<platform>-<branch> cross 100 routinely
-- -- made the catalog upsert fail, and because the write is best-effort the
-- error was swallowed into a warn: the pull returned 200 and the image
-- silently never indexed. Widen both columns to the grammar's bound.
--
-- Increasing a VARCHAR limit is a metadata-only change in Postgres: no table
-- rewrite and no rebuild of the UNIQUE(repository_id, name, version) /
-- UNIQUE(package_id, version) indexes.
ALTER TABLE packages ALTER COLUMN version TYPE VARCHAR(128);
ALTER TABLE package_versions ALTER COLUMN version TYPE VARCHAR(128);
