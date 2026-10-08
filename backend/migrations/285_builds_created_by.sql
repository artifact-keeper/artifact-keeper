-- GHSA-mvmh-g8wm-r3cp: record which principal created a build, so changing
-- the build's status or attaching artifacts to it can be limited to that
-- principal and administrators. Builds created before this migration keep
-- NULL and become administrator-only to change.
--
-- Nullable with no default and no foreign key: a catalogue-only change on
-- PostgreSQL 11+, with no table rewrite and no validation scan.
ALTER TABLE builds ADD COLUMN IF NOT EXISTS created_by UUID;
