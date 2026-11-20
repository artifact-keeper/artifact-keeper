-- #5188: per-repository immutability mode.
--
-- `write_once` (DEFAULT): re-uploading an existing filename answers 409, as
-- every repository did before this column existed. `mutable`: a re-upload
-- replaces the stored content ("latest build wins").
--
-- A mode rather than a boolean so #4812 can add `strict` (and exclusion
-- patterns alongside it) to the same setting instead of a second flag that
-- could contradict this one.
CREATE TYPE repository_immutability AS ENUM ('write_once', 'mutable');

ALTER TABLE repositories
    ADD COLUMN immutability repository_immutability NOT NULL DEFAULT 'write_once';
