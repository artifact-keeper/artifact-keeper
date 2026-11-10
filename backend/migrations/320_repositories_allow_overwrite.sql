-- #5188: per-repository mutability toggle.
--
-- When true, re-uploading an existing filename to a hosted repository
-- replaces the stored content ("latest build wins") instead of answering
-- 409. DEFAULT false: every existing repository keeps write-once semantics.
ALTER TABLE repositories
    ADD COLUMN allow_overwrite BOOLEAN NOT NULL DEFAULT false;
