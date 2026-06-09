-- Add an opt-in `promotion_only` attribute to repositories.
--
-- When set, a repository rejects DIRECT user uploads (e.g. PUT a brand-new
-- artifact straight into a release repo such as `maven-releases`). Artifacts
-- must instead arrive via the promotion path (staging -> promotion -> approval).
-- The promotion service writes through its own RAW SQL INSERT path (see
-- handlers/promotion.rs) and is unaffected by this flag.
--
-- DEFAULT false means existing repositories keep their current behavior: this
-- is purely opt-in and changes nothing until an admin flips the flag on a
-- specific repository.
ALTER TABLE repositories
    ADD COLUMN promotion_only BOOLEAN NOT NULL DEFAULT false;
