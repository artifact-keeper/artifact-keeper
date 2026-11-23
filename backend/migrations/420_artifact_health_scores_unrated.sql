-- 420_artifact_health_scores_unrated.sql
-- #5656: an artifact with no security, license, quality or metadata score is
-- UNRATED, stored as a NULL health_score and health_grade. It used to be
-- stored as 100 / 'A' (no data = healthy). Generic artifacts are no longer
-- scored on package metadata, so that default would have graded every
-- unscanned generic file A and let it through a quality gate's
-- min_health_score; an unrated artifact now fails that minimum instead.
--
-- Cost: DROP NOT NULL is a catalog-only change (no table scan or rewrite)
-- under a brief ACCESS EXCLUSIVE lock on artifact_health_scores, which only
-- the quality-check writer and the health endpoints touch. The CHECK
-- constraints already pass NULL. Existing rows keep their values; they are
-- re-rated the next time their artifact is checked. Down path: set NULL rows
-- back to 100 / 'A' and restore NOT NULL.
ALTER TABLE artifact_health_scores
    ALTER COLUMN health_score DROP NOT NULL,
    ALTER COLUMN health_grade DROP NOT NULL;
