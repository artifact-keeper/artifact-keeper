-- #5872: which Maven versions a hosted Maven or Gradle repository accepts.
-- 'mixed' is the behaviour before the policy existed
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS version_policy TEXT NOT NULL DEFAULT 'mixed';

ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_version_policy_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_version_policy_check
    CHECK (version_policy IN ('mixed', 'release', 'snapshot'));
