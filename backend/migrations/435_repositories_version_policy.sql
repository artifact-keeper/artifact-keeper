-- #5872: which Maven versions a hosted Maven or Gradle repository accepts.
-- 'mixed' is the behaviour before the policy existed
-- The CHECK sits on the column it adds, so it is an expand: no earlier release writes version_policy
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS version_policy TEXT NOT NULL DEFAULT 'mixed'
    CHECK (version_policy IN ('mixed', 'release', 'snapshot'));
