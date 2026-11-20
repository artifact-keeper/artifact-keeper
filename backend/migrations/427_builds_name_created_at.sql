-- artifact-keeper-web#618: the Builds page filters by exact build name and orders by
-- creation time, and the keep-last retention ranks builds per name. The
-- builds table is small next to artifacts, a plain index build is fine
CREATE INDEX IF NOT EXISTS idx_builds_name_created_at
    ON builds (name, created_at DESC);
