-- 178_artifact_quarantine_reason.sql
-- Record WHY an artifact is quarantined or rejected (policy violations,
-- admin action) so download-block errors can carry an actionable message.
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS quarantine_reason TEXT;
