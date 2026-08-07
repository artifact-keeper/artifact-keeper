-- Durable per-occurrence claims for backup schedules (DueRun pattern).
--
-- Every backend replica evaluates the same due schedules. The old scheduler
-- created and executed the archive before advancing next_run_at, so one due
-- occurrence could produce one backup per replica. This ledger is claimed
-- before archive creation and is uniquely keyed by the schedule's stored due
-- time. Expired running claims recover in place after a crashed worker.
CREATE TABLE backup_schedule_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id UUID NOT NULL REFERENCES backup_schedules(id) ON DELETE CASCADE,
    scheduled_for TIMESTAMPTZ NOT NULL,
    claimed_by TEXT NOT NULL,
    claim_token UUID NOT NULL,
    claim_expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed')),
    backup_id UUID REFERENCES backups(id) ON DELETE SET NULL,
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    UNIQUE (schedule_id, scheduled_for),
    CONSTRAINT backup_schedule_runs_terminal_state CHECK (
        (status = 'running' AND completed_at IS NULL)
        OR (status IN ('completed', 'failed') AND completed_at IS NOT NULL)
    )
);

CREATE INDEX idx_backup_schedule_runs_schedule
    ON backup_schedule_runs (schedule_id, started_at DESC);

CREATE INDEX idx_backup_schedule_runs_reclaim
    ON backup_schedule_runs (claim_expires_at)
    WHERE status = 'running';

COMMENT ON TABLE backup_schedule_runs IS
    'One durable run per (schedule, due time); claim before creating or executing a backup';
COMMENT ON COLUMN backup_schedule_runs.scheduled_for IS
    'The next_run_at occurrence this row satisfies; epoch represents an initially unscheduled row';
COMMENT ON COLUMN backup_schedule_runs.backup_id IS
    'The backups row created by BackupService for this occurrence; not the legacy backup_jobs table';
COMMENT ON COLUMN backup_schedule_runs.claim_token IS
    'Random ownership proof required by renewal and finalization';
