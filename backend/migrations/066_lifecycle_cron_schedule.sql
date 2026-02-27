ALTER TABLE lifecycle_policies ADD COLUMN IF NOT EXISTS cron_schedule TEXT;
COMMENT ON COLUMN lifecycle_policies.cron_schedule IS 'Optional cron expression (6-field) for automatic policy execution. NULL = default 6-hour interval.';
