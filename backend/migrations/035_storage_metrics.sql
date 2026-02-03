-- Storage metrics snapshots for trend reporting
CREATE TABLE IF NOT EXISTS storage_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
    total_repositories BIGINT NOT NULL DEFAULT 0,
    total_artifacts BIGINT NOT NULL DEFAULT 0,
    total_storage_bytes BIGINT NOT NULL DEFAULT 0,
    total_downloads BIGINT NOT NULL DEFAULT 0,
    total_users BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(snapshot_date)
);

-- Per-repository storage metrics for repo-level trending
CREATE TABLE IF NOT EXISTS repository_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
    artifact_count BIGINT NOT NULL DEFAULT 0,
    storage_bytes BIGINT NOT NULL DEFAULT 0,
    download_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repository_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_storage_metrics_date ON storage_metrics(snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_repository_metrics_date ON repository_metrics(snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_repository_metrics_repo ON repository_metrics(repository_id, snapshot_date DESC);

-- Lifecycle policies per repository
CREATE TABLE IF NOT EXISTS lifecycle_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    -- Policy rules (JSON for flexibility)
    policy_type TEXT NOT NULL CHECK (policy_type IN (
        'max_age_days',
        'max_versions',
        'no_downloads_days',
        'tag_pattern_keep',
        'tag_pattern_delete',
        'size_quota_bytes'
    )),
    -- Configuration for the policy
    config JSONB NOT NULL DEFAULT '{}',
    -- NULL repository_id means global policy
    priority INTEGER NOT NULL DEFAULT 0,
    last_run_at TIMESTAMPTZ,
    last_run_items_removed BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_policies_repo ON lifecycle_policies(repository_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_policies_enabled ON lifecycle_policies(enabled) WHERE enabled = true;

-- Telemetry settings and crash reports (opt-in)
CREATE TABLE IF NOT EXISTS telemetry_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL DEFAULT 'false',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default telemetry settings (all disabled)
INSERT INTO telemetry_settings (key, value) VALUES
    ('telemetry_enabled', 'false'),
    ('telemetry_review_before_send', 'true'),
    ('telemetry_scrub_level', '"standard"'),
    ('telemetry_include_logs', 'false')
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS crash_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_type TEXT NOT NULL,
    error_message TEXT NOT NULL,
    stack_trace TEXT,
    component TEXT NOT NULL, -- 'backend', 'database', 'meilisearch', 'trivy', etc.
    severity TEXT NOT NULL DEFAULT 'error' CHECK (severity IN ('warning', 'error', 'critical', 'panic')),
    app_version TEXT NOT NULL,
    os_info TEXT,
    uptime_seconds BIGINT,
    -- Scrubbed context (no PII)
    context JSONB DEFAULT '{}',
    -- Submission status
    submitted BOOLEAN NOT NULL DEFAULT false,
    submitted_at TIMESTAMPTZ,
    submission_error TEXT,
    -- Dedup signature
    error_signature TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_crash_reports_signature ON crash_reports(error_signature);
CREATE INDEX IF NOT EXISTS idx_crash_reports_submitted ON crash_reports(submitted) WHERE submitted = false;
CREATE INDEX IF NOT EXISTS idx_crash_reports_severity ON crash_reports(severity);

-- Health monitoring state
CREATE TABLE IF NOT EXISTS service_health_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('healthy', 'unhealthy', 'unavailable', 'degraded')),
    previous_status TEXT,
    message TEXT,
    response_time_ms INTEGER,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_health_log_service ON service_health_log(service_name, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_health_log_time ON service_health_log(checked_at DESC);

-- Alert suppression tracking
CREATE TABLE IF NOT EXISTS alert_state (
    service_name TEXT PRIMARY KEY,
    current_status TEXT NOT NULL DEFAULT 'healthy',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_alert_sent_at TIMESTAMPTZ,
    suppressed_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
