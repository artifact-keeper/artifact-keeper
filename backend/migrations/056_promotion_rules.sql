-- Auto-promotion rules engine: automatically promote artifacts from staging
-- to release repos when all configured policies pass.

CREATE TABLE IF NOT EXISTS promotion_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    source_repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    target_repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    -- Criteria: all must pass for auto-promotion
    max_cve_severity VARCHAR(20) DEFAULT 'medium',  -- max severity allowed
    allowed_licenses TEXT[] DEFAULT NULL,             -- NULL = any license OK
    require_signature BOOLEAN NOT NULL DEFAULT false,
    min_staging_hours INTEGER DEFAULT NULL,           -- minimum time in staging
    max_artifact_age_days INTEGER DEFAULT NULL,       -- maximum artifact age
    min_health_score INTEGER DEFAULT NULL,            -- minimum quality gate score
    -- Scheduling
    auto_promote BOOLEAN NOT NULL DEFAULT true,       -- promote immediately when criteria met
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_promotion_rules_source ON promotion_rules(source_repo_id);
CREATE INDEX IF NOT EXISTS idx_promotion_rules_enabled ON promotion_rules(is_enabled) WHERE is_enabled = true;
