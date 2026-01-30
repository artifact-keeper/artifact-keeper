-- Security scanning tables for vulnerability detection, scoring, and policy enforcement
-- Feature: Security & Artifact Scanning (epic 3he)

-- Per-repository scan configuration (opt-in)
CREATE TABLE IF NOT EXISTS scan_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL UNIQUE REFERENCES repositories(id) ON DELETE CASCADE,
    scan_enabled BOOLEAN NOT NULL DEFAULT false,
    scan_on_upload BOOLEAN NOT NULL DEFAULT false,
    scan_on_proxy BOOLEAN NOT NULL DEFAULT false,
    block_on_policy_violation BOOLEAN NOT NULL DEFAULT false,
    severity_threshold VARCHAR(20) NOT NULL DEFAULT 'high'
        CHECK (severity_threshold IN ('critical', 'high', 'medium', 'low', 'info')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scan execution records
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scan_type VARCHAR(30) NOT NULL
        CHECK (scan_type IN ('dependency', 'image', 'license', 'malware')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    findings_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    scanner_version VARCHAR(50),
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Individual vulnerability findings
CREATE TABLE IF NOT EXISTS scan_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_result_id UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    cve_id VARCHAR(30),
    affected_component VARCHAR(255),
    affected_version VARCHAR(100),
    fixed_version VARCHAR(100),
    source VARCHAR(100),
    source_url VARCHAR(512),
    is_acknowledged BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_reason TEXT,
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Materialized repository security scores
CREATE TABLE IF NOT EXISTS repo_security_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL UNIQUE REFERENCES repositories(id) ON DELETE CASCADE,
    score INTEGER NOT NULL DEFAULT 100 CHECK (score >= 0 AND score <= 100),
    grade CHAR(1) NOT NULL DEFAULT 'A' CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    acknowledged_count INTEGER NOT NULL DEFAULT 0,
    last_scan_at TIMESTAMPTZ,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security policies for enforcement
CREATE TABLE IF NOT EXISTS scan_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    max_severity VARCHAR(20) NOT NULL DEFAULT 'critical'
        CHECK (max_severity IN ('critical', 'high', 'medium', 'low')),
    block_unscanned BOOLEAN NOT NULL DEFAULT false,
    block_on_fail BOOLEAN NOT NULL DEFAULT false,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add quarantine status to artifacts for proxy scan support
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS quarantine_status VARCHAR(20)
    CHECK (quarantine_status IN ('unscanned', 'clean', 'flagged'));

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scan_configs_repo ON scan_configs(repository_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_artifact ON scan_results(artifact_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_repo_status ON scan_results(repository_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_results_created ON scan_results(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_result_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_artifact ON scan_findings(artifact_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_severity ON scan_findings(severity);
CREATE INDEX IF NOT EXISTS idx_scan_findings_cve ON scan_findings(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_findings_acknowledged ON scan_findings(is_acknowledged) WHERE is_acknowledged = false;
CREATE INDEX IF NOT EXISTS idx_scan_policies_repo ON scan_policies(repository_id);
CREATE INDEX IF NOT EXISTS idx_scan_policies_enabled ON scan_policies(is_enabled) WHERE is_enabled = true;
CREATE INDEX IF NOT EXISTS idx_artifacts_quarantine ON artifacts(quarantine_status) WHERE quarantine_status IS NOT NULL;
