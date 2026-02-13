-- =============================================================================
-- Migration 053: Artifact Health & Quality Gates
-- =============================================================================
-- Adds a SonarQube-inspired quality check system with:
--   - Pluggable quality checkers (metadata, helm lint, etc.)
--   - Per-artifact composite health scores (A-F grade)
--   - Per-repository aggregate health scores
--   - Configurable quality gates for promotion gating
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Quality check results (parallel to scan_results for security)
-- ---------------------------------------------------------------------------
CREATE TABLE quality_check_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    check_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    score INTEGER CHECK (score >= 0 AND score <= 100),
    passed BOOLEAN,
    details JSONB DEFAULT '{}',
    issues_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    checker_version VARCHAR(50),
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_qcr_artifact ON quality_check_results(artifact_id);
CREATE INDEX idx_qcr_repo_status ON quality_check_results(repository_id, status);
CREATE INDEX idx_qcr_check_type ON quality_check_results(check_type);
CREATE INDEX idx_qcr_created ON quality_check_results(created_at DESC);
CREATE INDEX idx_qcr_artifact_type ON quality_check_results(artifact_id, check_type, status)
    WHERE status = 'completed';

-- ---------------------------------------------------------------------------
-- Quality check issues (parallel to scan_findings)
-- ---------------------------------------------------------------------------
CREATE TABLE quality_check_issues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_result_id UUID NOT NULL REFERENCES quality_check_results(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    location VARCHAR(500),
    is_suppressed BOOLEAN NOT NULL DEFAULT false,
    suppressed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    suppressed_reason TEXT,
    suppressed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_qci_check_result ON quality_check_issues(check_result_id);
CREATE INDEX idx_qci_artifact ON quality_check_issues(artifact_id);
CREATE INDEX idx_qci_severity ON quality_check_issues(severity);

-- ---------------------------------------------------------------------------
-- Artifact health scores (per-artifact composite score)
-- ---------------------------------------------------------------------------
CREATE TABLE artifact_health_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL UNIQUE REFERENCES artifacts(id) ON DELETE CASCADE,
    health_score INTEGER NOT NULL DEFAULT 100
        CHECK (health_score >= 0 AND health_score <= 100),
    health_grade CHAR(1) NOT NULL DEFAULT 'A'
        CHECK (health_grade IN ('A', 'B', 'C', 'D', 'F')),
    security_score INTEGER CHECK (security_score >= 0 AND security_score <= 100),
    license_score INTEGER CHECK (license_score >= 0 AND license_score <= 100),
    quality_score INTEGER CHECK (quality_score >= 0 AND quality_score <= 100),
    metadata_score INTEGER CHECK (metadata_score >= 0 AND metadata_score <= 100),
    total_issues INTEGER NOT NULL DEFAULT 0,
    critical_issues INTEGER NOT NULL DEFAULT 0,
    checks_passed INTEGER NOT NULL DEFAULT 0,
    checks_total INTEGER NOT NULL DEFAULT 0,
    last_checked_at TIMESTAMPTZ,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ahs_health_score ON artifact_health_scores(health_score);
CREATE INDEX idx_ahs_health_grade ON artifact_health_scores(health_grade);

-- ---------------------------------------------------------------------------
-- Repository health scores (aggregate of artifact health)
-- ---------------------------------------------------------------------------
CREATE TABLE repo_health_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL UNIQUE REFERENCES repositories(id) ON DELETE CASCADE,
    health_score INTEGER NOT NULL DEFAULT 100
        CHECK (health_score >= 0 AND health_score <= 100),
    health_grade CHAR(1) NOT NULL DEFAULT 'A'
        CHECK (health_grade IN ('A', 'B', 'C', 'D', 'F')),
    avg_security_score INTEGER,
    avg_license_score INTEGER,
    avg_quality_score INTEGER,
    avg_metadata_score INTEGER,
    artifacts_evaluated INTEGER NOT NULL DEFAULT 0,
    artifacts_passing INTEGER NOT NULL DEFAULT 0,
    artifacts_failing INTEGER NOT NULL DEFAULT 0,
    last_evaluated_at TIMESTAMPTZ,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rhs_health_grade ON repo_health_scores(health_grade);

-- ---------------------------------------------------------------------------
-- Quality gates (configurable pass/fail thresholds per repository)
-- ---------------------------------------------------------------------------
CREATE TABLE quality_gates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    min_health_score INTEGER DEFAULT 0
        CHECK (min_health_score >= 0 AND min_health_score <= 100),
    min_security_score INTEGER
        CHECK (min_security_score >= 0 AND min_security_score <= 100),
    min_quality_score INTEGER
        CHECK (min_quality_score >= 0 AND min_quality_score <= 100),
    min_metadata_score INTEGER
        CHECK (min_metadata_score >= 0 AND min_metadata_score <= 100),
    max_critical_issues INTEGER DEFAULT 0,
    max_high_issues INTEGER,
    max_medium_issues INTEGER,
    required_checks TEXT[] DEFAULT '{}',
    enforce_on_promotion BOOLEAN NOT NULL DEFAULT true,
    enforce_on_download BOOLEAN NOT NULL DEFAULT false,
    action VARCHAR(20) NOT NULL DEFAULT 'warn'
        CHECK (action IN ('allow', 'warn', 'block')),
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_quality_gates_repo ON quality_gates(repository_id);
CREATE INDEX idx_quality_gates_enabled ON quality_gates(is_enabled) WHERE is_enabled = true;

-- ---------------------------------------------------------------------------
-- Quality gate evaluation history (audit trail)
-- ---------------------------------------------------------------------------
CREATE TABLE quality_gate_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    quality_gate_id UUID NOT NULL REFERENCES quality_gates(id) ON DELETE CASCADE,
    passed BOOLEAN NOT NULL,
    action VARCHAR(20) NOT NULL,
    health_score INTEGER,
    details JSONB DEFAULT '{}',
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_qge_artifact ON quality_gate_evaluations(artifact_id);
CREATE INDEX idx_qge_gate ON quality_gate_evaluations(quality_gate_id);
CREATE INDEX idx_qge_evaluated ON quality_gate_evaluations(evaluated_at DESC);

-- ---------------------------------------------------------------------------
-- Default quality gate (disabled by default, admin opts in)
-- ---------------------------------------------------------------------------
INSERT INTO quality_gates (name, description, min_health_score, max_critical_issues, enforce_on_promotion, action, is_enabled)
VALUES (
    'Default Quality Gate',
    'Requires minimum health score of 50 and no critical issues',
    50,
    0,
    true,
    'warn',
    false
);
