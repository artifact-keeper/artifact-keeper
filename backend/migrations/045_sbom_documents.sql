-- SBOM (Software Bill of Materials) document storage
-- Supports CycloneDX and SPDX formats

CREATE TABLE sbom_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,

    -- SBOM format and version
    format VARCHAR(20) NOT NULL CHECK (format IN ('cyclonedx', 'spdx')),
    format_version VARCHAR(20) NOT NULL, -- e.g., '1.4', '1.5' for CycloneDX, '2.3' for SPDX
    spec_version VARCHAR(20), -- Full spec version like 'CycloneDX 1.5' or 'SPDX-2.3'

    -- The actual SBOM content
    content JSONB NOT NULL,

    -- Component summary for quick queries
    component_count INT NOT NULL DEFAULT 0,
    dependency_count INT NOT NULL DEFAULT 0,
    license_count INT NOT NULL DEFAULT 0,

    -- Extracted licenses for policy checking
    licenses TEXT[] DEFAULT '{}',

    -- Hash of the SBOM content for deduplication
    content_hash VARCHAR(64) NOT NULL,

    -- Generation metadata
    generator VARCHAR(100), -- e.g., 'syft', 'cdxgen', 'trivy'
    generator_version VARCHAR(50),

    -- Timestamps
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX idx_sbom_artifact_id ON sbom_documents(artifact_id);
CREATE INDEX idx_sbom_repository_id ON sbom_documents(repository_id);
CREATE INDEX idx_sbom_format ON sbom_documents(format);
CREATE INDEX idx_sbom_content_hash ON sbom_documents(content_hash);
CREATE INDEX idx_sbom_licenses ON sbom_documents USING gin(licenses);
CREATE INDEX idx_sbom_generated_at ON sbom_documents(generated_at DESC);

-- Unique constraint: one SBOM per format per artifact
CREATE UNIQUE INDEX idx_sbom_artifact_format ON sbom_documents(artifact_id, format);

-- SBOM components table for efficient querying
CREATE TABLE sbom_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id UUID NOT NULL REFERENCES sbom_documents(id) ON DELETE CASCADE,

    -- Component identification
    name VARCHAR(500) NOT NULL,
    version VARCHAR(200),
    purl VARCHAR(1000), -- Package URL (e.g., pkg:npm/lodash@4.17.21)
    cpe VARCHAR(500), -- CPE identifier

    -- Component type
    component_type VARCHAR(50), -- library, application, framework, file, etc.

    -- License info
    licenses TEXT[] DEFAULT '{}',

    -- Hashes for vulnerability matching
    sha256 VARCHAR(64),
    sha1 VARCHAR(40),
    md5 VARCHAR(32),

    -- Supplier/author info
    supplier VARCHAR(500),
    author VARCHAR(500),

    -- External references (URLs, advisories, etc.)
    external_refs JSONB DEFAULT '[]',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sbom_components_sbom_id ON sbom_components(sbom_id);
CREATE INDEX idx_sbom_components_name ON sbom_components(name);
CREATE INDEX idx_sbom_components_purl ON sbom_components(purl);
CREATE INDEX idx_sbom_components_licenses ON sbom_components USING gin(licenses);

-- CVE history for retroactive tracking
CREATE TABLE cve_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    sbom_id UUID REFERENCES sbom_documents(id) ON DELETE SET NULL,
    component_id UUID REFERENCES sbom_components(id) ON DELETE SET NULL,
    scan_result_id UUID REFERENCES scan_results(id) ON DELETE SET NULL,

    -- CVE identification
    cve_id VARCHAR(30) NOT NULL,

    -- Affected component info
    affected_component VARCHAR(500),
    affected_version VARCHAR(200),
    fixed_version VARCHAR(200),

    -- Severity at time of detection
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),

    -- Timeline tracking
    cve_published_at TIMESTAMPTZ, -- When the CVE was first published (from NVD)
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- When we first found it
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- Most recent scan that found it

    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'acknowledged', 'false_positive')),
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cve_history_artifact_id ON cve_history(artifact_id);
CREATE INDEX idx_cve_history_cve_id ON cve_history(cve_id);
CREATE INDEX idx_cve_history_status ON cve_history(status);
CREATE INDEX idx_cve_history_first_detected ON cve_history(first_detected_at DESC);
CREATE INDEX idx_cve_history_severity ON cve_history(severity);
CREATE UNIQUE INDEX idx_cve_history_artifact_cve ON cve_history(artifact_id, cve_id);

-- License policies table
CREATE TABLE license_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE, -- NULL = global policy

    name VARCHAR(200) NOT NULL,
    description TEXT,

    -- Lists of licenses
    allowed_licenses TEXT[] DEFAULT '{}', -- Allowlist (empty = allow all)
    denied_licenses TEXT[] DEFAULT '{}', -- Denylist (takes precedence)

    -- Unknown license handling
    allow_unknown BOOLEAN NOT NULL DEFAULT true,

    -- Action on violation
    action VARCHAR(20) NOT NULL DEFAULT 'warn' CHECK (action IN ('allow', 'warn', 'block')),

    is_enabled BOOLEAN NOT NULL DEFAULT true,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_license_policies_repo ON license_policies(repository_id);

-- Insert default global license policy
INSERT INTO license_policies (name, description, allowed_licenses, denied_licenses, allow_unknown, action, is_enabled)
VALUES (
    'Default License Policy',
    'Default policy allowing common permissive licenses',
    ARRAY['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'CC0-1.0', 'Unlicense', '0BSD'],
    ARRAY['GPL-3.0', 'AGPL-3.0', 'GPL-3.0-only', 'AGPL-3.0-only'],
    true,
    'warn',
    false -- disabled by default
);
