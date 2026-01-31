-- Repository signing keys for GPG/RSA signatures on package metadata
-- Used by Debian/APT, RPM/YUM, Alpine/APK, and Conda repositories

CREATE TABLE signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    -- NULL repository_id means this is a global/shared key
    name VARCHAR(255) NOT NULL,
    key_type VARCHAR(50) NOT NULL CHECK (key_type IN ('gpg', 'rsa', 'ed25519')),
    -- GPG key fields
    fingerprint VARCHAR(64),              -- GPG key fingerprint (hex)
    key_id VARCHAR(16),                   -- Short key ID (last 8 hex chars)
    -- Key material (encrypted at rest using CredentialEncryption)
    public_key_pem TEXT NOT NULL,         -- Public key in PEM/ASCII-armored format
    private_key_enc BYTEA NOT NULL,       -- Private key encrypted with app secret
    -- Metadata
    algorithm VARCHAR(50) NOT NULL DEFAULT 'rsa4096',  -- rsa2048, rsa4096, ed25519
    uid_name VARCHAR(255),                -- GPG UID name (e.g., "Artifact Keeper Repo Signing")
    uid_email VARCHAR(255),               -- GPG UID email
    expires_at TIMESTAMP WITH TIME ZONE,  -- Key expiration (NULL = no expiry)
    is_active BOOLEAN NOT NULL DEFAULT true,
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    rotated_from UUID REFERENCES signing_keys(id), -- Previous key if this is a rotation
    last_used_at TIMESTAMP WITH TIME ZONE
);

-- Index for looking up active keys by repository
CREATE INDEX idx_signing_keys_repo ON signing_keys(repository_id) WHERE is_active = true;
CREATE INDEX idx_signing_keys_fingerprint ON signing_keys(fingerprint) WHERE fingerprint IS NOT NULL;

-- Repository signing configuration
CREATE TABLE repository_signing_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL UNIQUE REFERENCES repositories(id) ON DELETE CASCADE,
    signing_key_id UUID REFERENCES signing_keys(id),
    sign_metadata BOOLEAN NOT NULL DEFAULT false,     -- Sign Release/repomd.xml/APKINDEX
    sign_packages BOOLEAN NOT NULL DEFAULT false,     -- Verify package signatures on upload
    require_signatures BOOLEAN NOT NULL DEFAULT false, -- Reject unsigned uploads
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Audit log for key operations
CREATE TABLE signing_key_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signing_key_id UUID NOT NULL REFERENCES signing_keys(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL, -- 'created', 'rotated', 'revoked', 'used_for_signing', 'exported'
    performed_by UUID REFERENCES users(id),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signing_key_audit_key ON signing_key_audit(signing_key_id);
CREATE INDEX idx_signing_key_audit_time ON signing_key_audit(created_at);
