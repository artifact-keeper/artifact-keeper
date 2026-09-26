-- External trust attestations for signing keys.
-- Supports workflows where a root key (e.g. on YubiKey) signs an AK-managed
-- signing key out-of-band, and AK verifies/stores that attestation.

CREATE TABLE signing_key_trust_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signing_key_id UUID NOT NULL UNIQUE REFERENCES signing_keys(id) ON DELETE CASCADE,
    issuer_name VARCHAR(255),
    issuer_public_key_armored TEXT NOT NULL,
    issuer_fingerprint VARCHAR(64) NOT NULL,
    payload TEXT NOT NULL,
    signature_armored TEXT NOT NULL,
    signature_type VARCHAR(32) NOT NULL DEFAULT 'openpgp_detached',
    verification_status VARCHAR(32) NOT NULL DEFAULT 'verified'
        CHECK (verification_status IN ('verified', 'invalid', 'unverified')),
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_signing_key_attestations_fingerprint
    ON signing_key_trust_attestations(issuer_fingerprint);
