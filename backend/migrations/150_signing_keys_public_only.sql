-- Allow public-only trust anchors in signing_keys.
--
-- Debian/Ubuntu upstream verification needs the archive public key without a
-- corresponding private key. Existing signing keys keep their encrypted
-- private material; newly imported trust anchors store NULL.
ALTER TABLE signing_keys
    ALTER COLUMN private_key_enc DROP NOT NULL;

COMMENT ON COLUMN signing_keys.private_key_enc IS
    'Encrypted private key material for signing keys; NULL for public-only trust anchors used only for upstream verification';
