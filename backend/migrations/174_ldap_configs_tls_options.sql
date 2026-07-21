-- #2782 (LDAPS TLS trust options, per provider): surface the LDAP TLS trust
-- controls in the per-provider SSO configuration instead of only the global
-- `LDAP_INSECURE_TLS` / `LDAP_CA_CERT_PATH` environment variables.
--
-- Two new columns on `ldap_configs`:
--
--   * `insecure_skip_verify` — opt-in toggle to skip TLS certificate
--     verification for LDAPS/STARTTLS (matches Harbor's "insecure skip
--     verify"). Defaults FALSE (secure-by-default); verification stays on
--     unless an operator explicitly turns it off for this provider. When
--     true, the login and test-connection paths log a loud warning.
--
--   * `ca_certificate` — inline PEM CA certificate/chain trusted for this
--     provider's LDAPS/STARTTLS handshake, so a customer using a private CA
--     no longer has to import the whole chain into the host trust store or
--     mount a file and set an env var. NULL/empty means "use the system trust
--     store (plus any `LDAP_CA_CERT_PATH` fallback)".
--
-- The global environment variables continue to work as a fallback so existing
-- deployments are unaffected: the effective skip-verify is
-- `insecure_skip_verify OR LDAP_INSECURE_TLS`, and the inline `ca_certificate`
-- takes precedence over the env-configured CA path when both are present.
--
-- Reversible: DROP COLUMN restores the pre-#2782 shape.
ALTER TABLE ldap_configs
    ADD COLUMN IF NOT EXISTS insecure_skip_verify BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS ca_certificate TEXT;
