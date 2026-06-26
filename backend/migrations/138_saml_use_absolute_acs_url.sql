-- Opt-in flag: when true, the SAML AuthnRequest emits an absolute ACS URL
-- (scheme://host/api/v1/auth/sso/saml/<id>/acs) instead of the relative
-- "/api/v1/auth/sso/saml/<id>/acs" path that the codebase has always sent.
--
-- Some IdPs (notably stricter SAML 2.0 implementations and certain enterprise
-- deployments) reject a relative AssertionConsumerServiceURL outright, while
-- others happily resolve it against the SP host. Toggling the behaviour
-- per-provider lets operators turn on the absolute form for the IdPs that
-- require it without changing the wire format for every other provider — the
-- default stays false so existing SAML configurations keep their exact
-- pre-138 wire format with no behavioral change on upgrade.
--
-- When the flag is true, the absolute URL is built from the same external
-- base URL the rest of the SSO stack already uses (AK_EXTERNAL_URL env,
-- otherwise X-Forwarded-{Proto,Host} / Host headers — see
-- backend/src/api/extractors.rs::RequestBaseUrl), so a single deployment knob
-- already governs what host gets emitted.
ALTER TABLE saml_configs
    ADD COLUMN IF NOT EXISTS use_absolute_acs_url BOOLEAN NOT NULL DEFAULT false;
