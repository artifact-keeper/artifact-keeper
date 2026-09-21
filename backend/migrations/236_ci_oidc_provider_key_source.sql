-- CI OIDC: let a provider carry its own JWKS instead of discovering it (#1246).
--
-- Verification has only ever found signing keys through OIDC discovery at the
-- issuer. An on-prem Kubernetes cluster's issuer (kubeadm default
-- `https://kubernetes.default.svc.cluster.local`) and AKS without
-- `--enable-oidc-issuer` are not reachable from Artifact Keeper, so their
-- ServiceAccount tokens could not be verified at all.
--
--   key_source = 'discovery'  — keys come from the issuer's discovery document,
--                                exactly as before. Every existing row gets
--                                this value from the column default.
--   key_source = 'static'     — keys come from `static_jwks` only; no network
--                                request is made to the issuer.
--
-- `static_jwks` holds a whole JWKS (`{"keys": [...]}`), because that is what
-- `kubectl get --raw /openid/v1/jwks` returns and because several keys express
-- rotation overlap natively. It is replaced as a whole on update, so it lives
-- on the provider row rather than in a keys table. Public keys only: the
-- application refuses private members at save time.
--
-- `ci_oidc_providers` is a handful of operator-created rows and not a hot
-- table (`migration_safety::HOT_TABLES`), so a constant default and CHECK
-- constraints validated inline are free here.

ALTER TABLE ci_oidc_providers
    ADD COLUMN IF NOT EXISTS key_source VARCHAR(16) NOT NULL DEFAULT 'discovery',
    ADD COLUMN IF NOT EXISTS static_jwks JSONB;

ALTER TABLE ci_oidc_providers
    ADD CONSTRAINT ci_oidc_providers_key_source_check
        CHECK (key_source IN ('discovery', 'static')),
    ADD CONSTRAINT ci_oidc_providers_static_jwks_check
        CHECK ((key_source = 'static') = (static_jwks IS NOT NULL));
