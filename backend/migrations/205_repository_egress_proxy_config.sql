-- Per-repository outbound (egress) proxy configuration (#2469, #2811).
--
-- The settings reuse the existing generic `repository_config` key/value table
-- (created in 017) rather than adding columns, following the precedent set by
-- the per-repo custom User-Agent (#2080) and the upstream credentials
-- (`upstream_auth_type` / `upstream_auth_credentials`). Three keys are
-- reserved:
--
--   egress_proxy_mode      'inherit' | 'direct' | 'explicit'   (plaintext)
--   egress_proxy_url       the proxy URL                       (ENCRYPTED)
--   egress_proxy_no_proxy  comma-separated bypass list          (plaintext)
--
-- `egress_proxy_url` may embed `user:pass@` userinfo, so it is stored as
-- hex-encoded AES-256-GCM ciphertext using the same envelope as
-- `upstream_auth_credentials`. No schema change is required to hold it; this
-- migration records the contract on the table so that a future reader of the
-- schema, or an operator inspecting rows by hand, knows which values are
-- ciphertext and must never be dumped, logged, or exported in the clear.

COMMENT ON TABLE repository_config IS
    'Per-repository key/value settings. Some values are ENCRYPTED at rest '
    '(hex-encoded AES-256-GCM) and must never be logged or returned by an API '
    'in raw form: upstream_auth_credentials (#017) and egress_proxy_url '
    '(#2469). All other values are plaintext configuration.';

COMMENT ON COLUMN repository_config.value IS
    'Setting value. Ciphertext for the encrypted keys listed on the table '
    'comment (upstream_auth_credentials, egress_proxy_url); plaintext '
    'otherwise.';
