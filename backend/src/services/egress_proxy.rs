//! Per-repository outbound (egress) proxy configuration (#2469, #2811).
//!
//! A remote repository can route its upstream traffic through a specific
//! egress proxy, so segmented-network deployments can send different
//! upstreams out via different network paths.
//!
//! # Storage
//!
//! Settings live in the generic `repository_config` key/value table, exactly
//! like the per-repo `custom_user_agent` (#2080) and the upstream credentials
//! (`upstream_auth_type` / `upstream_auth_credentials`). Three keys:
//!
//! * [`EGRESS_PROXY_MODE_KEY`] — `inherit` / `direct` / `explicit` (plaintext,
//!   not a secret).
//! * [`EGRESS_PROXY_URL_KEY`] — the proxy URL, **encrypted at rest** with the
//!   same `encrypt_credentials` + hex envelope `upstream_auth_credentials`
//!   uses, because a proxy URL may embed `user:pass@` userinfo.
//! * [`EGRESS_PROXY_NO_PROXY_KEY`] — the per-repo `no_proxy` bypass list
//!   (plaintext, not a secret).
//!
//! # Precedence (explicit, see [`EgressProxyMode`])
//!
//! A per-repository setting **overrides** the process-wide `HTTP_PROXY` /
//! `HTTPS_PROXY` / `NO_PROXY` environment configuration for that repository —
//! it never composes with it. `inherit` (the default, and the state of every
//! pre-existing repository) is the only mode that uses the environment.
//!
//! # Secrets
//!
//! The proxy URL is treated as credential material end to end:
//! * encrypted at rest (above),
//! * never serialized into an API response in raw form — every read path goes
//!   through [`redact_proxy_url`], which replaces any userinfo with `***`,
//! * never logged — [`EgressProxyConfig`] has a hand-written [`std::fmt::Debug`]
//!   that redacts, so a `?config` tracing field or a `{:?}` in an error cannot
//!   leak it, and
//! * never handed to `reqwest` inside the proxy URL string:
//!   [`split_proxy_userinfo`] strips the userinfo and the credentials are
//!   applied via `reqwest::Proxy::basic_auth`, so the `Proxy`'s own `Debug`
//!   rendering carries no secret either.

use std::collections::HashSet;
use std::fmt;

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::auth_config_service::encryption_key;
use crate::services::upstream_auth::{decrypt_credentials_hex, encrypt_credentials_hex};

/// `repository_config` key holding the egress-proxy mode.
pub const EGRESS_PROXY_MODE_KEY: &str = "egress_proxy_mode";
/// `repository_config` key holding the **encrypted** egress-proxy URL.
pub const EGRESS_PROXY_URL_KEY: &str = "egress_proxy_url";
/// `repository_config` key holding the per-repo `no_proxy` bypass list.
pub const EGRESS_PROXY_NO_PROXY_KEY: &str = "egress_proxy_no_proxy";

/// Placeholder substituted for proxy-URL userinfo in every user-visible
/// rendering (API responses, logs, audit entries, error messages).
pub const REDACTED_USERINFO: &str = "***";

/// Maximum accepted length of a configured proxy URL. Bounds what a single
/// `repository_config` row can hold and what has to be parsed on the fetch
/// hot path.
const MAX_PROXY_URL_LEN: usize = 2048;

/// Maximum accepted length of a per-repo `no_proxy` list.
const MAX_NO_PROXY_LEN: usize = 4096;

/// How a repository resolves its outbound proxy. This is the **precedence
/// decision** for #2469 / #2811, stated as a closed enum rather than left
/// implicit:
///
/// | mode | behaviour |
/// |------|-----------|
/// | [`Inherit`](EgressProxyMode::Inherit) | Use the process-wide `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment, i.e. whatever the deployment already does. The default, and the state of every repository that predates this feature. |
/// | [`Direct`](EgressProxyMode::Direct) | Bypass the environment proxy entirely and connect straight out. Answers the other half of #2811 ("certain repos require a proxy, others do not") for a deployment whose *global* posture is proxied. |
/// | [`Explicit`](EgressProxyMode::Explicit) | Use this repository's own proxy URL and `no_proxy` list. The environment proxy variables are **ignored**, not merged. |
///
/// A per-repo setting therefore *overrides* the global environment; it never
/// composes with it. Merging was rejected deliberately: composing two
/// `no_proxy` lists and two proxy URLs has no unambiguous meaning, and an
/// egress control whose effective value depends on invisible process
/// environment is exactly the kind of ambiguity that produces a silent egress
/// bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressProxyMode {
    /// Follow the process-wide proxy environment (default).
    #[default]
    Inherit,
    /// Never use a proxy for this repository, even when the environment sets one.
    Direct,
    /// Use this repository's own configured proxy.
    Explicit,
}

impl EgressProxyMode {
    /// Stable wire/storage token for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            EgressProxyMode::Inherit => "inherit",
            EgressProxyMode::Direct => "direct",
            EgressProxyMode::Explicit => "explicit",
        }
    }

    /// Parse a stored/request mode token. Unknown and absent values fall back
    /// to [`EgressProxyMode::Inherit`] via [`parse_mode`]; this returns `None`
    /// so callers that must reject bad *input* (the API handler) can.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "inherit" => Some(EgressProxyMode::Inherit),
            "direct" => Some(EgressProxyMode::Direct),
            "explicit" => Some(EgressProxyMode::Explicit),
            _ => None,
        }
    }
}

/// A repository's resolved egress-proxy configuration.
///
/// `proxy_url` is SECRET (it may carry `user:pass@`). The hand-written
/// [`fmt::Debug`] below is what keeps it out of logs and error messages; do
/// not replace it with `#[derive(Debug)]`.
#[derive(Clone, PartialEq, Eq)]
pub struct EgressProxyConfig {
    pub mode: EgressProxyMode,
    /// Full proxy URL including any userinfo. `None` unless `mode` is
    /// [`EgressProxyMode::Explicit`].
    pub proxy_url: Option<String>,
    /// Per-repo `no_proxy` bypass list (comma-separated hosts/CIDRs).
    pub no_proxy: Option<String>,
}

impl fmt::Debug for EgressProxyConfig {
    /// Redacting `Debug`: a `tracing` field, an `unwrap` panic message or a
    /// `{:?}` in an error string must not print proxy credentials.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressProxyConfig")
            .field("mode", &self.mode)
            .field(
                "proxy_url",
                &self.proxy_url.as_deref().map(redact_proxy_url),
            )
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

impl EgressProxyConfig {
    /// The inert default: follow the process environment, no per-repo proxy.
    pub fn inherit() -> Self {
        Self {
            mode: EgressProxyMode::Inherit,
            proxy_url: None,
            no_proxy: None,
        }
    }

    /// True when this config changes anything about how the repository's
    /// outbound requests are routed relative to the shared client. `Inherit`
    /// is a no-op and lets the caller reuse the shared client.
    pub fn overrides_default_routing(&self) -> bool {
        !matches!(self.mode, EgressProxyMode::Inherit)
    }

    /// The redacted proxy URL, safe for API responses, logs and audit entries.
    pub fn redacted_proxy_url(&self) -> Option<String> {
        self.proxy_url.as_deref().map(redact_proxy_url)
    }

    /// True when the configured proxy URL carries userinfo (i.e. proxy
    /// credentials are stored). Exposed so an API response can say
    /// "credentials are configured" without revealing them, mirroring
    /// `upstream_auth_configured`.
    pub fn has_proxy_credentials(&self) -> bool {
        self.proxy_url
            .as_deref()
            .is_some_and(|u| proxy_userinfo(u).is_some())
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (no DB, no network) — unit-testable in isolation.
// ---------------------------------------------------------------------------

/// Resolve the effective mode from what is stored, tolerating absent or
/// unrecognised values by failing **safe** (to `Inherit`, the historical
/// behaviour) rather than dropping the proxy silently in some other way.
///
/// `Explicit` additionally requires a URL to actually be present: a row that
/// says `explicit` with no stored URL is a half-written config, and treating
/// it as `Inherit` would silently send traffic out via the environment proxy.
/// It resolves to `Direct` instead — the fail-closed reading, since the
/// operator's stated intent was "do not use the ambient path".
pub fn resolve_mode(stored_mode: Option<&str>, has_url: bool) -> EgressProxyMode {
    match stored_mode.and_then(EgressProxyMode::parse) {
        Some(EgressProxyMode::Explicit) if has_url => EgressProxyMode::Explicit,
        Some(EgressProxyMode::Explicit) => EgressProxyMode::Direct,
        Some(other) => other,
        None => EgressProxyMode::Inherit,
    }
}

/// Extract the `user:pass` userinfo from a proxy URL, if present.
///
/// Returns `(username, password)` with the password defaulting to an empty
/// string when the URL carries only a username.
pub fn proxy_userinfo(proxy_url: &str) -> Option<(String, String)> {
    let parsed = reqwest::Url::parse(proxy_url).ok()?;
    let user = parsed.username();
    if user.is_empty() && parsed.password().is_none() {
        return None;
    }
    Some((
        percent_decode(user),
        percent_decode(parsed.password().unwrap_or("")),
    ))
}

/// Percent-decode a userinfo component, falling back to the raw text when the
/// bytes are not valid UTF-8.
///
/// `reqwest::Url` stores userinfo percent-encoded, so a password containing
/// `@`, `:` or `/` (which an operator MUST encode for the URL to parse at all)
/// only round-trips to the value the proxy actually expects after decoding.
/// Written out longhand rather than pulling in `percent-encoding` as a new
/// direct dependency for one call site.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| value.to_string())
}

/// Split a proxy URL into `(url_without_userinfo, credentials)`.
///
/// The credential-free URL is what gets handed to `reqwest::Proxy::all`, so
/// the secret never lives inside the `Proxy`'s URL string (and therefore never
/// appears in its `Debug` rendering or in a reqwest error). The credentials are
/// applied separately via `Proxy::basic_auth`.
pub fn split_proxy_userinfo(proxy_url: &str) -> Result<(String, Option<(String, String)>)> {
    let mut parsed = reqwest::Url::parse(proxy_url)
        .map_err(|_| AppError::Validation("Invalid egress proxy URL".to_string()))?;
    let creds = proxy_userinfo(proxy_url);
    // Clear password before username so the `@` separator is removed cleanly,
    // mirroring `proxy_service::redact_url_for_diagnostics`.
    let _ = parsed.set_password(None);
    let _ = parsed.set_username("");
    Ok((parsed.to_string(), creds))
}

/// Replace any userinfo in a proxy URL with [`REDACTED_USERINFO`], keeping the
/// scheme, host and port (which are NOT secret and are the useful part of a
/// read-back).
///
/// `http://svc:hunter2@proxy.corp:3128` → `http://***@proxy.corp:3128/`
///
/// Unparseable input degrades to a conservative string-level strip so a value
/// that somehow bypassed validation still cannot leak a password.
pub fn redact_proxy_url(proxy_url: &str) -> String {
    if let Ok(mut parsed) = reqwest::Url::parse(proxy_url) {
        let had_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
        let _ = parsed.set_password(None);
        let _ = parsed.set_username("");
        // Also drop query/fragment: a proxy URL should not carry them, and if
        // one does it may hold a token (same reasoning as
        // `redact_url_for_diagnostics`).
        parsed.set_query(None);
        parsed.set_fragment(None);
        if !had_userinfo {
            return parsed.to_string();
        }
        // Re-insert the placeholder so the read-back makes it visible that
        // credentials ARE configured.
        let rendered = parsed.to_string();
        return match rendered.split_once("://") {
            Some((scheme, rest)) => format!("{scheme}://{REDACTED_USERINFO}@{rest}"),
            None => rendered,
        };
    }

    // Fallback for input `reqwest::Url` cannot parse: strip everything up to
    // and including the last `@` of the authority.
    let (scheme, rest) = match proxy_url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, proxy_url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let stripped = match authority.rfind('@') {
        Some(i) => format!("{REDACTED_USERINFO}@{}", &authority[i + 1..]),
        None => authority.to_string(),
    };
    match scheme {
        Some(s) => format!("{s}://{stripped}{tail}"),
        None => format!("{stripped}{tail}"),
    }
}

/// The bare host of a proxy URL, lowercased — the token used to exempt the
/// proxy's own address from the SSRF DNS guard (see [`validate_proxy_url`]).
pub fn proxy_host(proxy_url: &str) -> Option<String> {
    reqwest::Url::parse(proxy_url)
        .ok()?
        .host_str()
        .map(|h| h.to_ascii_lowercase())
}

/// Validate a per-repository egress proxy URL.
///
/// # Trust class (SSRF)
///
/// The proxy URL is checked with [`OutboundUrlContext::TrustedInternal`]
/// semantics: RFC1918 / CGNAT / IPv6 unique-local addresses are **permitted**
/// (a corporate egress proxy legitimately lives on the internal network — that
/// is the entire point of the feature), while cloud-metadata endpoints,
/// loopback, link-local and unspecified addresses stay **hard-blocked**.
///
/// Permitting private addresses here is safe for the same reason it is safe for
/// the scanner-adapter URL (#2389): writing this field requires repository
/// `admin` (the `set_egress_proxy` handler enforces the same gate as
/// `set_upstream_auth`, #2603), so it is operator configuration, not
/// attacker-influenceable input. Keeping the metadata / loopback / link-local
/// hard-blocks is what stops the proxy slot from being repurposed as an SSRF
/// primitive: an admin cannot point a repository at `http://169.254.169.254/`
/// or `http://127.0.0.1:22/` and use upstream fetches as a metadata reader or a
/// localhost port-scan oracle.
///
/// [`OutboundUrlContext::TrustedInternal`]: crate::api::validation::OutboundUrlContext::TrustedInternal
pub fn validate_proxy_url(proxy_url: &str) -> Result<()> {
    let trimmed = proxy_url.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(
            "Egress proxy URL must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_PROXY_URL_LEN {
        return Err(AppError::Validation(format!(
            "Egress proxy URL must be at most {MAX_PROXY_URL_LEN} characters"
        )));
    }

    // Scheme allowlist. `validate_outbound_internal_url` already rejects
    // non-http(s), but check first so the error names the actual problem
    // rather than the generic "must use http or https".
    let scheme = trimmed.split("://").next().unwrap_or("");
    if !matches!(scheme, "http" | "https") {
        return Err(AppError::Validation(
            "Egress proxy URL must use http or https (socks proxies are not supported)".to_string(),
        ));
    }

    crate::api::validation::validate_outbound_internal_url(trimmed, "Egress proxy URL")?;

    // A proxy URL is an endpoint, not a resource: reject anything carrying a
    // path/query/fragment so a mis-pasted value fails loudly instead of being
    // silently truncated by reqwest.
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|_| AppError::Validation("Invalid egress proxy URL".to_string()))?;
    if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() || parsed.fragment().is_some()
    {
        return Err(AppError::Validation(
            "Egress proxy URL must be a bare scheme://host[:port] endpoint".to_string(),
        ));
    }

    Ok(())
}

/// Validate a per-repo `no_proxy` bypass list. Comma-separated hosts, domain
/// suffixes (`.corp.example`) or CIDRs, as accepted by `reqwest::NoProxy`.
pub fn validate_no_proxy(no_proxy: &str) -> Result<()> {
    if no_proxy.len() > MAX_NO_PROXY_LEN {
        return Err(AppError::Validation(format!(
            "Egress proxy no_proxy list must be at most {MAX_NO_PROXY_LEN} characters"
        )));
    }
    // Reject control characters and whitespace-only entries; `reqwest::NoProxy`
    // silently ignores malformed entries, which would turn a typo into an
    // unnoticed egress bypass.
    for entry in no_proxy.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if entry
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b == b' ' || b == b'\t')
        {
            return Err(AppError::Validation(format!(
                "Invalid no_proxy entry: {entry:?}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

/// Build a `reqwest::Client` that routes this repository's outbound requests
/// per `config`.
///
/// Starts from [`http_client::base_client_builder`] so the custom-CA handling,
/// redirect SSRF policy, timeouts and content-encoding posture are byte-for-byte
/// what every other upstream fetch gets. Only the proxy routing and the DNS
/// resolver's proxy-host exemption differ.
///
/// [`http_client::base_client_builder`]: crate::services::http_client::base_client_builder
pub fn build_repo_client(config: &EgressProxyConfig) -> Result<reqwest::Client> {
    let mut builder = crate::services::http_client::base_client_builder();

    match config.mode {
        EgressProxyMode::Inherit => {
            // Caller should not have reached here (see
            // `overrides_default_routing`), but build the environment-following
            // client rather than surprising them.
        }
        EgressProxyMode::Direct => {
            // Override, not compose: ignore HTTP_PROXY/HTTPS_PROXY/NO_PROXY.
            builder = builder.no_proxy();
            // No proxy is dialed, so nothing may be exempted from the guard.
            builder = builder.dns_resolver(
                crate::services::ssrf_dns::ssrf_guard_resolver_exempting(HashSet::new()),
            );
        }
        EgressProxyMode::Explicit => {
            let raw = config.proxy_url.as_deref().ok_or_else(|| {
                AppError::Config("Egress proxy mode is 'explicit' but no URL is set".to_string())
            })?;
            let (sanitized, creds) = split_proxy_userinfo(raw)?;

            let mut proxy = reqwest::Proxy::all(&sanitized).map_err(|e| {
                // `e` renders the URL it was given — which is already
                // credential-free — but redact defensively anyway.
                AppError::Validation(format!(
                    "Invalid egress proxy URL {}: {e}",
                    redact_proxy_url(&sanitized)
                ))
            })?;
            if let Some((user, pass)) = creds {
                proxy = proxy.basic_auth(&user, &pass);
            }
            if let Some(list) = config.no_proxy.as_deref() {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(list));
            }

            // `.no_proxy()` FIRST clears any environment-derived proxy, then
            // `.proxy()` installs this repository's own. Without the clear,
            // reqwest would still consult the environment for schemes this
            // proxy does not cover — i.e. the per-repo setting would compose
            // with the global one instead of overriding it.
            builder = builder.no_proxy().proxy(proxy);

            // The proxy's own address must be reachable or every fetch for this
            // repository fails closed at the SSRF DNS guard (#2570). Exempt
            // exactly this host — full-host equality, no suffix matching — and
            // nothing else.
            let mut exempt = HashSet::new();
            if let Some(host) = proxy_host(&sanitized) {
                exempt.insert(host);
            }
            builder = builder.dns_resolver(
                crate::services::ssrf_dns::ssrf_guard_resolver_exempting(exempt),
            );
        }
    }

    builder
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build egress-proxy HTTP client: {e}")))
}

/// Re-apply the destination SSRF check that routing through a proxy would
/// otherwise skip.
///
/// **Why this exists.** When `reqwest` routes a request through a proxy it does
/// not resolve the destination host locally at all — it dials the proxy and
/// hands over the hostname (`CONNECT host:443`, or an absolute-form request
/// line for plain HTTP). The connect-time SSRF DNS resolver
/// (`ssrf_dns::SsrfGuardResolver`, defense layer 2 in
/// [`crate::api::validation`]) therefore never sees the destination, and a
/// per-repo proxy would silently remove that layer for the repository that
/// configured one. This restores the equivalent check explicitly, before the
/// request is issued.
///
/// **Residual gap, stated plainly.** This is a string/literal-IP and
/// resolution-at-check-time test, so it cannot close DNS rebinding for proxied
/// requests the way the resolver does for direct ones — we are not the party
/// doing the final resolution. That matches the pre-existing "Residual gaps"
/// note in [`crate::api::validation`]; the mitigation for a proxied deployment
/// is the egress proxy's own allowlist, which is normally the reason the proxy
/// is there.
pub fn ensure_proxied_destination_allowed(target_url: &str) -> Result<()> {
    crate::api::validation::validate_outbound_url(target_url, "Upstream URL")
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Load a repository's egress-proxy configuration.
///
/// Returns [`EgressProxyConfig::inherit`] when nothing is configured, so
/// callers never have to distinguish "absent" from "explicitly inherit".
pub async fn load_egress_proxy(db: &PgPool, repo_id: Uuid) -> Result<EgressProxyConfig> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT key, value FROM repository_config \
         WHERE repository_id = $1 AND key = ANY($2)",
    )
    .bind(repo_id)
    .bind(vec![
        EGRESS_PROXY_MODE_KEY.to_string(),
        EGRESS_PROXY_URL_KEY.to_string(),
        EGRESS_PROXY_NO_PROXY_KEY.to_string(),
    ])
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut stored_mode: Option<String> = None;
    let mut encrypted_url: Option<String> = None;
    let mut no_proxy: Option<String> = None;
    for (key, value) in rows {
        let value = match value {
            Some(v) if !v.is_empty() => v,
            _ => continue,
        };
        match key.as_str() {
            EGRESS_PROXY_MODE_KEY => stored_mode = Some(value),
            EGRESS_PROXY_URL_KEY => encrypted_url = Some(value),
            EGRESS_PROXY_NO_PROXY_KEY => no_proxy = Some(value),
            _ => {}
        }
    }

    let proxy_url = match encrypted_url {
        Some(hex) => Some(decrypt_credentials_hex(&hex, &encryption_key())?),
        None => None,
    };

    let mode = resolve_mode(stored_mode.as_deref(), proxy_url.is_some());
    Ok(EgressProxyConfig {
        mode,
        // Only surface the URL for the mode that uses it, so a stale row left
        // behind by a mode change can never route traffic.
        proxy_url: match mode {
            EgressProxyMode::Explicit => proxy_url,
            _ => None,
        },
        no_proxy: match mode {
            EgressProxyMode::Explicit => no_proxy,
            _ => None,
        },
    })
}

/// Persist a repository's egress-proxy configuration, encrypting the URL.
pub async fn save_egress_proxy(
    db: &PgPool,
    repo_id: Uuid,
    config: &EgressProxyConfig,
) -> Result<()> {
    upsert(db, repo_id, EGRESS_PROXY_MODE_KEY, config.mode.as_str()).await?;

    match config.mode {
        EgressProxyMode::Explicit => {
            let url = config.proxy_url.as_deref().ok_or_else(|| {
                AppError::Validation("proxy_url is required when mode is 'explicit'".to_string())
            })?;
            let encrypted = encrypt_credentials_hex(url, &encryption_key());
            upsert(db, repo_id, EGRESS_PROXY_URL_KEY, &encrypted).await?;
            match config.no_proxy.as_deref() {
                Some(list) if !list.is_empty() => {
                    upsert(db, repo_id, EGRESS_PROXY_NO_PROXY_KEY, list).await?;
                }
                _ => delete_keys(db, repo_id, &[EGRESS_PROXY_NO_PROXY_KEY]).await?,
            }
        }
        // Leaving an encrypted URL behind for a repo switched to inherit/direct
        // would keep a secret at rest that nothing can read back. Drop it.
        _ => {
            delete_keys(
                db,
                repo_id,
                &[EGRESS_PROXY_URL_KEY, EGRESS_PROXY_NO_PROXY_KEY],
            )
            .await?
        }
    }
    Ok(())
}

/// Remove all egress-proxy configuration for a repository (back to `inherit`).
pub async fn remove_egress_proxy(db: &PgPool, repo_id: Uuid) -> Result<()> {
    delete_keys(
        db,
        repo_id,
        &[
            EGRESS_PROXY_MODE_KEY,
            EGRESS_PROXY_URL_KEY,
            EGRESS_PROXY_NO_PROXY_KEY,
        ],
    )
    .await
}

async fn upsert(db: &PgPool, repo_id: Uuid, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $3, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(key)
    .bind(value)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

async fn delete_keys(db: &PgPool, repo_id: Uuid, keys: &[&str]) -> Result<()> {
    sqlx::query("DELETE FROM repository_config WHERE repository_id = $1 AND key = ANY($2)")
        .bind(repo_id)
        .bind(keys.iter().map(|k| k.to_string()).collect::<Vec<_>>())
        .execute(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- mode parsing / precedence ------------------------------------

    #[test]
    fn mode_round_trips_through_its_token() {
        for mode in [
            EgressProxyMode::Inherit,
            EgressProxyMode::Direct,
            EgressProxyMode::Explicit,
        ] {
            assert_eq!(EgressProxyMode::parse(mode.as_str()), Some(mode));
        }
    }

    #[test]
    fn mode_parsing_is_case_insensitive_and_trims() {
        assert_eq!(
            EgressProxyMode::parse("  ExPlIcIt "),
            Some(EgressProxyMode::Explicit)
        );
        assert_eq!(EgressProxyMode::parse("socks"), None);
        assert_eq!(EgressProxyMode::parse(""), None);
    }

    #[test]
    fn default_mode_is_inherit_so_existing_repos_are_unchanged() {
        assert_eq!(EgressProxyMode::default(), EgressProxyMode::Inherit);
        assert_eq!(resolve_mode(None, false), EgressProxyMode::Inherit);
        assert_eq!(EgressProxyConfig::inherit().mode, EgressProxyMode::Inherit);
        assert!(!EgressProxyConfig::inherit().overrides_default_routing());
    }

    #[test]
    fn unrecognised_stored_mode_falls_back_to_inherit() {
        assert_eq!(resolve_mode(Some("wat"), true), EgressProxyMode::Inherit);
    }

    #[test]
    fn explicit_without_a_url_resolves_to_direct_not_inherit() {
        // Fail-closed: a half-written config must not silently fall back to
        // the ambient environment proxy.
        assert_eq!(
            resolve_mode(Some("explicit"), false),
            EgressProxyMode::Direct
        );
        assert_eq!(
            resolve_mode(Some("explicit"), true),
            EgressProxyMode::Explicit
        );
    }

    #[test]
    fn direct_mode_overrides_default_routing() {
        let cfg = EgressProxyConfig {
            mode: EgressProxyMode::Direct,
            proxy_url: None,
            no_proxy: None,
        };
        assert!(cfg.overrides_default_routing());
    }

    // ---- redaction -----------------------------------------------------

    fn explicit(url: &str) -> EgressProxyConfig {
        EgressProxyConfig {
            mode: EgressProxyMode::Explicit,
            proxy_url: Some(url.to_string()),
            no_proxy: None,
        }
    }

    #[test]
    fn redaction_removes_userinfo_but_keeps_host_and_port() {
        let out = redact_proxy_url("http://svc:hunter2@proxy.corp:3128");
        assert!(!out.contains("hunter2"), "password leaked: {out}");
        assert!(!out.contains("svc"), "username leaked: {out}");
        assert!(out.contains("proxy.corp"), "host lost: {out}");
        assert!(out.contains("3128"), "port lost: {out}");
        assert!(out.contains(REDACTED_USERINFO), "no marker: {out}");
    }

    #[test]
    fn redaction_leaves_a_credential_free_url_alone() {
        assert_eq!(
            redact_proxy_url("http://proxy.corp:3128"),
            "http://proxy.corp:3128/"
        );
        assert!(!redact_proxy_url("http://proxy.corp:3128").contains(REDACTED_USERINFO));
    }

    #[test]
    fn redaction_handles_username_only_and_odd_passwords() {
        for raw in [
            "http://svc@proxy.corp:3128",
            "http://svc:p%40ss%3Aword@proxy.corp:3128",
            "https://u:p@10.0.0.5:8080",
        ] {
            let out = redact_proxy_url(raw);
            assert!(!out.contains("p@ss"), "{raw} -> {out}");
            assert!(!out.contains("p%40ss"), "{raw} -> {out}");
            assert!(!out.contains("svc"), "{raw} -> {out}");
            assert!(!out.contains(":p@"), "{raw} -> {out}");
        }
    }

    #[test]
    fn redaction_of_unparseable_input_still_strips_credentials() {
        let out = redact_proxy_url("://svc:hunter2@proxy.corp:3128");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("proxy.corp"), "{out}");
    }

    /// The single most important test for #2469's secret handling: prove the
    /// password cannot surface through ANY of the renderings a proxy URL can
    /// reach — `Debug`, the API read-back accessor, or the URL handed to
    /// `reqwest`.
    #[test]
    fn proxy_credentials_are_redacted_everywhere_they_could_surface() {
        const SECRET: &str = "sup3rs3cret";
        let cfg = explicit(&format!("http://svc:{SECRET}@proxy.corp:3128"));

        // 1. Debug (tracing fields, panic messages, `{:?}` in errors).
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains(SECRET),
            "Debug leaked the password: {debug}"
        );
        assert!(debug.contains(REDACTED_USERINFO), "{debug}");

        // 2. The API read-back accessor.
        let redacted = cfg.redacted_proxy_url().expect("some");
        assert!(!redacted.contains(SECRET), "{redacted}");

        // 3. The URL actually handed to reqwest::Proxy::all.
        let (sanitized, creds) = split_proxy_userinfo(cfg.proxy_url.as_deref().unwrap()).unwrap();
        assert!(
            !sanitized.contains(SECRET),
            "sanitized proxy URL leaked the password: {sanitized}"
        );
        assert!(!sanitized.contains("svc"), "{sanitized}");
        assert_eq!(
            creds,
            Some(("svc".to_string(), SECRET.to_string())),
            "credentials must survive the split so basic_auth can apply them"
        );

        // 4. And the presence flag is still readable without the secret.
        assert!(cfg.has_proxy_credentials());
        assert!(!explicit("http://proxy.corp:3128").has_proxy_credentials());
    }

    #[test]
    fn split_preserves_percent_encoded_credentials() {
        let (sanitized, creds) =
            split_proxy_userinfo("http://us%3Aer:p%40ss@proxy.corp:3128").unwrap();
        assert_eq!(sanitized, "http://proxy.corp:3128/");
        assert_eq!(creds, Some(("us:er".to_string(), "p@ss".to_string())));
    }

    #[test]
    fn split_of_a_credential_free_url_yields_no_credentials() {
        let (sanitized, creds) = split_proxy_userinfo("http://proxy.corp:3128").unwrap();
        assert_eq!(sanitized, "http://proxy.corp:3128/");
        assert_eq!(creds, None);
    }

    #[test]
    fn percent_decode_handles_encoded_and_literal_text() {
        assert_eq!(percent_decode("p%40ss"), "p@ss");
        assert_eq!(percent_decode("us%3Aer"), "us:er");
        assert_eq!(percent_decode("plain"), "plain");
        // Malformed escapes are left alone rather than swallowing characters.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%2"), "%2");
    }

    #[test]
    fn proxy_host_is_lowercased() {
        assert_eq!(
            proxy_host("http://PROXY.Corp:3128").as_deref(),
            Some("proxy.corp")
        );
        assert_eq!(
            proxy_host("http://10.0.0.5:3128").as_deref(),
            Some("10.0.0.5")
        );
    }

    // ---- validation / SSRF --------------------------------------------

    #[test]
    fn a_normal_corporate_proxy_is_accepted() {
        // Public hostname and RFC1918 literal: both are the point of the feature.
        assert!(validate_proxy_url("http://proxy.corp.example.com:3128").is_ok());
        assert!(validate_proxy_url("http://10.0.0.5:3128").is_ok());
        assert!(validate_proxy_url("https://172.16.4.9:8443").is_ok());
        assert!(validate_proxy_url("http://svc:pw@proxy.corp.example.com:3128").is_ok());
    }

    #[test]
    fn cloud_metadata_endpoints_are_rejected_as_a_proxy() {
        for url in [
            "http://169.254.169.254",
            "http://169.254.169.254:80",
            // AWS IMDS over IPv6 lives inside the unique-local range that the
            // TrustedInternal class otherwise permits, so it needs (and now
            // has) its own hard block in `api::validation`.
            "http://[fd00:ec2::254]",
            "http://[fd00:ec2::254]:80",
            "http://192.0.0.192:3128",
            "http://100.100.100.200:3128",
            "http://metadata.google.internal:3128",
        ] {
            assert!(
                validate_proxy_url(url).is_err(),
                "metadata endpoint accepted as an egress proxy: {url}"
            );
        }
    }

    #[test]
    fn loopback_is_rejected_as_a_proxy() {
        for url in [
            "http://127.0.0.1:3128",
            "http://127.0.0.1:22",
            "http://[::1]:3128",
            "http://localhost:3128",
        ] {
            assert!(
                validate_proxy_url(url).is_err(),
                "loopback accepted as an egress proxy (localhost port-scan oracle): {url}"
            );
        }
    }

    #[test]
    fn link_local_is_rejected_as_a_proxy() {
        assert!(validate_proxy_url("http://169.254.1.1:3128").is_err());
        assert!(validate_proxy_url("http://[fe80::1]:3128").is_err());
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        for url in [
            "socks5://proxy.corp:1080",
            "socks5h://proxy.corp:1080",
            "ftp://proxy.corp:21",
            "file:///etc/passwd",
            "not-a-url",
        ] {
            assert!(validate_proxy_url(url).is_err(), "accepted: {url}");
        }
    }

    #[test]
    fn a_proxy_url_must_be_a_bare_endpoint() {
        assert!(validate_proxy_url("http://proxy.corp:3128/path").is_err());
        assert!(validate_proxy_url("http://proxy.corp:3128/?token=abc").is_err());
        assert!(validate_proxy_url("http://proxy.corp:3128#frag").is_err());
        // A bare trailing slash is fine.
        assert!(validate_proxy_url("http://proxy.corp:3128/").is_ok());
    }

    #[test]
    fn empty_and_oversized_proxy_urls_are_rejected() {
        assert!(validate_proxy_url("").is_err());
        assert!(validate_proxy_url("   ").is_err());
        let long = format!("http://{}.example.com", "a".repeat(MAX_PROXY_URL_LEN));
        assert!(validate_proxy_url(&long).is_err());
    }

    #[test]
    fn no_proxy_validation_rejects_control_characters() {
        assert!(validate_no_proxy("*.corp.example,10.0.0.0/8,localhost").is_ok());
        assert!(validate_no_proxy("").is_ok());
        assert!(validate_no_proxy("a\nb").is_err());
        assert!(validate_no_proxy("has space").is_err());
        assert!(validate_no_proxy(&"a,".repeat(MAX_NO_PROXY_LEN)).is_err());
    }

    // ---- client construction ------------------------------------------

    #[test]
    fn building_a_direct_client_succeeds() {
        let cfg = EgressProxyConfig {
            mode: EgressProxyMode::Direct,
            proxy_url: None,
            no_proxy: None,
        };
        assert!(build_repo_client(&cfg).is_ok());
    }

    #[test]
    fn building_an_explicit_client_succeeds_with_credentials_and_no_proxy_list() {
        let cfg = EgressProxyConfig {
            mode: EgressProxyMode::Explicit,
            proxy_url: Some("http://svc:pw@proxy.corp.example.com:3128".to_string()),
            no_proxy: Some("*.internal.example,10.0.0.0/8".to_string()),
        };
        assert!(build_repo_client(&cfg).is_ok());
    }

    #[test]
    fn building_an_explicit_client_without_a_url_is_an_error_not_a_silent_direct() {
        let cfg = EgressProxyConfig {
            mode: EgressProxyMode::Explicit,
            proxy_url: None,
            no_proxy: None,
        };
        assert!(build_repo_client(&cfg).is_err());
    }

    #[test]
    fn inherit_builds_the_environment_following_client() {
        assert!(build_repo_client(&EgressProxyConfig::inherit()).is_ok());
    }

    // ---- DB-backed round trip -----------------------------------------

    /// The encryption helpers panic without a key in the environment; skip
    /// (rather than fail) when the harness has none, matching the guard the
    /// `upstream_auth` DB tests use.
    fn encryption_key_configured() -> bool {
        std::env::var("JWT_SECRET").is_ok() || std::env::var("SSO_ENCRYPTION_KEY").is_ok()
    }

    /// Save → load round trip against a real database, proving:
    /// * the stored URL is CIPHERTEXT (the password does not appear in the row),
    /// * the plaintext survives decryption, and
    /// * mode/no_proxy come back intact.
    #[tokio::test]
    async fn egress_proxy_round_trips_and_is_encrypted_at_rest() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        if !encryption_key_configured() {
            return;
        }
        let (repo_id, _key, _dir) = tdh::create_repo(&pool, "remote", "maven").await;

        const SECRET: &str = "r0undtr1p-secret";
        let url = format!("http://svc:{SECRET}@proxy.corp.example.com:3128");
        let config = EgressProxyConfig {
            mode: EgressProxyMode::Explicit,
            proxy_url: Some(url.clone()),
            no_proxy: Some("*.internal.example".to_string()),
        };
        save_egress_proxy(&pool, repo_id, &config)
            .await
            .expect("save");

        // The row must be ciphertext, not the plaintext URL.
        let stored: String = sqlx::query_scalar(
            "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
        )
        .bind(repo_id)
        .bind(EGRESS_PROXY_URL_KEY)
        .fetch_one(&pool)
        .await
        .expect("stored row");
        assert!(
            !stored.contains(SECRET),
            "proxy password stored in cleartext: {stored}"
        );
        assert!(
            !stored.contains("proxy.corp.example.com"),
            "proxy URL stored in cleartext: {stored}"
        );

        let loaded = load_egress_proxy(&pool, repo_id).await.expect("load");
        assert_eq!(loaded.mode, EgressProxyMode::Explicit);
        assert_eq!(loaded.proxy_url.as_deref(), Some(url.as_str()));
        assert_eq!(loaded.no_proxy.as_deref(), Some("*.internal.example"));
        assert!(loaded.has_proxy_credentials());
        // ...and the read-back rendering still hides the secret.
        assert!(!loaded.redacted_proxy_url().unwrap().contains(SECRET));
        assert!(!format!("{loaded:?}").contains(SECRET));

        // Switching to `direct` must DELETE the stored ciphertext, not orphan it.
        save_egress_proxy(
            &pool,
            repo_id,
            &EgressProxyConfig {
                mode: EgressProxyMode::Direct,
                proxy_url: None,
                no_proxy: None,
            },
        )
        .await
        .expect("save direct");
        let remaining: Option<String> = sqlx::query_scalar(
            "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
        )
        .bind(repo_id)
        .bind(EGRESS_PROXY_URL_KEY)
        .fetch_optional(&pool)
        .await
        .expect("query")
        .flatten();
        assert!(
            remaining.is_none(),
            "switching away from 'explicit' must drop the encrypted URL, found: {remaining:?}"
        );
        let loaded = load_egress_proxy(&pool, repo_id).await.expect("load");
        assert_eq!(loaded.mode, EgressProxyMode::Direct);
        assert_eq!(loaded.proxy_url, None);

        remove_egress_proxy(&pool, repo_id).await.expect("remove");
        let loaded = load_egress_proxy(&pool, repo_id).await.expect("load");
        assert_eq!(
            loaded.mode,
            EgressProxyMode::Inherit,
            "removing all rows must return the repo to the default"
        );
    }

    /// A repository with no configuration at all resolves to `inherit`, so
    /// every pre-existing repository keeps its current behaviour.
    #[tokio::test]
    async fn unconfigured_repository_inherits() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, _dir) = tdh::create_repo(&pool, "remote", "maven").await;
        let loaded = load_egress_proxy(&pool, repo_id).await.expect("load");
        assert_eq!(loaded.mode, EgressProxyMode::Inherit);
        assert!(!loaded.overrides_default_routing());
        assert_eq!(loaded.proxy_url, None);
    }

    /// A half-written config (`mode = explicit` with no URL row) must NOT fall
    /// back to the ambient environment proxy. Written directly to the table to
    /// simulate a partial write or a hand-edited row.
    #[tokio::test]
    async fn half_written_explicit_config_falls_back_to_direct() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, _dir) = tdh::create_repo(&pool, "remote", "maven").await;
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3)",
        )
        .bind(repo_id)
        .bind(EGRESS_PROXY_MODE_KEY)
        .bind("explicit")
        .execute(&pool)
        .await
        .expect("insert mode");

        let loaded = load_egress_proxy(&pool, repo_id).await.expect("load");
        assert_eq!(
            loaded.mode,
            EgressProxyMode::Direct,
            "an explicit-but-URL-less config must fail closed to direct, never inherit"
        );
    }

    // ---- proxied-destination SSRF re-check ----------------------------

    #[test]
    fn proxied_destination_check_still_refuses_internal_targets() {
        // The whole point: configuring a proxy must not become a way to reach
        // a destination the upstream guard would otherwise refuse.
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22/",
            "http://localhost/admin",
            "http://metadata.google.internal/",
        ] {
            assert!(
                ensure_proxied_destination_allowed(url).is_err(),
                "proxied destination check let an internal target through: {url}"
            );
        }
        assert!(ensure_proxied_destination_allowed("https://pypi.org/simple/").is_ok());
    }
}
