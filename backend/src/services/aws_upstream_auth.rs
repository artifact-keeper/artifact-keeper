//! Dynamic AWS upstream auth providers for remote repositories (#1559).
//!
//! Amazon ECR and AWS CodeArtifact do not accept a static password. Both mint
//! short-lived credentials through an IAM-authenticated `GetAuthorizationToken`
//! call (ECR ~12 h, CodeArtifact up to 12 h), so a remote repository pinned to
//! a fixed `basic`/`bearer` credential works until the token silently expires.
//!
//! The `aws_ecr` and `aws_codeartifact` upstream auth types turn that into a
//! credential *provider*: the process's own AWS identity signs a
//! `GetAuthorizationToken` request, the minted token is cached in memory and
//! refreshed before it expires, and only the non-secret provider settings
//! (region, registry id / domain) are stored in `repository_config`. Nothing
//! AWS-vended is ever persisted.
//!
//! ## Where the AWS credentials come from
//!
//! The default credential chain, via `object_store`'s S3 builder — already a
//! dependency for S3 storage, so this adds no second AWS SDK stack. In
//! resolution order that is: static `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`
//! (+ `AWS_SESSION_TOKEN`), web identity (`AWS_WEB_IDENTITY_TOKEN_FILE` +
//! `AWS_ROLE_ARN` — how IRSA is delivered), the ECS task role
//! (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`), EKS Pod Identity
//! (`AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`),
//! and finally IMDS for an instance profile. The deployment models the issue
//! asks for — IRSA and EKS Pod Identity — therefore need no secret in the
//! database at all.
//!
//! Assuming a per-repository `role_arn` / `external_id` is deliberately NOT
//! implemented here; see the module docs in `docs/aws-upstream-auth.md`.
//!
//! ## Secrecy
//!
//! A minted token is a password. It is never persisted, never returned by the
//! repository API (`upstream_auth_configured` reports only that auth exists),
//! and never rendered into a log line or an error: [`MintedToken`] has a
//! redacting `Debug`, AWS error bodies are parsed for their `__type`/`message`
//! rather than echoed raw, and every URL that reaches a diagnostic goes through
//! `redact_url_for_diagnostics`.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use base64::Engine as _;
use chrono::{DateTime, TimeDelta, Utc};
use object_store::aws::{AmazonS3Builder, AwsAuthorizer, AwsCredential, AwsCredentialProvider};
use object_store::client::{HttpRequest, HttpRequestBody};
use reqwest::Client;
use serde::Deserialize;

use crate::error::{AppError, Result};
use crate::models::repository::RepositoryFormat;
use crate::services::upstream_auth::UpstreamAuthType;

/// `upstream_auth_type` value selecting the Amazon ECR provider.
pub const AUTH_TYPE_ECR: &str = "aws_ecr";
/// `upstream_auth_type` value selecting the AWS CodeArtifact provider.
pub const AUTH_TYPE_CODEARTIFACT: &str = "aws_codeartifact";

/// Mint a replacement once the cached token has less than this long left.
///
/// Both providers hand out ~12 h tokens, so 15 minutes is ~2 % of the lifetime:
/// long enough that a `GetAuthorizationToken` outage has many retry attempts
/// before anything expires (every proxy fetch in the window retries), short
/// enough that the extra API calls stay negligible. A failed refresh inside the
/// window keeps serving the token already held — see [`resolve`].
const REFRESH_MARGIN: TimeDelta = TimeDelta::minutes(15);

/// A cached token with less than this left is treated as gone: it is not served
/// even when a refresh has just failed, because a fetch started now could still
/// be in flight when it expires.
const MIN_SERVABLE_REMAINING: TimeDelta = TimeDelta::minutes(1);

/// Cap on the AWS error text carried into an operator-facing error/log line.
const MAX_AWS_ERROR_CHARS: usize = 300;

/// Timeout for a `GetAuthorizationToken` call. The AWS control plane answers in
/// well under a second; this only bounds the stall a pull inherits when it does
/// not.
const AWS_API_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Provider configuration (the non-secret half stored in repository_config)
// ---------------------------------------------------------------------------

/// The provider settings an operator configures for a remote repository.
///
/// Every field here is non-secret: it names *which* AWS resource to mint a
/// token for, never a credential. The AWS identity itself comes from the
/// process (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsProviderConfig {
    Ecr {
        region: String,
        /// Registry (account) id of the ECR registry being proxied. Optional:
        /// `GetAuthorizationToken` always mints for the *caller's* registry and
        /// a cross-account pull is authorized by the target registry's policy,
        /// so this is used only to pin the configured upstream host and to make
        /// the cache key explicit about which registry it belongs to.
        registry_id: Option<String>,
    },
    CodeArtifact {
        region: String,
        domain: String,
        /// Account id owning the domain. Omitted means "the caller's account",
        /// which is also what AWS defaults to.
        domain_owner: Option<String>,
        /// Requested token lifetime. AWS clamps it to [900, 43200] seconds
        /// (0 means "valid as long as the calling principal's session").
        duration_seconds: Option<u32>,
    },
}

impl AwsProviderConfig {
    /// The `upstream_auth_type` string this config is stored under.
    pub fn auth_type(&self) -> &'static str {
        match self {
            Self::Ecr { .. } => AUTH_TYPE_ECR,
            Self::CodeArtifact { .. } => AUTH_TYPE_CODEARTIFACT,
        }
    }

    fn region(&self) -> &str {
        match self {
            Self::Ecr { region, .. } | Self::CodeArtifact { region, .. } => region,
        }
    }

    /// Stable identity of the AWS resource this config mints tokens for. Used
    /// as the token-cache key (see [`resolve`]) and for diagnostics; contains
    /// no secret.
    fn cache_key(&self) -> String {
        match self {
            Self::Ecr {
                region,
                registry_id,
            } => format!(
                "{AUTH_TYPE_ECR}|{region}|{}",
                registry_id.as_deref().unwrap_or("")
            ),
            Self::CodeArtifact {
                region,
                domain,
                domain_owner,
                duration_seconds,
            } => format!(
                "{AUTH_TYPE_CODEARTIFACT}|{region}|{domain}|{}|{}",
                domain_owner.as_deref().unwrap_or(""),
                duration_seconds.map(|d| d.to_string()).unwrap_or_default()
            ),
        }
    }
}

/// True when `auth_type` selects one of the dynamic AWS providers.
pub fn is_aws_auth_type(auth_type: &str) -> bool {
    auth_type == AUTH_TYPE_ECR || auth_type == AUTH_TYPE_CODEARTIFACT
}

/// True when `region` is a syntactically valid AWS region code.
///
/// The region is spliced into the AWS API hostname, so it is validated as a
/// strict DNS label (lowercase alphanumerics and inner hyphens) rather than
/// trusted: anything else could redirect a signed request at another host.
fn valid_region(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 32
        && region.starts_with(|c: char| c.is_ascii_lowercase())
        && region.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// True when `id` is a 12-digit AWS account id.
fn valid_account_id(id: &str) -> bool {
    id.len() == 12 && id.chars().all(|c| c.is_ascii_digit())
}

/// True when `domain` is a valid CodeArtifact domain name.
fn valid_domain(domain: &str) -> bool {
    (2..=50).contains(&domain.len())
        && domain.starts_with(|c: char| c.is_ascii_lowercase())
        && domain.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && domain
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Parse a stored/`PUT`-supplied provider config, rejecting anything that would
/// be spliced into a hostname or a signed request unvalidated.
pub fn parse_provider_config(
    auth_type: &str,
    value: &serde_json::Value,
) -> Result<AwsProviderConfig> {
    let field = |name: &str| -> Option<String> {
        value
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    let region = field("region").ok_or_else(|| {
        AppError::Validation(format!(
            "{auth_type} upstream auth requires an AWS `region`"
        ))
    })?;
    if !valid_region(&region) {
        return Err(AppError::Validation(format!(
            "Invalid AWS region for {auth_type} upstream auth: {region}"
        )));
    }

    match auth_type {
        AUTH_TYPE_ECR => {
            let registry_id = field("registry_id");
            if let Some(ref id) = registry_id {
                if !valid_account_id(id) {
                    return Err(AppError::Validation(
                        "Invalid ECR registry_id: expected a 12-digit AWS account id".to_string(),
                    ));
                }
            }
            Ok(AwsProviderConfig::Ecr {
                region,
                registry_id,
            })
        }
        AUTH_TYPE_CODEARTIFACT => {
            let domain = field("domain").ok_or_else(|| {
                AppError::Validation(
                    "aws_codeartifact upstream auth requires a CodeArtifact `domain`".to_string(),
                )
            })?;
            if !valid_domain(&domain) {
                return Err(AppError::Validation(format!(
                    "Invalid CodeArtifact domain: {domain}"
                )));
            }
            let domain_owner = field("domain_owner");
            if let Some(ref id) = domain_owner {
                if !valid_account_id(id) {
                    return Err(AppError::Validation(
                        "Invalid CodeArtifact domain_owner: expected a 12-digit AWS account id"
                            .to_string(),
                    ));
                }
            }
            let duration_seconds = match value.get("duration_seconds") {
                None | Some(serde_json::Value::Null) => None,
                Some(v) => {
                    let secs = v.as_u64().filter(|s| *s == 0 || (900..=43200).contains(s));
                    Some(secs.ok_or_else(|| {
                        AppError::Validation(
                            "Invalid CodeArtifact duration_seconds: expected 0 or 900..=43200"
                                .to_string(),
                        )
                    })? as u32)
                }
            };
            Ok(AwsProviderConfig::CodeArtifact {
                region,
                domain,
                domain_owner,
                duration_seconds,
            })
        }
        other => Err(AppError::Validation(format!(
            "Unknown AWS upstream auth type: {other}"
        ))),
    }
}

/// Serialize a provider config back to the JSON stored in `repository_config`.
pub fn provider_config_json(config: &AwsProviderConfig) -> String {
    match config {
        AwsProviderConfig::Ecr {
            region,
            registry_id,
        } => serde_json::json!({"region": region, "registry_id": registry_id}).to_string(),
        AwsProviderConfig::CodeArtifact {
            region,
            domain,
            domain_owner,
            duration_seconds,
        } => serde_json::json!({
            "region": region,
            "domain": domain,
            "domain_owner": domain_owner,
            "duration_seconds": duration_seconds,
        })
        .to_string(),
    }
}

// ---------------------------------------------------------------------------
// Upstream host pinning
// ---------------------------------------------------------------------------

/// DNS suffix of the AWS partition `region` belongs to.
fn dns_suffix(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    }
}

/// Reject attaching an AWS-minted credential to an upstream that is not the
/// AWS service the provider mints for.
///
/// The upstream URL and the provider config are set independently (and the URL
/// can be edited after the credentials are configured), so it is checked when the
/// credentials are saved *and* again on every resolve rather than trusted once. Without it a
/// repository could be pointed at an arbitrary host while keeping an `aws_ecr`
/// credential provider attached, and every pull would hand that host a live
/// registry password. This is the same "credentials only go to the host the
/// operator configured" invariant the OCI bearer realm pin enforces
/// (GHSA-78h6-3wp8-2542).
pub fn validate_upstream_host(
    config: &AwsProviderConfig,
    upstream_url: Option<&str>,
) -> Result<()> {
    let url = upstream_url.unwrap_or_default();
    let parsed = reqwest::Url::parse(url).map_err(|_| {
        AppError::Validation(format!(
            "{} upstream auth requires the repository's upstream URL to be set to an AWS endpoint",
            config.auth_type()
        ))
    })?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();

    match config {
        AwsProviderConfig::Ecr {
            region,
            registry_id,
        } => {
            // `<account>.dkr.ecr.<region>.<suffix>`, or the FIPS endpoint
            // `<account>.dkr.ecr-fips.<region>.<suffix>`.
            let ok = [
                format!(".dkr.ecr.{region}.{}", dns_suffix(region)),
                format!(".dkr.ecr-fips.{region}.{}", dns_suffix(region)),
            ]
            .iter()
            .any(|suffix| match host.strip_suffix(suffix.as_str()) {
                Some(account) => {
                    !account.is_empty()
                        && registry_id.as_deref().map_or(true, |want| account == want)
                }
                None => false,
            });
            if !ok {
                return Err(AppError::Validation(format!(
                    "Upstream host {host} is not an Amazon ECR registry endpoint for region \
                     {region}; expected <account-id>.dkr.ecr.{region}.{}",
                    dns_suffix(region)
                )));
            }
        }
        AwsProviderConfig::CodeArtifact {
            region,
            domain,
            domain_owner,
            ..
        } => {
            // `<domain>-<owner>.d.codeartifact.<region>.<suffix>`.
            let suffix = format!(".d.codeartifact.{region}.{}", dns_suffix(region));
            let ok = match host.strip_suffix(suffix.as_str()) {
                Some(label) => match label.rsplit_once('-') {
                    Some((label_domain, label_owner)) => {
                        label_domain == domain
                            && domain_owner
                                .as_deref()
                                .map_or(true, |want| label_owner == want)
                    }
                    None => false,
                },
                None => false,
            };
            if !ok {
                return Err(AppError::Validation(format!(
                    "Upstream host {host} is not the AWS CodeArtifact endpoint for domain \
                     {domain} in region {region}; expected \
                     {domain}-<owner>.d.codeartifact.{region}.{}",
                    dns_suffix(region)
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The minted token and its cache
// ---------------------------------------------------------------------------

/// One AWS-vended credential, with the instant it stops being usable.
#[derive(Clone)]
struct MintedToken {
    auth: UpstreamAuthType,
    expires_at: DateTime<Utc>,
}

/// Redacting `Debug`: the wrapped credential is a live registry password, so it
/// must not reach a log line, a span field, or an `AppError` message through an
/// incidental `{:?}`.
impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedToken")
            .field("auth", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl MintedToken {
    /// Fresh enough to serve without refreshing.
    fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        self.expires_at - now > REFRESH_MARGIN
    }

    /// Still usable, though due for a refresh. Serving one of these is what
    /// keeps a repository up across a `GetAuthorizationToken` outage.
    fn is_servable(&self, now: DateTime<Utc>) -> bool {
        self.expires_at - now > MIN_SERVABLE_REMAINING
    }
}

/// Per-resource cache slot.
///
/// `current` is read without blocking on the hot path; `refresh` serialises
/// minting so a burst of concurrent pulls against a cold or due-for-refresh
/// slot performs ONE `GetAuthorizationToken` call rather than one per pull.
#[derive(Default)]
struct ProviderSlot {
    current: RwLock<Option<MintedToken>>,
    refresh: tokio::sync::Mutex<()>,
}

/// Token cache, keyed by [`AwsProviderConfig::cache_key`] — provider, region
/// and the registry/domain the token is for.
///
/// The effective AWS identity is deliberately NOT part of the key. It is a
/// process-wide singleton (the default credential chain), and for every
/// role-based source its access-key id rotates on each session refresh, so
/// keying on it would force a needless re-mint roughly hourly. A per-repository
/// `role_arn` would change that — it is stable, and whenever it lands the key
/// must gain it.
fn token_cache() -> &'static RwLock<HashMap<String, Arc<ProviderSlot>>> {
    static CACHE: OnceLock<RwLock<HashMap<String, Arc<ProviderSlot>>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Get (or create) the slot for `key`, dropping slots whose token has expired
/// outright so a long-lived process does not accumulate one per deleted repo.
fn slot_for(key: &str) -> Arc<ProviderSlot> {
    if let Ok(cache) = token_cache().read() {
        if let Some(slot) = cache.get(key) {
            return Arc::clone(slot);
        }
    }

    let mut cache = match token_cache().write() {
        Ok(cache) => cache,
        // A poisoned lock must not take the provider down: fall back to a
        // private slot, which costs one extra mint and nothing else.
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = Utc::now();
    cache.retain(|_, slot| match slot.current.read() {
        Ok(current) => current.as_ref().map_or(true, |t| t.is_servable(now)),
        Err(_) => true,
    });
    Arc::clone(cache.entry(key.to_string()).or_default())
}

/// Test hook: point every AWS API call for `region` at `base` (a mock server
/// origin, no trailing slash). Keyed by region so tests that share a process
/// stay independent.
#[cfg(test)]
pub(crate) fn set_endpoint_override(region: &str, base: &str) {
    endpoint_overrides()
        .write()
        .unwrap()
        .insert(region.to_string(), base.to_string());
}

#[cfg(test)]
fn endpoint_override(region: &str) -> Option<String> {
    endpoint_overrides().read().ok()?.get(region).cloned()
}

#[cfg(test)]
fn endpoint_overrides() -> &'static RwLock<HashMap<String, String>> {
    static OVERRIDES: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    OVERRIDES.get_or_init(|| RwLock::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Resolve the upstream credential for `config`, minting or refreshing through
/// AWS only when the cached token is missing or due.
///
/// Concurrency: the fast path takes a read lock and returns; a refresh holds
/// `ProviderSlot::refresh` and re-checks under it, so N concurrent pulls
/// produce one `GetAuthorizationToken` call and N-1 cache hits.
///
/// Availability: if the refresh fails while the slot still holds a usable
/// token, the failure is logged and the held token is served. A repository only
/// starts failing once it has no usable token at all.
pub async fn resolve(
    client: &Client,
    config: &AwsProviderConfig,
    format: &RepositoryFormat,
) -> Result<UpstreamAuthType> {
    let slot = slot_for(&config.cache_key());

    if let Some(token) = read_fresh(&slot, Utc::now()) {
        return Ok(token);
    }

    let _refreshing = slot.refresh.lock().await;

    // Re-check: another task may have refreshed while we waited for the lock.
    if let Some(token) = read_fresh(&slot, Utc::now()) {
        return Ok(token);
    }

    match mint(client, config, format).await {
        Ok(minted) => {
            let auth = minted.auth.clone();
            if let Ok(mut current) = slot.current.write() {
                *current = Some(minted);
            }
            Ok(auth)
        }
        Err(err) => {
            let held = slot
                .current
                .read()
                .ok()
                .and_then(|c| c.clone())
                .filter(|t| t.is_servable(Utc::now()));
            match held {
                Some(token) => {
                    tracing::warn!(
                        provider = config.auth_type(),
                        expires_at = %token.expires_at,
                        error = %err,
                        "AWS upstream token refresh failed; continuing with the token already \
                         held until it expires"
                    );
                    Ok(token.auth)
                }
                None => Err(err),
            }
        }
    }
}

/// Read the slot's token if it is fresh enough to serve without refreshing.
fn read_fresh(slot: &ProviderSlot, now: DateTime<Utc>) -> Option<UpstreamAuthType> {
    slot.current
        .read()
        .ok()?
        .as_ref()
        .filter(|t| t.is_fresh(now))
        .map(|t| t.auth.clone())
}

/// Call the provider's `GetAuthorizationToken` and shape the result into an
/// upstream credential.
async fn mint(
    client: &Client,
    config: &AwsProviderConfig,
    format: &RepositoryFormat,
) -> Result<MintedToken> {
    let region = config.region();
    let credential = aws_credentials(region).await?;
    match config {
        AwsProviderConfig::Ecr { .. } => {
            mint_ecr(client, &credential, region, &ecr_endpoint(region)).await
        }
        AwsProviderConfig::CodeArtifact {
            domain,
            domain_owner,
            duration_seconds,
            ..
        } => {
            let url =
                codeartifact_endpoint(region, domain, domain_owner.as_deref(), *duration_seconds);
            mint_codeartifact(client, &credential, region, &url, format).await
        }
    }
}

/// Origin of the AWS API for `service` in `region`.
///
/// In tests this is redirected at a mock server per region (see
/// [`set_endpoint_override`]); nothing else about the request changes, so the
/// signing, parsing, caching and refresh paths under test are the production
/// ones.
fn api_base(service: &str, region: &str) -> String {
    #[cfg(test)]
    if let Some(base) = endpoint_override(region) {
        return base;
    }
    format!("https://{service}.{region}.{}", dns_suffix(region))
}

fn ecr_endpoint(region: &str) -> String {
    format!("{}/", api_base("api.ecr", region))
}

fn codeartifact_endpoint(
    region: &str,
    domain: &str,
    domain_owner: Option<&str>,
    duration_seconds: Option<u32>,
) -> String {
    let mut url = format!(
        "{}/v1/authorization-token?domain={domain}",
        api_base("codeartifact", region)
    );
    if let Some(owner) = domain_owner {
        url.push_str(&format!("&domain-owner={owner}"));
    }
    if let Some(duration) = duration_seconds {
        url.push_str(&format!("&duration={duration}"));
    }
    url
}

// ---------------------------------------------------------------------------
// AWS credentials + SigV4
// ---------------------------------------------------------------------------

/// Per-region credential providers from the default chain.
///
/// Building one allocates an HTTP client and re-reads the environment, and each
/// provider caches the credential it resolves internally (an IMDS/STS
/// credential is re-fetched only near its own expiry), so they are built once
/// per region and reused.
fn credential_providers() -> &'static RwLock<HashMap<String, AwsCredentialProvider>> {
    static PROVIDERS: OnceLock<RwLock<HashMap<String, AwsCredentialProvider>>> = OnceLock::new();
    PROVIDERS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Resolve the process's AWS identity for `region` through the default chain.
///
/// `AmazonS3Builder` is used purely as the chain's entry point: no S3 request
/// is ever issued, only [`AmazonS3::credentials`] is taken, and the bucket name
/// it requires is a placeholder that is never sent anywhere.
async fn aws_credentials(region: &str) -> Result<Arc<AwsCredential>> {
    let cached = credential_providers()
        .read()
        .ok()
        .and_then(|p| p.get(region).cloned());

    let provider = match cached {
        Some(provider) => provider,
        None => {
            let store = AmazonS3Builder::from_env()
                .with_region(region)
                .with_bucket_name("artifact-keeper-aws-upstream-auth")
                .build()
                .map_err(|e| {
                    AppError::Config(format!(
                        "Could not initialise the AWS credential chain for region {region}: {e}"
                    ))
                })?;
            let provider = Arc::clone(store.credentials());
            if let Ok(mut providers) = credential_providers().write() {
                providers.insert(region.to_string(), Arc::clone(&provider));
            }
            provider
        }
    };

    provider.get_credential().await.map_err(|e| {
        AppError::Config(format!(
            "No usable AWS credentials for region {region}: {e}. Artifact Keeper uses the default \
             AWS credential chain (static keys, IRSA/web identity, ECS task role, EKS Pod \
             Identity, instance profile); check that the pod or host carries one of them."
        ))
    })
}

/// Sign `body` as a SigV4 POST to `url` and send it.
///
/// The signing itself is `object_store`'s [`AwsAuthorizer`] — the same SigV4
/// implementation this build already uses for S3 storage.
async fn signed_post(
    client: &Client,
    credential: &AwsCredential,
    service: &str,
    region: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<reqwest::Response> {
    // `AwsAuthorizer::authorize` parses the URI and unwraps; refuse anything it
    // could panic on before handing it over.
    reqwest::Url::parse(url)
        .map_err(|e| AppError::Config(format!("Invalid AWS endpoint {url}: {e}")))?;

    let mut request: HttpRequest = http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .body(HttpRequestBody::from(body.to_string()))
        .map_err(|e| AppError::Internal(format!("Could not build the AWS API request: {e}")))?;
    for (name, value) in headers {
        let value = http::HeaderValue::from_str(value).map_err(|e| {
            AppError::Internal(format!("Invalid AWS API request header {name}: {e}"))
        })?;
        let name = http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| AppError::Internal(format!("Invalid AWS API request header name: {e}")))?;
        request.headers_mut().insert(name, value);
    }

    AwsAuthorizer::new(credential, service, region).authorize(&mut request, None);

    let mut outgoing = client
        .post(url)
        .timeout(AWS_API_TIMEOUT)
        .body(body.to_string());
    for (name, value) in request.headers() {
        outgoing = outgoing.header(name, value);
    }

    outgoing.send().await.map_err(|e| {
        AppError::Config(format!(
            "{service} GetAuthorizationToken request to {} failed: {e}. Check that the configured \
             region is correct and that the endpoint is reachable.",
            crate::services::proxy_service::redact_url_for_diagnostics(url)
        ))
    })
}

/// Read an AWS error response into an operator-facing [`AppError`].
///
/// The raw body is never echoed: only the `__type` / `message` pair AWS
/// documents, truncated. Throttling and transient service faults become a 503
/// (they are retryable and should not page as a server bug); everything else is
/// a configuration fault, which logs in full and answers clients generically.
async fn aws_error(service: &str, response: reqwest::Response) -> AppError {
    let status = response.status();
    let error_type = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(['-', ':']).next().unwrap_or(v).to_string());
    let body = response.text().await.unwrap_or_default();
    let parsed: Option<serde_json::Value> = serde_json::from_str(&body).ok();
    let error_type = error_type.or_else(|| {
        parsed
            .as_ref()
            .and_then(|v| v.get("__type").or_else(|| v.get("code")))
            .and_then(|v| v.as_str())
            .map(|v| v.rsplit('#').next().unwrap_or(v).to_string())
    });
    let message: String = parsed
        .as_ref()
        .and_then(|v| v.get("message").or_else(|| v.get("Message")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(MAX_AWS_ERROR_CHARS)
        .collect();
    let error_type = error_type.unwrap_or_else(|| format!("HTTP {}", status.as_u16()));

    let explanation = match error_type.as_str() {
        t if t.contains("Throttling")
            || t.contains("TooManyRequests")
            || t.contains("RequestLimit") =>
        {
            return AppError::ServiceUnavailable(format!(
                "AWS throttled the {service} GetAuthorizationToken call ({error_type}); \
                 the upstream credential could not be refreshed right now"
            ));
        }
        _ if status.is_server_error() => {
            return AppError::ServiceUnavailable(format!(
                "AWS returned {status} for the {service} GetAuthorizationToken call; \
                 the upstream credential could not be refreshed right now"
            ));
        }
        t if t.contains("AccessDenied") || t.contains("NotAuthorized") => {
            "the IAM identity Artifact Keeper runs as is not permitted to call \
             GetAuthorizationToken for this resource"
        }
        t if t.contains("ExpiredToken")
            || t.contains("InvalidClientTokenId")
            || t.contains("UnrecognizedClient")
            || t.contains("InvalidSignature") =>
        {
            "the AWS credentials Artifact Keeper resolved are expired or not valid for this \
             region — an assumed role may have lapsed, or the region may be wrong"
        }
        t if t.contains("ResourceNotFound") || t.contains("RegistryNotFound") => {
            "the registry or domain named in this repository's AWS upstream auth config does \
             not exist in the configured region"
        }
        _ => "the AWS API rejected the request",
    };

    AppError::Config(format!(
        "{service} GetAuthorizationToken failed ({error_type}, HTTP {}): {explanation}. AWS said: \
         {message}",
        status.as_u16()
    ))
}

// ---------------------------------------------------------------------------
// Amazon ECR
// ---------------------------------------------------------------------------

/// `X-Amz-Target` for ECR's `GetAuthorizationToken` (AWS JSON 1.1).
const ECR_TARGET: &str = "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken";

#[derive(Deserialize)]
struct EcrAuthorizationResponse {
    #[serde(rename = "authorizationData", default)]
    authorization_data: Vec<EcrAuthorizationData>,
}

#[derive(Deserialize)]
struct EcrAuthorizationData {
    #[serde(rename = "authorizationToken")]
    authorization_token: String,
    #[serde(rename = "expiresAt")]
    expires_at: f64,
}

/// Mint an ECR registry credential.
///
/// The request body is `{}`: `GetAuthorizationToken` mints for the *caller's*
/// registry, and a cross-account pull is authorized by the target registry's
/// policy against that same token. (`registryIds` is deprecated in the API and
/// is deliberately not sent.)
async fn mint_ecr(
    client: &Client,
    credential: &AwsCredential,
    region: &str,
    endpoint: &str,
) -> Result<MintedToken> {
    let response = signed_post(
        client,
        credential,
        "ecr",
        region,
        endpoint,
        &[
            ("content-type", "application/x-amz-json-1.1"),
            ("x-amz-target", ECR_TARGET),
        ],
        "{}",
    )
    .await?;

    if !response.status().is_success() {
        return Err(aws_error("ecr", response).await);
    }

    let body = response.text().await.map_err(|e| {
        AppError::Config(format!(
            "Could not read the ECR authorization response: {e}"
        ))
    })?;
    let parsed: EcrAuthorizationResponse = serde_json::from_str(&body).map_err(|e| {
        // The body carries the token: report the parse failure, never the body.
        AppError::Config(format!("Malformed ECR authorization response: {e}"))
    })?;
    let data = parsed
        .authorization_data
        .into_iter()
        .next()
        .ok_or_else(|| {
            AppError::Config(
                "ECR GetAuthorizationToken returned no authorization data for this registry"
                    .to_string(),
            )
        })?;

    // `authorizationToken` is base64 of `AWS:<password>` — exactly the value of
    // an HTTP Basic credential, which is how `docker login` consumes it.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data.authorization_token.as_bytes())
        .map_err(|_| {
            AppError::Config("ECR returned an authorization token that is not base64".to_string())
        })?;
    let decoded = String::from_utf8(decoded).map_err(|_| {
        AppError::Config("ECR returned an authorization token that is not UTF-8".to_string())
    })?;
    let (username, password) = decoded.split_once(':').ok_or_else(|| {
        AppError::Config(
            "ECR returned an authorization token that is not a `user:password` pair".to_string(),
        )
    })?;

    Ok(MintedToken {
        auth: UpstreamAuthType::Basic {
            username: username.to_string(),
            password: password.to_string(),
        },
        expires_at: epoch_to_datetime(data.expires_at)?,
    })
}

// ---------------------------------------------------------------------------
// AWS CodeArtifact
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CodeArtifactAuthorizationResponse {
    #[serde(rename = "authorizationToken")]
    authorization_token: String,
    expiration: f64,
}

/// Mint a CodeArtifact repository credential.
async fn mint_codeartifact(
    client: &Client,
    credential: &AwsCredential,
    region: &str,
    url: &str,
    format: &RepositoryFormat,
) -> Result<MintedToken> {
    let response = signed_post(client, credential, "codeartifact", region, url, &[], "").await?;

    if !response.status().is_success() {
        return Err(aws_error("codeartifact", response).await);
    }

    let body = response.text().await.map_err(|e| {
        AppError::Config(format!(
            "Could not read the CodeArtifact authorization response: {e}"
        ))
    })?;
    let parsed: CodeArtifactAuthorizationResponse = serde_json::from_str(&body).map_err(|e| {
        AppError::Config(format!(
            "Malformed CodeArtifact authorization response: {e}"
        ))
    })?;

    Ok(MintedToken {
        auth: codeartifact_auth(format, parsed.authorization_token),
        expires_at: epoch_to_datetime(parsed.expiration)?,
    })
}

/// The auth shape CodeArtifact expects for a given package format.
///
/// AWS documents the token differently per client: npm and Cargo are configured
/// with a bearer token (`_authToken` / `token = "Bearer …"`), while Maven,
/// pip/twine, NuGet and the rest use HTTP Basic with the fixed user name `aws`.
/// Both reach the same endpoint, so the format decides the header.
fn codeartifact_auth(format: &RepositoryFormat, token: String) -> UpstreamAuthType {
    match format {
        RepositoryFormat::Npm
        | RepositoryFormat::Yarn
        | RepositoryFormat::Pnpm
        | RepositoryFormat::Bower
        | RepositoryFormat::Cargo => UpstreamAuthType::Bearer { token },
        _ => UpstreamAuthType::Basic {
            username: "aws".to_string(),
            password: token,
        },
    }
}

/// Convert an AWS epoch-seconds timestamp (which may carry a fraction) to UTC.
fn epoch_to_datetime(epoch: f64) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp(epoch as i64, 0).ok_or_else(|| {
        AppError::Config(format!(
            "AWS returned an out-of-range token expiry: {epoch}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Give the process a static AWS identity so the default credential chain
    /// resolves without touching IMDS/STS. No test ever contacts AWS: the API
    /// endpoint is redirected at a `wiremock` server.
    fn static_aws_identity() {
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE");
        std::env::set_var(
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
    }

    /// Base64 of `AWS:<password>`, the shape ECR returns.
    fn ecr_token(password: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(format!("AWS:{password}"))
    }

    fn ecr_body(password: &str, expires_in: TimeDelta) -> serde_json::Value {
        serde_json::json!({
            "authorizationData": [{
                "authorizationToken": ecr_token(password),
                "expiresAt": (Utc::now() + expires_in).timestamp(),
                "proxyEndpoint": "https://123456789012.dkr.ecr.us-east-1.amazonaws.com",
            }]
        })
    }

    fn ecr_config(region: &str) -> AwsProviderConfig {
        AwsProviderConfig::Ecr {
            region: region.to_string(),
            registry_id: Some("123456789012".to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // Config parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_ecr_config() {
        let value = serde_json::json!({"region": "us-east-1", "registry_id": "123456789012"});
        assert_eq!(
            parse_provider_config(AUTH_TYPE_ECR, &value).unwrap(),
            ecr_config("us-east-1")
        );
    }

    #[test]
    fn test_parse_ecr_config_requires_region() {
        let err = parse_provider_config(AUTH_TYPE_ECR, &serde_json::json!({})).unwrap_err();
        assert!(
            err.to_string().contains("requires an AWS `region`"),
            "{err}"
        );
    }

    #[test]
    fn test_parse_rejects_region_that_would_escape_the_hostname() {
        for region in [
            "us-east-1/../evil.com",
            "US-EAST-1",
            "evil.com",
            "-us-east-1",
        ] {
            let value = serde_json::json!({ "region": region });
            assert!(
                parse_provider_config(AUTH_TYPE_ECR, &value).is_err(),
                "region {region} must be rejected"
            );
        }
    }

    #[test]
    fn test_parse_rejects_non_account_registry_id() {
        let value = serde_json::json!({"region": "us-east-1", "registry_id": "not-an-account"});
        assert!(parse_provider_config(AUTH_TYPE_ECR, &value).is_err());
    }

    #[test]
    fn test_parse_codeartifact_config() {
        let value = serde_json::json!({
            "region": "eu-west-1",
            "domain": "platform",
            "domain_owner": "123456789012",
            "duration_seconds": 3600,
        });
        assert_eq!(
            parse_provider_config(AUTH_TYPE_CODEARTIFACT, &value).unwrap(),
            AwsProviderConfig::CodeArtifact {
                region: "eu-west-1".to_string(),
                domain: "platform".to_string(),
                domain_owner: Some("123456789012".to_string()),
                duration_seconds: Some(3600),
            }
        );
    }

    #[test]
    fn test_parse_codeartifact_requires_domain() {
        let value = serde_json::json!({"region": "eu-west-1"});
        let err = parse_provider_config(AUTH_TYPE_CODEARTIFACT, &value).unwrap_err();
        assert!(err.to_string().contains("`domain`"), "{err}");
    }

    #[test]
    fn test_parse_codeartifact_rejects_out_of_range_duration() {
        let value =
            serde_json::json!({"region": "eu-west-1", "domain": "p", "duration_seconds": 60});
        assert!(parse_provider_config(AUTH_TYPE_CODEARTIFACT, &value).is_err());
    }

    #[test]
    fn test_provider_config_json_roundtrip() {
        let config = ecr_config("us-east-1");
        let json: serde_json::Value = serde_json::from_str(&provider_config_json(&config)).unwrap();
        assert_eq!(parse_provider_config(AUTH_TYPE_ECR, &json).unwrap(), config);
    }

    // -----------------------------------------------------------------------
    // Upstream host pinning
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_upstream_host_accepts_ecr_registry() {
        validate_upstream_host(
            &ecr_config("us-east-1"),
            Some("https://123456789012.dkr.ecr.us-east-1.amazonaws.com"),
        )
        .unwrap();
    }

    #[test]
    fn test_validate_upstream_host_rejects_foreign_host() {
        for url in [
            "https://evil.example.com",
            // Right service, wrong region.
            "https://123456789012.dkr.ecr.eu-west-1.amazonaws.com",
            // Right service and region, a different account than configured.
            "https://999999999999.dkr.ecr.us-east-1.amazonaws.com",
            // Suffix-confusion attempt.
            "https://123456789012.dkr.ecr.us-east-1.amazonaws.com.evil.example",
        ] {
            let err = validate_upstream_host(&ecr_config("us-east-1"), Some(url)).unwrap_err();
            assert!(
                err.to_string()
                    .contains("not an Amazon ECR registry endpoint"),
                "{url} should be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn test_validate_upstream_host_requires_an_upstream_url() {
        assert!(validate_upstream_host(&ecr_config("us-east-1"), None).is_err());
    }

    #[test]
    fn test_validate_upstream_host_codeartifact() {
        let config = AwsProviderConfig::CodeArtifact {
            region: "eu-west-1".to_string(),
            domain: "platform".to_string(),
            domain_owner: Some("123456789012".to_string()),
            duration_seconds: None,
        };
        validate_upstream_host(
            &config,
            Some("https://platform-123456789012.d.codeartifact.eu-west-1.amazonaws.com/npm/main/"),
        )
        .unwrap();
        assert!(validate_upstream_host(
            &config,
            Some("https://other-123456789012.d.codeartifact.eu-west-1.amazonaws.com/npm/main/")
        )
        .is_err());
    }

    // -----------------------------------------------------------------------
    // Minting
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ecr_mint_returns_basic_credential_and_signs_sigv4() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ecr_body("s3cret", TimeDelta::hours(12))),
            )
            .mount(&server)
            .await;

        let credential = AwsCredential {
            key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            token: None,
        };
        let minted = mint_ecr(
            &Client::new(),
            &credential,
            "us-east-1",
            &format!("{}/", server.uri()),
        )
        .await
        .unwrap();

        assert_eq!(
            minted.auth,
            UpstreamAuthType::Basic {
                username: "AWS".to_string(),
                password: "s3cret".to_string(),
            }
        );
        assert!(minted.is_fresh(Utc::now()));

        let request = &server.received_requests().await.unwrap()[0];
        let authorization = request.headers["authorization"].to_str().unwrap();
        assert!(
            authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"),
            "{authorization}"
        );
        assert!(
            authorization.contains("/us-east-1/ecr/aws4_request"),
            "{authorization}"
        );
        assert_eq!(
            request.headers["x-amz-target"].to_str().unwrap(),
            ECR_TARGET
        );
        assert!(request.headers.contains_key("x-amz-date"));
    }

    #[tokio::test]
    async fn test_ecr_mint_reports_missing_permission_clearly() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "__type": "AccessDeniedException",
                "message": "User: arn:aws:sts::1:assumed-role/ak is not authorized",
            })))
            .mount(&server)
            .await;

        let credential = AwsCredential {
            key_id: "AKIA".to_string(),
            secret_key: "secret".to_string(),
            token: None,
        };
        let err = mint_ecr(
            &Client::new(),
            &credential,
            "us-east-1",
            &format!("{}/", server.uri()),
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("AccessDeniedException"), "{message}");
        assert!(
            message.contains("not permitted to call GetAuthorizationToken"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn test_ecr_mint_maps_throttling_to_service_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "__type": "ThrottlingException",
                "message": "Rate exceeded",
            })))
            .mount(&server)
            .await;

        let credential = AwsCredential {
            key_id: "AKIA".to_string(),
            secret_key: "secret".to_string(),
            token: None,
        };
        let err = mint_ecr(
            &Client::new(),
            &credential,
            "us-east-1",
            &format!("{}/", server.uri()),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::ServiceUnavailable(_)),
            "throttling must be retryable, got: {err:?}"
        );
        assert!(err.to_string().contains("throttled"), "{err}");
    }

    #[tokio::test]
    async fn test_ecr_mint_reports_expired_credentials_clearly() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "__type": "ExpiredTokenException",
                "message": "The security token included in the request is expired",
            })))
            .mount(&server)
            .await;

        let credential = AwsCredential {
            key_id: "AKIA".to_string(),
            secret_key: "secret".to_string(),
            token: None,
        };
        let err = mint_ecr(
            &Client::new(),
            &credential,
            "us-east-1",
            &format!("{}/", server.uri()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("expired or not valid"), "{err}");
    }

    #[tokio::test]
    async fn test_codeartifact_mint_uses_the_documented_auth_shape_per_format() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/authorization-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorizationToken": "ca-token",
                "expiration": (Utc::now() + TimeDelta::hours(12)).timestamp(),
            })))
            .mount(&server)
            .await;

        let credential = AwsCredential {
            key_id: "AKIA".to_string(),
            secret_key: "secret".to_string(),
            token: None,
        };
        let url = format!("{}/v1/authorization-token?domain=platform", server.uri());

        let npm = mint_codeartifact(
            &Client::new(),
            &credential,
            "eu-west-1",
            &url,
            &RepositoryFormat::Npm,
        )
        .await
        .unwrap();
        assert_eq!(
            npm.auth,
            UpstreamAuthType::Bearer {
                token: "ca-token".to_string()
            }
        );

        let maven = mint_codeartifact(
            &Client::new(),
            &credential,
            "eu-west-1",
            &url,
            &RepositoryFormat::Maven,
        )
        .await
        .unwrap();
        assert_eq!(
            maven.auth,
            UpstreamAuthType::Basic {
                username: "aws".to_string(),
                password: "ca-token".to_string(),
            }
        );
    }

    #[test]
    fn test_codeartifact_auth_shape_covers_every_proxied_format() {
        for format in [
            RepositoryFormat::Npm,
            RepositoryFormat::Yarn,
            RepositoryFormat::Pnpm,
            RepositoryFormat::Cargo,
        ] {
            assert!(matches!(
                codeartifact_auth(&format, "t".to_string()),
                UpstreamAuthType::Bearer { .. }
            ));
        }
        for format in [
            RepositoryFormat::Maven,
            RepositoryFormat::Gradle,
            RepositoryFormat::Pypi,
            RepositoryFormat::Nuget,
            RepositoryFormat::Generic,
        ] {
            assert!(matches!(
                codeartifact_auth(&format, "t".to_string()),
                UpstreamAuthType::Basic { .. }
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Cache: refresh, singleflight, degradation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_resolve_reuses_a_fresh_token_without_calling_aws_again() {
        static_aws_identity();
        let region = "us-fresh-1";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ecr_body("pw", TimeDelta::hours(12))),
            )
            .mount(&server)
            .await;
        set_endpoint_override(region, &server.uri());

        let config = ecr_config(region);
        let client = Client::new();
        for _ in 0..5 {
            resolve(&client, &config, &RepositoryFormat::Docker)
                .await
                .unwrap();
        }

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_resolve_refreshes_before_the_token_expires() {
        static_aws_identity();
        let region = "us-refresh-1";
        let server = MockServer::start().await;
        // Inside REFRESH_MARGIN: still valid, but due for replacement.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ecr_body("pw", TimeDelta::minutes(10))),
            )
            .mount(&server)
            .await;
        set_endpoint_override(region, &server.uri());

        let config = ecr_config(region);
        let client = Client::new();
        resolve(&client, &config, &RepositoryFormat::Docker)
            .await
            .unwrap();
        resolve(&client, &config, &RepositoryFormat::Docker)
            .await
            .unwrap();

        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "a token inside the refresh margin must be re-minted, not served until it expires"
        );
    }

    #[tokio::test]
    async fn test_resolve_keeps_serving_a_valid_token_when_the_refresh_fails() {
        static_aws_identity();
        let region = "us-degrade-1";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ecr_body("held", TimeDelta::minutes(10))),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        set_endpoint_override(region, &server.uri());

        let config = ecr_config(region);
        let client = Client::new();
        let first = resolve(&client, &config, &RepositoryFormat::Docker)
            .await
            .unwrap();
        let second = resolve(&client, &config, &RepositoryFormat::Docker)
            .await
            .expect("a failed refresh must not take down a repo that still holds a valid token");

        assert_eq!(first, second);
        assert_eq!(
            second,
            UpstreamAuthType::Basic {
                username: "AWS".to_string(),
                password: "held".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn test_resolve_surfaces_the_failure_once_no_usable_token_is_held() {
        static_aws_identity();
        let region = "us-nocreds-1";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "__type": "AccessDeniedException",
                "message": "nope",
            })))
            .mount(&server)
            .await;
        set_endpoint_override(region, &server.uri());

        let err = resolve(
            &Client::new(),
            &ecr_config(region),
            &RepositoryFormat::Docker,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("AccessDeniedException"), "{err}");
    }

    #[tokio::test]
    async fn test_concurrent_pulls_trigger_a_single_mint() {
        static_aws_identity();
        let region = "us-herd-1";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(ecr_body("pw", TimeDelta::hours(12)))
                    .set_delay(std::time::Duration::from_millis(150)),
            )
            .mount(&server)
            .await;
        set_endpoint_override(region, &server.uri());

        let config = Arc::new(ecr_config(region));
        let client = Arc::new(Client::new());
        let mut tasks = Vec::new();
        for _ in 0..24 {
            let (config, client) = (Arc::clone(&config), Arc::clone(&client));
            tasks.push(tokio::spawn(async move {
                resolve(&client, &config, &RepositoryFormat::Docker).await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }

        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "a burst of concurrent pulls must singleflight into ONE GetAuthorizationToken call"
        );
    }

    // -----------------------------------------------------------------------
    // The token is a password: it must not reach a log, an error, or a Debug
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_the_minted_token_never_appears_in_a_rendered_string() {
        static_aws_identity();
        let region = "us-secret-1";
        let secret = "tOpS3cretECRp4ssw0rd";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ecr_body(secret, TimeDelta::hours(12))),
            )
            .mount(&server)
            .await;
        set_endpoint_override(region, &server.uri());

        let config = ecr_config(region);
        let auth = resolve(&Client::new(), &config, &RepositoryFormat::Docker)
            .await
            .unwrap();

        // The credential itself is correct...
        assert!(matches!(&auth, UpstreamAuthType::Basic { password, .. } if password == secret));

        // ...but nothing that can reach a log line or an error body renders it.
        let slot = slot_for(&config.cache_key());
        let minted = slot.current.read().unwrap().clone().unwrap();
        for rendered in [
            format!("{auth:?}"),
            format!("{minted:?}"),
            format!("{:?}", slot.current.read().unwrap().as_ref()),
            crate::services::proxy_service::redact_url_for_diagnostics(&format!(
                "https://AWS:{secret}@123456789012.dkr.ecr.us-east-1.amazonaws.com/v2/"
            )),
        ] {
            assert!(
                !rendered.contains(secret),
                "the minted token leaked into: {rendered}"
            );
        }
        assert!(format!("{auth:?}").contains("<redacted>"));
    }

    #[tokio::test]
    async fn test_an_aws_error_does_not_echo_the_response_body() {
        // A malformed 200 still carries a token in the body; the parse error
        // must describe the failure, never quote what failed to parse.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"authorizationData":[{"authorizationToken":"QVdTOmxlYWs=","expiresAt":"nope"}]}"#,
            ))
            .mount(&server)
            .await;

        let credential = AwsCredential {
            key_id: "AKIA".to_string(),
            secret_key: "secret".to_string(),
            token: None,
        };
        let err = mint_ecr(
            &Client::new(),
            &credential,
            "us-east-1",
            &format!("{}/", server.uri()),
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("Malformed ECR authorization response"),
            "{message}"
        );
        assert!(!message.contains("QVdTOmxlYWs"), "{message}");
    }

    #[test]
    fn test_upstream_auth_debug_is_redacted() {
        let basic = UpstreamAuthType::Basic {
            username: "AWS".to_string(),
            password: "hunter2".to_string(),
        };
        let bearer = UpstreamAuthType::Bearer {
            token: "ca-token".to_string(),
        };
        assert!(!format!("{basic:?}").contains("hunter2"));
        assert!(format!("{basic:?}").contains("AWS"));
        assert!(!format!("{bearer:?}").contains("ca-token"));
    }
}
