//! Per-deployment scoping of the proxy-cache key space (#3454).
//!
//! # The problem
//!
//! Proxy-cache content is anchored at the storage **root**, never under
//! `S3_PREFIX` (see [`crate::storage::BUCKET_ROOT_KEY_NAMESPACES`] and #3368).
//! That is deliberate — it is what makes a prefixed deployment read back the
//! objects it wrote — but it also meant the whole namespace was
//! `proxy-cache/<repo_key>/<path>/__content__`, with nothing in it naming the
//! deployment that produced it.
//!
//! Two Artifact Keeper deployments pointed at the same bucket and separated
//! only by `S3_PREFIX` therefore shared ONE proxy-cache key space. Two
//! repositories that happen to carry the same key — `maven-proxy`,
//! `npm-remote`, whatever the operator called it — addressed the same physical
//! object in both deployments. Each one served the other's cached upstream
//! bytes: content it never fetched, from an upstream it is not configured to
//! use, possibly retrieved with the other deployment's upstream credentials.
//! The last writer won, so it is a two-way exchange, not a leak in one
//! direction.
//!
//! # The scope
//!
//! A [`ProxyCacheScope`] inserts one segment immediately after the reserved
//! `proxy-cache/` namespace:
//!
//! ```text
//! proxy-cache/<scope>/<repo_key>/<path>/__content__
//! ```
//!
//! Placing the segment INSIDE the reserved namespace rather than moving the
//! namespace under `S3_PREFIX` is what keeps the blast radius small:
//!
//! * `key_is_bucket_root_anchored` still returns true, so the S3 and
//!   filesystem backends still resolve the key at the shared root and #3368
//!   stays fixed.
//! * `ProxyService::is_proxy_cache_key` and every `storage_key NOT LIKE
//!   'proxy-cache/%'` predicate in the accounting SQL still match, so storage
//!   analytics, the usage ledger and the quota admission path are unchanged.
//! * The IAM `Resource` list operators were told to grant in `.env.example`
//!   (`arn:aws:s3:::<bucket>/proxy-cache/*`) still covers the new keys, so no
//!   policy has to be re-cut.
//! * The `proxy-cache-staging/` namespace is left unscoped: its keys are
//!   freshly minted v4 UUIDs that cannot collide across deployments, and
//!   leaving it alone keeps the single documented lifecycle rule valid.
//!
//! # Choosing the identifier
//!
//! The scope is the deployment's persistent **peer instance id** — the UUID in
//! the `peer_instance_identity` table that `init_peer_identity` seeds on first
//! boot and never rewrites. It is the right identifier for a cache scope for
//! three reasons:
//!
//! * **Stable.** It is written once and only read afterwards; restarts,
//!   upgrades, rescheduling and replica count do not change it. Every replica
//!   of one deployment reads the same row, so a horizontally-scaled deployment
//!   shares one cache — which is the whole point of having one.
//! * **Immune to unrelated config edits.** `PEER_INSTANCE_NAME` and
//!   `PEER_PUBLIC_ENDPOINT` are reconciled into that row on every boot, but the
//!   id is not. Keying the cache on a mutable setting would silently orphan the
//!   entire cache the first time an operator renamed something.
//! * **Unique per deployment.** It is a v4 UUID minted against the
//!   deployment's own database, and two deployments sharing a bucket by
//!   definition have separate databases.
//!
//! An operator who wants a legible or pinned value can override it with
//! `PROXY_CACHE_SCOPE`; see [`ProxyCacheScope::from_env_and_identity`]. There
//! is deliberately no value that turns scoping off.

use uuid::Uuid;

use crate::error::{AppError, Result};

/// The reserved namespace every proxy-cache key starts with. Kept in lockstep
/// with `services::proxy_service::PROXY_CACHE_KEY_PREFIX` and
/// [`crate::storage::BUCKET_ROOT_KEY_NAMESPACES`];
/// `namespace_matches_bucket_root_declaration` pins the three together.
pub const PROXY_CACHE_NAMESPACE: &str = "proxy-cache/";

/// Environment variable that overrides the derived scope segment.
pub const PROXY_CACHE_SCOPE_ENV: &str = "PROXY_CACHE_SCOPE";

/// Longest an explicit `PROXY_CACHE_SCOPE` override may be. The segment is
/// charged against the 1024-byte object-key budget
/// (`ProxyService::check_cache_key_length`), so an unbounded value would
/// silently shrink the longest cacheable upstream path.
const MAX_SCOPE_SEGMENT_LEN: usize = 64;

/// The deployment-scoped root of the proxy-cache key space.
///
/// Holds the fully composed root (`proxy-cache/<scope>/`, or `proxy-cache/`
/// for [`ProxyCacheScope::unscoped`]) so that every key builder, prefix
/// listing and prefix parser in `proxy_service` reads one precomputed string
/// and none of them can compose the layout differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCacheScope {
    /// `proxy-cache/` or `proxy-cache/<segment>/`. Always ends in `/`.
    root: String,
    /// The scope segment, or `None` for the legacy unscoped layout.
    segment: Option<String>,
}

impl ProxyCacheScope {
    /// The pre-#3454 layout: `proxy-cache/<repo_key>/...`, shared by every
    /// deployment addressing the bucket.
    ///
    /// This is what objects cached before the upgrade are keyed under, and it
    /// is what the existing key-shape tests pin. It is NOT reachable from
    /// configuration — there is no `PROXY_CACHE_SCOPE` value that selects it —
    /// because a deployment that opts out of scoping re-opens #3454 for
    /// everyone else sharing its bucket.
    pub fn unscoped() -> Self {
        Self {
            root: PROXY_CACHE_NAMESPACE.to_string(),
            segment: None,
        }
    }

    /// Scope derived from this deployment's persistent peer instance id.
    pub fn from_deployment_id(deployment_id: Uuid) -> Self {
        Self::from_segment(deployment_id.to_string())
    }

    /// Resolve the scope an operator's configuration asks for.
    ///
    /// * `PROXY_CACHE_SCOPE` unset (the default) — derived from
    ///   `deployment_id`, the row `init_peer_identity` maintains. Nothing to
    ///   configure, and every deployment gets a distinct cache tree.
    /// * `PROXY_CACHE_SCOPE=<token>` — that token, for operators who would
    ///   rather see a legible tree (`proxy-cache/prod-eu/...`) or who need the
    ///   scope to survive a database re-initialisation. Restricted to
    ///   `[A-Za-z0-9._-]`, 1..={MAX} bytes, and rejected if it would
    ///   reintroduce a separator.
    ///
    /// An invalid override is a hard configuration error rather than a silent
    /// fall back to the derived value: an operator who pinned a scope on
    /// purpose and mistyped it would otherwise get a different — and, on a
    /// shared bucket, differently-isolated — key space than the one they asked
    /// for, with nothing but a log line to say so.
    pub fn from_env_and_identity(raw_override: Option<&str>, deployment_id: Uuid) -> Result<Self> {
        match raw_override.map(str::trim).filter(|s| !s.is_empty()) {
            Some(explicit) => Self::from_explicit_segment(explicit),
            None => Ok(Self::from_deployment_id(deployment_id)),
        }
    }

    /// Validate and wrap an explicit operator-supplied segment.
    fn from_explicit_segment(segment: &str) -> Result<Self> {
        if segment.len() > MAX_SCOPE_SEGMENT_LEN {
            return Err(AppError::Validation(format!(
                "{PROXY_CACHE_SCOPE_ENV} must be at most {MAX_SCOPE_SEGMENT_LEN} bytes (got {})",
                segment.len()
            )));
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(AppError::Validation(format!(
                "{PROXY_CACHE_SCOPE_ENV} may only contain ASCII letters, digits, '.', '_' and '-' \
                 (got {segment:?})"
            )));
        }
        // `.` and `..` are path traversal in every backend that maps keys onto
        // a filesystem, and a leading/trailing dot is a portability hazard on
        // object stores that normalize names.
        if segment.chars().all(|c| c == '.') {
            return Err(AppError::Validation(format!(
                "{PROXY_CACHE_SCOPE_ENV} must not be a dot segment (got {segment:?})"
            )));
        }
        Ok(Self::from_segment(segment.to_string()))
    }

    fn from_segment(segment: String) -> Self {
        Self {
            root: format!("{PROXY_CACHE_NAMESPACE}{segment}/"),
            segment: Some(segment),
        }
    }

    /// The root every key, listing prefix and prefix parser in this
    /// deployment's proxy cache is built from. Always ends in `/`.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// The scope segment, or `None` for the legacy unscoped layout. Logged at
    /// startup so an operator can find their deployment's cache tree.
    pub fn segment(&self) -> Option<&str> {
        self.segment.as_deref()
    }

    /// `proxy-cache/<scope>/<repo_key>/` — the listing prefix and parse anchor
    /// for everything cached for one repository in this deployment.
    pub fn repo_root(&self, repo_key: &str) -> String {
        format!("{}{repo_key}/", self.root)
    }

    /// Bytes this scope adds to every cache key, charged against the
    /// object-store key-length budget.
    pub fn key_overhead_bytes(&self) -> usize {
        self.root.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOY_A: Uuid = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    const DEPLOY_B: Uuid = Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000);

    /// The reserved namespace this module composes must be the same string the
    /// storage layer anchors at the bucket root. If they drift, a scoped key
    /// gets `S3_PREFIX` prepended on one side and not the other, which is
    /// exactly the #3368 defect that #3513 fixed.
    #[test]
    fn namespace_matches_bucket_root_declaration() {
        assert!(
            crate::storage::BUCKET_ROOT_KEY_NAMESPACES.contains(&PROXY_CACHE_NAMESPACE),
            "proxy-cache namespace {PROXY_CACHE_NAMESPACE:?} is not declared bucket-root anchored"
        );
        assert!(crate::storage::key_is_bucket_root_anchored(
            &ProxyCacheScope::from_deployment_id(DEPLOY_A).repo_root("some-repo")
        ));
    }

    #[test]
    fn unscoped_root_is_the_legacy_layout() {
        assert_eq!(ProxyCacheScope::unscoped().root(), "proxy-cache/");
        assert_eq!(
            ProxyCacheScope::unscoped().repo_root("maven-proxy"),
            "proxy-cache/maven-proxy/"
        );
        assert_eq!(ProxyCacheScope::unscoped().segment(), None);
    }

    #[test]
    fn derived_scope_is_the_deployment_id() {
        let scope = ProxyCacheScope::from_deployment_id(DEPLOY_A);
        assert_eq!(scope.segment(), Some(DEPLOY_A.to_string().as_str()));
        assert_eq!(
            scope.repo_root("maven-proxy"),
            format!("proxy-cache/{DEPLOY_A}/maven-proxy/")
        );
    }

    /// The scope segment sits INSIDE the reserved namespace, so every
    /// consumer that classifies a key by its leading `proxy-cache/` token —
    /// `is_proxy_cache_key`, the `NOT LIKE 'proxy-cache/%'` accounting
    /// predicates, `key_is_bucket_root_anchored` — keeps working unchanged.
    #[test]
    fn scoped_keys_stay_inside_the_reserved_namespace() {
        for scope in [
            ProxyCacheScope::unscoped(),
            ProxyCacheScope::from_deployment_id(DEPLOY_A),
            ProxyCacheScope::from_explicit_segment("prod-eu").unwrap(),
        ] {
            assert!(
                scope.repo_root("r").starts_with(PROXY_CACHE_NAMESPACE),
                "{} left the reserved namespace",
                scope.root()
            );
        }
    }

    /// Two deployments must not address one another's cache objects.
    #[test]
    fn two_deployments_do_not_share_a_repository_cache_root() {
        let a = ProxyCacheScope::from_deployment_id(DEPLOY_A);
        let b = ProxyCacheScope::from_deployment_id(DEPLOY_B);
        assert_ne!(a.repo_root("maven-proxy"), b.repo_root("maven-proxy"));
        // ...and neither is a prefix of the other, so a prefix LISTING in one
        // deployment cannot enumerate the other's objects either.
        assert!(!a
            .repo_root("maven-proxy")
            .starts_with(&b.repo_root("maven-proxy")));
        assert!(!b
            .repo_root("maven-proxy")
            .starts_with(&a.repo_root("maven-proxy")));
    }

    /// The unset default must isolate. A deployment that configures nothing
    /// gets its own tree, not the shared one.
    #[test]
    fn unset_override_derives_a_scope_rather_than_falling_back_to_shared() {
        let resolved = ProxyCacheScope::from_env_and_identity(None, DEPLOY_A).unwrap();
        assert_eq!(resolved, ProxyCacheScope::from_deployment_id(DEPLOY_A));
        assert_ne!(resolved, ProxyCacheScope::unscoped());
        assert!(resolved.segment().is_some());
    }

    /// Blank/whitespace overrides are treated as unset, not as "no scope".
    #[test]
    fn blank_override_is_treated_as_unset() {
        for raw in ["", "   ", "\t"] {
            let resolved = ProxyCacheScope::from_env_and_identity(Some(raw), DEPLOY_A).unwrap();
            assert_eq!(
                resolved,
                ProxyCacheScope::from_deployment_id(DEPLOY_A),
                "{raw:?} should fall through to the derived scope"
            );
        }
    }

    #[test]
    fn explicit_override_wins_over_the_deployment_id() {
        let resolved = ProxyCacheScope::from_env_and_identity(Some(" prod-eu "), DEPLOY_A).unwrap();
        assert_eq!(resolved.segment(), Some("prod-eu"));
        assert_eq!(resolved.root(), "proxy-cache/prod-eu/");
    }

    /// A malformed override is a startup error, never a silent downgrade to
    /// the derived scope or to the shared layout.
    #[test]
    fn malformed_override_is_rejected_not_silently_replaced() {
        for bad in [
            "has/slash",
            "..",
            ".",
            "has space",
            "has\\backslash",
            "sco\0pe",
            "emoji-\u{1f600}",
        ] {
            match ProxyCacheScope::from_env_and_identity(Some(bad), DEPLOY_A) {
                Err(AppError::Validation(_)) => {}
                other => panic!("{bad:?} must be rejected as invalid, got {other:?}"),
            }
        }
        let too_long = "a".repeat(MAX_SCOPE_SEGMENT_LEN + 1);
        assert!(ProxyCacheScope::from_env_and_identity(Some(&too_long), DEPLOY_A).is_err());
        assert!(ProxyCacheScope::from_env_and_identity(
            Some(&"a".repeat(MAX_SCOPE_SEGMENT_LEN)),
            DEPLOY_A
        )
        .is_ok());
    }

    /// There must be no configuration value that reinstates the shared layout.
    #[test]
    fn no_override_value_can_select_the_shared_layout() {
        for attempt in ["", " ", "none", "off", "false", "shared", "legacy", "/"] {
            if let Ok(scope) = ProxyCacheScope::from_env_and_identity(Some(attempt), DEPLOY_A) {
                assert_ne!(
                    scope,
                    ProxyCacheScope::unscoped(),
                    "{attempt:?} selected the pre-#3454 shared layout"
                );
            }
        }
    }

    #[test]
    fn key_overhead_is_the_root_length() {
        assert_eq!(ProxyCacheScope::unscoped().key_overhead_bytes(), 12);
        let scope = ProxyCacheScope::from_deployment_id(DEPLOY_A);
        assert_eq!(scope.key_overhead_bytes(), scope.root().len());
        assert!(scope.key_overhead_bytes() > ProxyCacheScope::unscoped().key_overhead_bytes());
    }
}
