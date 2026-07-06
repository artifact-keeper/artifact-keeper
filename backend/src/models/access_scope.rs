//! Repository-scope authorization decision type.
//!
//! Historically, "which repositories may this principal touch?" was modelled
//! as an `Option<Vec<Uuid>>` (`None` = unrestricted/admin, `Some` = allowlist)
//! threaded through the auth middleware and the OCI/SBOM services. That
//! stringly/optionally-typed shape invites the "`None` falls open" bug class:
//! a reader (or a refactor) can confuse "no restriction / admin" with
//! "restricted to nothing", and an accidental `None` silently grants full
//! cross-repo access.
//!
//! [`AccessScope`] makes the decision explicit and exhaustively matched. It is
//! an internal type only — it changes no API/wire representation and bridges
//! to/from the legacy `Option<Vec<Uuid>>` via `From` so the migration can
//! proceed incrementally (#1617, Phase 4).

use uuid::Uuid;

/// Explicit repository-scope authorization decision for a token/principal.
///
/// Replaces the footgun-prone `Option<Vec<Uuid>>` shape used by
/// `AuthExtension::allowed_repo_ids` and the SBOM read paths. The point of the
/// enum is that "no restriction / admin" can never be confused with
/// "restricted to nothing":
///
/// - [`AccessScope::Admin`] — **no** repository restriction; grants access to
///   every repository. Corresponds to the legacy `None` (admin/root tokens,
///   JWT sessions, system workers).
/// - [`AccessScope::Restricted`] — an explicit allowlist. **Deny-by-default:**
///   `Restricted(vec![])` grants access to *nothing* (it does NOT fall open),
///   and `Restricted([r])` grants access only to `r`. Corresponds to the
///   legacy `Some(v)`.
///
/// Bridges to/from `Option<Vec<Uuid>>` (and the borrowed `Option<&[Uuid]>`)
/// via `From`, preserving today's semantics exactly: `None <-> Admin`,
/// `Some(v) <-> Restricted(v)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessScope {
    /// No repository restriction; grants access to all repositories.
    Admin,
    /// Restricted to an explicit allowlist. An empty allowlist grants access
    /// to nothing (deny-by-default), never to everything.
    Restricted(Vec<Uuid>),
}

impl AccessScope {
    /// Returns `true` if this scope grants access to `repo_id`.
    ///
    /// [`Admin`](AccessScope::Admin) grants everything;
    /// [`Restricted`](AccessScope::Restricted) grants only repositories present
    /// in its allowlist — so `Restricted(vec![])` grants nothing.
    pub fn grants(&self, repo_id: Uuid) -> bool {
        match self {
            AccessScope::Admin => true,
            AccessScope::Restricted(ids) => ids.contains(&repo_id),
        }
    }

    /// Borrow this scope as the legacy `Option<&[Uuid]>` view without
    /// allocating.
    ///
    /// `Admin -> None`, `Restricted(v) -> Some(&v)`. Lets service APIs that
    /// still accept `Option<&[Uuid]>` be driven from an [`AccessScope`] during
    /// the incremental migration.
    pub fn as_allowed_repo_ids(&self) -> Option<&[Uuid]> {
        match self {
            AccessScope::Admin => None,
            AccessScope::Restricted(ids) => Some(ids),
        }
    }
}

impl Default for AccessScope {
    /// Deny-by-default: the default scope grants access to **nothing**
    /// (`Restricted(vec![])`), never `Admin`. This is what `..Default::default()`
    /// resolves to when an `AuthExtension` literal omits `allowed_repo_ids`
    /// (e.g. test fixtures). If any production path ever constructs an
    /// `AuthExtension` via `..Default::default()`, it MUST fail CLOSED — an
    /// accidental omission can never silently grant cross-repo access.
    fn default() -> Self {
        AccessScope::Restricted(Vec::new())
    }
}

impl From<Option<Vec<Uuid>>> for AccessScope {
    fn from(value: Option<Vec<Uuid>>) -> Self {
        match value {
            None => AccessScope::Admin,
            Some(ids) => AccessScope::Restricted(ids),
        }
    }
}

impl From<&Option<Vec<Uuid>>> for AccessScope {
    fn from(value: &Option<Vec<Uuid>>) -> Self {
        match value {
            None => AccessScope::Admin,
            Some(ids) => AccessScope::Restricted(ids.clone()),
        }
    }
}

impl From<Option<&[Uuid]>> for AccessScope {
    fn from(value: Option<&[Uuid]>) -> Self {
        match value {
            None => AccessScope::Admin,
            Some(ids) => AccessScope::Restricted(ids.to_vec()),
        }
    }
}

impl From<AccessScope> for Option<Vec<Uuid>> {
    fn from(scope: AccessScope) -> Self {
        match scope {
            AccessScope::Admin => None,
            AccessScope::Restricted(ids) => Some(ids),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn admin_grants_every_repo() {
        let scope = AccessScope::Admin;
        assert!(scope.grants(repo(1)));
        assert!(scope.grants(repo(2)));
        assert!(scope.grants(Uuid::nil()));
    }

    /// SECURITY-CRITICAL (#1394): the derived `Default` — reached whenever an
    /// `AuthExtension` is built via `..Default::default()` — must fail CLOSED.
    /// It is `Restricted(vec![])` (grants nothing), never `Admin`.
    #[test]
    fn default_is_deny_by_default_never_admin() {
        let scope = AccessScope::default();
        assert_eq!(scope, AccessScope::Restricted(Vec::new()));
        assert_ne!(scope, AccessScope::Admin);
        assert!(!scope.grants(repo(1)));
        assert!(!scope.grants(Uuid::nil()));
    }

    #[test]
    fn restricted_empty_denies_by_default() {
        // The load-bearing case: an empty allowlist must grant NOTHING, not
        // fall open to everything.
        let scope = AccessScope::Restricted(vec![]);
        assert!(!scope.grants(repo(1)));
        assert!(!scope.grants(Uuid::nil()));
    }

    #[test]
    fn restricted_single_grants_only_that_repo() {
        let scope = AccessScope::Restricted(vec![repo(7)]);
        assert!(scope.grants(repo(7)));
        assert!(!scope.grants(repo(8)));
    }

    #[test]
    fn from_option_none_is_admin() {
        assert_eq!(AccessScope::from(None::<Vec<Uuid>>), AccessScope::Admin);
    }

    #[test]
    fn from_option_some_is_restricted() {
        assert_eq!(
            AccessScope::from(Some(vec![repo(3)])),
            AccessScope::Restricted(vec![repo(3)])
        );
        // Empty Some must map to Restricted(empty) (deny), never to Admin.
        assert_eq!(
            AccessScope::from(Some(Vec::<Uuid>::new())),
            AccessScope::Restricted(vec![])
        );
    }

    #[test]
    fn round_trip_option_to_scope_to_option() {
        for original in [None, Some(vec![]), Some(vec![repo(1), repo(2)])] {
            let scope = AccessScope::from(original.clone());
            let back: Option<Vec<Uuid>> = scope.into();
            assert_eq!(back, original);
        }
    }

    #[test]
    fn from_borrowed_option_matches_owned() {
        let owned = Some(vec![repo(5)]);
        assert_eq!(AccessScope::from(&owned), AccessScope::from(owned.clone()));
        let none: Option<Vec<Uuid>> = None;
        assert_eq!(AccessScope::from(&none), AccessScope::Admin);
    }

    #[test]
    fn from_borrowed_slice_option() {
        let ids = [repo(1), repo(2)];
        assert_eq!(
            AccessScope::from(Some(ids.as_slice())),
            AccessScope::Restricted(vec![repo(1), repo(2)])
        );
        assert_eq!(AccessScope::from(None::<&[Uuid]>), AccessScope::Admin);
    }

    #[test]
    fn as_allowed_repo_ids_round_trips() {
        assert_eq!(AccessScope::Admin.as_allowed_repo_ids(), None);
        let ids = vec![repo(9)];
        let scope = AccessScope::Restricted(ids.clone());
        assert_eq!(scope.as_allowed_repo_ids(), Some(ids.as_slice()));
        // Reconstructing from the borrowed view yields the same scope.
        assert_eq!(AccessScope::from(scope.as_allowed_repo_ids()), scope);
    }
}
