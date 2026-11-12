//! Request-scoped facts the IAM shadow comparison (#4214) needs from the
//! legacy request path.
//!
//! * A legacy handler that refuses a caller who may not see a resource answers
//!   the same 404 as an unknown key, so the response alone cannot tell a
//!   refusal from a missing resource. The hiding helpers call
//!   [`note_hidden_refusal`] with the repository they hid.
//! * The shared legacy checks record the strongest check that passed for a
//!   resource ([`note_passed`] for a repository, [`note_passed_on`] for any
//!   resource), so a later 4xx can be told from a refusal that came before
//!   the check ran.
//! * A handler records refusals it keeps after enforcement
//!   ([`note_kept_refusal`]) and, for a resource its body names, the target it
//!   authorized ([`note_target`]).
//! * The authentication middleware runs inside each `/api/v1` nest, below the
//!   shadow layer, so it records the principal it resolved
//!   ([`note_principal`]) and the API token that authenticated it
//!   ([`note_api_token`]).
//!
//! Everything is task-local: nothing reaches the response, so no client can
//! observe it, and outside a [`scope`] every `note_*` call is a no-op.

use std::cell::{Cell, RefCell};
use std::future::Future;

use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::models::access_scope::AccessScope;
use crate::services::iam_legacy_projection::ScopeRef;

/// The authenticated principal, reduced to what a comparison needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedPrincipal {
    pub user_id: Uuid,
    pub is_service_account: bool,
    pub is_api_token: bool,
    /// The credential carries an action-scope list or a repository allow-list.
    pub restricted: bool,
}

impl RecordedPrincipal {
    pub fn of(ext: &AuthExtension) -> RecordedPrincipal {
        RecordedPrincipal {
            user_id: ext.user_id,
            is_service_account: ext.is_service_account,
            is_api_token: ext.is_api_token,
            restricted: ext.scopes.is_some() || !matches!(ext.allowed_repo_ids, AccessScope::Admin),
        }
    }
}

/// A legacy repository check, by the action it proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegacyLevel {
    Read,
    Write,
    Delete,
    Admin,
}

impl LegacyLevel {
    /// The level a legacy action string proves, if it is one.
    pub fn of_action(action: &str) -> Option<LegacyLevel> {
        match action {
            "read" => Some(LegacyLevel::Read),
            "write" => Some(LegacyLevel::Write),
            "delete" => Some(LegacyLevel::Delete),
            "admin" => Some(LegacyLevel::Admin),
            _ => None,
        }
    }

    /// Whether a passed check at `self` proves a check at `needed`: the same
    /// action, `admin` (every action), or any check for a read.
    pub fn satisfies(self, needed: LegacyLevel) -> bool {
        self == needed || self == LegacyLevel::Admin || needed == LegacyLevel::Read
    }
}

/// What the legacy request path recorded while it ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recorded {
    /// The repository of the first existence-hiding refusal.
    pub hidden_refusal: Option<Uuid>,
    /// The strongest check that passed, per resource.
    pub passed: Vec<(ScopeRef, LegacyLevel)>,
    /// The first refusal the handler keeps after enforcement, by reason.
    pub kept_refusal: Option<&'static str>,
    /// The resource a body-resolved declaration was authorized on.
    pub target: Option<ScopeRef>,
    pub principal: Option<RecordedPrincipal>,
    pub api_token: Option<Uuid>,
}

impl Recorded {
    /// The strongest check that passed on `resource`.
    pub fn passed_on(&self, resource: ScopeRef) -> Option<LegacyLevel> {
        self.passed
            .iter()
            .find(|(r, _)| *r == resource)
            .map(|(_, level)| *level)
    }
}

#[derive(Default)]
struct Recorder {
    hidden_refusal: Cell<Option<Uuid>>,
    passed: RefCell<Vec<(ScopeRef, LegacyLevel)>>,
    kept_refusal: Cell<Option<&'static str>>,
    target: Cell<Option<ScopeRef>>,
    principal: Cell<Option<RecordedPrincipal>>,
    api_token: Cell<Option<Uuid>>,
}

tokio::task_local! {
    static RECORDER: Recorder;
}

/// Record that the request in flight was refused with an existence-hiding
/// answer for `repository_id`; the first call wins.
pub fn note_hidden_refusal(repository_id: Uuid) {
    let _ = RECORDER.try_with(|r| {
        if r.hidden_refusal.get().is_none() {
            r.hidden_refusal.set(Some(repository_id));
        }
    });
}

/// Record that a legacy check at `level` passed on `repository_id`; the
/// strongest level per repository is kept.
pub fn note_passed(repository_id: Uuid, level: LegacyLevel) {
    note_passed_on(ScopeRef::Repository(repository_id), level);
}

/// Record that a legacy check at `level` passed on `resource`; the strongest
/// level per resource is kept.
pub fn note_passed_on(resource: ScopeRef, level: LegacyLevel) {
    let _ = RECORDER.try_with(|r| {
        let mut passed = r.passed.borrow_mut();
        match passed.iter_mut().find(|(kept_on, _)| *kept_on == resource) {
            Some((_, kept)) => *kept = (*kept).max(level),
            None => passed.push((resource, level)),
        }
    });
}

/// Record a refusal the handler keeps after enforcement, by a fixed reason;
/// the first call wins.
pub fn note_kept_refusal(reason: &'static str) {
    let _ = RECORDER.try_with(|r| {
        if r.kept_refusal.get().is_none() {
            r.kept_refusal.set(Some(reason));
        }
    });
}

/// Record `error` as a refusal the handler keeps after enforcement when it is
/// one (an authentication, authorization or not-found answer), under a fixed
/// `reason`; returns it unchanged.
pub fn keep_refusal(reason: &'static str, error: crate::error::AppError) -> crate::error::AppError {
    use crate::error::AppError;
    if matches!(
        error,
        AppError::Authentication(_)
            | AppError::Unauthorized(_)
            | AppError::Authorization(_)
            | AppError::NotFound(_)
    ) {
        note_kept_refusal(reason);
    }
    error
}

/// Record the resource the handler authorized for a body-resolved
/// declaration; the last call wins.
pub fn note_target(target: ScopeRef) {
    let _ = RECORDER.try_with(|r| r.target.set(Some(target)));
}

/// Record the principal the authentication middleware resolved; the last call
/// wins.
pub fn note_principal(ext: &AuthExtension) {
    let _ = RECORDER.try_with(|r| r.principal.set(Some(RecordedPrincipal::of(ext))));
}

/// Record the API token that authenticated the request; the last call wins.
pub fn note_api_token(token_id: Uuid) {
    let _ = RECORDER.try_with(|r| r.api_token.set(Some(token_id)));
}

/// Run `fut` with the recorder in effect; returns its output and what was
/// recorded while it ran.
pub async fn scope<F: Future>(fut: F) -> (F::Output, Recorded) {
    RECORDER
        .scope(Recorder::default(), async {
            let output = fut.await;
            let recorded = RECORDER.with(|r| Recorded {
                hidden_refusal: r.hidden_refusal.get(),
                passed: r.passed.borrow().clone(),
                kept_refusal: r.kept_refusal.get(),
                target: r.target.get(),
                principal: r.principal.get(),
                api_token: r.api_token.get(),
            });
            (output, recorded)
        })
        .await
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    /// `scope`, keeping only whether a hidden refusal was marked.
    async fn marked<F: Future>(fut: F) -> (F::Output, bool) {
        let (output, recorded) = scope(fut).await;
        (output, recorded.hidden_refusal.is_some())
    }

    #[tokio::test]
    async fn notes_are_seen_inside_their_scope_only() {
        let token = Uuid::new_v4();
        let ext = crate::api::handlers::test_db_helpers::make_auth(Uuid::new_v4(), "u");
        let ((), recorded) = scope(async {
            note_principal(&ext);
            note_api_token(token);
        })
        .await;
        assert_eq!(recorded.principal, Some(RecordedPrincipal::of(&ext)));
        assert_eq!(recorded.api_token, Some(token));
        assert!(recorded.hidden_refusal.is_none());
        // Outside a scope: no panic, and the next scope starts empty.
        note_principal(&ext);
        note_api_token(token);
        let ((), recorded) = scope(async {}).await;
        assert_eq!(recorded, Recorded::default());
    }

    #[test]
    fn a_principal_is_restricted_by_scopes_or_a_repository_allow_list() {
        let mut ext = crate::api::handlers::test_db_helpers::make_auth(Uuid::new_v4(), "u");
        assert!(!RecordedPrincipal::of(&ext).restricted);
        ext.scopes = Some(vec!["read:artifacts".into()]);
        assert!(RecordedPrincipal::of(&ext).restricted);
        ext.scopes = None;
        ext.allowed_repo_ids = AccessScope::Restricted(vec![]);
        assert!(RecordedPrincipal::of(&ext).restricted);
    }

    #[tokio::test]
    async fn a_noted_refusal_is_seen_inside_its_scope_only() {
        let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
        let ((), recorded) = scope(async {
            note_hidden_refusal(first);
            note_hidden_refusal(second);
        })
        .await;
        assert_eq!(recorded.hidden_refusal, Some(first), "the first mark wins");
        let ((), hidden) = marked(async {}).await;
        assert!(!hidden);
        // Outside a scope: no panic, nothing recorded anywhere.
        note_hidden_refusal(first);
        let ((), hidden) = marked(async {}).await;
        assert!(!hidden);
    }

    #[tokio::test]
    async fn passes_keep_the_strongest_level_per_repository() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let ((), recorded) = scope(async {
            note_passed(a, LegacyLevel::Admin);
            note_passed(a, LegacyLevel::Read);
            note_passed(b, LegacyLevel::Read);
            note_passed(b, LegacyLevel::Write);
        })
        .await;
        assert_eq!(
            recorded.passed_on(ScopeRef::Repository(a)),
            Some(LegacyLevel::Admin)
        );
        assert_eq!(
            recorded.passed_on(ScopeRef::Repository(b)),
            Some(LegacyLevel::Write)
        );
        assert_eq!(
            recorded.passed_on(ScopeRef::Repository(Uuid::new_v4())),
            None
        );
        note_passed(a, LegacyLevel::Admin);
        let ((), recorded) = scope(async {}).await;
        assert!(recorded.passed.is_empty());
    }

    #[tokio::test]
    async fn passes_on_different_kinds_of_resource_are_kept_apart() {
        let id = Uuid::new_v4();
        let ((), recorded) = scope(async {
            note_passed(id, LegacyLevel::Read);
            note_passed_on(ScopeRef::Project(id), LegacyLevel::Admin);
            note_passed_on(ScopeRef::Instance, LegacyLevel::Admin);
        })
        .await;
        assert_eq!(
            recorded.passed_on(ScopeRef::Repository(id)),
            Some(LegacyLevel::Read)
        );
        assert_eq!(
            recorded.passed_on(ScopeRef::Project(id)),
            Some(LegacyLevel::Admin)
        );
        assert_eq!(recorded.passed_on(ScopeRef::Group(id)), None);
        assert_eq!(
            recorded.passed_on(ScopeRef::Instance),
            Some(LegacyLevel::Admin)
        );
    }

    #[tokio::test]
    async fn kept_refusals_and_targets_are_recorded() {
        let project = ScopeRef::Project(Uuid::new_v4());
        let ((), recorded) = scope(async {
            note_kept_refusal("token_owner");
            note_kept_refusal("immutable_release");
            note_target(ScopeRef::Instance);
            note_target(project);
        })
        .await;
        assert_eq!(recorded.kept_refusal, Some("token_owner"), "the first wins");
        assert_eq!(recorded.target, Some(project), "the last wins");
        note_kept_refusal("token_owner");
        note_target(project);
        let ((), recorded) = scope(async {}).await;
        assert_eq!(recorded, Recorded::default());
    }

    #[test]
    fn levels_satisfy_the_same_action_admin_or_a_read() {
        use LegacyLevel::*;
        assert!(Write.satisfies(Write) && Admin.satisfies(Delete) && Read.satisfies(Read));
        assert!(Write.satisfies(Read) && Delete.satisfies(Read));
        assert!(!Read.satisfies(Write) && !Delete.satisfies(Write) && !Write.satisfies(Admin));
        assert_eq!(LegacyLevel::of_action("delete"), Some(Delete));
        assert_eq!(LegacyLevel::of_action("own"), None);
    }

    use crate::api::handlers::artifacts::check_artifact_visibility;
    use crate::api::handlers::repositories::{hide_write_denial_from_non_readers, require_visible};
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::error::AppError;
    use crate::services::repository_service::RepositoryService;
    use axum::response::IntoResponse;
    use uuid::Uuid;

    #[allow(clippy::disallowed_methods)] // STREAMING-EXEMPT: test reads a small, bounded error body
    async fn body_of(err: AppError) -> (axum::http::StatusCode, bytes::Bytes) {
        let response = err.into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, body)
    }

    #[tokio::test]
    async fn repository_hiding_branches_mark_and_others_do_not() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let service = RepositoryService::new(pool.clone());
        let (outsider, outsider_name) = tdh::create_user(&pool).await;
        let (reader, reader_name) = tdh::create_user(&pool).await;
        let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::grant_repo_role(&pool, repo_id, reader, "reader").await;
        let repo = service.get_by_id(repo_id).await.unwrap();
        let outsider = Some(tdh::make_auth(outsider, &outsider_name));
        let reader = tdh::make_auth(reader, &reader_name);

        // require_visible: a hidden refusal marks; a permit does not.
        let (result, recorded) = scope(require_visible(&repo, &outsider, &service)).await;
        let refusal = result.expect_err("outsider is refused");
        assert_eq!(
            recorded.hidden_refusal,
            Some(repo_id),
            "the mark names the repository"
        );
        assert_eq!(recorded.passed_on(ScopeRef::Repository(repo_id)), None);
        let (result, hidden) = marked(require_visible(&repo, &None, &service)).await;
        assert!(result.is_err() && hidden, "anonymous is refused and marked");
        let (result, recorded) =
            scope(require_visible(&repo, &Some(reader.clone()), &service)).await;
        assert!(result.is_ok() && recorded.hidden_refusal.is_none());
        assert_eq!(
            recorded.passed_on(ScopeRef::Repository(repo_id)),
            Some(LegacyLevel::Read)
        );

        // The hidden answer is byte-identical to the unknown-key 404.
        let unknown = service
            .get_by_key(&format!("no-such-{}", Uuid::new_v4()))
            .await
            .expect_err("unknown key");
        assert_eq!(body_of(refusal).await, body_of(unknown).await);

        // hide_write_denial_from_non_readers: hiding marks, a reader's 403
        // stays visible and unmarked, a permit passes unmarked.
        let denied = || Err(AppError::Authorization("no write".into()));
        let (result, hidden) = marked(hide_write_denial_from_non_readers(
            denied(),
            outsider.as_ref().unwrap(),
            &repo,
            &service,
        ))
        .await;
        assert!(matches!(result, Err(AppError::NotFound(_))) && hidden);
        let (result, hidden) = marked(hide_write_denial_from_non_readers(
            denied(),
            &reader,
            &repo,
            &service,
        ))
        .await;
        assert!(matches!(result, Err(AppError::Authorization(_))) && !hidden);
        let (result, hidden) = marked(hide_write_denial_from_non_readers(
            Ok(()),
            &reader,
            &repo,
            &service,
        ))
        .await;
        assert!(result.is_ok() && !hidden);
    }

    #[tokio::test]
    async fn artifact_hiding_branches_mark_and_others_do_not() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (outsider, outsider_name) = tdh::create_user(&pool).await;
        let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let artifact: Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) \
             VALUES ($1, 'm/1.0/m.bin', 'm.bin', 1, repeat('0', 64), \
                     'application/octet-stream', $2) RETURNING id",
        )
        .bind(repo_id)
        .bind(format!("m/{repo_id}"))
        .fetch_one(&pool)
        .await
        .unwrap();
        let outsider = Some(tdh::make_auth(outsider, &outsider_name));
        let mut scoped_elsewhere = outsider.clone().unwrap();
        scoped_elsewhere.is_admin = true;
        scoped_elsewhere.allowed_repo_ids =
            crate::models::access_scope::AccessScope::Restricted(vec![Uuid::new_v4()]);

        for auth in [None, outsider.clone(), Some(scoped_elsewhere.clone())] {
            let (result, hidden) =
                marked(check_artifact_visibility(&auth, artifact, &pool, "read")).await;
            assert!(matches!(result, Err(AppError::NotFound(_))), "{auth:?}");
            assert!(hidden, "{auth:?}");
        }
        // A token write outside its ceiling keeps the 403, unmarked.
        let (result, hidden) = marked(check_artifact_visibility(
            &Some(scoped_elsewhere),
            artifact,
            &pool,
            "write",
        ))
        .await;
        assert!(matches!(result, Err(AppError::Authorization(_))) && !hidden);
        // A missing artifact is not a refusal.
        let (result, hidden) = marked(check_artifact_visibility(
            &outsider,
            Uuid::new_v4(),
            &pool,
            "read",
        ))
        .await;
        assert!(result.is_ok() && !hidden);
        // An admin is admitted, unmarked.
        let Some(mut admin) = outsider else {
            unreachable!("built as Some above")
        };
        admin.is_admin = true;
        let (result, hidden) = marked(check_artifact_visibility(
            &Some(admin),
            artifact,
            &pool,
            "read",
        ))
        .await;
        assert!(result.is_ok() && !hidden);
    }
}
