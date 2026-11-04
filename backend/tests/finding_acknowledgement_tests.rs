//! Regression tests for #5153: an acknowledgement is a decision about an
//! advisory in a component of specific bytes, not a flag on one finding row.
//!
//! Every scenario goes through the real write paths (`create_findings`,
//! `copy_scan_results`, `convert_to_reused`) and asserts on the readers an
//! operator depends on: the scan-policy gate, the finding listing and the
//! shared severity counts.
//!
//! ```sh
//! AK_TESTS_REQUIRE_DB=1 DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo nextest run --run-ignored ignored-only --test finding_acknowledgement_tests
//! ```

use std::path::PathBuf;

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::error::AppError;
use artifact_keeper_backend::models::access_scope::AccessScope;
use artifact_keeper_backend::models::sbom::CveStatus;
use artifact_keeper_backend::models::security::{FindingClass, RawFinding, ScanResult, Severity};
use artifact_keeper_backend::services::finding_acknowledgements::{
    AckActor, AcknowledgeOptions, AcknowledgementFilter, AcknowledgementScope, CarryOutcome,
    CarryPrincipal, FindingAcknowledgementService,
};
use artifact_keeper_backend::services::open_findings::{severity_counts, FindingScope};
use artifact_keeper_backend::services::policy_service::PolicyService;
use artifact_keeper_backend::services::promotion_policy_service::{
    PromotionGateContext, PromotionPolicyService,
};
use artifact_keeper_backend::services::promotion_rule_service::PromotionRuleService;
use artifact_keeper_backend::services::quarantine_service::enforce_download_gate;
use artifact_keeper_backend::services::sbom_service::SbomService;
use artifact_keeper_backend::services::scan_result_service::{
    FindingListFilter, ScanResultService,
};

const LODASH: &str = "lodash";
const CVE_A: &str = "CVE-2021-23337";
const CVE_B: &str = "CVE-2020-8203";

struct Fx {
    pool: PgPool,
    svc: ScanResultService,
    admin: Uuid,
    repos: Vec<Uuid>,
}

impl Fx {
    async fn new() -> Self {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
            .await
            .expect("connect");
        let admin = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
             VALUES ($1, $2, $3, 'unused', 'local', true, true)",
        )
        .bind(admin)
        .bind(format!("ack-admin-{admin}"))
        .bind(format!("ack-admin-{admin}@test.local"))
        .execute(&pool)
        .await
        .expect("insert admin");
        sqlx::query(
            "INSERT INTO role_assignments (user_id, role_id) \
             SELECT $1, r.id FROM roles r WHERE r.name = 'admin'",
        )
        .bind(admin)
        .execute(&pool)
        .await
        .expect("grant the global admin role");
        Self {
            svc: ScanResultService::new(pool.clone()),
            pool,
            admin,
            repos: Vec::new(),
        }
    }

    fn actor(&self) -> AckActor {
        AckActor::new(self.admin, AccessScope::Admin)
    }

    fn admin_principal(&self) -> CarryPrincipal {
        CarryPrincipal {
            user_id: self.admin,
            may_acknowledge: true,
        }
    }

    /// A hosted repository whose enabled policy blocks `high` and above.
    async fn repo(&mut self) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $2, $3, 'local', 'generic')",
        )
        .bind(id)
        .bind(format!("ack-5153-{id}"))
        .bind(format!("/tmp/ack-5153-{id}"))
        .execute(&self.pool)
        .await
        .expect("insert repo");
        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'high', false, false, true)",
        )
        .bind(format!("ack-5153-{id}"))
        .bind(id)
        .execute(&self.pool)
        .await
        .expect("insert policy");
        self.repos.push(id);
        id
    }

    async fn artifact(&self, repo: Uuid, name: &str, digest: &str) -> Uuid {
        let id = Uuid::new_v4();
        let path = format!("{id}/{name}");
        sqlx::query(
            "INSERT INTO artifacts (id, repository_id, name, path, size_bytes, checksum_sha256, \
                                    content_type, storage_key) \
             VALUES ($1, $2, $3, $4, 1, $5, 'application/octet-stream', $4)",
        )
        .bind(id)
        .bind(repo)
        .bind(name)
        .bind(&path)
        .bind(digest)
        .execute(&self.pool)
        .await
        .expect("insert artifact");
        id
    }

    /// One completed scan through the real writers. Returns its id.
    async fn scan(
        &self,
        repo: Uuid,
        artifact: Uuid,
        scan_type: &str,
        findings: &[RawFinding],
    ) -> Uuid {
        let digest: String =
            sqlx::query_scalar("SELECT checksum_sha256 FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&self.pool)
                .await
                .expect("digest");
        let row = self
            .svc
            .create_scan_result_with_checksum(artifact, repo, scan_type, Some(digest.trim()))
            .await
            .expect("create scan");
        self.svc
            .create_findings(row.id, artifact, findings)
            .await
            .expect("create findings");
        self.complete(row.id, findings.len() as i32, "complete")
            .await;
        row.id
    }

    async fn unfinished_scan(&self, repo: Uuid, artifact: Uuid) -> ScanResult {
        let digest: String =
            sqlx::query_scalar("SELECT checksum_sha256 FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&self.pool)
                .await
                .expect("digest");
        self.svc
            .create_scan_result_with_checksum(artifact, repo, "dependency", Some(digest.trim()))
            .await
            .expect("create scan")
    }

    async fn complete(&self, scan: Uuid, count: i32, completeness: &str) {
        self.svc
            .complete_scan(
                scan,
                count,
                0,
                count,
                0,
                0,
                0,
                Some("test-1"),
                Utc::now(),
                completeness,
                None,
                None,
                None,
            )
            .await
            .expect("complete scan");
    }

    async fn finding_ids(&self, scan: Uuid) -> Vec<Uuid> {
        sqlx::query_scalar("SELECT id FROM scan_findings WHERE scan_result_id = $1 ORDER BY id")
            .bind(scan)
            .fetch_all(&self.pool)
            .await
            .expect("finding ids")
    }

    async fn ack_scan(&self, scan: Uuid) {
        for id in self.finding_ids(scan).await {
            self.svc
                .acknowledge_finding(id, &self.actor(), "accepted: SEC-421", Default::default())
                .await
                .expect("acknowledge");
        }
    }

    async fn allowed(&self, repo: Uuid, artifact: Uuid) -> bool {
        PolicyService::new(self.pool.clone())
            .evaluate_artifact(artifact, repo)
            .await
            .expect("evaluate")
            .allowed
    }

    /// Whether the listing reports every finding of `scan` as acknowledged.
    async fn listed_acknowledged(&self, scan: Uuid) -> bool {
        let filter = no_filter();
        let (rows, total) = self
            .svc
            .list_findings(scan, &filter, 0, 100)
            .await
            .expect("list");
        assert!(total > 0, "scan {scan} has no findings to judge");
        rows.iter().all(|f| f.is_acknowledged)
    }

    async fn open_count(&self, artifact: Uuid) -> i64 {
        severity_counts(&self.pool, FindingScope::Artifact(artifact))
            .await
            .expect("counts")
            .open
    }

    /// The audit write is fire-and-forget, so poll until the row lands.
    async fn audit_count(&self, action: &str, needle: &str) -> i64 {
        let mut count = 0;
        for _ in 0..100 {
            count = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_log WHERE action = $1 AND details::text LIKE $2",
            )
            .bind(action)
            .bind(format!("%{needle}%"))
            .fetch_one(&self.pool)
            .await
            .expect("audit count");
            if count > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        count
    }

    async fn cleanup(self) {
        sqlx::query("DELETE FROM artifacts WHERE repository_id = ANY($1)")
            .bind(&self.repos)
            .execute(&self.pool)
            .await
            .expect("remove artifacts");
        sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
            .bind(&self.repos)
            .execute(&self.pool)
            .await
            .expect("remove repositories");
        sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
            .bind(self.admin)
            .execute(&self.pool)
            .await
            .expect("remove role");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(self.admin)
            .execute(&self.pool)
            .await
            .expect("remove admin");
    }
}

fn no_filter() -> FindingListFilter<'static> {
    FindingListFilter {
        severity: None,
        source: None,
        cve_id: None,
        finding_class: None,
    }
}

fn digest() -> String {
    format!("{:064x}", Uuid::new_v4().as_u128())
}

fn finding(cve: &str, component: &str, version: &str) -> RawFinding {
    finding_from(cve, component, version, "grype", Severity::High)
}

fn finding_from(
    cve: &str,
    component: &str,
    version: &str,
    source: &str,
    severity: Severity,
) -> RawFinding {
    RawFinding {
        severity,
        title: format!("{cve} in {component}"),
        description: None,
        cve_id: Some(cve.to_string()),
        affected_component: Some(component.to_string()),
        affected_version: Some(version.to_string()),
        fixed_version: None,
        source: Some(source.to_string()),
        source_url: None,
        finding_class: FindingClass::Vulnerability,
    }
}

// ---------------------------------------------------------------------------
// Survival
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn acknowledgement_survives_a_rescan() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "lodash.tgz", &digest()).await;
    let findings = [finding(CVE_A, LODASH, "4.17.15")];

    let first = fx.scan(repo, artifact, "dependency", &findings).await;
    assert!(
        !fx.allowed(repo, artifact).await,
        "unacknowledged high must block"
    );
    fx.ack_scan(first).await;
    assert!(
        fx.allowed(repo, artifact).await,
        "acknowledged high must not block"
    );

    let rescan = fx.scan(repo, artifact, "dependency", &findings).await;
    assert!(
        fx.allowed(repo, artifact).await,
        "the rescan's identical finding must stay covered"
    );
    assert!(
        fx.listed_acknowledged(rescan).await,
        "the listing must report the rescan's row as acknowledged"
    );
    let counts = severity_counts(&fx.pool, FindingScope::Artifact(artifact))
        .await
        .expect("counts");
    assert_eq!((counts.open, counts.acknowledged), (0, 1));
    enforce_download_gate(&fx.pool, artifact)
        .await
        .expect("the download gate must serve it");

    fx.cleanup().await;
}

/// Walkthrough finding F6: two engines reporting one CVE in one component are
/// one decision, not two.
#[tokio::test]
#[ignore]
async fn one_decision_covers_every_engine_reporting_the_same_component() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "lodash.tgz", &digest()).await;

    let grype = fx
        .scan(
            repo,
            artifact,
            "image",
            &[finding(CVE_A, LODASH, "4.17.15")],
        )
        .await;
    let osv = fx
        .scan(
            repo,
            artifact,
            "dependency",
            &[finding_from(
                CVE_A,
                LODASH,
                "4.17.15",
                "osv.dev",
                Severity::High,
            )],
        )
        .await;
    assert!(!fx.allowed(repo, artifact).await);

    fx.ack_scan(grype).await;
    assert!(fx.listed_acknowledged(osv).await);
    assert!(fx.allowed(repo, artifact).await);

    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn acknowledgement_survives_a_dedup_copy_of_the_same_bytes_in_the_repository() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let d = digest();
    let original = fx.artifact(repo, "a.tgz", &d).await;
    let source = fx
        .scan(
            repo,
            original,
            "dependency",
            &[finding(CVE_A, LODASH, "4.17.15")],
        )
        .await;
    fx.ack_scan(source).await;

    // copy_scan_results: the auto-scan path.
    let copy = fx.artifact(repo, "b.tgz", &d).await;
    let copied = fx
        .svc
        .copy_scan_results(source, copy, repo, "dependency", &d, None)
        .await
        .expect("copy");
    assert!(fx.listed_acknowledged(copied.id).await, "copy_scan_results");
    assert!(fx.allowed(repo, copy).await, "copy_scan_results gate");

    // convert_to_reused: the trigger-scan path.
    let converted_artifact = fx.artifact(repo, "c.tgz", &d).await;
    let placeholder = fx
        .svc
        .create_scan_result_with_checksum(converted_artifact, repo, "dependency", Some(&d))
        .await
        .expect("placeholder");
    fx.svc
        .convert_to_reused(placeholder.id, source, converted_artifact, None)
        .await
        .expect("convert");
    assert!(
        fx.listed_acknowledged(placeholder.id).await,
        "convert_to_reused"
    );
    assert!(
        fx.allowed(repo, converted_artifact).await,
        "convert_to_reused gate"
    );

    fx.cleanup().await;
}

/// The scope decision of #5153: an acknowledgement made in one repository does
/// not silently open another repository's gate for the same bytes. The
/// operator can say so explicitly.
#[tokio::test]
#[ignore]
async fn a_cross_repository_dedup_copy_is_covered_only_when_the_operator_said_so() {
    let mut fx = Fx::new().await;
    let dev = fx.repo().await;
    let prod = fx.repo().await;
    let d = digest();
    let original = fx.artifact(dev, "a.tgz", &d).await;
    let source = fx
        .scan(
            dev,
            original,
            "dependency",
            &[finding(CVE_A, LODASH, "4.17.15")],
        )
        .await;
    fx.ack_scan(source).await;

    let in_prod = fx.artifact(prod, "a.tgz", &d).await;
    let copied = fx
        .svc
        .copy_scan_results(source, in_prod, prod, "dependency", &d, None)
        .await
        .expect("copy");
    assert!(
        !fx.allowed(prod, in_prod).await,
        "a repository-scoped acknowledgement must not open another repository's gate"
    );
    assert!(!fx.listed_acknowledged(copied.id).await);
    assert!(
        fx.allowed(dev, original).await,
        "the original stays covered"
    );

    // Explicit widening.
    let id = fx.finding_ids(source).await[0];
    fx.svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "accepted everywhere: SEC-421",
            AcknowledgeOptions {
                scope: AcknowledgementScope::AllRepositories,
                ..Default::default()
            },
        )
        .await
        .expect("widen");
    assert!(fx.allowed(prod, in_prod).await, "explicitly widened");
    assert!(fx.listed_acknowledged(copied.id).await);

    // And the widened decision is revoked as one thing.
    fx.svc
        .revoke_acknowledgment(id, Some(dev), &fx.actor())
        .await
        .expect("revoke");
    assert!(!fx.allowed(prod, in_prod).await);
    assert!(!fx.allowed(dev, original).await);

    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn acknowledgement_survives_promotion_and_the_verdict_travels_with_it() {
    let mut fx = Fx::new().await;
    let staging = fx.repo().await;
    let release = fx.repo().await;
    sqlx::query("UPDATE scan_policies SET block_unscanned = true WHERE repository_id = $1")
        .bind(release)
        .execute(&fx.pool)
        .await
        .expect("block_unscanned");
    let d = digest();
    let original = fx.artifact(staging, "a.tgz", &d).await;
    let source = fx
        .scan(
            staging,
            original,
            "dependency",
            &[finding(CVE_A, LODASH, "4.17.15")],
        )
        .await;
    fx.ack_scan(source).await;

    let promoted = fx.artifact(release, "a.tgz", &d).await;
    assert!(
        !fx.allowed(release, promoted).await,
        "before the carry the promoted row has no scan on record"
    );
    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(original, promoted, fx.admin_principal())
        .await
        .expect("carry");
    assert!(
        fx.allowed(release, promoted).await,
        "the promoted copy carries the verdict and the decision"
    );
    let copied: Uuid = sqlx::query_scalar(
        "SELECT id FROM scan_results WHERE artifact_id = $1 AND source_scan_id = $2",
    )
    .bind(promoted)
    .bind(source)
    .fetch_one(&fx.pool)
    .await
    .expect("the copied verdict records its provenance");
    assert!(fx.listed_acknowledged(copied).await);

    // A later rescan on the target keeps it.
    fx.scan(
        release,
        promoted,
        "dependency",
        &[finding(CVE_A, LODASH, "4.17.15")],
    )
    .await;
    assert!(fx.allowed(release, promoted).await, "rescan on the target");

    fx.cleanup().await;
}

/// A copied verdict is provenance, not a pin: a staging repository can be emptied
/// after its artifacts were promoted, and the copy keeps its findings.
#[tokio::test]
#[ignore]
async fn the_source_of_a_carried_verdict_can_still_be_deleted() {
    let mut fx = Fx::new().await;
    let staging = fx.repo().await;
    let release = fx.repo().await;
    let d = digest();
    let original = fx.artifact(staging, "a.tgz", &d).await;
    let source = fx
        .scan(
            staging,
            original,
            "dependency",
            &[finding(CVE_A, LODASH, "1")],
        )
        .await;
    fx.ack_scan(source).await;
    let promoted = fx.artifact(release, "a.tgz", &d).await;
    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(original, promoted, fx.admin_principal())
        .await
        .expect("carry");

    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(staging)
        .execute(&fx.pool)
        .await
        .expect("the source repository can be deleted");
    fx.repos.retain(|r| *r != staging);

    let (source_scan, reused): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT source_scan_id, is_reused FROM scan_results WHERE artifact_id = $1")
            .bind(promoted)
            .fetch_one(&fx.pool)
            .await
            .expect("the copy remains");
    assert_eq!(source_scan, None);
    assert!(reused);
    assert!(
        fx.allowed(release, promoted).await,
        "the carried decision belongs to the target and stays"
    );
    fx.cleanup().await;
}

/// Promotion carries an open finding as open: nothing acknowledged in the
/// source means nothing covered in the target.
#[tokio::test]
#[ignore]
async fn promotion_does_not_invent_a_decision_for_an_open_finding() {
    let mut fx = Fx::new().await;
    let staging = fx.repo().await;
    let release = fx.repo().await;
    let d = digest();
    let original = fx.artifact(staging, "a.tgz", &d).await;
    fx.scan(
        staging,
        original,
        "dependency",
        &[finding(CVE_A, LODASH, "4.17.15")],
    )
    .await;
    let promoted = fx.artifact(release, "a.tgz", &d).await;
    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(original, promoted, fx.admin_principal())
        .await
        .expect("carry");
    assert!(
        !fx.allowed(release, promoted).await,
        "the copied open finding must block in the target"
    );
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn revoke_applies_everywhere_the_decision_reached() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let target = fx.repo().await;
    let d = digest();
    let original = fx.artifact(repo, "a.tgz", &d).await;
    let findings = [finding(CVE_A, LODASH, "4.17.15")];
    let first = fx.scan(repo, original, "dependency", &findings).await;
    fx.ack_scan(first).await;
    let rescan = fx.scan(repo, original, "dependency", &findings).await;
    let copy = fx.artifact(repo, "b.tgz", &d).await;
    let copied = fx
        .svc
        .copy_scan_results(first, copy, repo, "dependency", &d, None)
        .await
        .expect("copy");
    let promoted = fx.artifact(target, "a.tgz", &d).await;
    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(original, promoted, fx.admin_principal())
        .await
        .expect("carry");
    assert!(fx.allowed(repo, original).await);
    assert!(fx.allowed(repo, copy).await);
    assert!(fx.allowed(target, promoted).await);

    // Revoked through the OLDEST row: the old scan is not special.
    let oldest = fx.finding_ids(first).await[0];
    let revoked = fx
        .svc
        .revoke_acknowledgment(oldest, None, &fx.actor())
        .await
        .expect("revoke");
    assert!(!revoked.is_acknowledged);

    for (r, a, label) in [
        (repo, original, "rescanned artifact"),
        (repo, copy, "dedup copy"),
        (target, promoted, "promoted copy"),
    ] {
        assert!(!fx.allowed(r, a).await, "{label} must block after a revoke");
    }
    for scan in [first, rescan, copied.id] {
        let filter = no_filter();
        let (rows, _) = fx
            .svc
            .list_findings(scan, &filter, 0, 10)
            .await
            .expect("list");
        assert!(rows
            .iter()
            .all(|f| !f.is_acknowledged && f.acknowledged_by.is_none()));
    }

    // A later acknowledgement in the source is a new decision. It does not bring
    // the revoked copy in the target back.
    fx.svc
        .acknowledge_finding(
            fx.finding_ids(rescan).await[0],
            &fx.actor(),
            "accepted again",
            AcknowledgeOptions {
                repository_id: Some(repo),
                ..Default::default()
            },
        )
        .await
        .expect("acknowledge again");
    assert!(fx.allowed(repo, original).await);
    assert!(
        !fx.allowed(target, promoted).await,
        "a new decision in the source must not reopen the target"
    );

    fx.cleanup().await;
}

/// A decision made again on a live identity joins its lineage, so a revoke still
/// reaches what the first one was carried to.
#[tokio::test]
#[ignore]
async fn re_acknowledging_keeps_the_reach_of_a_revoke() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let target = fx.repo().await;
    let d = digest();
    let original = fx.artifact(repo, "a.tgz", &d).await;
    let scan = fx
        .scan(repo, original, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    fx.ack_scan(scan).await;
    let promoted = fx.artifact(target, "a.tgz", &d).await;
    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(original, promoted, fx.admin_principal())
        .await
        .expect("carry");
    let id = fx.finding_ids(scan).await[0];
    fx.svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "accepted again",
            AcknowledgeOptions {
                repository_id: Some(repo),
                ..Default::default()
            },
        )
        .await
        .expect("acknowledge again");
    assert!(fx.allowed(repo, original).await);
    assert!(fx.allowed(target, promoted).await);

    let id = fx.finding_ids(scan).await[0];
    fx.svc
        .revoke_acknowledgment(id, Some(repo), &fx.actor())
        .await
        .expect("revoke");
    assert!(!fx.allowed(repo, original).await);
    assert!(!fx.allowed(target, promoted).await);
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn revoking_a_finding_with_no_decision_changes_nothing_and_succeeds() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let scan = fx
        .scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let id = fx.finding_ids(scan).await[0];
    let f = fx
        .svc
        .revoke_acknowledgment(id, None, &fx.actor())
        .await
        .expect("idempotent revoke");
    assert!(!f.is_acknowledged);
    let missing = fx
        .svc
        .revoke_acknowledgment(Uuid::new_v4(), None, &fx.actor())
        .await;
    assert!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
    fx.cleanup().await;
}

/// A decision can be seen and revoked with no finding row to reach it through,
/// and its record stays after a revoke.
#[tokio::test]
#[ignore]
async fn decisions_are_listed_and_revoked_by_id() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let d = digest();
    let artifact = fx.artifact(repo, "a.tgz", &d).await;
    let scan = fx
        .scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    fx.ack_scan(scan).await;
    let svc = FindingAcknowledgementService::new(fx.pool.clone());
    let filter = AcknowledgementFilter {
        repository_id: Some(repo),
        checksum_sha256: Some(&d),
        advisory: Some(&CVE_A.to_lowercase()),
        include_inactive: false,
    };
    let (rows, total) = svc.list(filter, 0, 10).await.expect("list");
    assert_eq!(total, 1);
    assert_eq!(rows[0].state, "active");
    assert_eq!(rows[0].component_key, LODASH);
    assert_eq!(rows[0].acknowledged_by, Some(fx.admin));
    assert_eq!(rows[0].max_severity_rank, 3);

    assert_eq!(
        svc.revoke(rows[0].id, &fx.actor())
            .await
            .expect("revoke")
            .revoked,
        1
    );
    assert!(!fx.allowed(repo, artifact).await);
    let (active, _) = svc.list(filter, 0, 10).await.expect("list active");
    assert!(active.is_empty());
    let (all, _) = svc
        .list(
            AcknowledgementFilter {
                include_inactive: true,
                ..filter
            },
            0,
            10,
        )
        .await
        .expect("list all");
    assert_eq!(all[0].state, "revoked");
    assert_eq!(all[0].revoked_by, Some(fx.admin));
    assert_eq!(all[0].revoked_reason.as_deref(), Some("revoked"));

    let missing = svc.revoke(Uuid::new_v4(), &fx.actor()).await;
    assert!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn an_expired_acknowledgement_stops_covering_without_any_sweep() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let findings = [finding(CVE_A, LODASH, "4.17.15")];
    let scan = fx.scan(repo, artifact, "dependency", &findings).await;
    let id = fx.finding_ids(scan).await[0];

    let expires_at = Utc::now() + Duration::milliseconds(1500);
    let acked = fx
        .svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "until the upgrade",
            AcknowledgeOptions {
                expires_at: Some(expires_at),
                ..Default::default()
            },
        )
        .await
        .expect("acknowledge");
    assert!(acked.is_acknowledged);
    assert!(fx.allowed(repo, artifact).await, "covered until it expires");
    assert_eq!(fx.open_count(artifact).await, 0);

    tokio::time::sleep(std::time::Duration::from_millis(1800)).await;

    assert!(
        !fx.allowed(repo, artifact).await,
        "the gate honours expiry on its own"
    );
    assert!(!fx.listed_acknowledged(scan).await, "the listing too");
    assert_eq!(fx.open_count(artifact).await, 1, "and the counts");

    // The sweep records the lapse once and refreshes the stored score; it is
    // not what makes the gate correct.
    let svc = FindingAcknowledgementService::new(fx.pool.clone());
    assert!(svc.record_expired().await.expect("sweep") >= 1);
    let score_open: i32 =
        sqlx::query_scalar("SELECT high_count FROM repo_security_scores WHERE repository_id = $1")
            .bind(repo)
            .fetch_one(&fx.pool)
            .await
            .expect("score");
    assert_eq!(score_open, 1, "the sweep refreshes the materialized score");
    assert_eq!(
        svc.record_expired().await.expect("second sweep"),
        0,
        "a lapse is recorded once"
    );

    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn an_expiry_in_the_past_is_refused() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let scan = fx
        .scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let id = fx.finding_ids(scan).await[0];
    let res = fx
        .svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "already over",
            AcknowledgeOptions {
                expires_at: Some(Utc::now() - Duration::hours(1)),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(res, Err(AppError::Validation(_))), "{res:?}");
    assert!(!fx.allowed(repo, artifact).await);
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// What an acknowledgement never covers
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn a_new_finding_is_never_covered_by_an_old_acknowledgement() {
    let cases: [(&str, RawFinding); 4] = [
        ("a different CVE", finding(CVE_B, LODASH, "4.17.15")),
        (
            "the same CVE on another component",
            finding(CVE_A, "underscore", "4.17.15"),
        ),
        (
            "the same CVE on another version",
            finding(CVE_A, LODASH, "4.17.20"),
        ),
        (
            "the same finding at a higher severity than was accepted",
            finding_from(CVE_A, LODASH, "4.17.15", "grype", Severity::Critical),
        ),
    ];
    for (label, new) in cases {
        let mut fx = Fx::new().await;
        let repo = fx.repo().await;
        let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
        let accepted = finding(CVE_A, LODASH, "4.17.15");
        let first = fx
            .scan(
                repo,
                artifact,
                "dependency",
                std::slice::from_ref(&accepted),
            )
            .await;
        fx.ack_scan(first).await;
        assert!(fx.allowed(repo, artifact).await);

        let rescan = fx
            .scan(repo, artifact, "dependency", &[accepted, new])
            .await;
        assert!(!fx.allowed(repo, artifact).await, "{label} must block");
        assert!(
            !fx.listed_acknowledged(rescan).await,
            "{label} must list as open"
        );
        fx.cleanup().await;
    }
}

/// Different bytes under the same coordinate are not the artifact the operator
/// looked at, even when the scanner reports the same CVE in the same component.
#[tokio::test]
#[ignore]
async fn different_bytes_are_not_covered() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let findings = [finding(CVE_A, LODASH, "4.17.15")];
    let original = fx.artifact(repo, "a.tgz", &digest()).await;
    let first = fx.scan(repo, original, "dependency", &findings).await;
    fx.ack_scan(first).await;

    let rebuilt = fx.artifact(repo, "a.tgz", &digest()).await;
    fx.scan(repo, rebuilt, "dependency", &findings).await;
    assert!(fx.allowed(repo, original).await);
    assert!(!fx.allowed(repo, rebuilt).await);
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// The gate reads the current scan
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn a_superseded_scan_no_longer_blocks() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    fx.scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    assert!(!fx.allowed(repo, artifact).await);
    // The same engine no longer reports it.
    fx.scan(repo, artifact, "dependency", &[]).await;
    assert!(fx.allowed(repo, artifact).await, "history must not block");
    fx.cleanup().await;
}

/// A later scan that could not assess the artifact does not clear what a
/// complete scan reported.
#[tokio::test]
#[ignore]
async fn an_incomplete_rescan_does_not_clear_the_previous_verdict() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    fx.scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let blind = fx.unfinished_scan(repo, artifact).await;
    fx.complete(blind.id, 0, "not_cataloged").await;
    assert!(
        !fx.allowed(repo, artifact).await,
        "a scan that cataloged nothing must not clear the finding"
    );
    fx.cleanup().await;
}

/// Findings from a scan that died before completing are still graded, and a
/// newer crash can still add to an older completed verdict.
#[tokio::test]
#[ignore]
async fn findings_of_a_crashed_rescan_are_still_graded() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    fx.scan(repo, artifact, "dependency", &[]).await;
    assert!(fx.allowed(repo, artifact).await);
    let crashed = fx.unfinished_scan(repo, artifact).await;
    fx.svc
        .create_findings(crashed.id, artifact, &[finding(CVE_A, LODASH, "1")])
        .await
        .expect("findings");
    assert!(!fx.allowed(repo, artifact).await, "fail closed");
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// The other acknowledge path, audit, and the scan-policy hold (F5)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn the_security_tab_path_records_the_same_decision() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let findings = [
        finding(CVE_A, LODASH, "4.17.15"),
        finding(CVE_A, "underscore", "1.0"),
        finding(CVE_B, LODASH, "4.17.15"),
    ];
    fx.scan(repo, artifact, "dependency", &findings).await;
    let sbom = SbomService::new(fx.pool.clone());
    sbom.update_cve_status_by_artifact_cve(
        artifact,
        CVE_A,
        CveStatus::Acknowledged,
        Some(fx.admin),
        Some("not reachable"),
        AccessScope::Admin,
    )
    .await
    .expect("acknowledge");
    assert_eq!(fx.open_count(artifact).await, 1, "CVE_B stays open");

    // Survives a rescan for both components of CVE_A, and only those.
    let rescan = fx.scan(repo, artifact, "dependency", &findings).await;
    let ack_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_findings_effective WHERE scan_result_id = $1 AND is_acknowledged",
    )
    .bind(rescan)
    .fetch_one(&fx.pool)
    .await
    .expect("effective rows");
    assert_eq!(ack_rows, 2);

    sbom.update_cve_status_by_artifact_cve(
        artifact,
        CVE_A,
        CveStatus::Open,
        Some(fx.admin),
        None,
        AccessScope::Admin,
    )
    .await
    .expect("revoke");
    assert_eq!(fx.open_count(artifact).await, 2);

    let unknown = sbom
        .update_cve_status_by_artifact_cve(
            artifact,
            "CVE-1999-0001",
            CveStatus::Acknowledged,
            Some(fx.admin),
            None,
            AccessScope::Admin,
        )
        .await;
    assert!(matches!(unknown, Err(AppError::NotFound(_))), "{unknown:?}");
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn acknowledge_revoke_and_lapse_are_audited() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let cve = format!("CVE-2031-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let scan = fx
        .scan(repo, artifact, "dependency", &[finding(&cve, LODASH, "1")])
        .await;
    let needle = cve.to_uppercase();
    let id = fx.finding_ids(scan).await[0];
    fx.svc
        .acknowledge_finding(id, &fx.actor(), "accepted", Default::default())
        .await
        .expect("ack");
    assert_eq!(fx.audit_count("FINDING_ACKNOWLEDGED", &needle).await, 1);
    fx.svc
        .revoke_acknowledgment(id, None, &fx.actor())
        .await
        .expect("revoke");
    assert_eq!(
        fx.audit_count("FINDING_ACKNOWLEDGEMENT_REVOKED", &needle)
            .await,
        1
    );
    fx.svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "short",
            AcknowledgeOptions {
                expires_at: Some(Utc::now() + Duration::milliseconds(300)),
                ..Default::default()
            },
        )
        .await
        .expect("ack again");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    FindingAcknowledgementService::new(fx.pool.clone())
        .record_expired()
        .await
        .expect("sweep");
    assert_eq!(
        fx.audit_count("FINDING_ACKNOWLEDGEMENT_EXPIRED", &needle)
            .await,
        1
    );
    fx.cleanup().await;
}

async fn stamp_hold(fx: &Fx, artifact: Uuid, source: Option<&str>) {
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_until = NULL, \
         quarantine_reason = 'held', quarantine_source = $2 WHERE id = $1",
    )
    .bind(artifact)
    .bind(source)
    .execute(&fx.pool)
    .await
    .expect("stamp hold");
}

async fn hold_status(fx: &Fx, artifact: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT quarantine_status FROM artifacts WHERE id = $1")
        .bind(artifact)
        .fetch_one(&fx.pool)
        .await
        .expect("status")
}

/// Walkthrough finding F5: once every finding behind a scan-policy hold is
/// acknowledged the hold is over. Before #5153 the artifact kept answering 409
/// until an administrator released it by hand.
#[tokio::test]
#[ignore]
async fn acknowledging_the_last_finding_releases_a_scan_policy_hold() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let scan = fx
        .scan(
            repo,
            artifact,
            "dependency",
            &[finding(CVE_A, LODASH, "1"), finding(CVE_B, LODASH, "1")],
        )
        .await;
    stamp_hold(&fx, artifact, Some("scan_policy")).await;
    let ids = fx.finding_ids(scan).await;

    fx.svc
        .acknowledge_finding(ids[0], &fx.actor(), "accepted", Default::default())
        .await
        .expect("first");
    assert_eq!(
        hold_status(&fx, artifact).await.as_deref(),
        Some("quarantined"),
        "one finding is still open"
    );
    assert!(enforce_download_gate(&fx.pool, artifact).await.is_err());

    fx.svc
        .acknowledge_finding(ids[1], &fx.actor(), "accepted", Default::default())
        .await
        .expect("second");
    assert_eq!(
        hold_status(&fx, artifact).await.as_deref(),
        Some("released")
    );
    enforce_download_gate(&fx.pool, artifact)
        .await
        .expect("the hold is over");
    let mut audited: i64 = 0;
    for _ in 0..100 {
        audited = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'QUARANTINE_RELEASED' AND resource_id = $1",
        )
        .bind(artifact)
        .fetch_one(&fx.pool)
        .await
        .expect("audit");
        if audited > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(audited, 1);

    // A revoke reopens the block through the live policy half of the gate.
    fx.svc
        .revoke_acknowledgment(ids[1], None, &fx.actor())
        .await
        .expect("revoke");
    assert!(matches!(
        enforce_download_gate(&fx.pool, artifact).await,
        Err(AppError::Authorization(_))
    ));
    fx.cleanup().await;
}

/// An acknowledgement answers for findings, not for a person's decision to
/// hold an artifact, or for a hold whose origin nobody recorded.
#[tokio::test]
#[ignore]
async fn acknowledging_never_releases_a_hold_that_is_not_a_scan_policy_hold() {
    for source in [Some("admin"), None] {
        let mut fx = Fx::new().await;
        let repo = fx.repo().await;
        let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
        let scan = fx
            .scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
            .await;
        stamp_hold(&fx, artifact, source).await;
        fx.ack_scan(scan).await;
        assert_eq!(
            hold_status(&fx, artifact).await.as_deref(),
            Some("quarantined"),
            "source {source:?}"
        );
        assert!(matches!(
            enforce_download_gate(&fx.pool, artifact).await,
            Err(AppError::Conflict(_))
        ));
        fx.cleanup().await;
    }
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// The migration whose file name ends in `suffix`, whatever its number.
fn migration_file(suffix: &str) -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let file = std::fs::read_dir(&dir)
        .expect("migrations dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(suffix))
        })
        .unwrap_or_else(|| panic!("no migration ending in {suffix}"));
    std::fs::read_to_string(file).expect("read migration")
}

fn migration_backfill_sql() -> String {
    let sql = migration_file("_finding_acknowledgements_backfill.sql");
    let start = sql
        .find("-- BEGIN backfill")
        .expect("backfill start marker");
    let end = sql.find("-- END backfill").expect("backfill end marker");
    sql[start..end].to_string()
}

async fn legacy_ack(fx: &Fx, finding_id: Uuid, reason: &str) {
    sqlx::query(
        "UPDATE scan_findings SET is_acknowledged = true, acknowledged_by = $2, \
         acknowledged_reason = $3, acknowledged_at = NOW() WHERE id = $1",
    )
    .bind(finding_id)
    .bind(fx.admin)
    .bind(reason)
    .execute(&fx.pool)
    .await
    .expect("legacy ack");
}

async fn decisions_for(
    fx: &Fx,
    digest: &str,
) -> Vec<(Option<Uuid>, String, Option<String>, String)> {
    sqlx::query_as(
        "SELECT repository_id, advisory_key, reason, created_via \
         FROM finding_acknowledgements WHERE checksum_sha256 = $1 \
         ORDER BY advisory_key, repository_id",
    )
    .bind(digest)
    .fetch_all(&fx.pool)
    .await
    .expect("decisions")
}

#[tokio::test]
#[ignore]
async fn the_migration_carries_current_acknowledgements_and_nothing_else() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let backfill = migration_backfill_sql();

    // 1. Acknowledged in the current scan: migrates, keeps actor and reason,
    //    and then survives a rescan.
    let d1 = digest();
    let a1 = fx.artifact(repo, "one.tgz", &d1).await;
    let findings = [finding(CVE_A, LODASH, "1")];
    let s1 = fx.scan(repo, a1, "dependency", &findings).await;
    legacy_ack(&fx, fx.finding_ids(s1).await[0], "legacy reason").await;

    // 2. Acknowledged only in an older scan; the current scan reports it open.
    //    The operator sees it open today, so the migration must not hide it.
    let d2 = digest();
    let a2 = fx.artifact(repo, "two.tgz", &d2).await;
    let old = fx.scan(repo, a2, "dependency", &findings).await;
    legacy_ack(&fx, fx.finding_ids(old).await[0], "old").await;
    fx.scan(repo, a2, "dependency", &findings).await;

    // 3. One engine's row acknowledged, another engine's row for the same
    //    component open. Migrating would hide a row that blocks today.
    let d3 = digest();
    let a3 = fx.artifact(repo, "three.tgz", &d3).await;
    let s3 = fx.scan(repo, a3, "image", &findings).await;
    legacy_ack(&fx, fx.finding_ids(s3).await[0], "one engine").await;
    fx.scan(repo, a3, "dependency", &findings).await;

    // 4. Acknowledged in a scan the artifact no longer reports it in.
    let d4 = digest();
    let a4 = fx.artifact(repo, "four.tgz", &d4).await;
    let s4 = fx.scan(repo, a4, "dependency", &findings).await;
    legacy_ack(&fx, fx.finding_ids(s4).await[0], "gone").await;
    fx.scan(repo, a4, "dependency", &[]).await;

    // 5. Never acknowledged.
    let d5 = digest();
    let a5 = fx.artifact(repo, "five.tgz", &d5).await;
    fx.scan(repo, a5, "dependency", &findings).await;

    sqlx::raw_sql(sqlx::AssertSqlSafe(backfill.clone()))
        .execute(&fx.pool)
        .await
        .expect("backfill");

    let one = decisions_for(&fx, &d1).await;
    assert_eq!(one.len(), 1, "{one:?}");
    assert_eq!(one[0].0, Some(repo), "scoped to the repository");
    assert_eq!(one[0].1, CVE_A);
    assert_eq!(one[0].2.as_deref(), Some("legacy reason"));
    assert_eq!(one[0].3, "migration");
    let filter = no_filter();
    let (rows, _) = fx
        .svc
        .list_findings(s1, &filter, 0, 10)
        .await
        .expect("list");
    assert!(rows[0].is_acknowledged);
    assert_eq!(rows[0].acknowledged_by, Some(fx.admin));
    assert!(fx.allowed(repo, a1).await);
    fx.scan(repo, a1, "dependency", &findings).await;
    assert!(
        fx.allowed(repo, a1).await,
        "a migrated decision survives a rescan"
    );

    assert!(decisions_for(&fx, &d2).await.is_empty(), "history only");
    assert!(!fx.allowed(repo, a2).await);
    assert!(
        decisions_for(&fx, &d3).await.is_empty(),
        "another engine still open"
    );
    assert!(!fx.allowed(repo, a3).await);
    assert!(
        decisions_for(&fx, &d4).await.is_empty(),
        "no longer reported"
    );
    assert!(
        decisions_for(&fx, &d5).await.is_empty(),
        "never acknowledged"
    );
    assert!(!fx.allowed(repo, a5).await);

    // Running it again changes nothing.
    sqlx::raw_sql(sqlx::AssertSqlSafe(backfill))
        .execute(&fx.pool)
        .await
        .expect("backfill twice");
    assert_eq!(decisions_for(&fx, &d1).await.len(), 1);

    // The frozen flags no longer speak: a revoke leaves the legacy column as
    // it was and the finding is open anyway.
    fx.svc
        .revoke_acknowledgment(fx.finding_ids(s1).await[0], None, &fx.actor())
        .await
        .expect("revoke");
    assert!(!fx.allowed(repo, a1).await);

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// Promotion must never serve what the source's gate would block
// ---------------------------------------------------------------------------

/// A source and target with the same strict policy, and a promoted copy row.
async fn promotion_rig(fx: &mut Fx) -> (Uuid, Uuid, Uuid, Uuid, String) {
    let source_repo = fx.repo().await;
    let target_repo = fx.repo().await;
    sqlx::query(
        "UPDATE scan_policies SET block_unscanned = true, block_on_fail = true \
         WHERE repository_id = ANY($1)",
    )
    .bind(vec![source_repo, target_repo])
    .execute(&fx.pool)
    .await
    .expect("strict policies");
    let d = digest();
    let source = fx.artifact(source_repo, "a.tgz", &d).await;
    let target = fx.artifact(target_repo, "a.tgz", &d).await;
    (source_repo, target_repo, source, target, d)
}

async fn carry(
    fx: &Fx,
    source: Uuid,
    target: Uuid,
) -> artifact_keeper_backend::error::Result<CarryOutcome> {
    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(source, target, fx.admin_principal())
        .await
}

async fn scans_on(fx: &Fx, artifact: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM scan_results WHERE artifact_id = $1")
        .bind(artifact)
        .fetch_one(&fx.pool)
        .await
        .expect("scan count")
}

#[derive(Clone, Copy, Debug)]
enum SourceState {
    NotCatalogedRescan,
    PartialRescan,
    FailedRescanBesideCleanScanner,
    RunningRescanWithFindings,
    CrashedRescanWithFindings,
}

/// Findings of a complete scan, then a later row that must not hide them.
async fn build_source_state(fx: &Fx, repo: Uuid, artifact: Uuid, state: SourceState) {
    let high = [finding(CVE_A, LODASH, "1")];
    match state {
        SourceState::NotCatalogedRescan | SourceState::PartialRescan => {
            fx.scan(repo, artifact, "dependency", &high).await;
            let blind = fx.unfinished_scan(repo, artifact).await;
            let completeness = match state {
                SourceState::PartialRescan => "partial",
                _ => "not_cataloged",
            };
            fx.complete(blind.id, 0, completeness).await;
        }
        SourceState::FailedRescanBesideCleanScanner => {
            fx.scan(repo, artifact, "dependency", &[]).await;
            fx.scan(repo, artifact, "image", &[]).await;
            let failed = fx.unfinished_scan(repo, artifact).await;
            fx.svc
                .fail_scan(failed.id, "scanner crashed", None, Utc::now())
                .await
                .expect("fail");
        }
        SourceState::RunningRescanWithFindings | SourceState::CrashedRescanWithFindings => {
            fx.scan(repo, artifact, "dependency", &[]).await;
            let late = fx.unfinished_scan(repo, artifact).await;
            fx.svc
                .create_findings(late.id, artifact, &high)
                .await
                .expect("findings");
            if matches!(state, SourceState::CrashedRescanWithFindings) {
                fx.svc
                    .fail_scan(late.id, "crashed", None, Utc::now())
                    .await
                    .expect("fail");
            }
        }
    }
}

#[tokio::test]
#[ignore]
async fn the_target_never_serves_what_the_sources_gate_would_block() {
    for state in [
        SourceState::NotCatalogedRescan,
        SourceState::PartialRescan,
        SourceState::FailedRescanBesideCleanScanner,
        SourceState::RunningRescanWithFindings,
        SourceState::CrashedRescanWithFindings,
    ] {
        let mut fx = Fx::new().await;
        let (source_repo, target_repo, source, target, _) = promotion_rig(&mut fx).await;
        build_source_state(&fx, source_repo, source, state).await;
        assert!(
            !fx.allowed(source_repo, source).await,
            "{state:?}: the source must be blocked for this to prove anything"
        );

        carry(&fx, source, target).await.expect("carry");

        assert!(
            !fx.allowed(target_repo, target).await,
            "{state:?}: the target served what the source's gate blocks"
        );
        fx.cleanup().await;
    }
}

/// All or nothing: a failure on the second scan type leaves nothing from the
/// first, because a partial carry reads as a clean scanned artifact.
#[tokio::test]
#[ignore]
async fn a_failed_carry_leaves_nothing_behind() {
    let mut fx = Fx::new().await;
    let (source_repo, target_repo, source, target, _) = promotion_rig(&mut fx).await;
    fx.scan(source_repo, source, "dependency", &[]).await;
    let bad = finding("CVE-2031-0001", "boom-5153", "1");
    let image = fx.scan(source_repo, source, "image", &[bad]).await;
    fx.ack_scan(image).await;
    assert!(fx.allowed(source_repo, source).await);

    let trigger = format!("fail_5153_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION {trigger}() RETURNS trigger LANGUAGE plpgsql AS \
           $f$ BEGIN RAISE EXCEPTION 'injected'; END $f$; \
         CREATE TRIGGER {trigger} BEFORE INSERT ON scan_findings FOR EACH ROW \
           WHEN (NEW.affected_component = 'boom-5153' AND NEW.artifact_id = '{target}') \
           EXECUTE FUNCTION {trigger}();"
    )))
    .execute(&fx.pool)
    .await
    .expect("install failure");
    let result = carry(&fx, source, target).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {trigger} ON scan_findings; DROP FUNCTION {trigger}();"
    )))
    .execute(&fx.pool)
    .await
    .expect("remove failure");

    assert!(result.is_err());
    assert_eq!(scans_on(&fx, target).await, 0, "no partial verdict");
    let decisions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM finding_acknowledgements WHERE repository_id = $1",
    )
    .bind(target_repo)
    .fetch_one(&fx.pool)
    .await
    .expect("decisions");
    assert_eq!(decisions, 0, "the whole carry is one transaction");
    assert!(!fx.allowed(target_repo, target).await, "unscanned, refused");
    fx.cleanup().await;
}

/// The dedup safeguards apply: a verdict a byte-identical upload could not reuse
/// cannot satisfy `block_unscanned` on the target either.
#[tokio::test]
#[ignore]
async fn a_verdict_dedup_would_not_reuse_is_not_carried() {
    for (label, update) in [
        (
            "a clean verdict past the zero-findings limit",
            "completed_at = NOW() - INTERVAL '2 days'",
        ),
        (
            "a verdict from another pin",
            "pin_identity = 'npm:someone-else@1.0.0'",
        ),
        ("an imported verdict", "origin = 'imported'"),
    ] {
        let mut fx = Fx::new().await;
        let (source_repo, target_repo, source, target, _) = promotion_rig(&mut fx).await;
        fx.scan(source_repo, source, "dependency", &[]).await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE scan_results SET {update} WHERE artifact_id = $1"
        )))
        .bind(source)
        .execute(&fx.pool)
        .await
        .expect("age the verdict");

        carry(&fx, source, target).await.expect("carry");

        assert_eq!(scans_on(&fx, target).await, 0, "{label}");
        assert!(!fx.allowed(target_repo, target).await, "{label}");
        fx.cleanup().await;
    }
}

/// #5: only someone who could acknowledge in the target carries a decision past
/// its policy. The verdict still travels, so the finding is open there.
#[tokio::test]
#[ignore]
async fn a_principal_who_could_not_acknowledge_carries_the_verdict_and_no_decision() {
    let mut fx = Fx::new().await;
    let (source_repo, target_repo, source, target, d) = promotion_rig(&mut fx).await;
    let cve = format!("CVE-2032-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let scan = fx
        .scan(
            source_repo,
            source,
            "dependency",
            &[finding(&cve, LODASH, "1")],
        )
        .await;
    fx.ack_scan(scan).await;
    assert!(fx.allowed(source_repo, source).await);

    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(
            source,
            target,
            CarryPrincipal {
                user_id: fx.admin,
                may_acknowledge: false,
            },
        )
        .await
        .expect("carry");

    assert_eq!(scans_on(&fx, target).await, 1, "the verdict travels");
    assert!(
        !fx.allowed(target_repo, target).await,
        "the finding must be open on the target"
    );
    let in_target: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM finding_acknowledgements \
         WHERE repository_id = $1 AND checksum_sha256 = $2",
    )
    .bind(target_repo)
    .bind(&d)
    .fetch_one(&fx.pool)
    .await
    .expect("decisions");
    assert_eq!(in_target, 0);
    assert_eq!(
        fx.audit_count("FINDING_ACKNOWLEDGEMENT_NOT_CARRIED", &cve.to_uppercase())
            .await,
        1,
        "what was left behind is on the record"
    );
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// External scanners
// ---------------------------------------------------------------------------

fn external(cve: &str, vendor: &str, severity: Severity, class: FindingClass) -> RawFinding {
    RawFinding {
        severity,
        title: format!("{cve} from {vendor}"),
        description: None,
        cve_id: Some(cve.to_string()),
        affected_component: Some(LODASH.to_string()),
        affected_version: Some("1".to_string()),
        fixed_version: None,
        source: Some(vendor.to_string()),
        source_url: None,
        finding_class: class,
    }
}

async fn ingest(fx: &Fx, repo: Uuid, artifact: Uuid, findings: &[RawFinding]) {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count() as i32;
    let counts = [critical, 0, 0, 0, 0];
    fx.svc
        .create_completed_scan_with_findings(
            artifact,
            repo,
            "external",
            counts,
            Some("v1"),
            findings,
        )
        .await
        .expect("ingest");
}

/// Every external vendor writes `scan_type = 'external'`, so one vendor's clean
/// submission must not read as a rescan of another's verdict.
#[tokio::test]
#[ignore]
async fn one_vendors_clean_submission_does_not_clear_another_vendors_verdict() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    ingest(
        &fx,
        repo,
        artifact,
        &[external(
            "MAL-2031-1",
            "vendor-a",
            Severity::Critical,
            FindingClass::Malicious,
        )],
    )
    .await;
    assert!(!fx.allowed(repo, artifact).await);

    ingest(&fx, repo, artifact, &[]).await;

    assert!(
        !fx.allowed(repo, artifact).await,
        "a malware verdict must survive another vendor's clean submission"
    );
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// The promotion gate reads what the download gate reads
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn a_blind_rescan_does_not_clear_the_promotion_gate() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let critical = finding_from(CVE_A, LODASH, "1", "grype", Severity::Critical);
    let baseline = fx.scan(repo, artifact, "dependency", &[critical]).await;
    sqlx::query("UPDATE scan_results SET critical_count = 1, high_count = 0 WHERE id = $1")
        .bind(baseline)
        .execute(&fx.pool)
        .await
        .expect("counts");
    let blind = fx.unfinished_scan(repo, artifact).await;
    fx.complete(blind.id, 0, "not_cataloged").await;

    let summary = PromotionPolicyService::new(fx.pool.clone())
        .evaluate_artifact(artifact, repo)
        .await
        .expect("evaluate")
        .cve_summary
        .expect("summary");
    assert_eq!(summary.critical_count, 1, "the baseline's counts remain");
    assert_eq!(summary.open_cves, vec![CVE_A.to_string()]);
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// A copied verdict and its deleted source
// ---------------------------------------------------------------------------

/// A copy outlives its source with `source_scan_id` cleared and, through
/// `convert_to_reused`, a fresh `completed_at`. It must not then read as an
/// original scan with a restarted age limit.
#[tokio::test]
#[ignore]
async fn a_copy_whose_source_was_deleted_is_not_a_dedup_source() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let d = digest();
    let original = fx.artifact(repo, "a.tgz", &d).await;
    let source = fx
        .scan(repo, original, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let copy = fx.artifact(repo, "b.tgz", &d).await;
    let placeholder = fx
        .svc
        .create_scan_result_with_checksum(copy, repo, "dependency", Some(&d))
        .await
        .expect("placeholder");
    fx.svc
        .convert_to_reused(placeholder.id, source, copy, None)
        .await
        .expect("convert");
    assert_eq!(reusable(&fx, &d).await, Some(source));

    sqlx::query("DELETE FROM artifacts WHERE id = $1")
        .bind(original)
        .execute(&fx.pool)
        .await
        .expect("the source can go");

    assert_eq!(reusable(&fx, &d).await, None);
    fx.cleanup().await;
}

async fn reusable(fx: &Fx, d: &str) -> Option<Uuid> {
    fx.svc
        .find_reusable_scan(d, "dependency", 30, 1, None)
        .await
        .expect("find")
        .map(|s| s.id)
}

// ---------------------------------------------------------------------------
// Credentials, and the trail
// ---------------------------------------------------------------------------

/// Service-level pin of who may decide what; the HTTP surface is in `security.rs`.
#[tokio::test]
#[ignore]
async fn a_scoped_credential_stays_inside_its_scope() {
    let mut fx = Fx::new().await;
    let inside = fx.repo().await;
    let outside = fx.repo().await;
    let d = digest();
    let a = fx.artifact(inside, "a.tgz", &d).await;
    let b = fx.artifact(outside, "a.tgz", &digest()).await;
    let in_scan = fx
        .scan(inside, a, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let out_scan = fx
        .scan(outside, b, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let scoped = AckActor::new(fx.admin, AccessScope::Restricted(vec![inside]));

    let finding_b = fx.finding_ids(out_scan).await[0];
    let refused = fx
        .svc
        .acknowledge_finding(finding_b, &scoped, "no", Default::default())
        .await;
    assert!(matches!(refused, Err(AppError::NotFound(_))), "{refused:?}");
    assert!(!fx.allowed(outside, b).await);

    // Revoking something that reaches past the credential.
    let finding_a = fx.finding_ids(in_scan).await[0];
    fx.svc
        .acknowledge_finding(
            finding_a,
            &fx.actor(),
            "everywhere",
            AcknowledgeOptions {
                scope: AcknowledgementScope::AllRepositories,
                ..Default::default()
            },
        )
        .await
        .expect("widen");
    let refused = fx.svc.revoke_acknowledgment(finding_a, None, &scoped).await;
    assert!(
        matches!(refused, Err(AppError::Authorization(_))),
        "{refused:?}"
    );
    assert!(fx.allowed(inside, a).await, "the decision stands");

    // A lineage reaching another repository.
    fx.svc
        .revoke_acknowledgment(finding_a, None, &fx.actor())
        .await
        .expect("revoke");
    fx.ack_scan(in_scan).await;
    let promoted = fx.artifact(outside, "c.tgz", &d).await;
    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(a, promoted, fx.admin_principal())
        .await
        .expect("carry");
    let withdrawn = fx
        .svc
        .revoke_acknowledgment(finding_a, Some(inside), &scoped)
        .await
        .expect("a caller can withdraw in their own repository");
    assert_eq!(withdrawn.acknowledgements_left_effective, Some(1));
    assert!(!withdrawn.is_acknowledged);
    assert!(!fx.allowed(inside, a).await, "gone where the caller asked");
    assert!(
        fx.allowed(outside, promoted).await,
        "the copy the credential does not cover stays, and the answer said so"
    );
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn the_audit_trail_names_the_ceiling_and_records_a_supersede() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let cve = format!("CVE-2033-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let scan = fx
        .scan(repo, artifact, "dependency", &[finding(&cve, LODASH, "1")])
        .await;
    let needle = cve.to_uppercase();
    fx.ack_scan(scan).await;
    assert_eq!(fx.audit_count("FINDING_ACKNOWLEDGED", &needle).await, 1);
    let details: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM audit_log WHERE action = 'FINDING_ACKNOWLEDGED' \
         AND details::text LIKE $1",
    )
    .bind(format!("%{needle}%"))
    .fetch_one(&fx.pool)
    .await
    .expect("details");
    assert_eq!(details["max_severity"], "high");

    fx.ack_scan(scan).await;
    assert_eq!(
        fx.audit_count("FINDING_ACKNOWLEDGEMENT_REVOKED", &needle)
            .await,
        1,
        "the replaced decision leaves a row"
    );
    fx.cleanup().await;
}

/// On a rollback, or a 1.11 replica during a rolling upgrade, the frozen flag is
/// what is read. A revoked or lapsed decision must not read as acknowledged there.
#[tokio::test]
#[ignore]
async fn revoke_and_expiry_clear_the_frozen_flag() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let scan = fx
        .scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let id = fx.finding_ids(scan).await[0];
    let flag = |pool: PgPool| async move {
        let flagged: bool =
            sqlx::query_scalar("SELECT is_acknowledged FROM scan_findings WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("flag");
        flagged
    };
    legacy_ack(&fx, id, "legacy").await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(migration_backfill_sql()))
        .execute(&fx.pool)
        .await
        .expect("backfill");
    assert!(flag(fx.pool.clone()).await);
    fx.svc
        .revoke_acknowledgment(id, None, &fx.actor())
        .await
        .expect("revoke");
    assert!(!flag(fx.pool.clone()).await, "after a revoke");

    legacy_ack(&fx, id, "legacy").await;
    fx.svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "short",
            AcknowledgeOptions {
                expires_at: Some(Utc::now() + Duration::milliseconds(200)),
                ..Default::default()
            },
        )
        .await
        .expect("ack");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    FindingAcknowledgementService::new(fx.pool.clone())
        .record_expired()
        .await
        .expect("sweep");
    assert!(!flag(fx.pool.clone()).await, "after the lapse is recorded");
    fx.cleanup().await;
}

/// #7: nothing that holds a lock a download waits on may be held across the
/// backfill, which scans `scan_findings`.
#[tokio::test]
#[ignore]
async fn the_backfill_does_not_share_a_transaction_with_any_blocking_ddl() {
    let backfill = migration_file("_finding_acknowledgements_backfill.sql");
    let upper = backfill.to_uppercase();
    for forbidden in [
        "ALTER TABLE",
        "CREATE TABLE",
        "CREATE INDEX",
        "CREATE UNIQUE INDEX",
    ] {
        assert!(
            !upper.contains(forbidden),
            "{forbidden} in the backfill migration"
        );
    }
    let schema = migration_file("_finding_acknowledgements.sql");
    assert!(!schema.to_uppercase().contains("ALTER TABLE SCAN_RESULTS"));
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

/// The shape creating a repository leaves: an `is_admin` user with repository-scoped
/// roles on what it created and no instance-wide role.
async fn admin_holding_repository_roles(fx: &Fx, created: Uuid) -> Uuid {
    let id = plain_admin(fx).await;
    sqlx::query(
        "INSERT INTO role_assignments (user_id, role_id, repository_id) \
         SELECT $1, r.id, $2 FROM roles r WHERE r.name IN ('repository-owner', 'developer')",
    )
    .bind(id)
    .bind(created)
    .execute(&fx.pool)
    .await
    .expect("repository roles");
    let (instance_wide, on_repositories): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE repository_id IS NULL), \
                COUNT(*) FILTER (WHERE repository_id IS NOT NULL) \
         FROM role_assignments WHERE user_id = $1",
    )
    .bind(id)
    .fetch_one(&fx.pool)
    .await
    .expect("roles");
    assert_eq!(instance_wide, 0);
    assert!(on_repositories > 0);
    id
}

/// An `is_admin` user with no role row, as `POST /users` creates one.
async fn plain_admin(fx: &Fx) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
         VALUES ($1, $2, $3, 'unused', 'local', true, true)",
    )
    .bind(id)
    .bind(format!("ack-plain-{id}"))
    .bind(format!("ack-plain-{id}@test.local"))
    .execute(&fx.pool)
    .await
    .expect("admin");
    id
}

async fn make_private(fx: &Fx, repo: Uuid) {
    sqlx::query("UPDATE repositories SET visibility = 'private', is_public = false WHERE id = $1")
        .bind(repo)
        .execute(&fx.pool)
        .await
        .expect("private");
}

#[tokio::test]
#[ignore]
async fn an_admin_with_no_role_row_can_decide_and_withdraw_on_a_private_repository() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    make_private(&fx, repo).await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let scan = fx
        .scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let id = fx.finding_ids(scan).await[0];
    let admin = AckActor::new(plain_admin(&fx).await, AccessScope::Admin);
    fx.svc
        .acknowledge_finding(id, &admin, "accepted", Default::default())
        .await
        .expect("decide");
    assert!(fx.allowed(repo, artifact).await);
    fx.svc
        .revoke_acknowledgment(id, None, &admin)
        .await
        .expect("withdraw");
    assert!(!fx.allowed(repo, artifact).await);
    fx.svc
        .acknowledge_finding(
            id,
            &admin,
            "everywhere",
            AcknowledgeOptions {
                scope: AcknowledgementScope::AllRepositories,
                ..Default::default()
            },
        )
        .await
        .expect("an unbound admin can decide for every repository");
    fx.cleanup().await;
}

/// The id a listing hands out does not say which repository the caller is in, so
/// a revoke needs to be told as an acknowledge does, and each answers with the
/// state of the repository that was named.
#[tokio::test]
#[ignore]
async fn a_row_with_copies_elsewhere_needs_the_repository_named_and_answers_for_it() {
    let mut fx = Fx::new().await;
    let prod = fx.repo().await;
    let dev = fx.repo().await;
    let d = digest();
    let in_prod = fx.artifact(prod, "a.tgz", &d).await;
    let in_dev = fx.artifact(dev, "a.tgz", &d).await;
    let source = fx
        .scan(prod, in_prod, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    fx.svc
        .copy_scan_results(source, in_dev, dev, "dependency", &d, None)
        .await
        .expect("copy");
    let id = fx.finding_ids(source).await[0];
    let in_repo = |repository_id| AcknowledgeOptions {
        repository_id: Some(repository_id),
        ..Default::default()
    };

    for repo in [prod, dev] {
        let answered = fx
            .svc
            .acknowledge_finding(id, &fx.actor(), "accepted", in_repo(repo))
            .await
            .expect("decide");
        assert!(
            answered.is_acknowledged,
            "the state of the repository named"
        );
    }
    assert!(fx.allowed(prod, in_prod).await && fx.allowed(dev, in_dev).await);

    let ambiguous = fx.svc.revoke_acknowledgment(id, None, &fx.actor()).await;
    assert!(
        matches!(ambiguous, Err(AppError::Conflict(_))),
        "{ambiguous:?}"
    );
    assert!(fx.allowed(prod, in_prod).await, "nothing was revoked");

    let answered = fx
        .svc
        .revoke_acknowledgment(id, Some(dev), &fx.actor())
        .await
        .expect("revoke dev");
    assert!(
        !answered.is_acknowledged,
        "dev's state, though the row is prod's and prod's decision stands"
    );
    assert!(!fx.allowed(dev, in_dev).await);
    assert!(fx.allowed(prod, in_prod).await);
    fx.cleanup().await;
}

/// A credential that does not cover a finding learns nothing about it: the same
/// answer as for an id that does not exist, whatever else the request names.
#[tokio::test]
#[ignore]
async fn a_finding_outside_the_credential_reads_as_no_finding() {
    let mut fx = Fx::new().await;
    let inside = fx.repo().await;
    let outside = fx.repo().await;
    let d = digest();
    fx.artifact(inside, "a.tgz", &d).await;
    let foreign = fx.artifact(outside, "a.tgz", &d).await;
    let scan = fx
        .scan(
            outside,
            foreign,
            "dependency",
            &[finding(CVE_A, LODASH, "1")],
        )
        .await;
    let other_bytes = fx.artifact(outside, "b.tgz", &digest()).await;
    let scan2 = fx
        .scan(
            outside,
            other_bytes,
            "dependency",
            &[finding(CVE_B, LODASH, "1")],
        )
        .await;
    let scoped = AckActor::new(fx.admin, AccessScope::Restricted(vec![inside]));
    let in_inside = AcknowledgeOptions {
        repository_id: Some(inside),
        ..Default::default()
    };
    let absent = format!(
        "{:?}",
        fx.svc
            .acknowledge_finding(Uuid::new_v4(), &scoped, "x", in_inside)
            .await
            .expect_err("absent")
    );
    assert!(absent.contains("NotFound"), "{absent}");
    for (label, id) in [
        ("the same bytes, no copy", fx.finding_ids(scan).await[0]),
        ("other bytes", fx.finding_ids(scan2).await[0]),
    ] {
        for options in [in_inside, AcknowledgeOptions::default()] {
            let answer = format!(
                "{:?}",
                fx.svc
                    .acknowledge_finding(id, &scoped, "x", options)
                    .await
                    .expect_err(label)
            );
            assert_eq!(answer, absent, "{label}");
        }
        let answer = format!(
            "{:?}",
            fx.svc
                .revoke_acknowledgment(id, Some(inside), &scoped)
                .await
                .expect_err(label)
        );
        assert_eq!(answer, absent, "{label} revoke");
    }
    assert!(!fx.allowed(outside, foreign).await);
    fx.cleanup().await;
}

/// `max_cve_severity` and the promotion thresholds read open findings, as the
/// download gate does, so a retracted false positive that was acknowledged does
/// not block promotion for ever.
#[tokio::test]
#[ignore]
async fn the_promotion_gate_honours_an_acknowledged_external_finding() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    ingest(
        &fx,
        repo,
        artifact,
        &[external(
            CVE_A,
            "vendor-a",
            Severity::Critical,
            FindingClass::Vulnerability,
        )],
    )
    .await;
    ingest(&fx, repo, artifact, &[]).await;
    let summary = |pool: PgPool| async move {
        PromotionPolicyService::new(pool)
            .evaluate_artifact(artifact, repo)
            .await
            .expect("evaluate")
            .cve_summary
            .expect("summary")
    };
    assert_eq!(
        summary(fx.pool.clone()).await.critical_count,
        1,
        "open: it counts"
    );
    let open = severity_counts(&fx.pool, FindingScope::Artifact(artifact))
        .await
        .expect("counts");
    assert_eq!(open.critical, 1, "the tiles agree with the gate about it");

    let id: Uuid = sqlx::query_scalar("SELECT id FROM scan_findings WHERE artifact_id = $1")
        .bind(artifact)
        .fetch_one(&fx.pool)
        .await
        .expect("finding");
    fx.svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "retracted by the vendor",
            Default::default(),
        )
        .await
        .expect("acknowledge");
    let after = summary(fx.pool.clone()).await;
    assert_eq!(after.critical_count, 0, "acknowledged: it does not");
    assert!(after.open_cves.is_empty());
    assert!(fx.allowed(repo, artifact).await, "the download gate agrees");

    // Going somewhere else, it stays closed for a promoter who could carry the
    // decision or once it is for every repository, and only then.
    let target = fx.repo().await;
    let toward_target = |may_acknowledge: bool, pool: PgPool| async move {
        PromotionPolicyService::new(pool)
            .evaluate_promotion(
                artifact,
                repo,
                Some(PromotionGateContext {
                    target_repository_id: target,
                    promoter_may_acknowledge: may_acknowledge,
                }),
            )
            .await
            .expect("evaluate")
            .cve_summary
            .expect("summary")
            .critical_count
    };
    assert_eq!(toward_target(false, fx.pool.clone()).await, 1);
    assert_eq!(toward_target(true, fx.pool.clone()).await, 0);
    fx.svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "retracted, everywhere",
            AcknowledgeOptions {
                scope: AcknowledgementScope::AllRepositories,
                ..Default::default()
            },
        )
        .await
        .expect("acknowledge everywhere");
    assert_eq!(toward_target(false, fx.pool.clone()).await, 0);
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn the_foreign_key_migration_bounds_its_lock() {
    let sql = migration_file("_scan_results_source_scan_fk.sql");
    let set = sql.find("SET LOCAL lock_timeout").expect("a lock timeout");
    let alter = sql.find("ALTER TABLE").expect("the change");
    assert!(set < alter, "set before the lock is taken");
}

// ---------------------------------------------------------------------------
// A promotion gate guards the target
// ---------------------------------------------------------------------------

struct GateRig {
    source_repo: Uuid,
    target_repo: Uuid,
    artifact: Uuid,
    target_artifact: Uuid,
    finding: Uuid,
}

/// A critical finding on `staging`, a `staging -> prod` rule blocking `high`, and
/// the same bytes in `prod`, so a decision can be live there too.
async fn gate_rig(fx: &mut Fx) -> GateRig {
    let source_repo = fx.repo().await;
    let target_repo = fx.repo().await;
    let d = digest();
    let artifact = fx.artifact(source_repo, "a.tgz", &d).await;
    let target_artifact = fx.artifact(target_repo, "held.tgz", &d).await;
    let scan = fx
        .scan(
            source_repo,
            artifact,
            "dependency",
            &[finding_from(
                CVE_A,
                LODASH,
                "1",
                "grype",
                Severity::Critical,
            )],
        )
        .await;
    sqlx::query(
        "INSERT INTO promotion_rules (name, source_repo_id, target_repo_id, is_enabled, max_cve_severity) \
         VALUES ($1, $2, $3, true, 'high')",
    )
    .bind(format!("ack-gate-{source_repo}"))
    .bind(source_repo)
    .bind(target_repo)
    .execute(&fx.pool)
    .await
    .expect("rule");
    let finding = fx.finding_ids(scan).await[0];
    GateRig {
        source_repo,
        target_repo,
        artifact,
        target_artifact,
        finding,
    }
}

async fn decide_in(fx: &Fx, rig: &GateRig, repository_id: Uuid) {
    fx.svc
        .acknowledge_finding(
            rig.finding,
            &fx.actor(),
            "decided",
            AcknowledgeOptions {
                repository_id: Some(repository_id),
                ..Default::default()
            },
        )
        .await
        .expect("decide");
}

/// `(policy gate passes, rule gate passes)` for a promoter who can or cannot
/// acknowledge in the target.
async fn gates(fx: &Fx, rig: &GateRig, may_acknowledge: bool) -> (bool, bool) {
    let summary = PromotionPolicyService::new(fx.pool.clone())
        .evaluate_promotion(
            rig.artifact,
            rig.source_repo,
            Some(PromotionGateContext {
                target_repository_id: rig.target_repo,
                promoter_may_acknowledge: may_acknowledge,
            }),
        )
        .await
        .expect("policy")
        .cve_summary
        .expect("summary");
    assert_eq!(
        summary.critical_count == 0,
        summary.open_cves.is_empty(),
        "counts and open CVEs read the same findings"
    );
    let failing = PromotionRuleService::new(fx.pool.clone())
        .evaluate_for_promotion(
            rig.artifact,
            rig.source_repo,
            rig.target_repo,
            may_acknowledge,
        )
        .await
        .expect("rule");
    (summary.critical_count == 0, failing.is_empty())
}

#[tokio::test]
#[ignore]
async fn a_decision_scoped_to_the_source_opens_a_target_gate_only_for_who_could_carry_it() {
    let mut fx = Fx::new().await;
    let rig = gate_rig(&mut fx).await;
    assert_eq!(
        gates(&fx, &rig, true).await,
        (false, false),
        "nothing decided"
    );

    fx.svc
        .acknowledge_finding(rig.finding, &fx.actor(), "staging only", Default::default())
        .await
        .expect("acknowledge");
    assert_eq!(
        gates(&fx, &rig, false).await,
        (false, false),
        "plain promoter"
    );
    assert_eq!(
        gates(&fx, &rig, true).await,
        (true, true),
        "authorised promoter"
    );
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn a_decision_that_already_reaches_the_target_opens_its_gate_for_anyone() {
    let mut fx = Fx::new().await;
    let rig = gate_rig(&mut fx).await;
    let every = AcknowledgeOptions {
        scope: AcknowledgementScope::AllRepositories,
        ..Default::default()
    };
    fx.svc
        .acknowledge_finding(rig.finding, &fx.actor(), "everywhere", every)
        .await
        .expect("acknowledge everywhere");
    assert_eq!(
        gates(&fx, &rig, false).await,
        (true, true),
        "every repository"
    );
    fx.svc
        .revoke_acknowledgment(rig.finding, Some(rig.source_repo), &fx.actor())
        .await
        .expect("revoke");

    fx.svc
        .acknowledge_finding(
            rig.finding,
            &fx.actor(),
            "prod",
            AcknowledgeOptions {
                repository_id: Some(rig.target_repo),
                ..Default::default()
            },
        )
        .await
        .expect("acknowledge in the target");
    assert_eq!(
        gates(&fx, &rig, false).await,
        (true, true),
        "live in the target"
    );
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn a_lapsed_or_revoked_decision_opens_no_promotion_gate() {
    let mut fx = Fx::new().await;
    let rig = gate_rig(&mut fx).await;
    fx.svc
        .acknowledge_finding(
            rig.finding,
            &fx.actor(),
            "short",
            AcknowledgeOptions {
                scope: AcknowledgementScope::AllRepositories,
                expires_at: Some(Utc::now() + Duration::milliseconds(300)),
                ..Default::default()
            },
        )
        .await
        .expect("acknowledge");
    assert_eq!(gates(&fx, &rig, false).await, (true, true));
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(gates(&fx, &rig, true).await, (false, false), "expired");

    fx.svc
        .acknowledge_finding(rig.finding, &fx.actor(), "again", Default::default())
        .await
        .expect("acknowledge again");
    assert_eq!(gates(&fx, &rig, true).await, (true, true));
    fx.svc
        .revoke_acknowledgment(rig.finding, None, &fx.actor())
        .await
        .expect("revoke");
    assert_eq!(gates(&fx, &rig, true).await, (false, false), "revoked");
    fx.cleanup().await;
}

/// A row that claims findings it has no rows for: a dedup copy from before the two
/// inserts shared a transaction (#1035, #1058). The stored counts are all there is
/// to go on, and clean is not what they say.
#[tokio::test]
#[ignore]
async fn a_scan_claiming_findings_it_has_no_rows_for_still_counts() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let scan = fx.scan(repo, artifact, "dependency", &[]).await;
    sqlx::query(
        "UPDATE scan_results SET findings_count = 2, critical_count = 1, high_count = 1 WHERE id = $1",
    )
    .bind(scan)
    .execute(&fx.pool)
    .await
    .expect("counts");
    let summary = PromotionPolicyService::new(fx.pool.clone())
        .evaluate_artifact(artifact, repo)
        .await
        .expect("evaluate")
        .cve_summary
        .expect("summary");
    assert_eq!((summary.critical_count, summary.high_count), (1, 1));
    fx.cleanup().await;
}

/// `left_effective` is about what is still in force.
#[tokio::test]
#[ignore]
async fn left_effective_counts_only_what_is_still_in_force() {
    let mut fx = Fx::new().await;
    let inside = fx.repo().await;
    let outside = fx.repo().await;
    let d = digest();
    let a = fx.artifact(inside, "a.tgz", &d).await;
    let scan = fx
        .scan(inside, a, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    fx.ack_scan(scan).await;
    let promoted = fx.artifact(outside, "a.tgz", &d).await;
    carry(&fx, a, promoted).await.expect("carry");
    sqlx::query(
        "UPDATE finding_acknowledgements SET expires_at = NOW() - INTERVAL '1 hour' \
         WHERE repository_id = $1",
    )
    .bind(outside)
    .execute(&fx.pool)
    .await
    .expect("lapse the copy");
    let scoped = AckActor::new(fx.admin, AccessScope::Restricted(vec![inside]));
    let finding_id = fx.finding_ids(scan).await[0];
    let answered = fx
        .svc
        .revoke_acknowledgment(finding_id, Some(inside), &scoped)
        .await
        .expect("revoke");
    assert_eq!(answered.acknowledgements_left_effective, Some(0));
    fx.cleanup().await;
}

/// Revoking a repository's decision by id, while a separate every-repository
/// decision still covers that finding there, must not read as nothing left.
#[tokio::test]
#[ignore]
async fn revoking_by_id_says_when_another_decision_still_covers_the_finding() {
    let mut fx = Fx::new().await;
    let repo = fx.repo().await;
    let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
    let scan = fx
        .scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
        .await;
    let id = fx.finding_ids(scan).await[0];
    let scoped = fx
        .svc
        .acknowledge_finding(id, &fx.actor(), "here", Default::default())
        .await
        .expect("here")
        .acknowledgement_id
        .expect("decision");
    fx.svc
        .acknowledge_finding(
            id,
            &fx.actor(),
            "everywhere",
            AcknowledgeOptions {
                scope: AcknowledgementScope::AllRepositories,
                ..Default::default()
            },
        )
        .await
        .expect("everywhere");
    let outcome = FindingAcknowledgementService::new(fx.pool.clone())
        .revoke(scoped, &fx.actor())
        .await
        .expect("revoke");
    assert_eq!(outcome.revoked, 1);
    assert_eq!(outcome.left_effective, 1);
    assert!(
        fx.allowed(repo, artifact).await,
        "and it does still cover it"
    );
    fx.cleanup().await;
}

/// A gate that passes on a source decision is promising the carry will move it. An
/// expired row in the target must not stand in its way.
#[tokio::test]
#[ignore]
async fn a_carry_replaces_an_expired_decision_in_the_target() {
    let mut fx = Fx::new().await;
    let rig = gate_rig(&mut fx).await;
    decide_in(&fx, &rig, rig.source_repo).await;
    decide_in(&fx, &rig, rig.target_repo).await;
    sqlx::query(
        "UPDATE finding_acknowledgements SET expires_at = NOW() - INTERVAL '1 hour' \
         WHERE repository_id = $1",
    )
    .bind(rig.target_repo)
    .execute(&fx.pool)
    .await
    .expect("lapse the target's decision");
    assert_eq!(
        gates(&fx, &rig, true).await,
        (true, true),
        "the gate passes"
    );

    FindingAcknowledgementService::new(fx.pool.clone())
        .carry_to_promoted_artifact(rig.artifact, rig.target_artifact, fx.admin_principal())
        .await
        .expect("carry");

    assert!(
        fx.allowed(rig.target_repo, rig.target_artifact).await,
        "and the decision the gate relied on arrived"
    );
    let rows: Vec<(Option<String>, String)> = sqlx::query_as(
        "SELECT revoked_reason, created_via FROM finding_acknowledgements \
         WHERE repository_id = $1 ORDER BY created_at",
    )
    .bind(rig.target_repo)
    .fetch_all(&fx.pool)
    .await
    .expect("rows");
    assert_eq!(
        rows,
        vec![
            (Some("superseded".to_string()), "api".to_string()),
            (None, "promotion".to_string()),
        ]
    );
    fx.cleanup().await;
}

/// The carry keeps a live decision in the target, so the gate must not rely on a
/// higher ceiling that will never arrive there.
#[tokio::test]
#[ignore]
async fn a_lower_ceiling_live_in_the_target_keeps_the_gate_shut() {
    let mut fx = Fx::new().await;
    let rig = gate_rig(&mut fx).await;
    decide_in(&fx, &rig, rig.source_repo).await;
    decide_in(&fx, &rig, rig.target_repo).await;
    assert_eq!(
        gates(&fx, &rig, false).await,
        (true, true),
        "the target's own"
    );

    let set_target_ceiling = |rank: i16, pool: PgPool, repo: Uuid| async move {
        sqlx::query(
            "UPDATE finding_acknowledgements SET max_severity_rank = $1 \
             WHERE repository_id = $2 AND revoked_at IS NULL",
        )
        .bind(rank)
        .bind(repo)
        .execute(&pool)
        .await
        .expect("ceiling");
    };
    set_target_ceiling(3, fx.pool.clone(), rig.target_repo).await;
    assert_eq!(
        gates(&fx, &rig, true).await,
        (false, false),
        "source decision"
    );

    // The narrower decision speaks in the target, as it does at the download gate.
    fx.svc
        .acknowledge_finding(
            rig.finding,
            &fx.actor(),
            "everywhere",
            AcknowledgeOptions {
                scope: AcknowledgementScope::AllRepositories,
                ..Default::default()
            },
        )
        .await
        .expect("everywhere");
    assert_eq!(
        gates(&fx, &rig, false).await,
        (false, false),
        "every repository"
    );
    // The same finding scanned in the target: the download gate reads it the same way.
    fx.scan(
        rig.target_repo,
        rig.target_artifact,
        "dependency",
        &[finding_from(
            CVE_A,
            LODASH,
            "1",
            "grype",
            Severity::Critical,
        )],
    )
    .await;
    assert!(
        !fx.allowed(rig.target_repo, rig.target_artifact).await,
        "agrees"
    );
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// An administrator's reach
// ---------------------------------------------------------------------------

/// #5250: what repository roles an administrator holds does not narrow where they
/// may decide, on a repository they created or one they did not.
#[tokio::test]
#[ignore]
async fn an_admin_holding_repository_roles_decides_everywhere() {
    let mut fx = Fx::new().await;
    let created = fx.repo().await;
    let other = fx.repo().await;
    make_private(&fx, other).await;
    let id = admin_holding_repository_roles(&fx, created).await;
    let admin = AckActor::new(id, AccessScope::Admin);

    for repo in [created, other] {
        let artifact = fx.artifact(repo, "a.tgz", &digest()).await;
        let scan = fx
            .scan(repo, artifact, "dependency", &[finding(CVE_A, LODASH, "1")])
            .await;
        let finding_id = fx.finding_ids(scan).await[0];
        fx.svc
            .acknowledge_finding(finding_id, &admin, "accepted", Default::default())
            .await
            .expect("decide");
        assert!(fx.allowed(repo, artifact).await);
        fx.svc
            .revoke_acknowledgment(finding_id, None, &admin)
            .await
            .expect("withdraw");
        assert!(!fx.allowed(repo, artifact).await);

        let every = AcknowledgeOptions {
            scope: AcknowledgementScope::AllRepositories,
            ..Default::default()
        };
        fx.svc
            .acknowledge_finding(finding_id, &admin, "everywhere", every)
            .await
            .expect("decide for every repository");
        assert!(fx.allowed(repo, artifact).await);
        fx.svc
            .revoke_acknowledgment(finding_id, None, &admin)
            .await
            .expect("withdraw for every repository");
        assert!(!fx.allowed(repo, artifact).await);
    }
    fx.cleanup().await;
}

/// A revoke by such an administrator reaches the whole lineage, including the
/// copy in a repository they hold no role on.
#[tokio::test]
#[ignore]
async fn an_admin_holding_repository_roles_revokes_a_whole_lineage() {
    let mut fx = Fx::new().await;
    let created = fx.repo().await;
    let other = fx.repo().await;
    make_private(&fx, other).await;
    let admin = AckActor::new(
        admin_holding_repository_roles(&fx, created).await,
        AccessScope::Admin,
    );
    let d = digest();
    let original = fx.artifact(created, "a.tgz", &d).await;
    let scan = fx
        .scan(
            created,
            original,
            "dependency",
            &[finding(CVE_A, LODASH, "1")],
        )
        .await;
    let finding_id = fx.finding_ids(scan).await[0];
    fx.svc
        .acknowledge_finding(finding_id, &admin, "accepted", Default::default())
        .await
        .expect("decide");
    let promoted = fx.artifact(other, "a.tgz", &d).await;
    carry(&fx, original, promoted).await.expect("carry");
    assert!(fx.allowed(other, promoted).await);

    let withdrawn = fx
        .svc
        .revoke_acknowledgment(finding_id, Some(created), &admin)
        .await
        .expect("revoke");
    assert_eq!(withdrawn.acknowledgements_left_effective, Some(0));
    assert!(!fx.allowed(created, original).await);
    assert!(!fx.allowed(other, promoted).await);
    fx.cleanup().await;
}

/// The same administrator on a credential restricted to one repository stays there.
#[tokio::test]
#[ignore]
async fn a_restricted_credential_stays_limited_whatever_roles_its_owner_holds() {
    let mut fx = Fx::new().await;
    let created = fx.repo().await;
    let other = fx.repo().await;
    let id = admin_holding_repository_roles(&fx, created).await;
    let restricted = AckActor::new(id, AccessScope::Restricted(vec![created]));
    let in_scope = fx.artifact(created, "a.tgz", &digest()).await;
    let scan = fx
        .scan(
            created,
            in_scope,
            "dependency",
            &[finding(CVE_A, LODASH, "1")],
        )
        .await;
    let out_of_scope = fx.artifact(other, "a.tgz", &digest()).await;
    let other_scan = fx
        .scan(
            other,
            out_of_scope,
            "dependency",
            &[finding(CVE_A, LODASH, "1")],
        )
        .await;

    let elsewhere = fx
        .svc
        .acknowledge_finding(
            fx.finding_ids(other_scan).await[0],
            &restricted,
            "no",
            Default::default(),
        )
        .await;
    assert!(
        matches!(elsewhere, Err(AppError::NotFound(_))),
        "{elsewhere:?}"
    );
    assert!(!fx.allowed(other, out_of_scope).await);

    let finding_id = fx.finding_ids(scan).await[0];
    let every = fx
        .svc
        .acknowledge_finding(
            finding_id,
            &restricted,
            "no",
            AcknowledgeOptions {
                scope: AcknowledgementScope::AllRepositories,
                ..Default::default()
            },
        )
        .await;
    assert!(
        matches!(every, Err(AppError::Authorization(_))),
        "{every:?}"
    );
    fx.svc
        .acknowledge_finding(finding_id, &restricted, "here", Default::default())
        .await
        .expect("inside the credential");
    assert!(fx.allowed(created, in_scope).await);
    fx.cleanup().await;
}
