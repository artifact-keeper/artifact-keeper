# Package Curation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add package curation to Artifact Keeper, starting with RPM and DEB. Packages from upstream mirrors flow through a staging repo where rules and policies auto-approve or flag them for manual review. Only approved packages appear in the client-facing index.

**Architecture:** New `curation_packages` and `curation_rules` tables store the package catalog and rules. A `CurationService` evaluates packages against a three-layer rules engine (explicit rules, policy-based scanning, default stance). A background sync job periodically fetches upstream metadata indexes and populates the staging catalog. The existing staging repo, promotion, and virtual repo infrastructure is reused. New `curation_enabled` columns on the `repositories` table activate curation behavior.

**Tech Stack:** Rust 1.75+, axum, sqlx (PostgreSQL), tokio, serde, utoipa, glob-match

**Design doc:** `docs/plans/2026-03-07-package-curation-design.md`

---

### Task 1: Database migration for curation tables

**Files:**
- Create: `backend/migrations/071_curation.sql`

**Step 1: Write the migration**

```sql
-- Package curation: rules engine and package catalog

-- Curation rules (explicit allow/block lists)
CREATE TABLE IF NOT EXISTS curation_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staging_repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    package_pattern TEXT NOT NULL,
    version_constraint TEXT NOT NULL DEFAULT '*',
    architecture    TEXT NOT NULL DEFAULT '*',
    action          TEXT NOT NULL CHECK (action IN ('allow', 'block')),
    priority        INT NOT NULL DEFAULT 100,
    reason          TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_curation_rules_repo ON curation_rules(staging_repo_id) WHERE staging_repo_id IS NOT NULL;
CREATE INDEX idx_curation_rules_global ON curation_rules(priority) WHERE staging_repo_id IS NULL;

-- Curation package catalog (upstream packages tracked through staging)
CREATE TABLE IF NOT EXISTS curation_packages (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staging_repo_id     UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    remote_repo_id      UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    format              TEXT NOT NULL,
    package_name        TEXT NOT NULL,
    version             TEXT NOT NULL,
    release             TEXT,
    architecture        TEXT,
    checksum_sha256     TEXT,
    upstream_path       TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'blocked', 'review')),
    evaluated_at        TIMESTAMPTZ,
    evaluated_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    evaluation_reason   TEXT,
    rule_id             UUID REFERENCES curation_rules(id) ON DELETE SET NULL,
    metadata            JSONB NOT NULL DEFAULT '{}',
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    upstream_updated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_curation_pkg_unique ON curation_packages(staging_repo_id, format, package_name, version, COALESCE(release, ''), COALESCE(architecture, ''));
CREATE INDEX idx_curation_pkg_status ON curation_packages(staging_repo_id, status);
CREATE INDEX idx_curation_pkg_name ON curation_packages(staging_repo_id, package_name);

-- Curation columns on repositories table
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS curation_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS curation_source_repo_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS curation_target_repo_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS curation_default_action TEXT NOT NULL DEFAULT 'allow' CHECK (curation_default_action IN ('allow', 'review')),
    ADD COLUMN IF NOT EXISTS curation_sync_interval_secs INT NOT NULL DEFAULT 3600,
    ADD COLUMN IF NOT EXISTS curation_auto_fetch BOOLEAN NOT NULL DEFAULT false;
```

**Step 2: Verify migration applies cleanly**

Run: `cd /Users/khan/ak/artifact-keeper && DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" sqlx migrate run`
Expected: migration 071 applied successfully

**Step 3: Rebuild SQLx offline cache**

Run: `cd /Users/khan/ak/artifact-keeper && cargo sqlx prepare --workspace`
Expected: query cache files updated in `.sqlx/`

**Step 4: Commit**

```bash
git add backend/migrations/071_curation.sql .sqlx/
git commit -m "feat: add curation tables migration (rules, packages, repo columns)"
```

---

### Task 2: Curation models

**Files:**
- Create: `backend/src/models/curation.rs`
- Modify: `backend/src/models/mod.rs`
- Modify: `backend/src/models/repository.rs`

**Step 1: Create the curation model file**

Create `backend/src/models/curation.rs`:

```rust
//! Curation models for package vetting through staging repos.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An explicit allow/block rule for package curation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct CurationRule {
    pub id: Uuid,
    pub staging_repo_id: Option<Uuid>,
    pub package_pattern: String,
    pub version_constraint: String,
    pub architecture: String,
    pub action: String,
    pub priority: i32,
    pub reason: String,
    pub enabled: bool,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A package tracked in the curation staging catalog.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct CurationPackage {
    pub id: Uuid,
    pub staging_repo_id: Uuid,
    pub remote_repo_id: Uuid,
    pub format: String,
    pub package_name: String,
    pub version: String,
    pub release: Option<String>,
    pub architecture: Option<String>,
    pub checksum_sha256: Option<String>,
    pub upstream_path: String,
    pub status: String,
    pub evaluated_at: Option<DateTime<Utc>>,
    pub evaluated_by: Option<Uuid>,
    pub evaluation_reason: Option<String>,
    pub rule_id: Option<Uuid>,
    pub metadata: serde_json::Value,
    pub first_seen_at: DateTime<Utc>,
    pub upstream_updated_at: Option<DateTime<Utc>>,
}
```

**Step 2: Register the model module**

Add `pub mod curation;` to `backend/src/models/mod.rs` (after the `backup` line, alphabetical order).

**Step 3: Add curation fields to Repository model**

Add the new columns to the `Repository` struct in `backend/src/models/repository.rs` after the `promotion_policy_id` field:

```rust
    /// Curation: enable upstream package vetting for this staging repo
    pub curation_enabled: bool,
    /// Curation: the remote repo to sync upstream metadata from
    pub curation_source_repo_id: Option<Uuid>,
    /// Curation: the local repo to promote approved packages into
    pub curation_target_repo_id: Option<Uuid>,
    /// Curation: default action for packages not matching any rule (allow or review)
    pub curation_default_action: String,
    /// Curation: seconds between upstream metadata syncs
    pub curation_sync_interval_secs: i32,
    /// Curation: whether to pre-fetch approved package bytes
    pub curation_auto_fetch: bool,
```

**Step 4: Verify it compiles**

Run: `cd /Users/khan/ak/artifact-keeper && cargo check --workspace`
Expected: compiles with no errors (warnings OK)

**Step 5: Commit**

```bash
git add backend/src/models/curation.rs backend/src/models/mod.rs backend/src/models/repository.rs
git commit -m "feat: add CurationRule and CurationPackage models"
```

---

### Task 3: Curation service with rules evaluation

**Files:**
- Create: `backend/src/services/curation_service.rs`
- Modify: `backend/src/services/mod.rs`

**Step 1: Write unit tests for glob matching and rule evaluation**

Create `backend/src/services/curation_service.rs` with tests first:

```rust
//! Curation service: rules evaluation, package management, upstream sync.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::curation::{CurationPackage, CurationRule};

/// Result of evaluating a package against curation rules.
#[derive(Debug, Clone, Serialize)]
pub struct RuleEvaluation {
    pub action: String,       // "allow", "block", or "review"
    pub reason: String,
    pub rule_id: Option<Uuid>, // None if decided by default stance
}

pub struct CurationService {
    db: PgPool,
}

impl CurationService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Check if a package name matches a glob pattern.
    /// Supports `*` (any chars) and `?` (single char).
    pub fn pattern_matches(pattern: &str, name: &str) -> bool {
        glob_match(pattern, name)
    }

    /// Check if a version satisfies a constraint string.
    /// Supports: `*` (any), `= 1.0`, `>= 1.0`, `> 1.0`, `<= 1.0`, `< 1.0`.
    /// Falls back to lexicographic comparison for non-semver versions (RPM epochs, etc.).
    pub fn version_matches(constraint: &str, version: &str) -> bool {
        let constraint = constraint.trim();
        if constraint == "*" {
            return true;
        }

        let (op, target) = if let Some(v) = constraint.strip_prefix(">=") {
            (">=", v.trim())
        } else if let Some(v) = constraint.strip_prefix("<=") {
            ("<=", v.trim())
        } else if let Some(v) = constraint.strip_prefix('>') {
            (">", v.trim())
        } else if let Some(v) = constraint.strip_prefix('<') {
            ("<", v.trim())
        } else if let Some(v) = constraint.strip_prefix('=') {
            ("=", v.trim())
        } else {
            ("=", constraint)
        };

        let cmp = version_compare(version, target);
        match op {
            ">=" => cmp >= 0,
            "<=" => cmp <= 0,
            ">" => cmp > 0,
            "<" => cmp < 0,
            "=" => cmp == 0,
            _ => false,
        }
    }

    /// Evaluate a package against all applicable rules (repo-specific + global),
    /// returning the first matching rule's action or the default stance.
    pub async fn evaluate_package(
        &self,
        staging_repo_id: Uuid,
        default_action: &str,
        package_name: &str,
        version: &str,
        architecture: Option<&str>,
    ) -> Result<RuleEvaluation, sqlx::Error> {
        // Fetch all enabled rules for this repo + global, ordered by priority
        let rules: Vec<CurationRule> = sqlx::query_as(
            r#"SELECT * FROM curation_rules
               WHERE enabled = true
                 AND (staging_repo_id = $1 OR staging_repo_id IS NULL)
               ORDER BY priority ASC, created_at ASC"#,
        )
        .bind(staging_repo_id)
        .fetch_all(&self.db)
        .await?;

        for rule in &rules {
            if !Self::pattern_matches(&rule.package_pattern, package_name) {
                continue;
            }
            if !Self::version_matches(&rule.version_constraint, version) {
                continue;
            }
            if rule.architecture != "*" {
                if let Some(arch) = architecture {
                    if rule.architecture != arch {
                        continue;
                    }
                }
            }

            return Ok(RuleEvaluation {
                action: rule.action.clone(),
                reason: rule.reason.clone(),
                rule_id: Some(rule.id),
            });
        }

        // No rule matched: use default stance
        Ok(RuleEvaluation {
            action: default_action.to_string(),
            reason: format!("No matching rule; default action: {default_action}"),
            rule_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple glob matching: `*` matches any sequence, `?` matches one char.
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut p = pattern.chars().peekable();
    let mut t = text.chars().peekable();
    glob_match_inner(&mut p.collect::<Vec<_>>(), &t.collect::<Vec<_>>(), 0, 0)
}

fn glob_match_inner(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() && ti == text.len() {
        return true;
    }
    if pi == pattern.len() {
        return false;
    }

    if pattern[pi] == '*' {
        // Try matching * against 0..n characters
        for skip in 0..=(text.len() - ti) {
            if glob_match_inner(pattern, text, pi + 1, ti + skip) {
                return true;
            }
        }
        return false;
    }

    if ti == text.len() {
        return false;
    }

    if pattern[pi] == '?' || pattern[pi] == text[ti] {
        return glob_match_inner(pattern, text, pi + 1, ti + 1);
    }

    false
}

/// Compare two version strings. Returns -1, 0, or 1.
/// Splits on `.` and `-`, compares segments numerically when possible.
fn version_compare(a: &str, b: &str) -> i32 {
    let seg_a: Vec<&str> = a.split(|c| c == '.' || c == '-').collect();
    let seg_b: Vec<&str> = b.split(|c| c == '.' || c == '-').collect();

    for i in 0..seg_a.len().max(seg_b.len()) {
        let sa = seg_a.get(i).unwrap_or(&"0");
        let sb = seg_b.get(i).unwrap_or(&"0");

        // Try numeric comparison first
        match (sa.parse::<u64>(), sb.parse::<u64>()) {
            (Ok(na), Ok(nb)) => {
                if na < nb {
                    return -1;
                }
                if na > nb {
                    return 1;
                }
            }
            _ => {
                // Lexicographic fallback
                match sa.cmp(sb) {
                    std::cmp::Ordering::Less => return -1,
                    std::cmp::Ordering::Greater => return 1,
                    std::cmp::Ordering::Equal => {}
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- glob matching --

    #[test]
    fn test_glob_exact_match() {
        assert!(CurationService::pattern_matches("nginx", "nginx"));
        assert!(!CurationService::pattern_matches("nginx", "apache"));
    }

    #[test]
    fn test_glob_star_suffix() {
        assert!(CurationService::pattern_matches("telnet*", "telnet"));
        assert!(CurationService::pattern_matches("telnet*", "telnet-server"));
        assert!(!CurationService::pattern_matches("telnet*", "curl"));
    }

    #[test]
    fn test_glob_star_prefix() {
        assert!(CurationService::pattern_matches("*-dev", "libssl-dev"));
        assert!(!CurationService::pattern_matches("*-dev", "libssl"));
    }

    #[test]
    fn test_glob_star_middle() {
        assert!(CurationService::pattern_matches("lib*-dev", "libssl-dev"));
        assert!(CurationService::pattern_matches("lib*-dev", "libcurl-dev"));
        assert!(!CurationService::pattern_matches("lib*-dev", "nginx-dev"));
    }

    #[test]
    fn test_glob_question_mark() {
        assert!(CurationService::pattern_matches("lib?", "liba"));
        assert!(!CurationService::pattern_matches("lib?", "libab"));
    }

    #[test]
    fn test_glob_match_all() {
        assert!(CurationService::pattern_matches("*", "anything"));
        assert!(CurationService::pattern_matches("*", ""));
    }

    // -- version constraint matching --

    #[test]
    fn test_version_wildcard() {
        assert!(CurationService::version_matches("*", "1.2.3"));
        assert!(CurationService::version_matches("*", "0.0.1"));
    }

    #[test]
    fn test_version_exact() {
        assert!(CurationService::version_matches("= 1.2.3", "1.2.3"));
        assert!(!CurationService::version_matches("= 1.2.3", "1.2.4"));
    }

    #[test]
    fn test_version_gte() {
        assert!(CurationService::version_matches(">= 3.0", "3.0"));
        assert!(CurationService::version_matches(">= 3.0", "3.1"));
        assert!(!CurationService::version_matches(">= 3.0", "2.9"));
    }

    #[test]
    fn test_version_lt() {
        assert!(CurationService::version_matches("< 2.17", "2.16"));
        assert!(!CurationService::version_matches("< 2.17", "2.17"));
        assert!(!CurationService::version_matches("< 2.17", "3.0"));
    }

    #[test]
    fn test_version_gt() {
        assert!(CurationService::version_matches("> 1.0", "1.1"));
        assert!(!CurationService::version_matches("> 1.0", "1.0"));
    }

    #[test]
    fn test_version_lte() {
        assert!(CurationService::version_matches("<= 1.0", "1.0"));
        assert!(CurationService::version_matches("<= 1.0", "0.9"));
        assert!(!CurationService::version_matches("<= 1.0", "1.1"));
    }

    #[test]
    fn test_version_rpm_style() {
        // RPM versions like 1.24.0-1.el9
        assert!(CurationService::version_matches(">= 1.24.0", "1.24.0-1.el9"));
        assert!(!CurationService::version_matches(">= 1.25.0", "1.24.0-1.el9"));
    }

    #[test]
    fn test_version_implicit_equals() {
        // No operator means exact match
        assert!(CurationService::version_matches("1.2.3", "1.2.3"));
        assert!(!CurationService::version_matches("1.2.3", "1.2.4"));
    }
}
```

**Step 2: Register the service module**

Add `pub mod curation_service;` to `backend/src/services/mod.rs` (after `crash_reporting_service`, alphabetical order).

**Step 3: Run tests to verify they pass**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib curation_service`
Expected: all tests pass

**Step 4: Commit**

```bash
git add backend/src/services/curation_service.rs backend/src/services/mod.rs
git commit -m "feat: add CurationService with glob matching and version constraint evaluation"
```

---

### Task 4: Curation service CRUD operations

**Files:**
- Modify: `backend/src/services/curation_service.rs`

**Step 1: Add CRUD methods for rules and packages**

Add the following methods to the `CurationService` impl block, after `evaluate_package`:

```rust
    // ---------------------------------------------------------------------------
    // Rule CRUD
    // ---------------------------------------------------------------------------

    pub async fn create_rule(
        &self,
        staging_repo_id: Option<Uuid>,
        package_pattern: &str,
        version_constraint: &str,
        architecture: &str,
        action: &str,
        priority: i32,
        reason: &str,
        created_by: Uuid,
    ) -> Result<CurationRule, sqlx::Error> {
        sqlx::query_as(
            r#"INSERT INTO curation_rules
               (staging_repo_id, package_pattern, version_constraint, architecture, action, priority, reason, created_by)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING *"#,
        )
        .bind(staging_repo_id)
        .bind(package_pattern)
        .bind(version_constraint)
        .bind(architecture)
        .bind(action)
        .bind(priority)
        .bind(reason)
        .bind(created_by)
        .fetch_one(&self.db)
        .await
    }

    pub async fn list_rules(&self, staging_repo_id: Option<Uuid>) -> Result<Vec<CurationRule>, sqlx::Error> {
        if let Some(repo_id) = staging_repo_id {
            sqlx::query_as(
                r#"SELECT * FROM curation_rules
                   WHERE staging_repo_id = $1 OR staging_repo_id IS NULL
                   ORDER BY priority ASC, created_at ASC"#,
            )
            .bind(repo_id)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as(
                r#"SELECT * FROM curation_rules
                   ORDER BY priority ASC, created_at ASC"#,
            )
            .fetch_all(&self.db)
            .await
        }
    }

    pub async fn update_rule(
        &self,
        rule_id: Uuid,
        package_pattern: &str,
        version_constraint: &str,
        architecture: &str,
        action: &str,
        priority: i32,
        reason: &str,
        enabled: bool,
    ) -> Result<CurationRule, sqlx::Error> {
        sqlx::query_as(
            r#"UPDATE curation_rules SET
               package_pattern = $2, version_constraint = $3, architecture = $4,
               action = $5, priority = $6, reason = $7, enabled = $8, updated_at = now()
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(rule_id)
        .bind(package_pattern)
        .bind(version_constraint)
        .bind(architecture)
        .bind(action)
        .bind(priority)
        .bind(reason)
        .bind(enabled)
        .fetch_one(&self.db)
        .await
    }

    pub async fn delete_rule(&self, rule_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM curation_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Package catalog
    // ---------------------------------------------------------------------------

    pub async fn upsert_package(
        &self,
        staging_repo_id: Uuid,
        remote_repo_id: Uuid,
        format: &str,
        package_name: &str,
        version: &str,
        release: Option<&str>,
        architecture: Option<&str>,
        checksum_sha256: Option<&str>,
        upstream_path: &str,
        metadata: &serde_json::Value,
    ) -> Result<CurationPackage, sqlx::Error> {
        sqlx::query_as(
            r#"INSERT INTO curation_packages
               (staging_repo_id, remote_repo_id, format, package_name, version, release,
                architecture, checksum_sha256, upstream_path, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (staging_repo_id, format, package_name, version,
                           COALESCE(release, ''), COALESCE(architecture, ''))
               DO UPDATE SET checksum_sha256 = EXCLUDED.checksum_sha256,
                            upstream_path = EXCLUDED.upstream_path,
                            metadata = EXCLUDED.metadata,
                            upstream_updated_at = now()
               RETURNING *"#,
        )
        .bind(staging_repo_id)
        .bind(remote_repo_id)
        .bind(format)
        .bind(package_name)
        .bind(version)
        .bind(release)
        .bind(architecture)
        .bind(checksum_sha256)
        .bind(upstream_path)
        .bind(metadata)
        .fetch_one(&self.db)
        .await
    }

    pub async fn list_packages(
        &self,
        staging_repo_id: Uuid,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CurationPackage>, sqlx::Error> {
        if let Some(status) = status {
            sqlx::query_as(
                r#"SELECT * FROM curation_packages
                   WHERE staging_repo_id = $1 AND status = $2
                   ORDER BY package_name ASC, version ASC
                   LIMIT $3 OFFSET $4"#,
            )
            .bind(staging_repo_id)
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as(
                r#"SELECT * FROM curation_packages
                   WHERE staging_repo_id = $1
                   ORDER BY package_name ASC, version ASC
                   LIMIT $2 OFFSET $3"#,
            )
            .bind(staging_repo_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
        }
    }

    pub async fn get_package(&self, id: Uuid) -> Result<CurationPackage, sqlx::Error> {
        sqlx::query_as("SELECT * FROM curation_packages WHERE id = $1")
            .bind(id)
            .fetch_one(&self.db)
            .await
    }

    pub async fn set_package_status(
        &self,
        id: Uuid,
        status: &str,
        reason: &str,
        evaluated_by: Option<Uuid>,
        rule_id: Option<Uuid>,
    ) -> Result<CurationPackage, sqlx::Error> {
        sqlx::query_as(
            r#"UPDATE curation_packages SET
               status = $2, evaluation_reason = $3, evaluated_by = $4,
               rule_id = $5, evaluated_at = now()
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(id)
        .bind(status)
        .bind(reason)
        .bind(evaluated_by)
        .bind(rule_id)
        .fetch_one(&self.db)
        .await
    }

    pub async fn bulk_set_status(
        &self,
        ids: &[Uuid],
        status: &str,
        reason: &str,
        evaluated_by: Option<Uuid>,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"UPDATE curation_packages SET
               status = $2, evaluation_reason = $3, evaluated_by = $4, evaluated_at = now()
               WHERE id = ANY($1)"#,
        )
        .bind(ids)
        .bind(status)
        .bind(reason)
        .bind(evaluated_by)
        .execute(&self.db)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn count_by_status(
        &self,
        staging_repo_id: Uuid,
    ) -> Result<Vec<(String, i64)>, sqlx::Error> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT status, COUNT(*) as count
               FROM curation_packages
               WHERE staging_repo_id = $1
               GROUP BY status"#,
        )
        .bind(staging_repo_id)
        .fetch_all(&self.db)
        .await?;
        Ok(rows)
    }

    /// Evaluate all pending packages against current rules and update their status.
    pub async fn re_evaluate_pending(
        &self,
        staging_repo_id: Uuid,
        default_action: &str,
    ) -> Result<u64, sqlx::Error> {
        let pending: Vec<CurationPackage> = sqlx::query_as(
            "SELECT * FROM curation_packages WHERE staging_repo_id = $1 AND status = 'pending'",
        )
        .bind(staging_repo_id)
        .fetch_all(&self.db)
        .await?;

        let mut updated = 0u64;
        for pkg in &pending {
            let eval = self
                .evaluate_package(
                    staging_repo_id,
                    default_action,
                    &pkg.package_name,
                    &pkg.version,
                    pkg.architecture.as_deref(),
                )
                .await?;

            let new_status = match eval.action.as_str() {
                "allow" => "approved",
                "block" => "blocked",
                _ => "review",
            };

            self.set_package_status(pkg.id, new_status, &eval.reason, None, eval.rule_id)
                .await?;
            updated += 1;
        }
        Ok(updated)
    }
```

**Step 2: Verify it compiles**

Run: `cd /Users/khan/ak/artifact-keeper && cargo check --workspace`
Expected: compiles

**Step 3: Commit**

```bash
git add backend/src/services/curation_service.rs
git commit -m "feat: add CRUD operations and re-evaluation to CurationService"
```

---

### Task 5: Curation API handler

**Files:**
- Create: `backend/src/api/handlers/curation.rs`
- Modify: `backend/src/api/handlers/mod.rs`
- Modify: `backend/src/api/routes.rs`
- Modify: `backend/src/api/openapi.rs`

**Step 1: Create the curation handler**

Create `backend/src/api/handlers/curation.rs` with router, DTOs, and handler functions. Follow the pattern in `approval.rs`: axum Router with State, Extension for auth, Json for request/response, utoipa annotations.

Key endpoints to implement:

```rust
pub fn router() -> Router<SharedState> {
    Router::new()
        // Rules
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/:id", put(update_rule).delete(delete_rule))
        .route("/rules/:id/preview", post(preview_rule))
        // Packages
        .route("/packages", get(list_packages))
        .route("/packages/:id", get(get_package))
        .route("/packages/:id/approve", post(approve_package))
        .route("/packages/:id/block", post(block_package))
        .route("/packages/bulk-approve", post(bulk_approve))
        .route("/packages/bulk-block", post(bulk_block))
        .route("/packages/re-evaluate", post(re_evaluate))
        // Sync
        .route("/sync/:repo_id", post(trigger_sync))
        .route("/sync/:repo_id/status", get(sync_status))
        // Stats
        .route("/stats", get(stats))
}
```

Each handler follows the same pattern as `approval.rs`: extract `State<SharedState>`, `Extension<AuthExtension>`, deserialize query/body, call `CurationService`, return `Json<Response>`.

Request/response DTOs should use `#[derive(Deserialize, ToSchema)]` for requests and `#[derive(Serialize, ToSchema)]` for responses.

Add `#[derive(OpenApi)]` struct `CurationApiDoc` at the top with all paths and schemas listed.

**Step 2: Register the handler module**

Add `pub mod curation;` to `backend/src/api/handlers/mod.rs` (after `cran`, alphabetical).

**Step 3: Mount the router**

Add to `backend/src/api/routes.rs` after the quality gates `.nest()` block (around line 371):

```rust
        // Package curation routes with auth middleware
        .nest(
            "/curation",
            handlers::curation::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
```

**Step 4: Register OpenAPI docs**

Add to `backend/src/api/openapi.rs` after line 130:

```rust
    doc.merge(super::handlers::curation::CurationApiDoc::openapi());
```

**Step 5: Verify it compiles and tests pass**

Run: `cd /Users/khan/ak/artifact-keeper && cargo check --workspace && cargo test --workspace --lib`
Expected: compiles, all tests pass

**Step 6: Commit**

```bash
git add backend/src/api/handlers/curation.rs backend/src/api/handlers/mod.rs backend/src/api/routes.rs backend/src/api/openapi.rs
git commit -m "feat: add curation API handler with rules and package management endpoints"
```

---

### Task 6: RPM upstream metadata sync adapter

**Files:**
- Create: `backend/src/services/curation_sync.rs`
- Modify: `backend/src/services/mod.rs`

**Step 1: Write the RPM metadata parser with tests**

Create `backend/src/services/curation_sync.rs`:

```rust
//! Upstream metadata sync adapters for curation.
//!
//! Each adapter knows how to fetch and parse a format's upstream package index
//! into a list of CurationPackageEntry records for insertion into curation_packages.

use serde::{Deserialize, Serialize};

/// A parsed package entry from an upstream index.
#[derive(Debug, Clone)]
pub struct CurationPackageEntry {
    pub format: String,
    pub package_name: String,
    pub version: String,
    pub release: Option<String>,
    pub architecture: Option<String>,
    pub checksum_sha256: Option<String>,
    pub upstream_path: String,
    pub metadata: serde_json::Value,
}

/// Parse RPM primary.xml content into package entries.
/// The primary.xml lists all packages in a yum/dnf repository.
pub fn parse_rpm_primary_xml(xml: &str) -> Vec<CurationPackageEntry> {
    // RPM primary.xml structure:
    // <metadata><package type="rpm">
    //   <name>...</name><arch>...</arch>
    //   <version epoch="0" ver="1.0" rel="1.el9"/>
    //   <checksum type="sha256">abc123...</checksum>
    //   <location href="Packages/foo-1.0-1.el9.x86_64.rpm"/>
    //   <description>...</description>
    // </package></metadata>
    let mut entries = Vec::new();

    // Use simple string parsing to avoid adding an XML crate dependency.
    // primary.xml is well-structured and we only need a few fields.
    for pkg_block in xml.split("<package type=\"rpm\">").skip(1) {
        let pkg_block = match pkg_block.split("</package>").next() {
            Some(b) => b,
            None => continue,
        };

        let name = extract_xml_tag(pkg_block, "name").unwrap_or_default();
        let arch = extract_xml_tag(pkg_block, "arch").unwrap_or_default();
        let checksum = extract_xml_tag(pkg_block, "checksum").unwrap_or_default();
        let description = extract_xml_tag(pkg_block, "description").unwrap_or_default();

        // version tag: <version epoch="0" ver="1.0" rel="1.el9"/>
        let (ver, rel) = extract_rpm_version(pkg_block);

        // location tag: <location href="Packages/..."/>
        let href = extract_xml_attr(pkg_block, "location", "href").unwrap_or_default();

        if name.is_empty() || ver.is_empty() {
            continue;
        }

        entries.push(CurationPackageEntry {
            format: "rpm".to_string(),
            package_name: name.clone(),
            version: ver.clone(),
            release: if rel.is_empty() { None } else { Some(rel.clone()) },
            architecture: if arch.is_empty() { None } else { Some(arch.clone()) },
            checksum_sha256: if checksum.is_empty() { None } else { Some(checksum) },
            upstream_path: href,
            metadata: serde_json::json!({
                "name": name,
                "version": ver,
                "release": rel,
                "arch": arch,
                "description": description,
            }),
        });
    }

    entries
}

/// Parse Debian Packages index content into package entries.
/// Each package is a block of key-value lines separated by blank lines.
pub fn parse_deb_packages_index(content: &str, component: &str) -> Vec<CurationPackageEntry> {
    let mut entries = Vec::new();

    for block in content.split("\n\n") {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }

        let mut name = String::new();
        let mut version = String::new();
        let mut arch = String::new();
        let mut sha256 = String::new();
        let mut filename = String::new();
        let mut description = String::new();

        for line in block.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Architecture: ") {
                arch = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("SHA256: ") {
                sha256 = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Filename: ") {
                filename = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Description: ") {
                description = v.trim().to_string();
            }
        }

        if name.is_empty() || version.is_empty() {
            continue;
        }

        entries.push(CurationPackageEntry {
            format: "debian".to_string(),
            package_name: name.clone(),
            version: version.clone(),
            release: None,
            architecture: if arch.is_empty() { None } else { Some(arch.clone()) },
            checksum_sha256: if sha256.is_empty() { None } else { Some(sha256) },
            upstream_path: filename,
            metadata: serde_json::json!({
                "name": name,
                "version": version,
                "arch": arch,
                "component": component,
                "description": description,
            }),
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// XML helpers (minimal, no external dependency)
// ---------------------------------------------------------------------------

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)?;
    let after_open = &xml[start..];
    // Find the > that closes the opening tag
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end = content.find(&close)?;
    Some(content[..end].trim().to_string())
}

fn extract_xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let start = xml.find(&open)?;
    let tag_text = &xml[start..];
    let end = tag_text.find(|c| c == '>' || c == '/')?;
    let tag_content = &tag_text[..end];
    let attr_pattern = format!("{}=\"", attr);
    let attr_start = tag_content.find(&attr_pattern)? + attr_pattern.len();
    let attr_value = &tag_content[attr_start..];
    let attr_end = attr_value.find('"')?;
    Some(attr_value[..attr_end].to_string())
}

fn extract_rpm_version(xml: &str) -> (String, String) {
    let ver = extract_xml_attr(xml, "version", "ver").unwrap_or_default();
    let rel = extract_xml_attr(xml, "version", "rel").unwrap_or_default();
    (ver, rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rpm_primary_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">
<package type="rpm">
  <name>nginx</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.24.0" rel="1.el9"/>
  <checksum type="sha256">abc123def456</checksum>
  <location href="Packages/nginx-1.24.0-1.el9.x86_64.rpm"/>
  <description>A high performance web server</description>
</package>
<package type="rpm">
  <name>curl</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="8.5.0" rel="1.el9"/>
  <checksum type="sha256">def789ghi012</checksum>
  <location href="Packages/curl-8.5.0-1.el9.x86_64.rpm"/>
  <description>A URL transfer utility</description>
</package>
</metadata>"#;

        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].package_name, "nginx");
        assert_eq!(entries[0].version, "1.24.0");
        assert_eq!(entries[0].release.as_deref(), Some("1.el9"));
        assert_eq!(entries[0].architecture.as_deref(), Some("x86_64"));
        assert_eq!(entries[0].checksum_sha256.as_deref(), Some("abc123def456"));
        assert_eq!(entries[0].upstream_path, "Packages/nginx-1.24.0-1.el9.x86_64.rpm");

        assert_eq!(entries[1].package_name, "curl");
        assert_eq!(entries[1].version, "8.5.0");
    }

    #[test]
    fn test_parse_deb_packages_index() {
        let content = r#"Package: nginx
Version: 1.24.0-1
Architecture: amd64
SHA256: abc123def456
Filename: pool/main/n/nginx/nginx_1.24.0-1_amd64.deb
Description: High performance web server

Package: curl
Version: 8.5.0-2ubuntu1
Architecture: amd64
SHA256: def789ghi012
Filename: pool/main/c/curl/curl_8.5.0-2ubuntu1_amd64.deb
Description: Command line URL transfer tool
"#;

        let entries = parse_deb_packages_index(content, "main");
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].package_name, "nginx");
        assert_eq!(entries[0].version, "1.24.0-1");
        assert_eq!(entries[0].architecture.as_deref(), Some("amd64"));
        assert_eq!(entries[0].upstream_path, "pool/main/n/nginx/nginx_1.24.0-1_amd64.deb");

        assert_eq!(entries[1].package_name, "curl");
        assert_eq!(entries[1].version, "8.5.0-2ubuntu1");
    }

    #[test]
    fn test_parse_rpm_skips_incomplete_entries() {
        let xml = r#"<metadata>
<package type="rpm">
  <arch>x86_64</arch>
</package>
</metadata>"#;

        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_deb_skips_incomplete_entries() {
        let content = "Package: incomplete\n\n";
        let entries = parse_deb_packages_index(content, "main");
        assert_eq!(entries.len(), 0);
    }
}
```

**Step 2: Register the module**

Add `pub mod curation_sync;` to `backend/src/services/mod.rs` (after `curation_service`).

**Step 3: Run tests**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib curation_sync`
Expected: all tests pass

**Step 4: Commit**

```bash
git add backend/src/services/curation_sync.rs backend/src/services/mod.rs
git commit -m "feat: add RPM and DEB upstream metadata sync adapters with parsers"
```

---

### Task 7: Background curation sync job

**Files:**
- Modify: `backend/src/services/scheduler_service.rs`

**Step 1: Add curation sync task to scheduler**

Add a new background task block to the `spawn_all` function in `backend/src/services/scheduler_service.rs`, following the existing pattern:

```rust
    // Curation upstream metadata sync (checks every 5 minutes for repos due for sync)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(45)).await;
            let mut ticker = interval(Duration::from_secs(300)); // Check every 5 min

            loop {
                ticker.tick().await;
                tracing::debug!("Checking for curation repos due for upstream sync");

                if let Err(e) = run_curation_sync_cycle(&db).await {
                    tracing::warn!("Curation sync cycle failed: {}", e);
                }
            }
        });
    }
```

Add the sync cycle function at the bottom of the file:

```rust
/// Find all staging repos with curation enabled that are due for a sync,
/// fetch upstream metadata, parse it, and evaluate new packages.
async fn run_curation_sync_cycle(db: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    use crate::services::curation_service::CurationService;
    use crate::services::curation_sync;

    // Find repos due for sync: curation_enabled = true and either never synced
    // or last sync was more than curation_sync_interval_secs ago.
    let repos: Vec<(uuid::Uuid, String, uuid::Uuid, String, String, i32)> = sqlx::query_as(
        r#"SELECT r.id, r.format::text, r.curation_source_repo_id, remote.upstream_url,
                  r.curation_default_action, r.curation_sync_interval_secs
           FROM repositories r
           JOIN repositories remote ON remote.id = r.curation_source_repo_id
           WHERE r.curation_enabled = true
             AND r.curation_source_repo_id IS NOT NULL
             AND r.repo_type = 'staging'
             AND remote.upstream_url IS NOT NULL"#,
    )
    .fetch_all(db)
    .await?;

    let curation = CurationService::new(db.clone());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    for (staging_id, format, remote_id, upstream_url, default_action, _interval) in &repos {
        let entries = match format.as_str() {
            "rpm" => {
                let primary_url = format!("{}/repodata/primary.xml.gz", upstream_url.trim_end_matches('/'));
                match client.get(&primary_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        let bytes = resp.bytes().await?;
                        // Decompress gzip
                        use std::io::Read;
                        let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
                        let mut xml = String::new();
                        decoder.read_to_string(&mut xml)?;
                        curation_sync::parse_rpm_primary_xml(&xml)
                    }
                    Ok(resp) => {
                        tracing::warn!("RPM primary.xml fetch failed: {}", resp.status());
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("RPM primary.xml fetch error: {}", e);
                        continue;
                    }
                }
            }
            "debian" => {
                // Fetch Packages index (try .gz first, fall back to plain)
                let packages_url = format!("{}/Packages.gz", upstream_url.trim_end_matches('/'));
                match client.get(&packages_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        let bytes = resp.bytes().await?;
                        use std::io::Read;
                        let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
                        let mut content = String::new();
                        decoder.read_to_string(&mut content)?;
                        curation_sync::parse_deb_packages_index(&content, "main")
                    }
                    _ => {
                        tracing::warn!("DEB Packages.gz fetch failed for {}", upstream_url);
                        continue;
                    }
                }
            }
            _ => {
                tracing::debug!("Curation sync not yet implemented for format: {}", format);
                continue;
            }
        };

        tracing::info!(
            "Curation sync: {} entries parsed for staging repo {}",
            entries.len(),
            staging_id
        );

        // Upsert entries and evaluate
        for entry in &entries {
            match curation
                .upsert_package(
                    *staging_id,
                    *remote_id,
                    &entry.format,
                    &entry.package_name,
                    &entry.version,
                    entry.release.as_deref(),
                    entry.architecture.as_deref(),
                    entry.checksum_sha256.as_deref(),
                    &entry.upstream_path,
                    &entry.metadata,
                )
                .await
            {
                Ok(pkg) if pkg.status == "pending" => {
                    // Evaluate newly inserted packages
                    let eval = curation
                        .evaluate_package(
                            *staging_id,
                            default_action,
                            &entry.package_name,
                            &entry.version,
                            entry.architecture.as_deref(),
                        )
                        .await;

                    if let Ok(eval) = eval {
                        let status = match eval.action.as_str() {
                            "allow" => "approved",
                            "block" => "blocked",
                            _ => "review",
                        };
                        let _ = curation
                            .set_package_status(pkg.id, status, &eval.reason, None, eval.rule_id)
                            .await;
                    }
                }
                Ok(_) => {} // Already processed (upsert hit existing row)
                Err(e) => {
                    tracing::warn!("Failed to upsert curation package {}: {}", entry.package_name, e);
                }
            }
        }
    }

    Ok(())
}
```

**Step 2: Verify it compiles**

Run: `cd /Users/khan/ak/artifact-keeper && cargo check --workspace`
Expected: compiles (may need to add `flate2` and `reqwest` to Cargo.toml if not already present)

**Step 3: Commit**

```bash
git add backend/src/services/scheduler_service.rs
git commit -m "feat: add background curation sync job for RPM and DEB upstream metadata"
```

---

### Task 8: E2E test infrastructure

**Files:**
- Create: `scripts/curation-e2e/docker-compose.yml`
- Create: `scripts/curation-e2e/mock-rpm-repo/` (nginx config + test RPMs)
- Create: `scripts/curation-e2e/mock-deb-repo/` (nginx config + test DEBs)
- Create: `scripts/curation-e2e/run-tests.sh`

**Step 1: Create mock RPM repo**

Build test RPM packages using fpm (or use pre-built static fixtures). Set up an nginx container that serves them with a valid repomd.xml and primary.xml.gz.

**Step 2: Create mock DEB repo**

Build test DEB packages using fpm. Set up an nginx container serving them with valid Release and Packages files.

**Step 3: Create Docker Compose file**

Compose file with: mock-rpm-repo, mock-deb-repo, postgres, artifact-keeper backend, rpm-client (rocky linux), deb-client (ubuntu).

**Step 4: Write the test script**

`run-tests.sh` should:
1. Start the compose stack
2. Create remote repos pointing at the mock upstreams
3. Create staging repos with `curation_enabled=true`
4. Create local and virtual repos
5. Trigger sync and verify packages appear in curation catalog
6. Test approval/blocking via API
7. Verify yum/apt behavior on the client containers
8. Tear down

**Step 5: Commit**

```bash
git add scripts/curation-e2e/
git commit -m "test: add E2E test infrastructure for package curation"
```

---

### Task 9: Wire SQLx offline cache and verify full test suite

**Files:**
- Modify: `.sqlx/` (offline query cache)

**Step 1: Regenerate SQLx offline cache**

Run: `cd /Users/khan/ak/artifact-keeper && cargo sqlx prepare --workspace`

**Step 2: Run full unit test suite**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib`
Expected: all tests pass (6380+ existing + new curation tests)

**Step 3: Run clippy**

Run: `cd /Users/khan/ak/artifact-keeper && cargo clippy --workspace`
Expected: no errors

**Step 4: Run fmt check**

Run: `cd /Users/khan/ak/artifact-keeper && cargo fmt --check`
Expected: no formatting issues

**Step 5: Commit any remaining changes**

```bash
git add .sqlx/
git commit -m "chore: update SQLx offline cache for curation queries"
```

---

### Summary

| Task | What | Tests |
|------|------|-------|
| 1 | Migration: `curation_rules`, `curation_packages`, repo columns | Migration applies cleanly |
| 2 | Models: `CurationRule`, `CurationPackage`, repo fields | Compiles |
| 3 | CurationService: glob matching, version constraints, rule evaluation | 15 unit tests |
| 4 | CurationService: CRUD for rules and packages, re-evaluation | Compiles |
| 5 | Curation API handler: REST endpoints, DTOs, OpenAPI | Compiles, OpenAPI valid |
| 6 | Sync adapters: RPM primary.xml parser, DEB Packages parser | 4 unit tests |
| 7 | Background sync job: scheduler integration | Compiles |
| 8 | E2E tests: mock repos, Docker Compose, yum/apt client tests | 22 E2E scenarios |
| 9 | SQLx offline cache, full CI verification | Full suite passes |
