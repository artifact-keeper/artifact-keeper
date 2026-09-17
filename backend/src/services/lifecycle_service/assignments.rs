//! Explicit scope persistence. NULL in the legacy column is never a scope.

use super::*;

#[cfg(test)]
mod assignment_tests;

macro_rules! policy_select {
    ($suffix:literal) => {
        concat!(
            r#"
SELECT p.id, p.repository_id, p.applies_to_all,
       ARRAY(SELECT pr.repository_id FROM lifecycle_policy_repositories pr
             WHERE pr.policy_id = p.id ORDER BY pr.repository_id) AS repository_ids,
       p.name, p.description, p.enabled, p.policy_type, p.config, p.priority,
       p.last_run_at, p.last_run_items_removed, p.cron_schedule, p.created_at, p.updated_at
FROM lifecycle_policies p
"#,
            $suffix
        )
    };
}

pub(super) fn present_value<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn normalize_scope(applies_to_all: bool, mut repository_ids: Vec<Uuid>) -> Result<Vec<Uuid>> {
    if applies_to_all && !repository_ids.is_empty() {
        return Err(AppError::UnprocessableEntity(
            "Global policies cannot have explicit repository_ids".into(),
        ));
    }
    repository_ids.sort_unstable();
    repository_ids.dedup();
    Ok(repository_ids)
}

impl CreateLifecyclePolicyRequest {
    fn assigned_repositories(&self) -> Result<Vec<Uuid>> {
        if self.repository_id.is_some() && self.repository_ids.is_some() {
            return Err(AppError::UnprocessableEntity(
                "Use repository_ids or legacy repository_id, not both".into(),
            ));
        }
        normalize_scope(
            self.applies_to_all,
            self.repository_ids
                .clone()
                .unwrap_or_else(|| self.repository_id.into_iter().collect()),
        )
    }
}

fn validate_schedule(schedule: Option<&str>) -> Result<()> {
    if let Some(expression) = schedule {
        if cron::Schedule::from_str(&normalize_cron_expression(expression)).is_err() {
            return Err(AppError::Validation(format!(
                "Invalid cron expression: '{expression}'"
            )));
        }
    }
    Ok(())
}

impl LifecycleService {
    async fn policy_on(conn: &mut sqlx::PgConnection, id: Uuid) -> Result<LifecyclePolicy> {
        sqlx::query_as(policy_select!(" WHERE p.id = $1"))
            .bind(id)
            .fetch_optional(conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Lifecycle policy not found".into()))
    }

    async fn lock_policy(conn: &mut sqlx::PgConnection, id: Uuid) -> Result<LifecyclePolicy> {
        // Read the projection in a second statement AFTER obtaining the lock;
        // a waiter must not reuse a pre-lock snapshot of the assignment rows.
        let exists = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM lifecycle_policies WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if exists.is_none() {
            return Err(AppError::NotFound("Lifecycle policy not found".into()));
        }
        Self::policy_on(conn, id).await
    }

    async fn lock_repositories(conn: &mut sqlx::PgConnection, ids: &[Uuid]) -> Result<Vec<Uuid>> {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM repositories WHERE id = ANY($1) ORDER BY id FOR KEY SHARE",
        )
        .bind(ids)
        .fetch_all(conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    fn require_repositories(ids: &[Uuid], found: &[Uuid]) -> Result<()> {
        if let Some(missing) = ids.iter().find(|id| !found.contains(id)) {
            return Err(AppError::NotFound(format!(
                "Repository {missing} not found"
            )));
        }
        Ok(())
    }

    async fn assignment_transaction(
        &self,
        id: Uuid,
        required: &[Uuid],
    ) -> Result<(sqlx::Transaction<'_, sqlx::Postgres>, LifecyclePolicy)> {
        for _ in 0..3 {
            let mut tx = self
                .db
                .begin()
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            let snapshot = Self::policy_on(&mut tx, id).await?;
            let mut repositories = snapshot.repository_ids;
            repositories.extend_from_slice(required);
            let repositories = normalize_scope(false, repositories)?;
            // Match repository deletion's lock order, including removed members.
            let locked = Self::lock_repositories(&mut tx, &repositories).await?;
            Self::require_repositories(required, &locked)?;
            let policy = Self::lock_policy(&mut tx, id).await?;
            if policy.repository_ids.iter().all(|id| locked.contains(id)) {
                return Ok((tx, policy));
            }
            // A concurrent attach changed our snapshot. Do not acquire its
            // repository lock after the policy lock: that can deadlock deletion.
            tx.rollback()
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        }
        Err(AppError::Conflict(
            "Lifecycle assignments changed concurrently; retry the request".into(),
        ))
    }

    async fn replace_assignments(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
        ids: &[Uuid],
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM lifecycle_policy_repositories WHERE policy_id = $1 \
             AND NOT (repository_id = ANY($2))",
        )
        .bind(id)
        .bind(ids)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        sqlx::query(
            "INSERT INTO lifecycle_policy_repositories (policy_id, repository_id) \
             SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(ids)
        .execute(conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn create_policy(
        &self,
        req: CreateLifecyclePolicyRequest,
    ) -> Result<LifecyclePolicy> {
        PolicyType::parse(&req.policy_type).map_err(|_| {
            AppError::Validation(format!("Invalid policy_type '{}'", req.policy_type))
        })?;
        let ids = req.assigned_repositories()?;
        self.validate_policy_config(&req.policy_type, &req.config)?;
        validate_schedule(req.cron_schedule.as_deref())?;

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let found = Self::lock_repositories(&mut tx, &ids).await?;
        Self::require_repositories(&ids, &found)?;
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO lifecycle_policies \
             (applies_to_all, name, description, policy_type, config, priority, cron_schedule) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(req.applies_to_all)
        .bind(req.name)
        .bind(req.description)
        .bind(req.policy_type)
        .bind(req.config)
        .bind(req.priority.unwrap_or(0))
        .bind(req.cron_schedule)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Self::replace_assignments(&mut tx, id, &ids).await?;
        let policy = Self::policy_on(&mut tx, id).await?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(policy)
    }

    /// List all policies, or effective global and assigned policies for a repository.
    pub async fn list_policies(&self, repository_id: Option<Uuid>) -> Result<Vec<LifecyclePolicy>> {
        sqlx::query_as(policy_select!(
            " WHERE ($1::uuid IS NULL OR p.applies_to_all OR EXISTS \
             (SELECT 1 FROM lifecycle_policy_repositories pr \
              WHERE pr.policy_id = p.id AND pr.repository_id = $1)) \
             ORDER BY p.priority DESC, p.created_at ASC"
        ))
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    pub async fn get_policy(&self, id: Uuid) -> Result<LifecyclePolicy> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Self::policy_on(&mut conn, id).await
    }

    pub async fn update_policy(
        &self,
        id: Uuid,
        req: UpdateLifecyclePolicyRequest,
    ) -> Result<LifecyclePolicy> {
        let (mut tx, existing) = self
            .assignment_transaction(id, req.repository_ids.as_deref().unwrap_or_default())
            .await?;
        let applies_to_all = req.applies_to_all.unwrap_or(existing.applies_to_all);
        let ids = normalize_scope(
            applies_to_all,
            req.repository_ids.unwrap_or(existing.repository_ids),
        )?;
        let config = req.config.unwrap_or(existing.config);
        self.validate_policy_config(&existing.policy_type, &config)?;
        let schedule = req.cron_schedule.or(existing.cron_schedule);
        validate_schedule(schedule.as_deref())?;
        sqlx::query(
            "UPDATE lifecycle_policies SET name = $2, description = $3, enabled = $4, \
             config = $5, priority = $6, cron_schedule = $7, applies_to_all = $8, \
             updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(req.name.unwrap_or(existing.name))
        .bind(req.description.or(existing.description))
        .bind(req.enabled.unwrap_or(existing.enabled))
        .bind(config)
        .bind(req.priority.unwrap_or(existing.priority))
        .bind(schedule)
        .bind(applies_to_all)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Self::replace_assignments(&mut tx, id, &ids).await?;
        let policy = Self::policy_on(&mut tx, id).await?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(policy)
    }

    /// Incremental, idempotent mutation serialized with scope replacement.
    pub async fn set_repository_assignment(
        &self,
        id: Uuid,
        repository_id: Uuid,
        attached: bool,
    ) -> Result<LifecyclePolicy> {
        let (mut tx, policy) = self.assignment_transaction(id, &[repository_id]).await?;
        if policy.applies_to_all {
            return Err(AppError::UnprocessableEntity(
                "Global policies cannot be attached to or detached from individual repositories"
                    .into(),
            ));
        }
        let mut ids = policy.repository_ids;
        if attached {
            ids.push(repository_id);
        } else {
            ids.retain(|id| *id != repository_id);
        }
        let ids = normalize_scope(false, ids)?;
        Self::replace_assignments(&mut tx, id, &ids).await?;
        let policy = Self::policy_on(&mut tx, id).await?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(policy)
    }

    pub async fn delete_policy(&self, id: Uuid) -> Result<()> {
        let (mut tx, _) = self.assignment_transaction(id, &[]).await?;
        sqlx::query("DELETE FROM lifecycle_policies WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    pub(super) async fn load_enabled_policies(&self) -> Result<Vec<LifecyclePolicy>> {
        sqlx::query_as(policy_select!(
            " WHERE p.enabled AND (p.applies_to_all OR EXISTS \
             (SELECT 1 FROM lifecycle_policy_repositories pr WHERE pr.policy_id = p.id)) \
             ORDER BY p.priority DESC, p.created_at ASC"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    pub(super) async fn resolve_repositories(&self, policy: &LifecyclePolicy) -> Result<Vec<Uuid>> {
        if !policy.applies_to_all {
            return Ok(policy.repository_ids.clone());
        }
        sqlx::query_scalar("SELECT id FROM repositories ORDER BY id")
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))
    }
}
