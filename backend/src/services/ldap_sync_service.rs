//! Periodic LDAP directory reconcile (#3830).
//!
//! Before this, a federated LDAP user's standing was re-evaluated only when
//! they logged in: removing someone from an AD group, or deleting them from
//! the directory, left their API tokens and sessions working indefinitely,
//! and the documented `LDAP_SYNC_INTERVAL` was never read. This job runs every
//! `LDAP_SYNC_INTERVAL` seconds (default 3600, `0` disables) and re-reads each
//! active LDAP user's entry with the service account of the provider they
//! authenticated through (`users.ldap_provider_id`, recorded at login):
//!
//! - **present** (an entry at the stored DN): their LDAP-managed group
//!   memberships are re-synced through the same reconciler login uses, and --
//!   for users whose provider is recorded -- `is_admin` is recomputed from
//!   the provider's `admin_group_dn` exactly as login computes it. Demotions
//!   revoke tokens, are capped like deactivations, and never remove the last
//!   active admin. Local and other non-LDAP accounts are never touched.
//! - **moved** (nothing at the stored DN, but the username matches another
//!   entry): kept active, but nothing is re-synced from that entry -- it may
//!   be a different person who reused the username, and login identifies
//!   users by DN.
//! - **gone** (the directory answered: the entry no longer matches the
//!   provider's `user_filter`, or it is not at its DN *and* a username search
//!   finds it nowhere else): deactivated with every credential revoked -- but
//!   only when `LDAP_SYNC_DEACTIVATE=true`. By default a gone user is only
//!   reported, so upgrading cannot lock anyone out unannounced.
//!
//! Fail-safe rules:
//! - a directory that cannot be asked (connect, bind, search error, timeout,
//!   referral, ambiguous match) makes the user *unknown*, never gone;
//! - a user with no recorded provider (not logged in since the upgrade) is
//!   gone only when **every** enabled provider whose base covers their DN says
//!   so -- two providers can share a base and differ only in `user_filter`;
//! - a pass that would deactivate more than `LDAP_SYNC_MAX_DEACTIVATE`
//!   (default 25) users of one provider, or more than
//!   `LDAP_SYNC_MAX_DEACTIVATE_PERCENT` (default 10) percent of them (when
//!   more than one), deactivates nobody of that provider and logs ERROR;
//! - one replica runs a pass at a time (session `pg_try_advisory_lock` on a
//!   dedicated connection), each
//!   directory operation is bounded by [`OP_TIMEOUT`] and the pass by
//!   [`PASS_TIMEOUT`], and one bound connection per provider is reused for
//!   the whole pass.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::user::AuthProvider;
use crate::services::auth_config_service::AuthConfigService;
use crate::services::auth_service::{
    invalidate_user_token_cache_entries, invalidate_user_tokens, AuthService,
};
use crate::services::ldap_service::{DnLookup, LdapService, LdapUserInfo};

/// Environment variable carrying the reconcile interval in seconds.
pub const LDAP_SYNC_INTERVAL_ENV: &str = "LDAP_SYNC_INTERVAL";
/// Opt-in for deactivating users the directory no longer has.
pub const LDAP_SYNC_DEACTIVATE_ENV: &str = "LDAP_SYNC_DEACTIVATE";
/// Per-provider cap on deactivations in one pass, as a percentage.
pub const LDAP_SYNC_MAX_DEACTIVATE_PERCENT_ENV: &str = "LDAP_SYNC_MAX_DEACTIVATE_PERCENT";
/// Per-provider cap on deactivations in one pass, as a count.
pub const LDAP_SYNC_MAX_DEACTIVATE_ENV: &str = "LDAP_SYNC_MAX_DEACTIVATE";
/// Documented default interval.
pub const DEFAULT_LDAP_SYNC_INTERVAL_SECS: u64 = 3600;
/// Floor, so a typo cannot turn the job into a directory hammer.
pub const MIN_LDAP_SYNC_INTERVAL_SECS: u64 = 60;
/// Default for [`LDAP_SYNC_MAX_DEACTIVATE_PERCENT_ENV`].
pub const DEFAULT_MAX_DEACTIVATE_PERCENT: u64 = 10;
/// Default for [`LDAP_SYNC_MAX_DEACTIVATE_ENV`].
pub const DEFAULT_MAX_DEACTIVATE: usize = 25;
/// Bound on any single directory operation (connect+bind, one search).
pub const OP_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on a whole pass.
pub const PASS_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Cluster-wide advisory lock key for a reconcile pass ("LDAPSYNC").
const LDAP_SYNC_LOCK_ID: i64 = 0x4c44_4150_5359_4e43;

/// Parse `LDAP_SYNC_INTERVAL`: unset/empty or unparsable -> the default,
/// `0` -> disabled (`None`), anything else clamped to the floor.
pub fn parse_sync_interval(raw: Option<&str>) -> Option<Duration> {
    let secs = parse_or(raw, DEFAULT_LDAP_SYNC_INTERVAL_SECS, LDAP_SYNC_INTERVAL_ENV);
    if secs == 0 {
        return None;
    }
    Some(Duration::from_secs(secs.max(MIN_LDAP_SYNC_INTERVAL_SECS)))
}

/// The interval from the process environment.
pub fn sync_interval_from_env() -> Option<Duration> {
    parse_sync_interval(std::env::var(LDAP_SYNC_INTERVAL_ENV).ok().as_deref())
}

fn parse_or(raw: Option<&str>, default: u64, var: &str) -> u64 {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => default,
        Some(v) => v.parse::<u64>().unwrap_or_else(|_| {
            tracing::warn!(
                "{var}='{v}' is not a non-negative integer; using the default {default}"
            );
            default
        }),
    }
}

/// What a pass may do besides re-syncing groups and admin status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapSyncSettings {
    /// Deactivate users the directory no longer has (default false).
    pub deactivate: bool,
    pub max_deactivate_percent: u64,
    pub max_deactivate: usize,
}

impl Default for LdapSyncSettings {
    fn default() -> Self {
        LdapSyncSettings {
            deactivate: false,
            max_deactivate_percent: DEFAULT_MAX_DEACTIVATE_PERCENT,
            max_deactivate: DEFAULT_MAX_DEACTIVATE,
        }
    }
}

/// Parse the settings from raw variable values.
pub fn parse_settings(
    deactivate: Option<&str>,
    max_percent: Option<&str>,
    max_count: Option<&str>,
) -> LdapSyncSettings {
    LdapSyncSettings {
        deactivate: matches!(
            deactivate.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
            Some("true" | "1" | "yes")
        ),
        max_deactivate_percent: parse_or(
            max_percent,
            DEFAULT_MAX_DEACTIVATE_PERCENT,
            LDAP_SYNC_MAX_DEACTIVATE_PERCENT_ENV,
        ),
        max_deactivate: parse_or(
            max_count,
            DEFAULT_MAX_DEACTIVATE as u64,
            LDAP_SYNC_MAX_DEACTIVATE_ENV,
        ) as usize,
    }
}

/// The settings from the process environment.
pub fn settings_from_env() -> LdapSyncSettings {
    let var = |name: &str| std::env::var(name).ok();
    parse_settings(
        var(LDAP_SYNC_DEACTIVATE_ENV).as_deref(),
        var(LDAP_SYNC_MAX_DEACTIVATE_PERCENT_ENV).as_deref(),
        var(LDAP_SYNC_MAX_DEACTIVATE_ENV).as_deref(),
    )
}

/// Whether deactivating `gone` of a provider's `total` checked users in one
/// pass stays under the caps. A single deactivation is always within the
/// percentage cap so small directories can still offboard one person.
pub fn deactivation_allowed(gone: usize, total: usize, s: &LdapSyncSettings) -> bool {
    if gone == 0 {
        return true;
    }
    if gone > s.max_deactivate {
        return false;
    }
    !(gone > 1 && (gone as u64) * 100 > s.max_deactivate_percent * total as u64)
}

/// An active local LDAP user, as the reconcile sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapUserRef {
    pub id: Uuid,
    pub username: String,
    /// The directory DN recorded at login (`users.external_id`).
    pub dn: String,
    /// The provider recorded at login (`users.ldap_provider_id`).
    pub provider_id: Option<Uuid>,
    pub is_admin: bool,
}

/// What one provider's directory said about one user.
#[derive(Debug, Clone)]
pub enum Standing {
    /// An entry at the stored DN that matches the provider's filter.
    Present(LdapUserInfo),
    /// Nothing at the stored DN, but the username matches an entry elsewhere.
    /// That may be the same person after an OU move -- or a different person
    /// who reused the username. It keeps the account from being deactivated
    /// and drives nothing else: login identifies users by DN, so the other
    /// entry's groups and admin membership are never applied (#3830 review).
    Moved,
    Gone,
    /// The directory could not be asked. Never acted on.
    Unknown,
}

/// Combined verdict over every provider asked about a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Present according to the provider at this index of the input.
    Present(usize),
    /// Only a username match at a different DN: neither re-synced nor gone.
    Moved,
    Unknown,
    Gone,
}

/// Present if any provider found the user; otherwise unknown if any could
/// not be asked; gone only when every provider asked (at least one) says so.
pub fn combine_standings(standings: &[Standing]) -> Verdict {
    if let Some(i) = standings
        .iter()
        .position(|s| matches!(s, Standing::Present(_)))
    {
        return Verdict::Present(i);
    }
    if standings.iter().any(|s| matches!(s, Standing::Moved)) {
        return Verdict::Moved;
    }
    if standings.is_empty() || standings.iter().any(|s| matches!(s, Standing::Unknown)) {
        return Verdict::Unknown;
    }
    Verdict::Gone
}

/// The providers (indexes into `provider_bases`) to ask about `user`: the
/// recorded one when it is still enabled (none when it is not), otherwise
/// every provider whose user base covers the DN.
pub fn candidate_providers(provider_bases: &[(Uuid, String)], user: &LdapUserRef) -> Vec<usize> {
    match user.provider_id {
        Some(pid) => provider_bases
            .iter()
            .position(|(id, _)| *id == pid)
            .into_iter()
            .collect(),
        None => provider_bases
            .iter()
            .enumerate()
            .filter(|(_, (_, base))| LdapService::dn_under_base(&user.dn, base))
            .map(|(i, _)| i)
            .collect(),
    }
}

/// Totals for one reconcile pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapSyncReport {
    /// Another replica held the pass lock; nothing was done.
    pub skipped_locked: bool,
    pub checked: usize,
    pub present: usize,
    /// Users found only by username at a different DN.
    pub moved: usize,
    pub unknown: usize,
    pub gone: usize,
    pub deactivated: usize,
    /// Gone users left active because `LDAP_SYNC_DEACTIVATE` is off.
    pub would_deactivate: usize,
    /// Providers whose deactivations the caps refused.
    pub refused_providers: usize,
    pub groups_resynced: usize,
    pub promoted: usize,
    pub demoted: usize,
    /// Providers whose admin demotions a cap or the last-admin guard refused.
    pub refused_demotions: usize,
    /// Providers whose membership removals the cap refused.
    pub refused_group_removals: usize,
}

/// Record the provider a user authenticated through (called at LDAP login).
pub async fn record_ldap_provider(db: &PgPool, user_id: Uuid, provider_id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE users SET ldap_provider_id = $1 \
         WHERE id = $2 AND auth_provider = 'ldap' \
           AND ldap_provider_id IS DISTINCT FROM $1",
    )
    .bind(provider_id)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

async fn active_ldap_users(db: &PgPool) -> Result<Vec<LdapUserRef>> {
    let rows: Vec<(Uuid, String, String, Option<Uuid>, bool)> = sqlx::query_as(
        r#"
        SELECT id, username, external_id, ldap_provider_id, is_admin
        FROM users
        WHERE auth_provider = 'ldap' AND is_active = true AND external_id IS NOT NULL
        ORDER BY username
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(rows
        .into_iter()
        .map(|(id, username, dn, provider_id, is_admin)| LdapUserRef {
            id,
            username,
            dn,
            provider_id,
            is_admin,
        })
        .collect())
}

/// Demote an LDAP admin, revoking their tokens in the same step: before the
/// write (so nothing issued from here on outlives it) and after it (so a
/// cache refilled in between is dropped). Returns whether it changed.
async fn demote_ldap_admin(db: &PgPool, user_id: Uuid) -> Result<bool> {
    invalidate_user_token_cache_entries(user_id);
    invalidate_user_tokens(user_id);
    let changed = set_ldap_admin(db, user_id, false).await?;
    invalidate_user_token_cache_entries(user_id);
    invalidate_user_tokens(user_id);
    Ok(changed)
}

/// The LDAP-managed groups (of this provider) the user is a member of now.
async fn managed_group_names(db: &PgPool, user_id: Uuid, provider_id: Uuid) -> Result<Vec<String>> {
    sqlx::query_scalar(
        "SELECT g.name FROM user_group_members m JOIN groups g ON g.id = m.group_id \
         WHERE m.user_id = $1 AND g.external_source = 'ldap' AND g.external_provider_id = $2",
    )
    .bind(user_id)
    .bind(provider_id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

async fn apply_group_sync(
    db: &PgPool,
    user_id: Uuid,
    provider_id: Uuid,
    names: &[String],
    report: &mut LdapSyncReport,
) {
    match crate::api::handlers::sso::sync_federated_groups_to_local_groups(
        db,
        user_id,
        provider_id,
        "ldap",
        names,
    )
    .await
    {
        Ok(()) => report.groups_resynced += 1,
        Err(e) => {
            tracing::warn!(user_id = %user_id, error = %e, "LDAP reconcile: group re-sync failed")
        }
    }
}

async fn active_admin_count(db: &PgPool) -> Result<usize> {
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = true AND is_active = true")
            .fetch_one(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(n.max(0) as usize)
}

/// Set an LDAP user's `is_admin`; returns whether it changed.
async fn set_ldap_admin(db: &PgPool, user_id: Uuid, is_admin: bool) -> Result<bool> {
    let changed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE users SET is_admin = $1, updated_at = NOW() \
         WHERE id = $2 AND auth_provider = 'ldap' AND is_active = true AND is_admin <> $1 \
         RETURNING id",
    )
    .bind(is_admin)
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(changed.is_some())
}

async fn with_timeout<T>(op: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(OP_TIMEOUT, op)
        .await
        .unwrap_or_else(|_| Err(AppError::Internal("LDAP operation timed out".into())))
}

/// Open the provider's service connection on first use.
async fn ensure_session<'a>(
    svc: &LdapService,
    slot: &'a mut Option<ldap3::Ldap>,
) -> Result<&'a mut ldap3::Ldap> {
    if slot.is_none() {
        *slot = Some(with_timeout(svc.service_session()).await?);
    }
    Ok(slot.as_mut().expect("session just opened"))
}

/// Per-provider outcome of a pass, acted on after every user is checked.
#[derive(Default)]
struct Tally {
    total: usize,
    gone: Vec<LdapUserRef>,
    demote: Vec<LdapUserRef>,
}

/// One enabled provider for the duration of a pass.
struct ProviderCtx {
    id: Uuid,
    name: String,
    admin_group_dn: Option<String>,
    /// `None` when the provider has no usable service account.
    svc: Option<LdapService>,
    session: Option<ldap3::Ldap>,
}

impl ProviderCtx {
    /// Ask this provider's directory about `user`.
    async fn check(&mut self, user: &LdapUserRef) -> Standing {
        let Some(svc) = &self.svc else {
            return Standing::Unknown;
        };
        let session = &mut self.session;
        let name = &self.name;
        let outcome: Result<Standing> = async move {
            let ldap = ensure_session(svc, session).await?;
            match with_timeout(svc.lookup_dn_on(ldap, &user.dn, &user.username)).await? {
                DnLookup::Found(info) => Ok(Standing::Present(info)),
                DnLookup::FilteredOut => Ok(Standing::Gone),
                // Not at its DN: moved (OU reorg) or deleted. Only a username
                // search that also finds nothing makes it gone.
                DnLookup::NoSuchObject => {
                    match with_timeout(svc.find_username_on(ldap, &user.username)).await? {
                        Some(info) => {
                            tracing::warn!(
                                user_id = %user.id,
                                stored_dn = %user.dn,
                                found_dn = %info.dn,
                                provider = %name,
                                "LDAP reconcile: no entry at the user's DN, but the username \
                                 matches a different entry (moved, or a reused username); not \
                                 deactivating, and not re-syncing groups or admin from it"
                            );
                            Ok(Standing::Moved)
                        }
                        None => Ok(Standing::Gone),
                    }
                }
            }
        }
        .await;
        match outcome {
            Ok(standing) => standing,
            Err(e) => {
                tracing::warn!(
                    user_id = %user.id,
                    provider = %self.name,
                    error = %e,
                    "LDAP reconcile: directory lookup failed; user left unchanged"
                );
                // The connection may be wedged; reopen on the next user.
                self.session = None;
                Standing::Unknown
            }
        }
    }

    /// Re-sync a present user's LDAP group memberships from this provider.
    ///
    /// A re-sync that only adds memberships is applied at once. One that
    /// would remove any LDAP-managed membership is returned instead, so the
    /// caller can cap removals per provider before applying them (an entry
    /// read with an empty memberOf must not prune everyone in one pass).
    async fn resync(
        &mut self,
        db: &PgPool,
        user: &LdapUserRef,
        info: &LdapUserInfo,
        report: &mut LdapSyncReport,
    ) -> Option<Vec<String>> {
        let Some(svc) = &self.svc else {
            return None;
        };

        if svc.group_sync_configured() {
            let session = &mut self.session;
            let names: Result<Vec<String>> = async move {
                let ldap = ensure_session(svc, session).await?;
                with_timeout(svc.resolve_group_names_on(
                    ldap,
                    &info.dn,
                    &info.username,
                    &info.groups,
                ))
                .await
            }
            .await;
            match names {
                Ok(names) => match managed_group_names(db, user.id, self.id).await {
                    Ok(current) if current.iter().any(|g| !names.contains(g)) => {
                        return Some(names);
                    }
                    Ok(_) => apply_group_sync(db, user.id, self.id, &names, report).await,
                    Err(e) => tracing::warn!(
                        user_id = %user.id,
                        error = %e,
                        "LDAP reconcile: cannot read current memberships; left unchanged"
                    ),
                },
                Err(e) => {
                    // Skip rather than prune on a partial answer.
                    tracing::warn!(
                        user_id = %user.id,
                        provider = %self.name,
                        error = %e,
                        "LDAP reconcile: group search failed; memberships left unchanged"
                    );
                    self.session = None;
                }
            }
        }
        None
    }

    /// The `is_admin` login would compute from this entry (`map_groups_to_roles`
    /// over its memberOf), or `None` when no admin group is configured.
    fn desired_admin(&self, info: &LdapUserInfo) -> Option<bool> {
        let admin_group = self.admin_group_dn.as_deref()?;
        AuthService::map_groups_to_roles(&info.groups, Some(admin_group)).is_admin
    }

    async fn close(&mut self) {
        if let Some(mut ldap) = self.session.take() {
            let _ = tokio::time::timeout(OP_TIMEOUT, ldap.unbind()).await;
        }
    }
}

/// One reconcile pass over every enabled LDAP provider (#3830). Returns
/// `skipped_locked` when another replica is running one.
pub async fn run_ldap_sync(
    db: &PgPool,
    auth: &AuthService,
    settings: &LdapSyncSettings,
) -> Result<LdapSyncReport> {
    // Session-level lock on a dedicated connection taken out of the pool:
    // no transaction sits idle for the length of the pass, and if this task
    // dies the connection closes and Postgres releases the lock.
    use sqlx::Connection;
    let mut lock_conn = db
        .acquire()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .detach();
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(LDAP_SYNC_LOCK_ID)
        .fetch_one(&mut lock_conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if !locked {
        let _ = lock_conn.close().await;
        tracing::debug!("LDAP reconcile pass already running on another replica; skipping");
        return Ok(LdapSyncReport {
            skipped_locked: true,
            ..Default::default()
        });
    }

    let result = tokio::time::timeout(PASS_TIMEOUT, run_pass(db, auth, settings))
        .await
        .unwrap_or_else(|_| {
            Err(AppError::Internal(
                "LDAP directory reconcile pass timed out".into(),
            ))
        });
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LDAP_SYNC_LOCK_ID)
        .execute(&mut lock_conn)
        .await;
    let _ = lock_conn.close().await;

    if let Ok(r) = &result {
        tracing::info!(
            checked = r.checked,
            present = r.present,
            moved = r.moved,
            unknown = r.unknown,
            gone = r.gone,
            deactivated = r.deactivated,
            would_deactivate = r.would_deactivate,
            refused_providers = r.refused_providers,
            groups_resynced = r.groups_resynced,
            promoted = r.promoted,
            demoted = r.demoted,
            refused_demotions = r.refused_demotions,
            refused_group_removals = r.refused_group_removals,
            "LDAP directory reconcile pass finished"
        );
    }
    result
}

async fn run_pass(
    db: &PgPool,
    auth: &AuthService,
    settings: &LdapSyncSettings,
) -> Result<LdapSyncReport> {
    let mut report = LdapSyncReport::default();

    let mut providers = AuthConfigService::list_ldap(db).await?;
    providers.retain(|p| p.is_enabled);
    providers.sort_by_key(|p| p.priority);
    if providers.is_empty() {
        return Ok(report);
    }

    let bases: Vec<(Uuid, String)> = providers
        .iter()
        .map(|p| (p.id, p.user_base_dn.clone()))
        .collect();
    let mut ctxs = Vec::with_capacity(providers.len());
    for p in &providers {
        let svc = match AuthConfigService::get_ldap_decrypted(db, p.id).await {
            Ok((row, Some(pw))) if row.bind_dn.is_some() => Some(
                AuthConfigService::ldap_service_from_row(db.clone(), &row, Some(&pw)),
            ),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(provider = %p.name, error = %e, "LDAP reconcile: cannot load provider");
                None
            }
        };
        ctxs.push(ProviderCtx {
            id: p.id,
            name: p.name.clone(),
            admin_group_dn: p.admin_group_dn.clone(),
            svc,
            session: None,
        });
    }

    // Per attributed provider: users checked, found gone, and admins whose
    // admin-group membership is gone.
    let mut tally: BTreeMap<usize, Tally> = BTreeMap::new();
    // Per providing ctx: re-syncs that would remove memberships.
    let mut shrinks: BTreeMap<usize, Vec<(Uuid, Vec<String>)>> = BTreeMap::new();

    for user in active_ldap_users(db).await? {
        let candidates = candidate_providers(&bases, &user);
        let Some(&attributed) = candidates.first() else {
            continue;
        };
        report.checked += 1;

        let mut standings = Vec::with_capacity(candidates.len());
        for &i in &candidates {
            let standing = ctxs[i].check(&user).await;
            let present = matches!(standing, Standing::Present(_));
            standings.push(standing);
            if present {
                break;
            }
        }

        let entry = tally.entry(attributed).or_default();
        entry.total += 1;
        match combine_standings(&standings) {
            Verdict::Present(k) => {
                report.present += 1;
                let Standing::Present(info) = &standings[k] else {
                    continue;
                };
                let ctx = &mut ctxs[candidates[k]];
                if let Some(names) = ctx.resync(db, &user, info, &mut report).await {
                    shrinks
                        .entry(candidates[k])
                        .or_default()
                        .push((user.id, names));
                }
                // Admin is recomputed only against the provider the user
                // logged in through; an unrecorded user keeps is_admin.
                if user.provider_id != Some(ctx.id) {
                    continue;
                }
                match ctx.desired_admin(info) {
                    Some(true) if !user.is_admin => match set_ldap_admin(db, user.id, true).await {
                        Ok(true) => {
                            report.promoted += 1;
                            tracing::info!(user_id = %user.id, provider = %ctx.name, "LDAP reconcile: user granted admin via the admin group");
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!(user_id = %user.id, error = %e, "LDAP reconcile: admin promotion failed")
                        }
                    },
                    Some(false) if user.is_admin => entry.demote.push(user),
                    _ => {}
                }
            }
            Verdict::Moved => report.moved += 1,
            Verdict::Unknown => report.unknown += 1,
            Verdict::Gone => {
                report.gone += 1;
                entry.gone.push(user);
            }
        }
    }

    for ctx in &mut ctxs {
        ctx.close().await;
    }

    // Membership removals: capped per provider like deactivations, so an
    // entry read with an empty memberOf (broken group config, lost read
    // access) cannot strip every LDAP-managed membership in one pass.
    for (idx, batch) in shrinks {
        let total = tally
            .get(&idx)
            .map_or(batch.len(), |t| t.total.max(batch.len()));
        if !deactivation_allowed(batch.len(), total, settings) {
            report.refused_group_removals += 1;
            tracing::error!(
                provider = %ctxs[idx].name,
                users = batch.len(),
                checked = total,
                "LDAP reconcile: too many users of this provider would lose LDAP-managed group \
                 memberships in one pass; leaving their memberships unchanged. Check the \
                 provider's group settings and the service account's read access"
            );
            continue;
        }
        for (user_id, names) in batch {
            apply_group_sync(db, user_id, ctxs[idx].id, &names, &mut report).await;
        }
    }

    // Decide deactivations first: the admins among them count against the
    // last-admin guard, for these batches and for the demotions below.
    let mut admins_left = active_admin_count(db).await?;
    let mut to_deactivate: Vec<(usize, Vec<LdapUserRef>)> = Vec::new();
    for (idx, t) in tally.iter_mut() {
        let gone = std::mem::take(&mut t.gone);
        if gone.is_empty() {
            continue;
        }
        let provider = &ctxs[*idx].name;
        if !deactivation_allowed(gone.len(), t.total, settings) {
            report.refused_providers += 1;
            tracing::error!(
                provider = %provider,
                gone = gone.len(),
                checked = t.total,
                max_percent = settings.max_deactivate_percent,
                max_count = settings.max_deactivate,
                "LDAP reconcile: too many users of this provider are missing from the directory \
                 in one pass; refusing to deactivate any of them. Check the provider's \
                 user_base_dn / user_filter, or raise LDAP_SYNC_MAX_DEACTIVATE(_PERCENT)"
            );
            continue;
        }
        if !settings.deactivate {
            report.would_deactivate += gone.len();
            for user in &gone {
                tracing::warn!(
                    user_id = %user.id,
                    username = %user.username,
                    dn = %user.dn,
                    provider = %provider,
                    "LDAP reconcile: user no longer in the directory but left active; set \
                     LDAP_SYNC_DEACTIVATE=true to deactivate such users automatically"
                );
            }
            continue;
        }
        let gone_admins = gone.iter().filter(|u| u.is_admin).count();
        if gone_admins > 0 && gone_admins >= admins_left {
            report.refused_providers += 1;
            tracing::error!(
                provider = %provider,
                gone = gone.len(),
                gone_admins,
                active_admins = admins_left,
                "LDAP reconcile: deactivating these users would leave no active admin; refusing \
                 to deactivate any of them"
            );
            continue;
        }
        admins_left -= gone_admins;
        to_deactivate.push((*idx, gone));
    }

    // Demotions: same caps as deactivation, and never the last active admin.
    for (idx, t) in &tally {
        if t.demote.is_empty() {
            continue;
        }
        let provider = &ctxs[*idx].name;
        let n = t.demote.len();
        if !deactivation_allowed(n, t.total, settings) || n >= admins_left {
            report.refused_demotions += 1;
            tracing::error!(
                provider = %provider,
                demotions = n,
                checked = t.total,
                active_admins = admins_left,
                "LDAP reconcile: refusing to remove admin from these users in one pass -- too \
                 many at once, or it would leave no active admin. Check the provider's \
                 admin_group_dn and the service account's read access to memberOf"
            );
            continue;
        }
        for user in &t.demote {
            match demote_ldap_admin(db, user.id).await {
                Ok(true) => {
                    report.demoted += 1;
                    admins_left = admins_left.saturating_sub(1);
                    tracing::warn!(
                        target: "security",
                        user_id = %user.id,
                        provider = %provider,
                        "LDAP reconcile: user is no longer in the admin group; admin removed and tokens revoked"
                    );
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(user_id = %user.id, error = %e, "LDAP reconcile: admin demotion failed")
                }
            }
        }
    }

    for (idx, gone) in to_deactivate {
        let provider = &ctxs[idx].name;
        let ids: Vec<Uuid> = gone.iter().map(|u| u.id).collect();
        let deactivated = auth
            .deactivate_federated_users(AuthProvider::Ldap, &ids)
            .await?;
        for user in gone.iter().filter(|u| deactivated.contains(&u.id)) {
            tracing::warn!(
                target: "security",
                user_id = %user.id,
                username = %user.username,
                dn = %user.dn,
                provider = %provider,
                "LDAP reconcile: user no longer in the directory; deactivated and credentials revoked"
            );
        }
        report.deactivated += deactivated.len();
    }

    Ok(report)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ldap_service::tests::{
        spawn_scripted_directory, MockEntry, ScriptedDirectory, MOCK_SERVICE_DN,
    };

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_GROUP: &str = "cn=admins,ou=groups,dc=example,dc=com";

    fn info(dn: &str) -> LdapUserInfo {
        LdapUserInfo {
            dn: dn.to_string(),
            username: "u".to_string(),
            email: "u@example.com".to_string(),
            display_name: None,
            groups: vec![],
        }
    }

    fn uref(dn: &str, provider_id: Option<Uuid>) -> LdapUserRef {
        LdapUserRef {
            id: Uuid::new_v4(),
            username: "u".to_string(),
            dn: dn.to_string(),
            provider_id,
            is_admin: false,
        }
    }

    #[test]
    fn test_parse_sync_interval() {
        let default = Some(Duration::from_secs(DEFAULT_LDAP_SYNC_INTERVAL_SECS));
        assert_eq!(parse_sync_interval(None), default);
        assert_eq!(parse_sync_interval(Some("")), default);
        assert_eq!(parse_sync_interval(Some("soon")), default);
        assert_eq!(parse_sync_interval(Some("0")), None);
        assert_eq!(
            parse_sync_interval(Some(" 900 ")),
            Some(Duration::from_secs(900))
        );
        assert_eq!(
            parse_sync_interval(Some("5")),
            Some(Duration::from_secs(MIN_LDAP_SYNC_INTERVAL_SECS))
        );
    }

    /// Deactivation is opt-in (orchestrator decision on #3830).
    #[test]
    fn test_parse_settings_deactivation_is_opt_in() {
        assert_eq!(
            parse_settings(None, None, None),
            LdapSyncSettings::default()
        );
        assert!(!LdapSyncSettings::default().deactivate);
        assert!(!parse_settings(Some("false"), None, None).deactivate);
        assert!(parse_settings(Some("TRUE"), None, None).deactivate);
        let s = parse_settings(Some("1"), Some("50"), Some("3"));
        assert_eq!(s.max_deactivate_percent, 50);
        assert_eq!(s.max_deactivate, 3);
    }

    #[test]
    fn test_deactivation_caps() {
        let s = LdapSyncSettings::default(); // 10 %, 25
        assert!(deactivation_allowed(0, 0, &s));
        assert!(deactivation_allowed(1, 1, &s), "one user may always go");
        assert!(deactivation_allowed(1, 2, &s));
        assert!(!deactivation_allowed(2, 2, &s), "everyone gone is refused");
        assert!(!deactivation_allowed(3, 10, &s), "30 % > 10 %");
        assert!(deactivation_allowed(10, 100, &s), "10 % is within the cap");
        assert!(!deactivation_allowed(26, 1000, &s), "count cap");
        let tight = parse_settings(Some("true"), Some("100"), Some("2"));
        assert!(!deactivation_allowed(3, 3, &tight));
        assert!(deactivation_allowed(2, 2, &tight));
    }

    #[test]
    fn test_combine_standings_gone_only_when_every_provider_says_so() {
        assert_eq!(
            combine_standings(&[Standing::Gone, Standing::Present(info("x"))]),
            Verdict::Present(1)
        );
        assert_eq!(
            combine_standings(&[Standing::Gone, Standing::Unknown]),
            Verdict::Unknown
        );
        assert_eq!(
            combine_standings(&[Standing::Gone, Standing::Gone]),
            Verdict::Gone
        );
        assert_eq!(combine_standings(&[]), Verdict::Unknown);
        assert_eq!(
            combine_standings(&[Standing::Gone, Standing::Moved, Standing::Unknown]),
            Verdict::Moved
        );
    }

    #[test]
    fn test_candidate_providers_prefer_recorded_provider() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let bases = vec![(a, BASE.to_string()), (b, BASE.to_string())];
        let dn = "uid=alice,ou=people,dc=example,dc=com";
        assert_eq!(candidate_providers(&bases, &uref(dn, Some(b))), vec![1]);
        assert_eq!(candidate_providers(&bases, &uref(dn, None)), vec![0, 1]);
        // Recorded provider disabled or deleted: nobody to ask.
        assert!(candidate_providers(&bases, &uref(dn, Some(Uuid::new_v4()))).is_empty());
        assert!(candidate_providers(&bases, &uref("uid=x,dc=other,dc=org", None)).is_empty());
    }

    // -----------------------------------------------------------------------
    // run_ldap_sync against a real database and a scripted directory
    // -----------------------------------------------------------------------

    fn encryption_key_available() -> bool {
        std::env::var("SSO_ENCRYPTION_KEY").is_ok() || std::env::var("JWT_SECRET").is_ok()
    }

    async fn directory(entries: Vec<MockEntry>) -> u16 {
        spawn_scripted_directory(ScriptedDirectory {
            service_dn: MOCK_SERVICE_DN.to_string(),
            entries,
            references: vec![],
        })
        .await
    }

    fn dead_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    async fn provider(
        pool: &PgPool,
        name: &str,
        port: u16,
        user_filter: &str,
        priority: i32,
        admin_group_dn: Option<&str>,
    ) -> Uuid {
        AuthConfigService::create_ldap(
            pool,
            crate::services::auth_config_service::CreateLdapConfigRequest {
                name: name.into(),
                server_url: format!("ldap://127.0.0.1:{port}"),
                bind_dn: Some(MOCK_SERVICE_DN.into()),
                bind_password: Some("svc-secret".into()),
                user_base_dn: BASE.into(),
                user_filter: Some(user_filter.into()),
                group_base_dn: None,
                group_filter: None,
                email_attribute: None,
                display_name_attribute: None,
                username_attribute: None,
                groups_attribute: None,
                admin_group_dn: admin_group_dn.map(String::from),
                use_starttls: None,
                insecure_skip_verify: None,
                ca_certificate: None,
                is_enabled: Some(true),
                priority: Some(priority),
            },
        )
        .await
        .expect("create provider")
        .id
    }

    async fn insert_user(
        pool: &PgPool,
        username: &str,
        dn: &str,
        provider_id: Option<Uuid>,
        is_admin: bool,
        auth_provider: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, email, auth_provider, external_id, is_active, \
             is_admin, ldap_provider_id) \
             VALUES ($1, $2, $3, $4::auth_provider, $5, true, $6, $7)",
        )
        .bind(id)
        .bind(username)
        .bind(format!("{username}@example.com"))
        .bind(auth_provider)
        .bind(dn)
        .bind(is_admin)
        .bind(provider_id)
        .execute(pool)
        .await
        .expect("insert user");
        id
    }

    async fn flags(pool: &PgPool, id: Uuid) -> (bool, bool) {
        sqlx::query_as("SELECT is_active, is_admin FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    fn auth(pool: &PgPool) -> AuthService {
        AuthService::new(
            pool.clone(),
            std::sync::Arc::new(crate::config::Config::test_config()),
        )
    }

    fn deactivating() -> LdapSyncSettings {
        parse_settings(Some("true"), None, None)
    }

    fn dn(uid: &str, ou: &str) -> String {
        format!("uid={uid},ou={ou},{BASE}")
    }

    /// Two providers share a base and differ only in user_filter. Review
    /// blocker: every contractor was re-read with eng's filter -> gone ->
    /// deactivated. A recorded provider is used as is; an unrecorded user
    /// is gone only when every covering provider says so.
    #[tokio::test]
    async fn test_shared_base_providers_do_not_deactivate_each_others_users() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let port = directory(vec![
            MockEntry::user(&dn("carl", "people"), "carl", &[("ou", "contractors")]),
            MockEntry::user(&dn("cora", "people"), "cora", &[("ou", "contractors")]),
            MockEntry::user(&dn("erin", "people"), "erin", &[("ou", "eng")]),
        ])
        .await;
        let eng = provider(pool, "eng", port, "(&(uid={0})(ou=eng))", 0, None).await;
        let contractors = provider(
            pool,
            "contractors",
            port,
            "(&(uid={0})(ou=contractors))",
            1,
            None,
        )
        .await;
        let carl = insert_user(
            pool,
            "carl",
            &dn("carl", "people"),
            Some(contractors),
            false,
            "ldap",
        )
        .await;
        let cora = insert_user(pool, "cora", &dn("cora", "people"), None, false, "ldap").await;
        let erin = insert_user(
            pool,
            "erin",
            &dn("erin", "people"),
            Some(eng),
            false,
            "ldap",
        )
        .await;
        // Gone everywhere (no entry at all): the one legitimate deactivation.
        let gail = insert_user(pool, "gail", &dn("gail", "people"), None, false, "ldap").await;

        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert_eq!((r.checked, r.present, r.gone), (4, 3, 1), "{r:?}");
        assert!(
            flags(pool, carl).await.0,
            "recorded contractor must stay active"
        );
        assert!(
            flags(pool, cora).await.0,
            "unrecorded contractor must stay active"
        );
        assert!(flags(pool, erin).await.0);
        assert!(
            !flags(pool, gail).await.0,
            "user gone from every provider is deactivated"
        );
        assert_eq!(r.deactivated, 1);
    }

    /// Default settings report a gone user but never deactivate.
    #[tokio::test]
    async fn test_default_settings_only_report_gone_users() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let port = directory(vec![]).await;
        provider(pool, "corp", port, "(uid={0})", 0, None).await;
        let gail = insert_user(pool, "gail", &dn("gail", "people"), None, false, "ldap").await;
        let r = run_ldap_sync(pool, &auth(pool), &LdapSyncSettings::default())
            .await
            .unwrap();
        assert_eq!((r.gone, r.would_deactivate, r.deactivated), (1, 1, 0));
        assert!(flags(pool, gail).await.0);
    }

    /// An OU reorg moves an entry: rc 32 at the old DN must not mean gone
    /// when a username search finds the user elsewhere.
    #[tokio::test]
    async fn test_moved_user_is_not_deactivated() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let port = directory(vec![MockEntry::user(&dn("alice", "moved"), "alice", &[])]).await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, None).await;
        let alice = insert_user(
            pool,
            "alice",
            &dn("alice", "people"),
            Some(corp),
            false,
            "ldap",
        )
        .await;
        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert_eq!((r.moved, r.gone, r.deactivated), (1, 0, 0), "{r:?}");
        assert!(flags(pool, alice).await.0);
    }

    /// Too many users of one provider gone in one pass: deactivate nobody.
    #[tokio::test]
    async fn test_mass_disappearance_is_refused() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let port = directory(vec![MockEntry::user(&dn("u0", "people"), "u0", &[])]).await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, None).await;
        let mut ids = Vec::new();
        for i in 0..4 {
            let uid = format!("u{i}");
            ids.push(insert_user(pool, &uid, &dn(&uid, "people"), Some(corp), false, "ldap").await);
        }
        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert_eq!(
            (r.gone, r.refused_providers, r.deactivated),
            (3, 1, 0),
            "{r:?}"
        );
        for id in ids {
            assert!(flags(pool, id).await.0);
        }
    }

    /// A directory outage deactivates nobody.
    #[tokio::test]
    async fn test_unreachable_directory_deactivates_nobody() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let corp = provider(pool, "corp", dead_port(), "(uid={0})", 0, None).await;
        let alice = insert_user(
            pool,
            "alice",
            &dn("alice", "people"),
            Some(corp),
            false,
            "ldap",
        )
        .await;
        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert_eq!((r.unknown, r.deactivated), (1, 0));
        assert!(flags(pool, alice).await.0);
    }

    /// is_admin is recomputed from admin_group_dn like login does; local
    /// admins are never touched.
    #[tokio::test]
    async fn test_admin_status_recomputed_from_admin_group() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let port = directory(vec![
            MockEntry::user(&dn("alice", "people"), "alice", &[]),
            MockEntry::user(
                &dn("carol", "people"),
                "carol",
                &[("memberOf", ADMIN_GROUP)],
            ),
        ])
        .await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, Some(ADMIN_GROUP)).await;
        let alice = insert_user(
            pool,
            "alice",
            &dn("alice", "people"),
            Some(corp),
            true,
            "ldap",
        )
        .await;
        let carol = insert_user(
            pool,
            "carol",
            &dn("carol", "people"),
            Some(corp),
            false,
            "ldap",
        )
        .await;
        let root = insert_user(pool, "root", &dn("root", "people"), None, true, "local").await;
        let r = run_ldap_sync(pool, &auth(pool), &LdapSyncSettings::default())
            .await
            .unwrap();
        assert_eq!((r.demoted, r.promoted), (1, 1), "{r:?}");
        assert_eq!(
            flags(pool, alice).await,
            (true, false),
            "removed from admin group"
        );
        assert_eq!(flags(pool, carol).await, (true, true));
        assert_eq!(
            flags(pool, root).await,
            (true, true),
            "local admin untouched"
        );
    }

    /// Only one replica runs a pass.
    #[tokio::test]
    async fn test_pass_skipped_while_another_replica_holds_the_lock() {
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let mut other = pool.begin().await.unwrap();
        let _: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(LDAP_SYNC_LOCK_ID)
            .fetch_one(&mut *other)
            .await
            .unwrap();
        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert!(r.skipped_locked);
        other.rollback().await.unwrap();
        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert!(!r.skipped_locked);
    }

    #[tokio::test]
    async fn test_record_ldap_provider() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let corp = provider(pool, "corp", dead_port(), "(uid={0})", 0, None).await;
        let alice = insert_user(pool, "alice", &dn("alice", "people"), None, false, "ldap").await;
        record_ldap_provider(pool, alice, corp).await.unwrap();
        let recorded: Option<Uuid> =
            sqlx::query_scalar("SELECT ldap_provider_id FROM users WHERE id = $1")
                .bind(alice)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(recorded, Some(corp));
    }

    /// Round-2 review blocker: John (uid=jsmith,ou=people) is deleted and
    /// Jane (uid=jsmith,ou=it) -- an admin-group member -- is created. The
    /// username match must keep John's row from deactivation only: it must
    /// never promote it or re-sync anything from Jane's entry.
    #[tokio::test]
    async fn test_reused_username_never_promotes_the_old_account() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let port = directory(vec![MockEntry::user(
            &dn("jsmith", "it"),
            "jsmith",
            &[("memberOf", ADMIN_GROUP)],
        )])
        .await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, Some(ADMIN_GROUP)).await;
        let john = insert_user(
            pool,
            "jsmith",
            &dn("jsmith", "people"),
            Some(corp),
            false,
            "ldap",
        )
        .await;
        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert_eq!(
            (r.moved, r.promoted, r.groups_resynced, r.deactivated),
            (1, 0, 0, 0),
            "{r:?}"
        );
        assert_eq!(flags(pool, john).await, (true, false), "never promoted");
    }

    /// Only users with a recorded provider get admin recomputed.
    #[tokio::test]
    async fn test_unrecorded_user_admin_is_not_recomputed() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let port = directory(vec![
            MockEntry::user(&dn("dave", "people"), "dave", &[("memberOf", ADMIN_GROUP)]),
            MockEntry::user(&dn("erin", "people"), "erin", &[]),
        ])
        .await;
        provider(pool, "corp", port, "(uid={0})", 0, Some(ADMIN_GROUP)).await;
        let dave = insert_user(pool, "dave", &dn("dave", "people"), None, false, "ldap").await;
        let erin = insert_user(pool, "erin", &dn("erin", "people"), None, true, "ldap").await;
        let r = run_ldap_sync(pool, &auth(pool), &LdapSyncSettings::default())
            .await
            .unwrap();
        assert_eq!((r.present, r.promoted, r.demoted), (2, 0, 0), "{r:?}");
        assert_eq!(flags(pool, dave).await, (true, false));
        assert_eq!(flags(pool, erin).await, (true, true));
    }

    /// A broken admin_group_dn (or lost memberOf read access) must not demote
    /// every LDAP admin in one pass: the batch is capped like deactivation.
    #[tokio::test]
    async fn test_mass_demotion_is_refused() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let mut entries = Vec::new();
        for i in 0..3 {
            let uid = format!("a{i}");
            entries.push(MockEntry::user(&dn(&uid, "people"), &uid, &[]));
        }
        let port = directory(entries).await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, Some(ADMIN_GROUP)).await;
        let mut ids = Vec::new();
        for i in 0..3 {
            let uid = format!("a{i}");
            ids.push(insert_user(pool, &uid, &dn(&uid, "people"), Some(corp), true, "ldap").await);
        }
        insert_user(pool, "root", &dn("root", "people"), None, true, "local").await;
        let r = run_ldap_sync(pool, &auth(pool), &LdapSyncSettings::default())
            .await
            .unwrap();
        assert_eq!((r.demoted, r.refused_demotions), (0, 1), "{r:?}");
        for id in ids {
            assert_eq!(flags(pool, id).await, (true, true));
        }
    }

    /// Never demote the last active admin of the instance.
    #[tokio::test]
    async fn test_last_admin_is_never_demoted() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        // Migrations may seed a built-in admin; this test needs the LDAP
        // user to be the only active admin.
        sqlx::query("UPDATE users SET is_admin = false WHERE is_admin = true")
            .execute(pool)
            .await
            .unwrap();
        let port = directory(vec![MockEntry::user(&dn("solo", "people"), "solo", &[])]).await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, Some(ADMIN_GROUP)).await;
        let solo = insert_user(
            pool,
            "solo",
            &dn("solo", "people"),
            Some(corp),
            true,
            "ldap",
        )
        .await;
        let r = run_ldap_sync(pool, &auth(pool), &LdapSyncSettings::default())
            .await
            .unwrap();
        assert_eq!((r.demoted, r.refused_demotions), (0, 1), "{r:?}");
        assert_eq!(flags(pool, solo).await, (true, true));
    }

    /// Round-3 review S1: with only two LDAP admins, one dropped from the
    /// admin group and the other deleted from the directory, one pass must
    /// not demote the first and deactivate the second.
    #[tokio::test]
    async fn test_demotion_plus_deactivation_never_leave_zero_admins() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        sqlx::query("UPDATE users SET is_admin = false WHERE is_admin = true")
            .execute(pool)
            .await
            .unwrap();
        let port = directory(vec![MockEntry::user(&dn("anna", "people"), "anna", &[])]).await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, Some(ADMIN_GROUP)).await;
        let anna = insert_user(
            pool,
            "anna",
            &dn("anna", "people"),
            Some(corp),
            true,
            "ldap",
        )
        .await;
        let ben = insert_user(pool, "ben", &dn("ben", "people"), Some(corp), true, "ldap").await;
        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert_eq!(
            (r.deactivated, r.demoted, r.refused_demotions),
            (1, 0, 1),
            "{r:?}"
        );
        assert_eq!(flags(pool, ben).await, (false, true));
        assert_eq!(
            flags(pool, anna).await,
            (true, true),
            "the last admin stays admin"
        );
        assert_eq!(active_admin_count(pool).await.unwrap(), 1);
    }

    /// The deactivation batch has its own zero-admin guard.
    #[tokio::test]
    async fn test_deactivating_the_last_admin_is_refused() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        sqlx::query("UPDATE users SET is_admin = false WHERE is_admin = true")
            .execute(pool)
            .await
            .unwrap();
        let port = directory(vec![]).await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, None).await;
        let ben = insert_user(pool, "ben", &dn("ben", "people"), Some(corp), true, "ldap").await;
        let r = run_ldap_sync(pool, &auth(pool), &deactivating())
            .await
            .unwrap();
        assert_eq!((r.deactivated, r.refused_providers), (0, 1), "{r:?}");
        assert_eq!(flags(pool, ben).await, (true, true));
    }

    async fn ldap_memberships(pool: &PgPool, user_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_group_members m JOIN groups g ON g.id = m.group_id \
             WHERE m.user_id = $1 AND g.external_source = 'ldap'",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Round-3 review N1: entries read back with an empty memberOf must not
    /// strip every LDAP-managed membership in one pass.
    #[tokio::test]
    async fn test_mass_group_removal_is_refused() {
        if !encryption_key_available() {
            return;
        }
        let Some(iso) = crate::testing::try_isolated_pool().await else {
            return;
        };
        let pool = &iso.pool;
        let devs = "cn=devs,ou=groups,dc=example,dc=com";
        let uids = ["g0", "g1", "g2"];
        let with_group: Vec<MockEntry> = uids
            .iter()
            .map(|u| MockEntry::user(&dn(u, "people"), u, &[("memberOf", devs)]))
            .collect();
        let without: Vec<MockEntry> = uids
            .iter()
            .map(|u| MockEntry::user(&dn(u, "people"), u, &[]))
            .collect();
        let port = directory(with_group).await;
        let corp = provider(pool, "corp", port, "(uid={0})", 0, None).await;
        let mut update = crate::services::auth_config_service::UpdateLdapConfigRequest {
            name: None,
            server_url: None,
            bind_dn: None,
            bind_password: None,
            user_base_dn: None,
            user_filter: None,
            group_base_dn: Some("ou=groups,dc=example,dc=com".into()),
            group_filter: None,
            email_attribute: None,
            display_name_attribute: None,
            username_attribute: None,
            groups_attribute: None,
            admin_group_dn: None,
            use_starttls: None,
            insecure_skip_verify: None,
            ca_certificate: None,
            is_enabled: None,
            priority: None,
        };
        AuthConfigService::update_ldap(pool, corp, update.clone())
            .await
            .unwrap();
        let mut ids = Vec::new();
        for u in uids {
            ids.push(insert_user(pool, u, &dn(u, "people"), Some(corp), false, "ldap").await);
        }

        // Pass 1 only adds memberships: applied.
        let r = run_ldap_sync(pool, &auth(pool), &LdapSyncSettings::default())
            .await
            .unwrap();
        assert_eq!(r.groups_resynced, 3, "{r:?}");
        for id in &ids {
            assert_eq!(ldap_memberships(pool, *id).await, 1);
        }

        // Pass 2: every entry now comes back with no memberOf.
        let port = directory(without).await;
        update.group_base_dn = None;
        update.server_url = Some(format!("ldap://127.0.0.1:{port}"));
        AuthConfigService::update_ldap(pool, corp, update)
            .await
            .unwrap();
        let r = run_ldap_sync(pool, &auth(pool), &LdapSyncSettings::default())
            .await
            .unwrap();
        assert_eq!(r.refused_group_removals, 1, "{r:?}");
        for id in &ids {
            assert_eq!(ldap_memberships(pool, *id).await, 1, "membership kept");
        }
    }
}
