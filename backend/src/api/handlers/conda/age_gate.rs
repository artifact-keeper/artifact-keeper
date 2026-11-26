//! Server-side age gate (cooldown) for Remote conda channels and the Virtual
//! channels over them (#6526).
//!
//! A gated Remote serves its upstream's `repodata.json` with every record the
//! gate holds left out, and `current_repodata.json`, the CEP-16 shards and the
//! package route all follow that one document.
//!
//! **The sighting ledger.** Every file of the upstream index is recorded once
//! per channel (remote and subdir) by `(filename, sha256)`, at the database
//! clock (migration 427). A changed sha256 under a published filename is a
//! new sighting, so swapping a file's bytes in place restarts its clock.
//!
//! **The baseline.** The first complete snapshot of a subdir is recorded as
//! its baseline under an advisory lock on the channel. Until it exists the
//! gate refuses to serve the subdir (503 with `Retry-After`). A restarted
//! build completes it, because the inserts are insert-once. Repointing the
//! remote, or disabling and re-enabling the gate, never makes a new
//! baseline; only the audited re-baseline action does. A file of the
//! baseline is treated as old, unless its builder `timestamp` or its
//! `indexed_timestamp` falls inside the gate window: the builder's claim may
//! hold a record, never release one. The gate cannot help against an
//! upstream that was already compromised when the baseline was taken.
//!
//! **After the baseline.** A file first seen later is aged from
//! `max(indexed_timestamp, previous successful read of the subdir,
//! first sighting - refresh cap)`. A file first seen now was not in the
//! previous read, so an upstream `indexed_timestamp` older than that read
//! earns no credit. The refresh cap bounds the credit when nobody read the
//! subdir for a long time. An `indexed_timestamp` older than the sighting by
//! more than the cap is logged and counted as backdating. In mode
//! `first_seen` the upstream's `indexed_timestamp` earns no credit at all.
//!
//! **Always held** (while the gate asks for any age): a record whose builder
//! `timestamp` is in the future, or whose `indexed_timestamp` is earlier than
//! its `timestamp`. CEP 47 asks channel servers to flag both.
//!
//! **Decisions.** The repository's age-gate reviews, keyed by the record's
//! `(name, version)`. A rejection withholds the version whatever its age. A
//! manual approval under the current identity serves it early. Decisions are
//! part of the kept document's key, so they take effect on the next request.
//!
//! **Cost.** The gated document is built once per cached upstream document
//! and kept by the conda merge gate, for every encoding. A rebuild parses
//! the record facts once, inserts only the sightings this process has not
//! recorded (a per-channel set of keyed 128-bit hashes, keys random per
//! process), and reads back only the post-baseline sightings inside the gate
//! window. It makes no per-record query.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Duration, TimeZone, Utc};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::merge_gate::{self, MergeKeyBuilder, MergeKind, MergedDocument};
use super::virtual_merge::{self, MemberFailure};
use crate::models::repository::{Repository, RepositoryType};
use crate::services::age_gate_service::{
    review_identity_match, upstream_fingerprint, AgeGateMode, AgeGateRepoParams, AgeGateService,
    ReviewIdentityMatch,
};

/// Response header on a gated document: how many records the gate left out.
pub(super) const WITHHELD_HEADER: &str = "x-ak-age-gate-withheld";

/// Most credit a post-baseline sighting gets before its first sighting, in
/// seconds. Defaults to the proxy cache's metadata TTL, the interval at which
/// the upstream index is normally re-read.
const REFRESH_CAP_SECS_ENV: &str = "CONDA_AGE_GATE_REFRESH_CAP_SECS";

/// Ceiling on the sighting hashes kept in memory across every gated channel.
const KNOWN_CACHE_MAX_BYTES_ENV: &str = "CONDA_AGE_GATE_KNOWN_CACHE_MAX_BYTES";
const DEFAULT_KNOWN_CACHE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Rows written per sighting insert statement.
const INSERT_BATCH: usize = 5_000;

/// Advisory-lock class of the per-channel baseline build.
const BASELINE_LOCK_CLASS: i32 = 0x6526;

/// Rough bytes one parsed record fact holds beyond its strings.
const FACT_OVERHEAD_BYTES: usize = 160;

fn refresh_cap() -> Duration {
    let secs = std::env::var(REFRESH_CAP_SECS_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(crate::services::cache_classifier::MUTABLE_DEFAULT_TTL_SECS.max(1));
    Duration::seconds(secs)
}

fn unavailable(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "conda age gate failed; failing closed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (axum::http::header::RETRY_AFTER, "5"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        "The conda age gate could not be evaluated; retry shortly",
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// A conda review coordinate: the record's `(name, version)`.
type Coordinate = (String, String);

/// One gated Remote's policy and review decisions, read once per request.
#[derive(Debug)]
pub(super) struct ChannelGate {
    pub(super) params: AgeGateRepoParams,
    fingerprint: String,
    approved: HashSet<Coordinate>,
    rejected: HashSet<Coordinate>,
    /// Digest of the policy and every decision, part of the kept document's
    /// key so a decision takes effect on the next request.
    digest: [u8; 32],
}

impl ChannelGate {
    fn new(
        params: AgeGateRepoParams,
        mut approved: Vec<Coordinate>,
        mut rejected: Vec<Coordinate>,
    ) -> Self {
        let fingerprint = upstream_fingerprint(params.upstream_url.as_deref());
        approved.sort();
        approved.dedup();
        rejected.sort();
        rejected.dedup();
        let mut h = Sha256::new();
        h.update(b"conda-age-gate-v2\0");
        h.update(params.age_gate_mode.as_str().as_bytes());
        h.update(params.age_gate_min_age_days.to_le_bytes());
        h.update(fingerprint.as_bytes());
        for (tag, list) in [(b"A", &approved), (b"R", &rejected)] {
            h.update(tag);
            h.update((list.len() as u64).to_le_bytes());
            for (n, v) in list.iter() {
                h.update(n.as_bytes());
                h.update(b"\0");
                h.update(v.as_bytes());
                h.update(b"\0");
            }
        }
        Self {
            params,
            fingerprint,
            approved: approved.into_iter().collect(),
            rejected: rejected.into_iter().collect(),
            digest: h.finalize().into(),
        }
    }

    /// Add the policy and decisions to a kept document's key.
    pub(super) fn key_part(&self, key: &mut MergeKeyBuilder) {
        key.part(b"age-gate").part(&self.digest);
    }

    #[cfg(test)]
    pub(super) fn for_test(
        params: AgeGateRepoParams,
        approved: Vec<Coordinate>,
        rejected: Vec<Coordinate>,
    ) -> Self {
        Self::new(params, approved, rejected)
    }
}

/// The age-gate policy of every gated Remote among `ids`. A repository that
/// asked for gating but whose policy cannot be enforced is an error (fail
/// closed), never ungated.
pub(super) async fn load_gates(
    db: &PgPool,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, Arc<ChannelGate>>, Response> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        "SELECT id, key, format::TEXT AS format, age_gate_enabled, age_gate_min_age_days, \
                age_gate_mode, upstream_url \
           FROM repositories \
          WHERE id = ANY($1) AND repo_type = 'remote' AND age_gate_enabled",
    )
    .bind(ids)
    .fetch_all(db)
    .await
    .map_err(unavailable)?;
    if rows.is_empty() {
        return Ok(HashMap::new());
    }
    let mut params = Vec::with_capacity(rows.len());
    for row in rows {
        let mode: String = row.try_get("age_gate_mode").map_err(unavailable)?;
        let format: String = row.try_get("format").map_err(unavailable)?;
        let p = AgeGateRepoParams::from_parts(
            row.try_get("id").map_err(unavailable)?,
            row.try_get::<String, _>("key").map_err(unavailable)?,
            RepositoryType::Remote,
            crate::api::handlers::proxy_helpers::age_gate_format_from_str(&format),
            row.try_get("age_gate_enabled").map_err(unavailable)?,
            row.try_get("age_gate_min_age_days").map_err(unavailable)?,
            AgeGateMode::parse(&mode).map_err(|e| e.into_response())?,
            row.try_get("upstream_url").map_err(unavailable)?,
        );
        AgeGateService::require_enforceable(&p).map_err(|e| e.into_response())?;
        params.push(p);
    }
    let gated: Vec<Uuid> = params.iter().map(|p| p.id).collect();
    let decisions = sqlx::query(
        "SELECT repository_id, package_name, package_version, status, \
                basis_mode, basis_upstream_fingerprint \
           FROM age_gate_reviews \
          WHERE repository_id = ANY($1) \
            AND (status = 'rejected' OR (status = 'approved' AND reviewed_by IS NOT NULL))",
    )
    .bind(&gated)
    .fetch_all(db)
    .await
    .map_err(unavailable)?;
    let identity: HashMap<Uuid, (AgeGateMode, String)> = params
        .iter()
        .map(|p| {
            (
                p.id,
                (
                    p.age_gate_mode,
                    upstream_fingerprint(p.upstream_url.as_deref()),
                ),
            )
        })
        .collect();
    let mut by_repo: HashMap<Uuid, (Vec<Coordinate>, Vec<Coordinate>)> = HashMap::new();
    for row in decisions {
        let repo: Uuid = row.try_get("repository_id").map_err(unavailable)?;
        let coordinate = (
            row.try_get::<String, _>("package_name")
                .map_err(unavailable)?,
            row.try_get::<String, _>("package_version")
                .map_err(unavailable)?,
        );
        let status: String = row.try_get("status").map_err(unavailable)?;
        let entry = by_repo.entry(repo).or_default();
        if status == "rejected" {
            entry.1.push(coordinate);
            continue;
        }
        let Some((mode, fingerprint)) = identity.get(&repo) else {
            continue;
        };
        let basis_mode: Option<String> = row.try_get("basis_mode").map_err(unavailable)?;
        let basis_fp: Option<String> = row
            .try_get("basis_upstream_fingerprint")
            .map_err(unavailable)?;
        if review_identity_match(
            basis_mode.as_deref(),
            basis_fp.as_deref(),
            *mode,
            fingerprint,
        ) != ReviewIdentityMatch::Differs
        {
            entry.0.push(coordinate);
        }
    }
    Ok(params
        .into_iter()
        .map(|p| {
            let (approved, rejected) = by_repo.remove(&p.id).unwrap_or_default();
            (p.id, Arc::new(ChannelGate::new(p, approved, rejected)))
        })
        .collect())
}

/// The gate of one Remote, or `None` when it is not gated.
pub(super) async fn load_gate(
    db: &PgPool,
    repo_id: Uuid,
) -> Result<Option<Arc<ChannelGate>>, Response> {
    Ok(load_gates(db, &[repo_id]).await?.remove(&repo_id))
}

// ---------------------------------------------------------------------------
// Record facts
// ---------------------------------------------------------------------------

/// What the gate reads from one upstream record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordFacts {
    pub filename: String,
    pub sha256: String,
    pub name: String,
    pub version: String,
    /// The upstream's CEP 47 `indexed_timestamp`, when it sets a usable one.
    pub indexed: Option<DateTime<Utc>>,
    /// The builder `timestamp`, when the record carries a usable one.
    pub built: Option<DateTime<Utc>>,
}

impl RecordFacts {
    fn bytes(&self) -> usize {
        FACT_OVERHEAD_BYTES
            + self.filename.len()
            + self.sha256.len()
            + self.name.len()
            + self.version.len()
    }
}

#[derive(Deserialize)]
struct FactsDoc {
    #[serde(default)]
    info: Option<serde::de::IgnoredAny>,
    packages: Option<HashMap<String, RawFacts>>,
    #[serde(rename = "packages.conda")]
    packages_conda: Option<HashMap<String, RawFacts>>,
}

/// The refusal of a document that parses but carries neither package map
/// nor `info` (e.g. `{}` with a 200): not a channel index at all.
pub(super) const EMPTY_DOCUMENT: &str = "is not a conda channel index (no packages, no info)";

#[derive(Deserialize)]
struct RawFacts {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    indexed_timestamp: Option<serde_json::Value>,
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
}

/// A conda record time (CEP 34 `timestamp`, CEP 47 `indexed_timestamp`):
/// Unix time in milliseconds. A value small enough to be seconds (before
/// 1973 as milliseconds) is read as seconds, as conda reads `timestamp`.
/// Anything else (a string, a negative or non-finite number) is unusable.
pub(super) fn parse_record_time(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    let n = value.as_f64()?;
    if !n.is_finite() || n <= 0.0 {
        return None;
    }
    let millis = if n < 1e11 { n * 1000.0 } else { n };
    if millis > 253_402_300_799_000.0 {
        return None;
    }
    Utc.timestamp_millis_opt(millis as i64).single()
}

/// The facts of a decoded `repodata.json`. A missing `packages` or
/// `packages.conda` map is an empty one (a channel that publishes only one
/// archive format). A document that does not parse, or one with neither map
/// nor `info` ([`EMPTY_DOCUMENT`]), is refused: it never becomes a baseline
/// or a prune source.
pub(super) fn record_facts(json: &[u8]) -> Result<Vec<RecordFacts>, String> {
    let doc: FactsDoc =
        serde_json::from_slice(json).map_err(|e| format!("repodata does not parse: {e}"))?;
    if doc.packages.is_none() && doc.packages_conda.is_none() && doc.info.is_none() {
        return Err(EMPTY_DOCUMENT.to_string());
    }
    let packages = doc.packages.unwrap_or_default();
    let packages_conda = doc.packages_conda.unwrap_or_default();
    let mut out = Vec::with_capacity(packages.len() + packages_conda.len());
    for (filename, raw) in packages.into_iter().chain(packages_conda) {
        let from_file = crate::services::conda_allowlist::split_conda_filename(&filename)
            .map(|(n, v)| (n.to_string(), v.to_string()));
        let name = raw
            .name
            .or_else(|| from_file.as_ref().map(|(n, _)| n.clone()))
            .unwrap_or_else(|| filename.clone());
        let version = raw
            .version
            .or_else(|| from_file.as_ref().map(|(_, v)| v.clone()))
            .unwrap_or_default();
        out.push(RecordFacts {
            sha256: raw.sha256.unwrap_or_default().to_ascii_lowercase(),
            indexed: raw.indexed_timestamp.as_ref().and_then(parse_record_time),
            built: raw.timestamp.as_ref().and_then(parse_record_time),
            filename,
            name,
            version,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// What a withheld record's age was measured from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BasisKind {
    /// The upstream's `indexed_timestamp`, within what the sighting allows.
    Indexed,
    /// This server's first sighting of the file (and the previous read).
    FirstSeen,
    /// A baseline file held by a recent builder or index timestamp.
    Baseline,
    /// No age applies: a rejection or a suspicious timestamp.
    None,
}

/// Why a record is left out of the served document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WithheldReason {
    /// Younger than the gate.
    TooYoung,
    /// An administrator rejected the version.
    Rejected,
    /// The builder `timestamp` is in the future.
    TimestampInFuture,
    /// The `indexed_timestamp` is earlier than the builder `timestamp`.
    IndexedBeforeBuilt,
}

/// Why a record was left out of the served document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct WithheldRecord {
    pub name: String,
    pub version: String,
    pub reason: WithheldReason,
    pub age_basis: BasisKind,
    /// When the record's age starts (`None`: not age-based).
    pub basis: Option<DateTime<Utc>>,
    /// When the record becomes available on age alone (`None`: it does not).
    pub available_at: Option<DateTime<Utc>>,
    /// The upstream `indexed_timestamp` is older than this server's first
    /// sighting allows: the upstream may be backdating it.
    pub backdated: bool,
}

/// A post-baseline sighting inside the gate window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sighting {
    pub first_seen: DateTime<Utc>,
    pub prev_fetch: Option<DateTime<Utc>>,
}

/// What a gated document left out (and listed), kept with it so the package
/// route refuses exactly the files the index withholds or does not list.
#[derive(Debug, Default)]
pub(crate) struct Withheld {
    /// Whether the upstream publishes the document at all.
    pub published: bool,
    pub records: HashMap<String, WithheldRecord>,
    /// Every filename the upstream index lists (keyed hashes).
    listed: HashSet<u128>,
}

impl Withheld {
    pub(super) fn lists(&self, filename: &str) -> bool {
        self.listed.contains(&key_hash(filename, ""))
    }

    /// Bytes this record set holds, for the merge cache's weight.
    pub(super) fn weight(&self) -> usize {
        hash_set_bytes(self.listed.capacity())
            + self
                .records
                .iter()
                .map(|(k, v)| k.len() + v.name.len() + v.version.len() + 96)
                .sum::<usize>()
    }
}

/// Decide every record without I/O. `young` holds the post-baseline
/// sightings inside the gate window, keyed by `(filename, sha256)`; any
/// other record has a ledger row outside that set (a baseline file or a
/// sighting older than the window) and is old by this server's clock.
#[cfg(test)]
pub(super) fn classify(
    gate: &ChannelGate,
    facts: &[RecordFacts],
    young: &HashMap<(String, String), Sighting>,
    now: DateTime<Utc>,
    cap: Duration,
) -> HashMap<String, WithheldRecord> {
    classify_with_rows(gate, facts, young, &HashSet::new(), now, cap)
}

/// [`classify`], given the files the ledger update found without a row
/// (`rowless`, keyed by `(filename, sha256)`). Once the baseline exists a
/// file with no row is never old: it is first seen now, whatever the insert
/// step managed to record.
pub(super) fn classify_with_rows(
    gate: &ChannelGate,
    facts: &[RecordFacts],
    young: &HashMap<(String, String), Sighting>,
    rowless: &HashSet<(String, String)>,
    now: DateTime<Utc>,
    cap: Duration,
) -> HashMap<String, WithheldRecord> {
    let mode = gate.params.age_gate_mode;
    let min_age = gate.params.age_gate_min_age_days;
    let window = Duration::days(i64::from(min_age.max(0)));
    let decided = !gate.approved.is_empty() || !gate.rejected.is_empty();
    let has = |set: &HashSet<Coordinate>, f: &RecordFacts| {
        decided && set.contains(&(f.name.clone(), f.version.clone()))
    };
    let mut out = HashMap::new();
    for f in facts {
        let held = |reason, age_basis, basis: Option<DateTime<Utc>>, backdated| WithheldRecord {
            name: f.name.clone(),
            version: f.version.clone(),
            reason,
            age_basis,
            available_at: basis.map(|b| b + window),
            basis,
            backdated,
        };
        if has(&gate.rejected, f) {
            out.insert(
                f.filename.clone(),
                held(WithheldReason::Rejected, BasisKind::None, None, false),
            );
            continue;
        }
        if min_age <= 0 || has(&gate.approved, f) {
            continue;
        }
        if f.built.is_some_and(|b| b > now) {
            out.insert(
                f.filename.clone(),
                held(
                    WithheldReason::TimestampInFuture,
                    BasisKind::None,
                    None,
                    false,
                ),
            );
            continue;
        }
        if let (Some(i), Some(b)) = (f.indexed, f.built) {
            if i < b {
                out.insert(
                    f.filename.clone(),
                    held(
                        WithheldReason::IndexedBeforeBuilt,
                        BasisKind::None,
                        None,
                        false,
                    ),
                );
                continue;
            }
        }
        let cutoff = now - window;
        let key = (f.filename.clone(), f.sha256.clone());
        let unrecorded =
            (!young.contains_key(&key) && rowless.contains(&key)).then_some(Sighting {
                first_seen: now,
                prev_fetch: None,
            });
        let record = match young.get(&key).or(unrecorded.as_ref()) {
            Some(s) => {
                // First seen after the baseline: not older than the previous
                // read, nor older than the sighting by more than the cap.
                let floor = std::cmp::max(
                    s.prev_fetch.unwrap_or(s.first_seen - cap),
                    s.first_seen - cap,
                );
                let indexed = (mode == AgeGateMode::UpstreamPublishTime)
                    .then_some(f.indexed)
                    .flatten();
                let backdated = f.indexed.is_some_and(|i| i < s.first_seen - cap);
                let (basis, kind) = match indexed {
                    Some(i) if i > floor => (i, BasisKind::Indexed),
                    _ => (floor, BasisKind::FirstSeen),
                };
                (basis > cutoff)
                    .then(|| held(WithheldReason::TooYoung, kind, Some(basis), backdated))
            }
            None => {
                // A baseline file, or one first seen before the window: old,
                // unless a recent builder or index timestamp holds it.
                let recent = [f.built, f.indexed]
                    .into_iter()
                    .flatten()
                    .filter(|t| *t > cutoff)
                    .max();
                recent.map(|t| {
                    held(
                        WithheldReason::TooYoung,
                        BasisKind::Baseline,
                        Some(t),
                        false,
                    )
                })
            }
        };
        if let Some(r) = record {
            if r.backdated {
                crate::services::metrics_service::record_age_gate_filtered_metadata(
                    &gate.params.key,
                    "conda-backdated",
                );
                tracing::warn!(
                    repo = %gate.params.key,
                    file = %f.filename,
                    indexed = ?f.indexed,
                    "conda upstream indexed_timestamp predates this server's first sighting \
                     of the file by more than the refresh cap; holding it (#6526)"
                );
            }
            out.insert(f.filename.clone(), r);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The sighting ledger
// ---------------------------------------------------------------------------

/// Bytes a `HashSet<u128>` of `capacity` holds: hashbrown allocates a
/// power-of-two bucket count with at most 7/8 of it usable, and each bucket
/// is the 16-byte value plus one control byte (plus one group of trailing
/// control bytes).
fn hash_set_bytes(capacity: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    let buckets = (capacity.saturating_mul(8) / 7).max(1).next_power_of_two();
    buckets.saturating_mul(17).saturating_add(16)
}

/// Two process-random hash keys: a collision cannot be crafted from outside.
fn hash_keys() -> &'static (
    std::collections::hash_map::RandomState,
    std::collections::hash_map::RandomState,
) {
    static KEYS: OnceLock<(
        std::collections::hash_map::RandomState,
        std::collections::hash_map::RandomState,
    )> = OnceLock::new();
    KEYS.get_or_init(|| {
        (
            std::collections::hash_map::RandomState::new(),
            std::collections::hash_map::RandomState::new(),
        )
    })
}

fn key_hash(filename: &str, sha256: &str) -> u128 {
    let (a, b) = hash_keys();
    (u128::from(a.hash_one((filename, sha256))) << 64) | u128::from(b.hash_one((filename, sha256)))
}

/// The sightings a process has already recorded for one channel.
struct KnownSet {
    hashes: Mutex<HashSet<u128>>,
    /// The channel's ledger generation the set was loaded at.
    generation: i64,
}

impl KnownSet {
    fn bytes(&self) -> usize {
        self.hashes
            .lock()
            .map(|s| hash_set_bytes(s.capacity()))
            .unwrap_or(0)
    }
}

/// The per-channel sets, bounded by [`KNOWN_CACHE_MAX_BYTES_ENV`]: past the
/// bound the least recently used channels are dropped (and reloaded on their
/// next rebuild), never the one in use. The bound covers the sets the cache
/// holds; a set a running rebuild still uses after it was dropped stays alive
/// until that rebuild ends, so the peak is the bound plus the sets of the
/// rebuilds in flight (at most the merge gate's concurrent merges).
struct KnownCache {
    max_bytes: usize,
    sets: Mutex<HashMap<i64, (Arc<KnownSet>, Instant)>>,
}

impl KnownCache {
    fn get(&self, channel: i64) -> Option<Arc<KnownSet>> {
        let mut sets = self.sets.lock().ok()?;
        let entry = sets.get_mut(&channel)?;
        entry.1 = Instant::now();
        Some(Arc::clone(&entry.0))
    }

    fn insert(&self, channel: i64, set: Arc<KnownSet>) {
        let Ok(mut sets) = self.sets.lock() else {
            return;
        };
        sets.insert(channel, (set, Instant::now()));
        let mut total: usize = sets.values().map(|(s, _)| s.bytes()).sum();
        while total > self.max_bytes && sets.len() > 1 {
            let Some((&oldest, _)) = sets
                .iter()
                .filter(|(k, _)| **k != channel)
                .min_by_key(|(_, (_, used))| *used)
            else {
                break;
            };
            if let Some((s, _)) = sets.remove(&oldest) {
                total = total.saturating_sub(s.bytes());
            }
        }
    }

    fn forget(&self, channel: i64) {
        if let Ok(mut sets) = self.sets.lock() {
            sets.remove(&channel);
        }
    }
}

fn known_cache() -> &'static KnownCache {
    static CACHE: OnceLock<KnownCache> = OnceLock::new();
    CACHE.get_or_init(|| KnownCache {
        max_bytes: std::env::var(KNOWN_CACHE_MAX_BYTES_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_KNOWN_CACHE_MAX_BYTES),
        sets: Mutex::new(HashMap::new()),
    })
}

/// One channel's ledger row.
#[derive(Debug, Clone)]
struct Channel {
    id: i64,
    /// Bumped whenever ledger rows are deleted (a repoint prune), so every
    /// replica reloads its known set instead of trusting hashes of rows that
    /// are gone.
    generation: i64,
    fingerprint: String,
    baseline_at: Option<DateTime<Utc>>,
    last_fetch_at: Option<DateTime<Utc>>,
}

async fn channel(db: &PgPool, gate: &ChannelGate, subdir: &str) -> Result<Channel, Response> {
    let row = sqlx::query(
        "INSERT INTO conda_first_seen_channels (repository_id, subdir, upstream_fingerprint) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (repository_id, subdir) DO UPDATE SET subdir = EXCLUDED.subdir \
         RETURNING id, ledger_generation, upstream_fingerprint, baseline_at, last_fetch_at",
    )
    .bind(gate.params.id)
    .bind(subdir)
    .bind(&gate.fingerprint)
    .fetch_one(db)
    .await
    .map_err(unavailable)?;
    Ok(Channel {
        id: row.try_get("id").map_err(unavailable)?,
        generation: row.try_get("ledger_generation").map_err(unavailable)?,
        fingerprint: row.try_get("upstream_fingerprint").map_err(unavailable)?,
        baseline_at: row.try_get("baseline_at").map_err(unavailable)?,
        last_fetch_at: row.try_get("last_fetch_at").map_err(unavailable)?,
    })
}

/// The channel's known sightings, streamed from the ledger on first use and
/// whenever the ledger's generation moved.
async fn known_set(db: &PgPool, ch: &Channel) -> Result<Arc<KnownSet>, Response> {
    let channel = ch.id;
    if let Some(set) = known_cache().get(channel) {
        if set.generation == ch.generation {
            return Ok(set);
        }
    }
    let mut hashes = HashSet::new();
    let mut rows =
        sqlx::query("SELECT filename, sha256 FROM conda_record_first_seen WHERE channel_id = $1")
            .bind(channel)
            .fetch(db);
    while let Some(row) = rows.try_next().await.map_err(unavailable)? {
        let filename: &str = row.try_get("filename").map_err(unavailable)?;
        let sha256: &str = row.try_get("sha256").map_err(unavailable)?;
        hashes.insert(key_hash(filename, sha256));
    }
    drop(rows);
    let set = Arc::new(KnownSet {
        hashes: Mutex::new(hashes),
        generation: ch.generation,
    });
    known_cache().insert(channel, Arc::clone(&set));
    Ok(set)
}

/// Insert the sightings in `fresh` (insert-once), `in_baseline` for a
/// baseline build, and add them to the known set.
async fn insert_sightings(
    db: &PgPool,
    channel: &Channel,
    known: &KnownSet,
    fresh: &[(&str, &str, u128)],
    in_baseline: bool,
) -> Result<(), Response> {
    for chunk in fresh.chunks(INSERT_BATCH) {
        let names: Vec<&str> = chunk.iter().map(|(f, _, _)| *f).collect();
        let shas: Vec<&str> = chunk.iter().map(|(_, s, _)| *s).collect();
        sqlx::query(
            "INSERT INTO conda_record_first_seen \
                 (channel_id, filename, sha256, prev_fetch_at, in_baseline) \
             SELECT $1, f, s, $4, $5 FROM UNNEST($2::text[], $3::text[]) AS t(f, s) \
             ON CONFLICT (channel_id, filename, sha256) DO NOTHING",
        )
        .bind(channel.id)
        .bind(&names)
        .bind(&shas)
        .bind(channel.last_fetch_at)
        .bind(in_baseline)
        .execute(db)
        .await
        .map_err(unavailable)?;
        let mut set = known.hashes.lock().map_err(unavailable)?;
        set.extend(chunk.iter().map(|(_, _, h)| *h));
    }
    Ok(())
}

/// Record the snapshot `facts` as the channel's baseline, under an advisory
/// lock on the channel so replicas build it once. Idempotent: a build
/// interrupted by a restart is finished by the next one. `Ok(false)`: another
/// replica recorded the baseline while this one waited for the lock, from its
/// own (possibly older) document; the caller then records this document's
/// files as ordinary post-baseline sightings.
async fn build_baseline(
    db: &PgPool,
    gate: &ChannelGate,
    channel: &Channel,
    facts: &[RecordFacts],
) -> Result<bool, Response> {
    let mut conn = db.acquire().await.map_err(unavailable)?;
    sqlx::query("SELECT pg_advisory_lock($1, $2::int)")
        .bind(BASELINE_LOCK_CLASS)
        .bind(channel.id as i32)
        .execute(&mut *conn)
        .await
        .map_err(unavailable)?;
    let built = async {
        let done: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT baseline_at FROM conda_first_seen_channels WHERE id = $1")
                .bind(channel.id)
                .fetch_one(db)
                .await
                .map_err(unavailable)?;
        if done.is_some() {
            return Ok(false);
        }
        let known = known_set(db, channel).await?;
        let fresh: Vec<(&str, &str, u128)> = {
            let set = known.hashes.lock().map_err(unavailable)?;
            facts
                .iter()
                .map(|f| {
                    (
                        f.filename.as_str(),
                        f.sha256.as_str(),
                        key_hash(&f.filename, &f.sha256),
                    )
                })
                .filter(|(_, _, h)| !set.contains(h))
                .collect()
        };
        insert_sightings(db, channel, &known, &fresh, true).await?;
        sqlx::query(
            "UPDATE conda_first_seen_channels SET baseline_at = NOW(), last_fetch_at = NOW() \
              WHERE id = $1 AND baseline_at IS NULL",
        )
        .bind(channel.id)
        .execute(db)
        .await
        .map_err(unavailable)?;
        tracing::info!(
            repo = %gate.params.key,
            channel = channel.id,
            files = facts.len(),
            "recorded the conda age gate baseline of a channel (#6526)"
        );
        Ok::<bool, Response>(true)
    }
    .await;
    let _ = sqlx::query("SELECT pg_advisory_unlock($1, $2::int)")
        .bind(BASELINE_LOCK_CLASS)
        .bind(channel.id as i32)
        .execute(&mut *conn)
        .await;
    built
}

/// Bring the channel's ledger up to date with `facts` and return the
/// post-baseline sightings inside the gate window. `facts` come from a
/// document that was fetched and parsed successfully: a complete snapshot.
async fn observe(
    db: &PgPool,
    gate: &ChannelGate,
    subdir: &str,
    facts: &[RecordFacts],
) -> Result<Ledger, Response> {
    let ch = channel(db, gate, subdir).await?;
    observe_channel(db, gate, subdir, facts, ch).await
}

/// [`observe`] from a channel row already read (possibly before another
/// replica changed it).
///
/// The invariant [`classify`] relies on: when this returns, every file of
/// `facts` has a ledger row, so a file outside the returned window is a
/// baseline file or one first seen before the window. A file that has no
/// row yet is inserted here as a post-baseline sighting (first seen now),
/// never counted as baseline, including when another replica recorded the
/// baseline from an older document while this one waited for the lock.
async fn observe_channel(
    db: &PgPool,
    gate: &ChannelGate,
    subdir: &str,
    facts: &[RecordFacts],
    mut ch: Channel,
) -> Result<Ledger, Response> {
    if ch.fingerprint != gate.fingerprint {
        ch = repointed(db, gate, &ch, facts).await?;
    }
    if ch.baseline_at.is_none() {
        if build_baseline(db, gate, &ch, facts).await? {
            return Ok(Ledger {
                young: young_sightings(db, gate, ch.id).await?,
                rowless: HashSet::new(),
            });
        }
        // Lost the race: re-read the channel (its last read time and
        // generation), then record this document's other files below.
        ch = channel(db, gate, subdir).await?;
    }
    let known = known_set(db, &ch).await?;
    let fresh: Vec<(&str, &str, u128)> = {
        let set = known.hashes.lock().map_err(unavailable)?;
        facts
            .iter()
            .map(|f| {
                (
                    f.filename.as_str(),
                    f.sha256.as_str(),
                    key_hash(&f.filename, &f.sha256),
                )
            })
            .filter(|(_, _, h)| !set.contains(h))
            .collect()
    };
    insert_sightings(db, &ch, &known, &fresh, false).await?;
    if !fresh.is_empty() {
        known_cache().insert(ch.id, Arc::clone(&known));
        tracing::info!(
            repo = %gate.params.key,
            subdir,
            new_files = fresh.len(),
            "recorded new conda file sightings for the age gate (#6526)"
        );
    }
    // A prune on another replica may have committed after this one read the
    // channel: its known set then still holds hashes of rows that are gone,
    // and the insert above skipped them. When the generation moved, find
    // every file of the document that has no row (one query, only in that
    // case), record it, and tell `classify` it is first seen now.
    let mut rowless = HashSet::new();
    let generation: i64 =
        sqlx::query_scalar("SELECT ledger_generation FROM conda_first_seen_channels WHERE id = $1")
            .bind(ch.id)
            .fetch_one(db)
            .await
            .map_err(unavailable)?;
    if generation != known.generation {
        let names: Vec<&str> = facts.iter().map(|f| f.filename.as_str()).collect();
        let shas: Vec<&str> = facts.iter().map(|f| f.sha256.as_str()).collect();
        let missing: Vec<(String, String)> = sqlx::query_as(
            "SELECT t.f, t.h FROM UNNEST($2::text[], $3::text[]) AS t(f, h) \
              WHERE NOT EXISTS (SELECT 1 FROM conda_record_first_seen s \
                                 WHERE s.channel_id = $1 AND s.filename = t.f \
                                   AND s.sha256 = t.h)",
        )
        .bind(ch.id)
        .bind(&names)
        .bind(&shas)
        .fetch_all(db)
        .await
        .map_err(unavailable)?;
        known_cache().forget(ch.id);
        if !missing.is_empty() {
            let refreshed = Channel {
                generation,
                ..ch.clone()
            };
            let reloaded = known_set(db, &refreshed).await?;
            let rows: Vec<(&str, &str, u128)> = missing
                .iter()
                .map(|(f, h)| (f.as_str(), h.as_str(), key_hash(f, h)))
                .collect();
            insert_sightings(db, &refreshed, &reloaded, &rows, false).await?;
            tracing::warn!(
                repo = %gate.params.key,
                subdir,
                files = missing.len(),
                "conda age gate ledger changed during a rebuild; files without a sighting \
                 are first seen now (#6526)"
            );
        }
        rowless = missing.into_iter().collect();
    }
    sqlx::query("UPDATE conda_first_seen_channels SET last_fetch_at = NOW() WHERE id = $1")
        .bind(ch.id)
        .execute(db)
        .await
        .map_err(unavailable)?;
    Ok(Ledger {
        young: young_sightings(db, gate, ch.id).await?,
        rowless,
    })
}

/// What the ledger update tells [`classify_with_rows`].
pub(super) struct Ledger {
    /// Post-baseline sightings inside the gate window.
    pub young: HashMap<(String, String), Sighting>,
    /// Files the update found with no row (first seen now).
    pub rowless: HashSet<(String, String)>,
}

async fn young_sightings(
    db: &PgPool,
    gate: &ChannelGate,
    channel: i64,
) -> Result<HashMap<(String, String), Sighting>, Response> {
    let min_age = gate.params.age_gate_min_age_days;
    if min_age <= 0 {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        "SELECT filename, sha256, first_seen_at, prev_fetch_at FROM conda_record_first_seen \
          WHERE channel_id = $1 AND NOT in_baseline \
            AND first_seen_at > NOW() - make_interval(days => $2) - make_interval(secs => $3)",
    )
    .bind(channel)
    .bind(min_age)
    .bind(refresh_cap().num_seconds() as f64)
    .fetch_all(db)
    .await
    .map_err(unavailable)?;
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        out.insert(
            (
                row.try_get::<String, _>("filename").map_err(unavailable)?,
                row.try_get::<String, _>("sha256").map_err(unavailable)?,
            ),
            Sighting {
                first_seen: row.try_get("first_seen_at").map_err(unavailable)?,
                prev_fetch: row.try_get("prev_fetch_at").map_err(unavailable)?,
            },
        );
    }
    Ok(out)
}

/// The remote now reads another upstream. The baseline stays (a repoint is
/// never a silent re-baseline): files of the new upstream that the ledger
/// does not hold are new sightings and are held. Sightings of files the new
/// upstream's complete snapshot does not list are pruned; files it lists are
/// never pruned. `facts` is always a complete snapshot (a fetched, parsed
/// document): an upstream answer that could not be read never reaches here.
/// The prune bumps the channel's ledger generation, so every replica reloads
/// its set of known sightings.
async fn repointed(
    db: &PgPool,
    gate: &ChannelGate,
    ch: &Channel,
    facts: &[RecordFacts],
) -> Result<Channel, Response> {
    let names: Vec<&str> = facts.iter().map(|f| f.filename.as_str()).collect();
    let shas: Vec<&str> = facts.iter().map(|f| f.sha256.as_str()).collect();
    let mut tx = db.begin().await.map_err(unavailable)?;
    let pruned = sqlx::query(
        "DELETE FROM conda_record_first_seen s \
          WHERE s.channel_id = $1 \
            AND NOT EXISTS (SELECT 1 FROM UNNEST($2::text[], $3::text[]) AS t(f, h) \
                             WHERE t.f = s.filename AND t.h = s.sha256)",
    )
    .bind(ch.id)
    .bind(&names)
    .bind(&shas)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?
    .rows_affected();
    let generation: i64 = sqlx::query_scalar(
        "UPDATE conda_first_seen_channels \
            SET upstream_fingerprint = $2, ledger_generation = ledger_generation + 1 \
          WHERE id = $1 RETURNING ledger_generation",
    )
    .bind(ch.id)
    .bind(&gate.fingerprint)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    known_cache().forget(ch.id);
    tracing::warn!(
        repo = %gate.params.key,
        channel = ch.id,
        pruned,
        "conda remote now reads another upstream; its age gate baseline is kept and files \
         not seen before are held (#6526)"
    );
    Ok(Channel {
        generation,
        fingerprint: gate.fingerprint.clone(),
        ..ch.clone()
    })
}

/// Drop every ledger of `repo_id`, so each subdir takes a new baseline on its
/// next read: the explicit re-baseline action. Returns the channels dropped.
pub(crate) async fn rebaseline(db: &PgPool, repo_id: Uuid) -> Result<u64, Response> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "DELETE FROM conda_first_seen_channels WHERE repository_id = $1 RETURNING id",
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(unavailable)?;
    for id in &ids {
        known_cache().forget(*id);
    }
    bump_epoch(repo_id);
    Ok(ids.len() as u64)
}

/// A process-local generation per repository, bumped by a re-baseline so
/// this process stops serving the document built from the dropped ledger at
/// once (other replicas rebuild when their kept document goes stale).
fn epochs() -> &'static Mutex<HashMap<Uuid, u64>> {
    static EPOCHS: OnceLock<Mutex<HashMap<Uuid, u64>>> = OnceLock::new();
    EPOCHS.get_or_init(Default::default)
}

fn bump_epoch(repo_id: Uuid) {
    if let Ok(mut e) = epochs().lock() {
        *e.entry(repo_id).or_default() += 1;
    }
}

fn epoch(repo_id: Uuid) -> u64 {
    epochs()
        .lock()
        .map(|e| e.get(&repo_id).copied().unwrap_or(0))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The gated document
// ---------------------------------------------------------------------------

/// A gated Remote's `repodata.json` for `subdir`: the upstream document with
/// every withheld record left out, kept in the canonical zstd encoding with
/// the other encodings derived on demand, and the withheld and listed files
/// attached ([`MergedDocument::withheld`]). Kept while the upstream document
/// in the proxy cache is unchanged and fresh; each revalidation of it
/// re-evaluates the gate.
pub(super) async fn gated_repodata(
    db: &PgPool,
    proxy: Option<Arc<crate::services::proxy_service::ProxyService>>,
    remote: &Repository,
    gate: Arc<ChannelGate>,
    subdir: &str,
) -> Result<Arc<MergedDocument>, Response> {
    let kind = MergeKind::Repodata;
    let document = format!("{subdir}/repodata.json");
    let mut key = MergeKeyBuilder::new(kind);
    key.part(b"conda-age-gate")
        .part(remote.id.as_bytes())
        .part(remote.key.as_bytes())
        .part(
            remote
                .upstream_url
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        )
        .part(document.as_bytes())
        .part(&epoch(remote.id).to_le_bytes());
    gate.key_part(&mut key);
    let validate_proxy = proxy.clone();
    let remote = remote.clone();
    let subdir = subdir.to_string();
    let db = db.clone();
    merge_gate::gate_for(remote.id)
        .get_or_merge(
            kind,
            key.finish(),
            Some(format!("{}/{document}#age-gate", remote.id)),
            move |doc| validators_fresh(validate_proxy, doc),
            move |mut account| async move {
                let Some(proxy) = proxy else {
                    return Err(unavailable("the proxy service is not available"));
                };
                let (doc, published) = virtual_merge::fetch_member_document(
                    &proxy,
                    &remote,
                    &virtual_merge::repodata_candidates(&subdir),
                    virtual_merge::MemberLimits::from_env(),
                    true,
                    &mut account,
                )
                .await
                .map_err(|f| member_failure_response(&remote.key, &f))?;
                build_gated(
                    &db,
                    &remote.key,
                    &gate,
                    &subdir,
                    doc,
                    published,
                    &mut account,
                )
                .await
            },
        )
        .await
        .map_err(merge_gate::SharedResponse::into_response)
}

/// Filter one decoded upstream document through `gate`.
async fn build_gated(
    db: &PgPool,
    repo_key: &str,
    gate: &Arc<ChannelGate>,
    subdir: &str,
    doc: virtual_merge::MemberDocument,
    published: bool,
    account: &mut merge_gate::MergeAccount,
) -> Result<MergedDocument, Response> {
    let decoded_bytes = doc.json.len();
    let validator = doc.validator.clone();
    let doc = Arc::new(doc);
    let parse_doc = Arc::clone(&doc);
    // An upstream that does not publish the subdir answers with the empty
    // stand-in document: nothing to parse, record or refuse.
    let facts = tokio::task::spawn_blocking(move || {
        if published {
            record_facts(&parse_doc.json)
        } else {
            Ok(Vec::new())
        }
    })
    .await
    .map_err(unavailable)?
    .map_err(|e| {
        if e == EMPTY_DOCUMENT {
            tracing::warn!(
                repo = %repo_key,
                subdir,
                "upstream conda repodata parses but lists nothing and has no info; \
                 refusing it and keeping the age gate's previous state (#6526)"
            );
        }
        (
            StatusCode::BAD_GATEWAY,
            format!("Remote conda repository '{repo_key}': upstream {subdir}/repodata.json {e}"),
        )
            .into_response()
    })?;
    let facts_bytes: usize = facts.iter().map(RecordFacts::bytes).sum();
    account.track(facts_bytes);
    // An upstream that does not publish the subdir has no snapshot to take.
    let ledger = if published {
        observe(db, gate, subdir, &facts).await?
    } else {
        Ledger {
            young: HashMap::new(),
            rowless: HashSet::new(),
        }
    };
    let records = classify_with_rows(
        gate,
        &facts,
        &ledger.young,
        &ledger.rowless,
        Utc::now(),
        refresh_cap(),
    );
    let listed: HashSet<u128> = facts.iter().map(|f| key_hash(&f.filename, "")).collect();
    drop(facts);
    account.release(facts_bytes);
    if !records.is_empty() {
        crate::services::metrics_service::record_age_gate_filtered_metadata(repo_key, "conda");
    }
    account.track(merge_gate::merge_working_set(decoded_bytes, false));
    let withheld_names: HashSet<String> = records.keys().cloned().collect();
    let merge_key = repo_key.to_string();
    let merge_subdir = subdir.to_string();
    let (body, failures, _) = tokio::task::spawn_blocking(move || {
        let docs = std::slice::from_ref(doc.as_ref());
        virtual_merge::merge_repodata_withholding(
            &merge_key,
            &merge_subdir,
            &[],
            docs,
            &HashSet::new(),
            None,
            &withheld_names,
        )
    })
    .await
    .map_err(unavailable)?;
    if let Some(failure) = failures.first() {
        return Err(member_failure_response(repo_key, failure));
    }
    let virtual_merge::MergedBody {
        bytes: body,
        plain_len,
    } = body?;
    let stats = merge_gate::MergeStats {
        decoded_bytes,
        output_bytes: body.len(),
        reserved: account.reserved(),
        peak_need: account.peak_need(),
    };
    let all_validated = validator.is_some();
    Ok(MergedDocument::new(
        body,
        Vec::new(),
        None,
        validator.into_iter().collect(),
        all_validated,
        stats,
        false,
    )
    .with_renderings(plain_len)
    .with_withheld(Withheld {
        published,
        records,
        listed,
    }))
}

async fn validators_fresh(
    proxy: Option<Arc<crate::services::proxy_service::ProxyService>>,
    doc: Arc<MergedDocument>,
) -> bool {
    let Some(proxy) = proxy else {
        return false;
    };
    for v in &doc.validators {
        if proxy
            .fresh_cache_validator(&v.member, &v.path)
            .await
            .as_deref()
            != Some(v.checksum.as_str())
        {
            return false;
        }
    }
    true
}

/// A Remote's own upstream failure, answered as the client's failure.
pub(super) fn member_failure_response(repo_key: &str, failure: &MemberFailure) -> Response {
    tracing::warn!(
        repo = %repo_key,
        kind = failure.kind,
        reason = %failure.reason,
        "gated conda remote could not read its upstream repodata"
    );
    (
        StatusCode::BAD_GATEWAY,
        format!(
            "Remote conda repository '{repo_key}' cannot serve its repodata: {}",
            failure.reason
        ),
    )
        .into_response()
}

/// The withheld records a gated document carries (`None` for any other).
pub(super) fn withheld_count(doc: &MergedDocument) -> Option<usize> {
    doc.withheld.as_ref().map(|w| w.records.len())
}

/// What the package route decides for one file of a gated Remote.
pub(super) enum DownloadVerdict {
    /// The index serves it.
    Listed,
    /// The upstream index does not list it: a gated Remote does not serve it.
    Unlisted,
}

/// The `404` a gated Remote answers for a file its upstream index does not
/// list: files appear on the package route only once the index has listed
/// them and the gate has dated them.
pub(super) fn unlisted_response(filename: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::json!({
            "error": "age_gate_unlisted",
            "file": filename,
            "message": "The channel's index does not list this file, so the age gate cannot \
                        date it; it is served once the index lists it and it is old enough",
        })
        .to_string(),
    )
        .into_response()
}

/// Decide a download of `filename` from a gated Remote: the shared `451
/// age_gate_blocked` (with the age basis and the date it becomes available)
/// for a withheld file, [`DownloadVerdict::Unlisted`] for one the upstream
/// index does not list, else [`DownloadVerdict::Listed`]. A decision recorded
/// since the document was built is honored, because the final call goes
/// through [`AgeGateService::check`].
pub(super) async fn check_download(
    state: &crate::api::SharedState,
    remote: &Repository,
    gate: Arc<ChannelGate>,
    subdir: &str,
    filename: &str,
) -> Result<DownloadVerdict, Response> {
    let doc = gated_repodata(
        &state.db,
        state.proxy_service.clone(),
        remote,
        Arc::clone(&gate),
        subdir,
    )
    .await?;
    let Some(withheld) = doc.withheld.as_ref() else {
        return Ok(DownloadVerdict::Unlisted);
    };
    let Some(record) = withheld.records.get(filename) else {
        return Ok(if withheld.lists(filename) {
            DownloadVerdict::Listed
        } else {
            DownloadVerdict::Unlisted
        });
    };
    let Some(svc) = state.age_gate_service.as_deref() else {
        return Err(
            crate::api::handlers::proxy_helpers::age_gate_unavailable_response(
                &gate.params.key,
                &record.name,
            ),
        );
    };
    // Rejections and suspicious timestamps never pass on age: the review
    // decides them with no basis.
    let basis = match record.reason {
        WithheldReason::TooYoung => record.basis,
        _ => None,
    };
    match svc
        .check(&gate.params, &record.name, &record.version, basis)
        .await
        .map_err(|e| e.into_response())?
    {
        // An approval recorded since the document was built.
        crate::services::age_gate_service::AgeGateDecision::Allow => Ok(DownloadVerdict::Listed),
        crate::services::age_gate_service::AgeGateDecision::Block { review_id, .. } => {
            Err(blocked_response(review_id, &gate, record))
        }
    }
}

fn blocked_response(review_id: Uuid, gate: &ChannelGate, record: &WithheldRecord) -> Response {
    let mut body = crate::api::handlers::proxy_helpers::age_gate_blocked_body(
        review_id,
        &record.name,
        &record.version,
        gate.params.age_gate_min_age_days,
        record
            .basis
            .map(|b| AgeGateService::package_age_days(b, Utc::now())),
    );
    body["reason"] = serde_json::json!(record.reason);
    body["age_basis"] = serde_json::json!(record.age_basis);
    body["basis_at"] = serde_json::json!(record.basis);
    body["available_at"] = serde_json::json!(record.available_at);
    body["backdated_indexed_timestamp"] = serde_json::json!(record.backdated);
    (
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// One withheld file, as the admin lookup reports it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WithheldReport {
    pub filename: String,
    pub name: String,
    pub version: String,
    /// `too_young`, `rejected`, `timestamp_in_future` or `indexed_before_built`.
    pub reason: String,
    /// `indexed`, `first_seen`, `baseline` or `none`.
    pub age_basis: String,
    pub basis_at: Option<DateTime<Utc>>,
    pub available_at: Option<DateTime<Utc>>,
    pub backdated_indexed_timestamp: bool,
}

/// Every file a gated Remote's `subdir` withholds now, or just `filename`.
/// `Ok(None)`: the repository is not a gated conda Remote.
pub(crate) async fn withheld_report(
    state: &crate::api::SharedState,
    repo_id: Uuid,
    subdir: &str,
    filename: Option<&str>,
) -> Result<Option<Vec<WithheldReport>>, Response> {
    let Some(gate) = load_gate(&state.db, repo_id).await? else {
        return Ok(None);
    };
    let Some(upstream_url) = gate.params.upstream_url.clone() else {
        return Ok(None);
    };
    let remote = crate::api::handlers::proxy_helpers::build_remote_repo_with_format(
        repo_id,
        &gate.params.key,
        &upstream_url,
        crate::models::repository::RepositoryFormat::Conda,
    );
    let doc = gated_repodata(
        &state.db,
        state.proxy_service.clone(),
        &remote,
        Arc::clone(&gate),
        subdir,
    )
    .await?;
    let label = |v: serde_json::Value| v.as_str().unwrap_or_default().to_string();
    let mut out: Vec<WithheldReport> = doc
        .withheld
        .as_ref()
        .map(|w| {
            w.records
                .iter()
                .filter(|(f, _)| filename.is_none_or(|want| want == f.as_str()))
                .map(|(f, r)| WithheldReport {
                    filename: f.clone(),
                    name: r.name.clone(),
                    version: r.version.clone(),
                    reason: label(serde_json::json!(r.reason)),
                    age_basis: label(serde_json::json!(r.age_basis)),
                    basis_at: r.basis,
                    available_at: r.available_at,
                    backdated_indexed_timestamp: r.backdated,
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(Some(out))
}

/// The CEP-16 shards of a kept `repodata.json` (a gated Remote's, or a
/// Virtual's merge over a gated member): built from that document's records
/// and kept with it, so the shard index lists exactly what `repodata.json`
/// serves. Keyed by the document's ETag.
pub(super) async fn derived_shards(
    repo_id: Uuid,
    subdir: &str,
    merged: Arc<MergedDocument>,
) -> Result<Arc<MergedDocument>, Response> {
    let kind = MergeKind::ShardIndex;
    let mut key = MergeKeyBuilder::new(kind);
    key.part(b"conda-age-gate-shards")
        .part(repo_id.as_bytes())
        .part(subdir.as_bytes())
        .part(merged.etag.as_bytes());
    let subdir = subdir.to_string();
    merge_gate::gate_for(repo_id)
        .get_or_merge(
            kind,
            key.finish(),
            None,
            |_| async { true },
            move |mut account| async move {
                let body = merged.body.clone();
                let plain_len = merged.output_plain_len();
                account.track(merge_gate::merge_working_set(plain_len, false));
                let built_subdir = subdir.clone();
                let (index, shards) = tokio::task::spawn_blocking(move || {
                    let fail = |e: super::shard_synth::SynthError| {
                        virtual_merge::internal_error(format!("{e:?}"))
                    };
                    let (partitions, _) = super::shard_synth::spill_document(
                        body,
                        None,
                        super::RepodataEncoding::Zst,
                    )
                    .map_err(fail)?;
                    let mut by_name = std::collections::BTreeMap::new();
                    let mut shards = HashMap::new();
                    for path in &partitions.paths {
                        for (name, bytes, address) in
                            super::shard_synth::shards_of_partition(path).map_err(fail)?
                        {
                            by_name.insert(name, address.to_vec());
                            shards.insert(address.to_vec(), bytes::Bytes::from(bytes));
                        }
                    }
                    let index = super::serialize_msgpack_zst(&super::build_sharded_index(
                        &built_subdir,
                        &by_name,
                    ))?;
                    Ok::<_, Response>((index, shards))
                })
                .await
                .map_err(virtual_merge::internal_error)??;
                let stats = merge_gate::MergeStats {
                    decoded_bytes: plain_len,
                    output_bytes: index.len() + shards.values().map(|s| s.len()).sum::<usize>(),
                    reserved: account.reserved(),
                    peak_need: account.peak_need(),
                };
                Ok(MergedDocument::new(
                    index,
                    merged.failed.clone(),
                    merged.allowlist_dropped,
                    merged.validators.clone(),
                    merged.cacheable,
                    stats,
                    false,
                )
                .with_derived_shards(shards))
            },
        )
        .await
        .map_err(merge_gate::SharedResponse::into_response)
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::repository::RepositoryFormat;

    fn params(mode: AgeGateMode, min_age: i32) -> AgeGateRepoParams {
        AgeGateRepoParams::from_parts(
            Uuid::new_v4(),
            "remote",
            RepositoryType::Remote,
            RepositoryFormat::Conda,
            true,
            min_age,
            mode,
            Some("https://conda.example/channel".to_string()),
        )
    }

    fn facts(
        filename: &str,
        indexed: Option<DateTime<Utc>>,
        built: Option<DateTime<Utc>>,
    ) -> RecordFacts {
        let (n, v) = crate::services::conda_allowlist::split_conda_filename(filename).unwrap();
        RecordFacts {
            filename: filename.to_string(),
            sha256: format!("sha-{filename}"),
            name: n.to_string(),
            version: v.to_string(),
            indexed,
            built,
        }
    }

    fn sighting(
        f: &RecordFacts,
        first_seen: DateTime<Utc>,
        prev: Option<DateTime<Utc>>,
    ) -> ((String, String), Sighting) {
        (
            (f.filename.clone(), f.sha256.clone()),
            Sighting {
                first_seen,
                prev_fetch: prev,
            },
        )
    }

    const CAP: i64 = 300;

    fn withheld(
        gate: &ChannelGate,
        all: &[RecordFacts],
        young: &HashMap<(String, String), Sighting>,
        now: DateTime<Utc>,
    ) -> Vec<String> {
        let mut v: Vec<String> = classify(gate, all, young, now, Duration::seconds(CAP))
            .into_keys()
            .collect();
        v.sort();
        v
    }

    #[test]
    fn record_times_are_milliseconds_with_a_seconds_fallback() {
        let want = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        assert_eq!(
            parse_record_time(&serde_json::json!(1_700_000_000_000u64)),
            Some(want)
        );
        assert_eq!(
            parse_record_time(&serde_json::json!(1_700_000_000u64)),
            Some(want)
        );
        assert_eq!(parse_record_time(&serde_json::json!("1700000000")), None);
        assert_eq!(parse_record_time(&serde_json::json!(-5)), None);
        assert_eq!(parse_record_time(&serde_json::json!(0)), None);
    }

    #[test]
    fn record_facts_reads_both_maps_and_a_missing_map_is_empty() {
        let json = br#"{"info":{"subdir":"noarch"},
            "packages":{"a-1.0-0.tar.bz2":{"name":"a","version":"1.0","sha256":"AB","indexed_timestamp":1700000000000,"timestamp":1600000000000}},
            "packages.conda":{"b-2.0-py_0.conda":{}}}"#;
        let mut got = record_facts(json).unwrap();
        got.sort_by(|x, y| x.filename.cmp(&y.filename));
        assert_eq!(got[0].sha256, "ab");
        assert_eq!(
            got[0].indexed,
            Some(Utc.timestamp_opt(1_700_000_000, 0).unwrap())
        );
        assert_eq!(
            got[0].built,
            Some(Utc.timestamp_opt(1_600_000_000, 0).unwrap())
        );
        assert_eq!(
            (got[1].name.as_str(), got[1].version.as_str()),
            ("b", "2.0")
        );
        assert!(
            record_facts(br#"{"packages":{"x-1-0.tar.bz2":{}}}"#)
                .unwrap()
                .len()
                == 1,
            "a document without packages.conda is a channel with no .conda files"
        );
        assert!(record_facts(b"not json").is_err());
    }

    #[test]
    fn baseline_files_are_old_unless_a_timestamp_is_recent() {
        let now = Utc::now();
        let gate =
            ChannelGate::for_test(params(AgeGateMode::UpstreamPublishTime, 7), vec![], vec![]);
        let old = facts("old-1.0-0.conda", None, Some(now - Duration::days(400)));
        let plain = facts("plain-1.0-0.conda", None, None);
        let recent_build = facts("rb-1.0-0.conda", None, Some(now - Duration::hours(2)));
        let recent_index = facts("ri-1.0-0.conda", Some(now - Duration::hours(2)), None);
        let all = [old, plain, recent_build, recent_index];
        assert_eq!(
            withheld(&gate, &all, &HashMap::new(), now),
            vec!["rb-1.0-0.conda", "ri-1.0-0.conda"],
            "the baseline is not emptied; only a recent timestamp holds a baseline file"
        );
        let r =
            &classify(&gate, &all, &HashMap::new(), now, Duration::seconds(CAP))["rb-1.0-0.conda"];
        assert_eq!(r.age_basis, BasisKind::Baseline);
        assert_eq!(
            r.available_at,
            Some(now - Duration::hours(2) + Duration::days(7))
        );
    }

    #[test]
    fn a_post_baseline_sighting_is_aged_from_the_sighting() {
        let now = Utc::now();
        let gate =
            ChannelGate::for_test(params(AgeGateMode::UpstreamPublishTime, 7), vec![], vec![]);
        let backdated = facts("bd-1.0-0.conda", Some(now - Duration::days(300)), None);
        let fair = facts("fair-1.0-0.conda", Some(now - Duration::seconds(60)), None);
        let aged = facts("aged-1.0-0.conda", None, None);
        let young: HashMap<_, _> = [
            sighting(
                &backdated,
                now - Duration::hours(1),
                Some(now - Duration::hours(2)),
            ),
            sighting(
                &fair,
                now - Duration::seconds(30),
                Some(now - Duration::seconds(120)),
            ),
            sighting(
                &aged,
                now - Duration::days(8),
                Some(now - Duration::days(8)),
            ),
        ]
        .into_iter()
        .collect();
        let out = classify(
            &gate,
            &[backdated.clone(), fair.clone(), aged],
            &young,
            now,
            Duration::seconds(CAP),
        );
        let bd = &out["bd-1.0-0.conda"];
        assert!(
            bd.backdated,
            "an indexed_timestamp before the sighting is flagged"
        );
        assert_eq!(bd.age_basis, BasisKind::FirstSeen);
        assert_eq!(
            bd.basis,
            Some(now - Duration::hours(1) - Duration::seconds(CAP))
        );
        let fr = &out["fair-1.0-0.conda"];
        assert_eq!(
            fr.age_basis,
            BasisKind::Indexed,
            "credit up to the previous read"
        );
        assert!(!fr.backdated);
        assert!(
            !out.contains_key("aged-1.0-0.conda"),
            "a sighting past the window is old"
        );
    }

    #[test]
    fn a_new_sha256_is_a_new_sighting() {
        let now = Utc::now();
        let gate =
            ChannelGate::for_test(params(AgeGateMode::UpstreamPublishTime, 7), vec![], vec![]);
        let mut swapped = facts("old-1.0-0.conda", None, None);
        swapped.sha256 = "new-bytes".into();
        let young: HashMap<_, _> = [sighting(&swapped, now, Some(now - Duration::seconds(10)))]
            .into_iter()
            .collect();
        assert_eq!(
            withheld(&gate, &[swapped], &young, now),
            vec!["old-1.0-0.conda"]
        );
    }

    #[test]
    fn a_file_without_a_ledger_row_is_first_seen_now() {
        let now = Utc::now();
        let gate =
            ChannelGate::for_test(params(AgeGateMode::UpstreamPublishTime, 7), vec![], vec![]);
        let back = facts("back-1.0-0.conda", Some(now - Duration::days(300)), None);
        let rowless: HashSet<(String, String)> = [(back.filename.clone(), back.sha256.clone())]
            .into_iter()
            .collect();
        let out = classify_with_rows(
            &gate,
            std::slice::from_ref(&back),
            &HashMap::new(),
            &rowless,
            now,
            Duration::seconds(CAP),
        );
        let r = &out["back-1.0-0.conda"];
        assert_eq!(
            r.age_basis,
            BasisKind::FirstSeen,
            "never counted as baseline"
        );
        assert!(r.backdated);
        assert!(
            classify(&gate, &[back], &HashMap::new(), now, Duration::seconds(CAP)).is_empty(),
            "with a row outside the window the same file is old"
        );
    }

    #[test]
    fn a_document_with_no_packages_and_no_info_is_refused() {
        assert_eq!(record_facts(b"{}").unwrap_err(), EMPTY_DOCUMENT);
        assert!(record_facts(br#"{"info":{"subdir":"noarch"}}"#)
            .unwrap()
            .is_empty());
        assert!(record_facts(br#"{"packages":{}}"#).unwrap().is_empty());
    }

    #[test]
    fn suspicious_timestamps_are_held() {
        let now = Utc::now();
        let gate =
            ChannelGate::for_test(params(AgeGateMode::UpstreamPublishTime, 7), vec![], vec![]);
        let future = facts("fut-1.0-0.conda", None, Some(now + Duration::days(1)));
        let order = facts(
            "ord-1.0-0.conda",
            Some(now - Duration::days(30)),
            Some(now - Duration::days(20)),
        );
        let out = classify(
            &gate,
            &[future, order],
            &HashMap::new(),
            now,
            Duration::seconds(CAP),
        );
        assert_eq!(
            out["fut-1.0-0.conda"].reason,
            WithheldReason::TimestampInFuture
        );
        assert_eq!(
            out["ord-1.0-0.conda"].reason,
            WithheldReason::IndexedBeforeBuilt
        );
    }

    #[test]
    fn first_seen_mode_earns_no_indexed_credit() {
        let now = Utc::now();
        let gate = ChannelGate::for_test(params(AgeGateMode::FirstSeen, 7), vec![], vec![]);
        let f = facts("x-1.0-0.conda", Some(now - Duration::seconds(10)), None);
        let young: HashMap<_, _> = [sighting(&f, now, Some(now - Duration::seconds(60)))]
            .into_iter()
            .collect();
        let out = classify(&gate, &[f], &young, now, Duration::seconds(CAP));
        assert_eq!(out["x-1.0-0.conda"].age_basis, BasisKind::FirstSeen);
    }

    #[test]
    fn decisions_override_age_and_zero_days_holds_only_rejections() {
        let now = Utc::now();
        let gate = ChannelGate::for_test(
            params(AgeGateMode::UpstreamPublishTime, 7),
            vec![("new".to_string(), "1.0".to_string())],
            vec![("old".to_string(), "1.0".to_string())],
        );
        let old = facts("old-1.0-0.conda", None, None);
        let new = facts("new-1.0-0.conda", Some(now), None);
        let young: HashMap<_, _> = [sighting(&new, now, Some(now))].into_iter().collect();
        assert_eq!(
            withheld(&gate, &[old.clone(), new], &young, now),
            vec!["old-1.0-0.conda"]
        );
        let zero = ChannelGate::for_test(
            params(AgeGateMode::UpstreamPublishTime, 0),
            vec![],
            vec![("old".to_string(), "1.0".to_string())],
        );
        let fut = facts("fut-1.0-0.conda", None, Some(now + Duration::days(1)));
        assert_eq!(
            withheld(&zero, &[old, fut], &HashMap::new(), now),
            vec!["old-1.0-0.conda"]
        );
    }

    #[test]
    fn the_key_moves_with_policy_and_decisions() {
        let p = params(AgeGateMode::UpstreamPublishTime, 7);
        let a = ChannelGate::for_test(p.clone(), vec![], vec![]);
        let b = ChannelGate::for_test(p.clone(), vec![("n".into(), "1".into())], vec![]);
        let c = ChannelGate::for_test(p.clone(), vec![], vec![("n".into(), "1".into())]);
        let mut p2 = p.clone();
        p2.age_gate_min_age_days = 8;
        let d = ChannelGate::for_test(p2, vec![], vec![]);
        let digests = [a.digest, b.digest, c.digest, d.digest];
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(digests[i], digests[j]);
            }
        }
    }

    #[test]
    fn key_hashes_cover_filename_and_sha256() {
        assert_eq!(key_hash("a-1-0.conda", "x"), key_hash("a-1-0.conda", "x"));
        assert_ne!(key_hash("a-1-0.conda", "x"), key_hash("a-1-0.conda", "y"));
        assert_ne!(key_hash("a-1-0.conda", ""), key_hash("a-1-1.conda", ""));
    }

    #[test]
    fn the_known_cache_evicts_the_least_recently_used_channel() {
        let set = || {
            Arc::new(KnownSet {
                hashes: Mutex::new((0..50u128).collect()),
                generation: 0,
            })
        };
        // Room for two sets, not three.
        let cache = KnownCache {
            max_bytes: 2 * set().bytes() + 1,
            sets: Mutex::new(HashMap::new()),
        };
        cache.insert(1, set());
        cache.insert(2, set());
        let _ = cache.get(1);
        cache.insert(3, set());
        assert!(cache.get(2).is_none(), "the least recently used goes first");
        assert!(cache.get(1).is_some() && cache.get(3).is_some());
    }

    /// The ledger (#6526): the baseline is taken once and keeps the channel
    /// served; a replica that loses the baseline race still records its own
    /// newer files as sightings; a later file and a swapped sha256 are young
    /// sightings; a repoint keeps the baseline, prunes only unlisted files and
    /// moves the ledger generation.
    #[tokio::test]
    async fn the_ledger_takes_one_baseline_and_records_later_sightings() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let key = format!("cgate-{}", Uuid::new_v4().simple());
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO repositories (key, name, format, repo_type, storage_path, upstream_url, \
                                       age_gate_enabled, age_gate_min_age_days, age_gate_mode) \
             VALUES ($1, $1, 'conda', 'remote', '/tmp/cgate', 'https://conda.example/c', \
                     true, 7, 'upstream_publish_time') RETURNING id",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("insert repository");
        let gates = load_gates(&pool, &[id]).await.expect("load gates");
        let gate = gates.get(&id).expect("gated remote").clone();
        assert_eq!(gate.params.format, RepositoryFormat::Conda);

        let a = facts("a-1.0-0.conda", None, None);
        let b = facts("b-1.0-0.conda", None, None);
        // Two replicas race for the baseline: both read the channel before
        // either recorded it. Replica 1 records it from its document.
        let stale = channel(&pool, &gate, "noarch").await.expect("channel");
        assert!(stale.baseline_at.is_none());
        let young = observe(&pool, &gate, "noarch", &[a.clone(), b.clone()])
            .await
            .expect("baseline")
            .young;
        assert!(young.is_empty(), "baseline files are not young sightings");
        // Replica 2 waited on the lock with a newer document listing `n`; it
        // must record `n` as a sighting, never let it pass as baseline.
        let n = facts(
            "n-1.0-0.conda",
            Some(Utc::now() - Duration::days(300)),
            None,
        );
        known_cache().forget(stale.id);
        let young = observe_channel(
            &pool,
            &gate,
            "noarch",
            &[a.clone(), b.clone(), n.clone()],
            stale,
        )
        .await
        .expect("observe after losing the baseline race")
        .young;
        assert!(
            young.contains_key(&(n.filename.clone(), n.sha256.clone())),
            "a file the baseline did not hold is first seen now"
        );
        let out = classify(
            &gate,
            std::slice::from_ref(&n),
            &young,
            Utc::now(),
            refresh_cap(),
        );
        assert!(
            out["n-1.0-0.conda"].backdated,
            "its old indexed_timestamp earns no credit"
        );

        let c = facts("c-1.0-0.conda", None, None);
        let mut a2 = a.clone();
        a2.sha256 = "swapped".into();
        let young = observe(&pool, &gate, "noarch", &[a2.clone(), b.clone(), c.clone()])
            .await
            .expect("observe")
            .young;
        assert!(young.contains_key(&(c.filename.clone(), c.sha256.clone())));
        assert!(young.contains_key(&(a2.filename.clone(), a2.sha256.clone())));
        assert!(young.values().all(|s| s.prev_fetch.is_some()));

        // A repoint keeps the baseline and prunes only files no longer listed.
        let mut moved = (*gate).clone_for_test("https://elsewhere.example/c");
        moved.params.id = id;
        let before: i64 = sqlx::query_scalar(
            "SELECT ledger_generation FROM conda_first_seen_channels WHERE repository_id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("generation");
        let young = observe(&pool, &moved, "noarch", &[b.clone(), c.clone()])
            .await
            .expect("observe after repoint")
            .young;
        assert!(young.contains_key(&(c.filename.clone(), c.sha256.clone())));
        let baseline: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT baseline_at FROM conda_first_seen_channels WHERE repository_id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("channel");
        assert!(baseline.is_some(), "a repoint never drops the baseline");
        let (after, kept_b): (i64, bool) = sqlx::query_as(
            "SELECT c.ledger_generation, EXISTS (SELECT 1 FROM conda_record_first_seen s \
                     WHERE s.channel_id = c.id AND s.filename = 'b-1.0-0.conda' AND s.in_baseline) \
               FROM conda_first_seen_channels c WHERE c.repository_id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("generation after repoint");
        assert_eq!(after, before + 1, "a prune moves the ledger generation");
        assert!(
            kept_b,
            "a baseline file still listed upstream is never pruned"
        );

        // A replica that read the channel before another replica's prune
        // committed keeps a stale known set: a pruned file that returns is
        // found without a row and is first seen now.
        let ch = channel(&pool, &moved, "noarch").await.expect("channel");
        let _ = known_set(&pool, &ch).await.expect("known set");
        sqlx::query(
            "DELETE FROM conda_record_first_seen WHERE channel_id = $1 AND filename = 'b-1.0-0.conda'",
        )
        .bind(ch.id)
        .execute(&pool)
        .await
        .expect("prune b");
        sqlx::query(
            "UPDATE conda_first_seen_channels SET ledger_generation = ledger_generation + 1 \
              WHERE id = $1",
        )
        .bind(ch.id)
        .execute(&pool)
        .await
        .expect("bump generation");
        let ledger = observe_channel(&pool, &moved, "noarch", &[b.clone(), c.clone()], ch)
            .await
            .expect("observe with a stale known set");
        let key = (b.filename.clone(), b.sha256.clone());
        assert!(
            ledger.rowless.contains(&key),
            "the returning file had no row"
        );
        assert!(
            ledger.young.contains_key(&key),
            "and is recorded as first seen now"
        );

        assert_eq!(rebaseline(&pool, id).await.expect("rebaseline"), 1);
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    impl ChannelGate {
        fn clone_for_test(&self, upstream: &str) -> ChannelGate {
            let mut p = self.params.clone();
            p.upstream_url = Some(upstream.to_string());
            ChannelGate::new(p, vec![], vec![])
        }
    }
}
