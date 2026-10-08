//! Virtual conda channel merge: `repodata.json` and `channeldata.json` for a
//! virtual repository, assembled from its members.
//!
//! The merge order is fixed: every hosted (local/staging) member first, in
//! member priority order, then every remote member, in member priority order,
//! with first-writer-wins per filename. Hosted members also OWN their package
//! names ([`super::virtual_hosted_owned_names`]): a remote member contributes
//! no record under a name a hosted member has published.
//!
//! A virtual may also carry a package allowlist
//! ([`crate::services::conda_allowlist`], #4576): when it is enabled, a remote
//! record the list does not admit is dropped as well. Hosted records are never
//! filtered by it.
//!
//! Remote members are fetched in their compressed encodings, never as the
//! plain document: `repodata.json.zst`, then `.bz2`, then `.json`, each through
//! the capped, budgeted proxy path with the same 128 MiB default ceiling the
//! single-remote path uses (#4180). The ceiling bounds what is read from the
//! upstream; the decoded document has its own, larger ceiling, enforced while
//! the streaming decoder runs, so a decompression bomb stops at the cap instead
//! of at the allocator. Records are carried through the merge as raw JSON
//! (`serde_json::value::RawValue`) and never materialised as `Value` trees: a
//! conda-forge subdir is a few hundred MiB of JSON, and the tree form of it is
//! several times that.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::api::handlers::proxy_helpers;
use crate::models::repository::{Repository, RepositoryType};
use crate::services::conda_allowlist::CompiledAllowlist;
use crate::services::proxy_service::ProxyService;

/// Ceiling on the bytes read from one remote member for one document, as
/// fetched (i.e. compressed). Defaults to the single-remote repodata tier,
/// [`proxy_helpers::LARGE_METADATA_MAX_BYTES`].
pub(super) const MEMBER_MAX_BYTES_ENV: &str = "CONDA_VIRTUAL_MEMBER_MAX_BYTES";

/// Ceiling on one member document after decoding. conda-forge's largest
/// subdirs decode to roughly 300 MiB today; 1 GiB leaves headroom without
/// letting a crafted `.zst` inflate without bound.
pub(super) const MEMBER_MAX_DECODED_BYTES_ENV: &str = "CONDA_VIRTUAL_MEMBER_MAX_DECODED_BYTES";
const DEFAULT_MEMBER_MAX_DECODED_BYTES: usize = 1024 * 1024 * 1024;

/// Byte ceilings applied to each remote member fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MemberLimits {
    /// Bytes read from the upstream (compressed, as served).
    pub fetched: usize,
    /// Bytes after undoing the transfer coding and the file compression.
    pub decoded: usize,
}

impl MemberLimits {
    /// Read the ceilings from the environment; an unset, unparseable or zero
    /// value falls back to the default rather than disabling the cap.
    pub(super) fn from_env() -> Self {
        let read = |key: &str, default: usize| {
            std::env::var(key)
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(default)
        };
        Self {
            fetched: read(
                MEMBER_MAX_BYTES_ENV,
                proxy_helpers::LARGE_METADATA_MAX_BYTES,
            ),
            decoded: read(
                MEMBER_MAX_DECODED_BYTES_ENV,
                DEFAULT_MEMBER_MAX_DECODED_BYTES,
            ),
        }
    }
}

/// File compression of one candidate upstream document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileCodec {
    Zstd,
    Bzip2,
    Plain,
}

/// The upstream files that carry `{subdir}/repodata.json`, most compact first.
pub(super) fn repodata_candidates(subdir: &str) -> Vec<(String, FileCodec)> {
    vec![
        (format!("{subdir}/repodata.json.zst"), FileCodec::Zstd),
        (format!("{subdir}/repodata.json.bz2"), FileCodec::Bzip2),
        (format!("{subdir}/repodata.json"), FileCodec::Plain),
    ]
}

/// The upstream files that carry `channeldata.json`. Channels publish it only
/// uncompressed.
pub(super) fn channeldata_candidates() -> Vec<(String, FileCodec)> {
    vec![("channeldata.json".to_string(), FileCodec::Plain)]
}

/// Why a remote member contributed nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MemberFailure {
    /// The member repository's key.
    pub member: String,
    /// Stable, low-cardinality class for the failure metric: `fetch`, `cap`,
    /// `decode` or `parse`.
    pub kind: &'static str,
    /// What went wrong, phrased for an operator reading a 502 body.
    pub reason: String,
}

/// `repository_config` key on a VIRTUAL repository that opts it into
/// degraded merges (#4192). Absent or anything but `true`: strict.
pub(super) const PARTIAL_CONFIG_KEY: &str = "virtual_metadata_partial";

/// Response header naming the members a degraded merge left out.
pub(super) const PARTIAL_MEMBERS_HEADER: &str = "x-ak-partial-members";

/// What a virtual merge does when a member fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailurePolicy {
    /// Any member failure fails the request with 502 naming the member. The
    /// default: a merged index that silently lacks a member makes the client
    /// conclude those packages do not exist, or resolve a name present in
    /// two members to the lower-priority one.
    Strict,
    /// Serve the merge of the members that succeeded, marked partial and
    /// uncacheable. Opt-in per virtual repository.
    AllowPartial,
}

impl FailurePolicy {
    pub(super) fn from_config(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("allow") => {
                Self::AllowPartial
            }
            _ => Self::Strict,
        }
    }

    /// Read the policy for `virtual_repo_id`. A failed read is strict: the
    /// lookup failing must not loosen the guarantee.
    pub(super) async fn load(db: &sqlx::PgPool, virtual_repo_id: uuid::Uuid) -> Self {
        let value: Option<String> = sqlx::query_scalar(
            "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
        )
        .bind(virtual_repo_id)
        .bind(PARTIAL_CONFIG_KEY)
        .fetch_optional(db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "reading {PARTIAL_CONFIG_KEY} failed; using strict");
            None
        });
        Self::from_config(value.as_deref())
    }
}

/// Count every member failure (both policies) and turn the outcome into the
/// response the policy calls for. `Ok(None)`: no failures, serve as usual.
/// `Ok(Some(members))`: degraded, serve with the partial marking.
/// `Err(502)`: strict and something failed.
pub(super) fn apply_failure_policy(
    policy: FailurePolicy,
    virtual_repo_key: &str,
    document: &str,
    failed: &[MemberFailure],
) -> Result<Option<String>, Response> {
    if failed.is_empty() {
        return Ok(None);
    }
    for f in failed {
        metrics::counter!(
            "ak_virtual_member_metadata_failures_total",
            "format" => "conda",
            "virtual_repo" => virtual_repo_key.to_string(),
            "member" => f.member.clone(),
            "reason" => f.kind,
        )
        .increment(1);
        tracing::warn!(
            virtual_repo = %virtual_repo_key,
            member = %f.member,
            document,
            reason = %f.reason,
            ?policy,
            "conda virtual member could not contribute to the merged document"
        );
    }
    match policy {
        FailurePolicy::Strict => {
            let detail = failed
                .iter()
                .map(|f| format!("member '{}' failed: {}", f.member, f.reason))
                .collect::<Vec<_>>()
                .join("; ");
            Err((
                StatusCode::BAD_GATEWAY,
                format!(
                    "Virtual conda channel '{virtual_repo_key}' cannot serve {document}: {detail}"
                ),
            )
                .into_response())
        }
        FailurePolicy::AllowPartial => Ok(Some(
            failed
                .iter()
                .map(|f| f.member.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )),
    }
}

/// Mark a degraded response: name the missing members, forbid caching (a
/// partial document must never be cached as the complete one) and add a
/// `Warning: 199`.
pub(super) fn mark_partial(response: &mut Response, missing: &str) {
    use axum::http::header::{CACHE_CONTROL, ETAG, WARNING};
    use axum::http::HeaderValue;
    let headers = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(missing) {
        headers.insert(PARTIAL_MEMBERS_HEADER, v);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.remove(ETAG);
    if let Ok(v) = HeaderValue::from_str(&format!(
        "199 - \"partial merge: members {missing} are missing\""
    )) {
        headers.insert(WARNING, v);
    }
}

/// A remote member's document, decoded to JSON bytes.
pub(super) struct MemberDocument {
    pub member: String,
    pub json: Vec<u8>,
}

/// Undo the HTTP transfer coding (normally none: the proxy asks for identity)
/// and then the file compression, refusing to produce more than `cap` bytes.
pub(super) fn decode_member_document(
    content: &[u8],
    transfer_coding: Option<&str>,
    codec: FileCodec,
    cap: usize,
) -> Result<Vec<u8>, String> {
    let transfer: Box<dyn Read + '_> = match transfer_coding.map(str::trim) {
        None | Some("") | Some("identity") => Box::new(content),
        Some(c) if c.eq_ignore_ascii_case("gzip") || c.eq_ignore_ascii_case("x-gzip") => {
            Box::new(flate2::read::MultiGzDecoder::new(content))
        }
        Some(c) if c.eq_ignore_ascii_case("deflate") => {
            Box::new(flate2::read::ZlibDecoder::new(content))
        }
        Some(c) if c.eq_ignore_ascii_case("zstd") => Box::new(
            zstd::stream::read::Decoder::new(content)
                .map_err(|e| format!("zstd transfer coding: {e}"))?,
        ),
        Some(other) => return Err(format!("unsupported Content-Encoding {other:?}")),
    };
    let file: Box<dyn Read + '_> = match codec {
        FileCodec::Plain => transfer,
        FileCodec::Zstd => {
            Box::new(zstd::stream::read::Decoder::new(transfer).map_err(|e| format!("zstd: {e}"))?)
        }
        FileCodec::Bzip2 => Box::new(bzip2::read::MultiBzDecoder::new(transfer)),
    };
    let mut out = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("decode failed: {e}"))?;
    if out.len() > cap {
        return Err(format!(
            "decoded document exceeds the {cap}-byte member ceiling ({MEMBER_MAX_DECODED_BYTES_ENV})"
        ));
    }
    Ok(out)
}

/// Fetch one remote member's document, trying `candidates` in order and moving
/// to the next only when the upstream answers 404 for the current one.
///
/// Members are fetched one at a time by the caller, and each fetch releases
/// its share of the shared buffered-metadata budget before returning, so a
/// virtual request never holds one reservation while waiting for another (the
/// hold-and-wait shape #4129 removed from the single-remote path).
pub(super) async fn fetch_member_document(
    proxy: &ProxyService,
    member: &Repository,
    candidates: &[(String, FileCodec)],
    limits: MemberLimits,
    missing_is_empty: bool,
) -> Result<MemberDocument, MemberFailure> {
    let fail = |kind: &'static str, reason: String| MemberFailure {
        member: member.key.clone(),
        kind,
        reason,
    };
    let Some(upstream_url) = member.upstream_url.as_deref() else {
        return Err(fail(
            "fetch",
            "remote member has no upstream URL".to_string(),
        ));
    };
    let mut last_status = None;
    for (path, codec) in candidates {
        let fetched = proxy_helpers::proxy_fetch_capped_budgeted_with_encoding(
            proxy,
            member.id,
            &member.key,
            upstream_url,
            path,
            limits.fetched,
        )
        .await;
        match fetched {
            Ok(proxy_helpers::CappedMetadataGet::Buffered {
                content,
                content_encoding,
                budget_permit,
                ..
            }) => {
                let codec = *codec;
                let path = path.clone();
                let decoded = tokio::task::spawn_blocking(move || {
                    // Held until the compressed buffer is decoded and dropped.
                    let _budget_permit = budget_permit;
                    decode_member_document(
                        &content,
                        content_encoding.as_deref(),
                        codec,
                        limits.decoded,
                    )
                })
                .await
                .map_err(|e| fail("decode", format!("decoder task failed: {e}")))?;
                return decoded
                    .map(|json| MemberDocument {
                        member: member.key.clone(),
                        json,
                    })
                    .map_err(|e| fail("decode", format!("{path}: {e}")));
            }
            Ok(proxy_helpers::CappedMetadataGet::OverCap) => {
                return Err(fail(
                    "cap",
                    format!(
                        "{path} exceeds the {}-byte member ceiling ({MEMBER_MAX_BYTES_ENV})",
                        limits.fetched
                    ),
                ));
            }
            Err(response) if response.status() == StatusCode::NOT_FOUND => {
                last_status = Some(response.status());
                continue;
            }
            Err(response) => {
                return Err(fail(
                    "fetch",
                    format!("{path}: upstream fetch failed with {}", response.status()),
                ));
            }
        }
    }
    if missing_is_empty && last_status == Some(StatusCode::NOT_FOUND) {
        // Every candidate answered 404: the upstream does not publish this
        // subdir at all (conda-forge has no `unknown/`, most channels lack
        // most platforms). A conda client treats a missing subdir as empty, so
        // the member contributes nothing rather than failing the merge.
        return Ok(MemberDocument {
            member: member.key.clone(),
            json: b"{}".to_vec(),
        });
    }
    Err(fail(
        "fetch",
        format!(
            "no candidate document available upstream (last status {})",
            last_status.map_or_else(|| "none".to_string(), |s| s.to_string())
        ),
    ))
}

/// Fetch every remote member in `members` (already in priority order),
/// sequentially. Successful documents and failures are returned separately,
/// each in member order.
pub(super) async fn fetch_remote_members(
    proxy: Option<&ProxyService>,
    members: &[Repository],
    candidates: &[(String, FileCodec)],
    limits: MemberLimits,
    missing_is_empty: bool,
) -> (Vec<MemberDocument>, Vec<MemberFailure>) {
    let mut documents = Vec::new();
    let mut failures = Vec::new();
    for member in members
        .iter()
        .filter(|m| m.repo_type == RepositoryType::Remote)
    {
        let Some(proxy) = proxy else {
            failures.push(MemberFailure {
                member: member.key.clone(),
                kind: "fetch",
                reason: "the proxy service is not available".to_string(),
            });
            continue;
        };
        match fetch_member_document(proxy, member, candidates, limits, missing_is_empty).await {
            Ok(doc) => documents.push(doc),
            Err(failure) => failures.push(failure),
        }
    }
    (documents, failures)
}

// ---------------------------------------------------------------------------
// repodata.json
// ---------------------------------------------------------------------------

/// The parts of an upstream `repodata.json` the merge reads. Records stay raw.
#[derive(Deserialize)]
struct UpstreamRepodata<'a> {
    #[serde(default, borrow)]
    packages: BTreeMap<String, &'a RawValue>,
    #[serde(default, borrow, rename = "packages.conda")]
    packages_conda: BTreeMap<String, &'a RawValue>,
}

/// Just the `name` of a record, borrowed where the JSON has no escapes.
#[derive(Deserialize)]
struct RecordName<'a> {
    #[serde(default, borrow)]
    name: Option<std::borrow::Cow<'a, str>>,
}

/// The `name` and `version` a record claims for itself.
#[derive(Deserialize)]
struct RecordIdentity<'a> {
    #[serde(default, borrow)]
    name: Option<std::borrow::Cow<'a, str>>,
    #[serde(default, borrow)]
    version: Option<std::borrow::Cow<'a, str>>,
}

/// The merged document. Field order is the serialized key order, which is the
/// sorted order the hosted document uses.
#[derive(Serialize)]
struct MergedRepodata<'a> {
    info: RepodataInfo<'a>,
    packages: BTreeMap<&'a str, &'a RawValue>,
    #[serde(rename = "packages.conda")]
    packages_conda: BTreeMap<&'a str, &'a RawValue>,
    removed: [&'a str; 0],
    repodata_version: u32,
}

#[derive(Serialize)]
struct RepodataInfo<'a> {
    base_url: &'a str,
    subdir: &'a str,
}

/// One hosted record, ready to merge.
pub(super) struct HostedRecord {
    pub filename: String,
    pub is_v2: bool,
    pub record: Box<RawValue>,
}

/// Whether a remote record names a package a hosted member owns, by the
/// record's own `name` or by its filename.
fn remote_record_is_owned(filename: &str, raw: &RawValue, owned: &HashSet<String>) -> bool {
    if owned.is_empty() {
        return false;
    }
    let by_filename = super::conda_name_from_filename(filename)
        .is_some_and(|n| owned.contains(&n.to_ascii_lowercase()));
    by_filename
        || serde_json::from_str::<RecordName<'_>>(raw.get())
            .ok()
            .and_then(|r| r.name)
            .is_some_and(|n| owned.contains(&n.to_ascii_lowercase()))
}

/// Whether the allowlist admits a remote record: by the name and version its
/// filename carries (what the download seam checks) AND by the `name` and
/// `version` the record itself claims, when it carries them. A record whose
/// own identity disagrees with an admitted filename is dropped; the filename
/// is checked first so the common case (not admitted) never parses the record.
fn remote_record_is_admitted(
    subdir: &str,
    filename: &str,
    raw: &RawValue,
    allowlist: &CompiledAllowlist,
) -> bool {
    let Some((file_name, file_version)) =
        crate::services::conda_allowlist::split_conda_filename(filename)
    else {
        return false;
    };
    if !allowlist.admits(file_name, file_version, subdir) {
        return false;
    }
    let Ok(id) = serde_json::from_str::<RecordIdentity<'_>>(raw.get()) else {
        return false;
    };
    let name = id.name.as_deref().unwrap_or(file_name);
    let version = id.version.as_deref().unwrap_or(file_version);
    (name == file_name && version == file_version) || allowlist.admits(name, version, subdir)
}

/// Remote records a merge left out, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct MergeDrops {
    /// Records under a name a hosted member owns.
    pub owned: usize,
    /// Records the virtual's allowlist does not admit.
    pub not_allowed: usize,
}

/// Merge hosted records and remote member documents into one encoded
/// `repodata.json`. CPU-bound over upstream-sized input: run it on a blocking
/// thread. A member document that does not parse is reported as that member's
/// failure; the others still merge.
pub(super) fn merge_repodata(
    subdir: &str,
    base_url: &str,
    hosted: &[HostedRecord],
    remote: &[MemberDocument],
    owned: &HashSet<String>,
    allowlist: Option<&CompiledAllowlist>,
    encoding: super::RepodataEncoding,
) -> (Result<Vec<u8>, Response>, Vec<MemberFailure>, MergeDrops) {
    let mut packages: BTreeMap<&str, &RawValue> = BTreeMap::new();
    let mut packages_conda: BTreeMap<&str, &RawValue> = BTreeMap::new();
    for h in hosted {
        let target = if h.is_v2 {
            &mut packages_conda
        } else {
            &mut packages
        };
        target.entry(h.filename.as_str()).or_insert(&h.record);
    }

    let mut failures = Vec::new();
    let mut dropped = MergeDrops::default();
    let mut parsed: Vec<UpstreamRepodata<'_>> = Vec::with_capacity(remote.len());
    for doc in remote {
        match serde_json::from_slice::<UpstreamRepodata<'_>>(&doc.json) {
            Ok(p) => parsed.push(p),
            Err(e) => failures.push(MemberFailure {
                member: doc.member.clone(),
                kind: "parse",
                reason: format!("repodata does not parse: {e}"),
            }),
        }
    }
    for p in &parsed {
        for (source, target) in [
            (&p.packages, &mut packages),
            (&p.packages_conda, &mut packages_conda),
        ] {
            for (filename, raw) in source {
                if remote_record_is_owned(filename, raw, owned) {
                    dropped.owned += 1;
                    continue;
                }
                if let Some(allowlist) = allowlist {
                    if !remote_record_is_admitted(subdir, filename, raw, allowlist) {
                        dropped.not_allowed += 1;
                        continue;
                    }
                }
                target.entry(filename.as_str()).or_insert(*raw);
            }
        }
    }

    let merged = MergedRepodata {
        info: RepodataInfo { base_url, subdir },
        packages,
        packages_conda,
        removed: [],
        repodata_version: 1,
    };
    (encoding.encode(&merged), failures, dropped)
}

// ---------------------------------------------------------------------------
// channeldata.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UpstreamChanneldata<'a> {
    #[serde(default, borrow)]
    packages: BTreeMap<String, &'a RawValue>,
}

#[derive(Serialize)]
struct MergedChanneldata<'a> {
    channeldata_version: u32,
    packages: BTreeMap<&'a str, &'a RawValue>,
}

/// Merge hosted channeldata entries (name -> entry, already first-writer-wins
/// across hosted members) with remote member documents into a pretty-printed
/// `channeldata.json`. Remote entries for owned names are dropped, and so are
/// remote entries whose name the allowlist (when enabled) admits under no
/// entry; channeldata is a per-name summary, so versions and subdirs do not
/// enter into it. Returns the number of entries the allowlist dropped.
pub(super) fn merge_channeldata(
    hosted: &[(String, Box<RawValue>)],
    remote: &[MemberDocument],
    owned: &HashSet<String>,
    allowlist: Option<&CompiledAllowlist>,
) -> (serde_json::Result<Vec<u8>>, Vec<MemberFailure>, usize) {
    let mut packages: BTreeMap<&str, &RawValue> = BTreeMap::new();
    for (name, entry) in hosted {
        packages.entry(name.as_str()).or_insert(entry);
    }
    let mut failures = Vec::new();
    let mut not_allowed = 0usize;
    let mut parsed = Vec::with_capacity(remote.len());
    for doc in remote {
        match serde_json::from_slice::<UpstreamChanneldata<'_>>(&doc.json) {
            Ok(p) => parsed.push(p),
            Err(e) => failures.push(MemberFailure {
                member: doc.member.clone(),
                kind: "parse",
                reason: format!("channeldata does not parse: {e}"),
            }),
        }
    }
    for p in &parsed {
        for (name, raw) in &p.packages {
            if owned.contains(&name.to_ascii_lowercase()) {
                continue;
            }
            if allowlist.is_some_and(|a| !a.admits_name(name)) {
                not_allowed += 1;
                continue;
            }
            packages.entry(name.as_str()).or_insert(*raw);
        }
    }
    let merged = MergedChanneldata {
        channeldata_version: 1,
        packages,
    };
    (serde_json::to_vec_pretty(&merged), failures, not_allowed)
}

/// The 500 a failed merge task or serialization answers with.
pub(super) fn internal_error(e: impl std::fmt::Display) -> Response {
    tracing::error!("conda virtual merge failed: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
}
