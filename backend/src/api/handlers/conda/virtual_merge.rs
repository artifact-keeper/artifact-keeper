//! Virtual conda channel merge: `repodata.json`, `run_exports.json` and
//! `channeldata.json` for a virtual repository, assembled from its members
//! (`current_repodata.json` is derived from the merged `repodata.json`, see
//! [`super::current_repodata`]).
//!
//! The merge order is fixed: every hosted (local/staging) member first, in
//! member priority order, then every remote member, in member priority order,
//! with first-writer-wins per filename. Hosted members also OWN their package
//! names ([`super::virtual_hosted_owned_names`]): a remote member contributes
//! no record under a name a hosted member has published.
//!
//! A virtual may also carry a package allowlist
//! ([`crate::services::conda_allowlist`], #4576): when it is enabled, a record
//! the list does not admit is dropped as well. By default that holds for
//! hosted records too (#5055); a list scoped `remote_only` filters remote
//! records only. A hosted record the list drops still owns its name, so the
//! remote records of that name stay excluded.
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
use sha2::Digest;

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
    #[cfg(test)]
    pub(super) fn from_config(value: Option<&str>) -> Self {
        if proxy_helpers::virtual_metadata_partial_opted_in(value) {
            Self::AllowPartial
        } else {
            Self::Strict
        }
    }

    /// Read the policy for `virtual_repo_id`. A failed read is strict: the
    /// lookup failing must not loosen the guarantee.
    pub(super) async fn load(db: &sqlx::PgPool, virtual_repo_id: uuid::Uuid) -> Self {
        if proxy_helpers::virtual_metadata_partial_allowed(db, virtual_repo_id).await {
            Self::AllowPartial
        } else {
            Self::Strict
        }
    }
}

/// Count the remote records one member lost to the virtual's allowlist in one
/// merge (#4711). Called once per member per merge rather than once per
/// record: a merge can drop most of an upstream channel, and the merge result
/// is cached, so a request served from the cache adds nothing.
pub(super) fn count_allowlist_drops(virtual_repo_key: &str, member: &str, dropped: usize) {
    crate::services::metrics_service::record_conda_allowlist_dropped(
        virtual_repo_key,
        member,
        dropped as u64,
    );
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
    proxy_helpers::mark_partial_metadata_response(response, missing);
}

/// A remote member's document, decoded to JSON bytes.
pub(super) struct MemberDocument {
    pub member: String,
    pub json: Vec<u8>,
    /// The proxy-cache entry the document was read from, by the checksum of
    /// the bytes read (#4608). `None` when the read cannot be tied to a fresh
    /// cache entry holding those bytes (an upstream that does not publish the
    /// document, or an entry that changed or expired meanwhile): a merge built
    /// from it is not kept.
    pub validator: Option<super::merge_gate::MemberValidator>,
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
/// The fetch buffer and the decoded document are covered by the merge's own
/// budget reservation (#4608) and tracked in `account`: the buffer until it is
/// decoded, the document until the merge ends. Members are fetched one at a
/// time, and nothing here waits for budget.
pub(super) async fn fetch_member_document(
    proxy: &ProxyService,
    member: &Repository,
    candidates: &[(String, FileCodec)],
    limits: MemberLimits,
    missing_is_empty: bool,
    account: &mut super::merge_gate::MergeAccount,
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
        let permit = account.fetch_permit();
        let fetched = proxy_helpers::proxy_fetch_capped_with_encoding_reserved(
            proxy,
            member.id,
            &member.key,
            upstream_url,
            path,
            limits.fetched,
            permit,
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
                let fetched_len = content.len();
                account.track(fetched_len);
                let decoded = tokio::task::spawn_blocking(move || {
                    // Dropped with the compressed buffer once it is decoded.
                    let _budget_permit = budget_permit;
                    let checksum = hex::encode(sha2::Sha256::digest(&content));
                    decode_member_document(
                        &content,
                        content_encoding.as_deref(),
                        codec,
                        limits.decoded,
                    )
                    .map(|json| (json, checksum))
                })
                .await;
                account.release(fetched_len);
                let (json, checksum) = match decoded {
                    Ok(Ok(decoded)) => decoded,
                    Ok(Err(e)) => return Err(fail("decode", format!("{path}: {e}"))),
                    Err(e) => return Err(fail("decode", format!("decoder task failed: {e}"))),
                };
                account.track(json.len());
                // The entry must still be fresh and hold the bytes just read;
                // otherwise the merge is served but not kept.
                let validator = proxy
                    .fresh_cache_validator(&member.key, path)
                    .await
                    .filter(|current| *current == checksum)
                    .map(|checksum| super::merge_gate::MemberValidator {
                        member: member.key.clone(),
                        path: path.clone(),
                        checksum,
                    });
                return Ok(MemberDocument {
                    member: member.key.clone(),
                    json,
                    validator,
                });
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
        // document at all (conda-forge has no `unknown/`, most channels lack
        // most platforms, many publish no channeldata.json). A conda client
        // treats a missing subdir as empty, so the member contributes nothing
        // rather than failing the merge (#4601 for channeldata).
        tracing::info!(
            member = %member.key,
            document = candidates.first().map(|(p, _)| p.as_str()).unwrap_or_default(),
            "conda virtual member's upstream does not publish this document; it contributes \
             no entries"
        );
        return Ok(MemberDocument {
            member: member.key.clone(),
            json: b"{}".to_vec(),
            validator: None,
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
    account: &mut super::merge_gate::MergeAccount,
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
        match fetch_member_document(proxy, member, candidates, limits, missing_is_empty, account)
            .await
        {
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
    // No `base_url`: packages are beside the document (CEP-15's default),
    // see `super::build_repodata_envelope` (#4580).
    subdir: &'a str,
}

/// One hosted record, ready to merge.
pub(super) struct HostedRecord {
    /// Key of the hosted member the record comes from (the
    /// `ak_conda_allowlist_dropped_total` `member` label).
    pub member: String,
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

/// Whether the allowlist admits a record: by the name and version its
/// filename carries (what the download seam checks) AND by the `name` and
/// `version` the record itself claims, when it carries them. A record whose
/// own identity disagrees with an admitted filename is dropped; the filename
/// is checked first so the common case (not admitted) never parses the record.
fn record_is_admitted(
    subdir: &str,
    filename: &str,
    raw: &RawValue,
    allowlist: &CompiledAllowlist,
) -> bool {
    if !allowlist.admits_filename(subdir, filename) {
        return false;
    }
    let Ok(id) = serde_json::from_str::<RecordIdentity<'_>>(raw.get()) else {
        return false;
    };
    identity_is_admitted(
        subdir,
        filename,
        id.name.as_deref(),
        id.version.as_deref(),
        allowlist,
    )
}

/// The identity half of [`record_is_admitted`], for a record whose filename
/// the list admits: the `name`/`version` the record claims (absent: the
/// filename's) must be the filename's or be admitted themselves. Shared with
/// the hosted rows a virtual builds its shards and channeldata from, so every
/// seam applies one rule.
pub(super) fn identity_is_admitted(
    subdir: &str,
    filename: &str,
    name: Option<&str>,
    version: Option<&str>,
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
    let name = name.unwrap_or(file_name);
    let version = version.unwrap_or(file_version);
    (name == file_name && version == file_version) || allowlist.admits(name, version, subdir)
}

/// The allowlist as it applies to hosted members: `Some` only when one is
/// enforced and its scope is every member (#5055).
pub(super) fn hosted_allowlist(
    allowlist: Option<&CompiledAllowlist>,
) -> Option<&CompiledAllowlist> {
    allowlist.filter(|a| a.applies_to_hosted())
}

/// Remote records a merge left out, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct MergeDrops {
    /// Remote records under a name a hosted member owns.
    pub owned: usize,
    /// Records the virtual's allowlist does not admit, hosted (when the list
    /// applies to every member) and remote.
    pub not_allowed: usize,
}

/// The package maps of a merged document (`packages`, `packages.conda`).
type PackageMaps<'a> = (
    BTreeMap<&'a str, &'a RawValue>,
    BTreeMap<&'a str, &'a RawValue>,
);

/// Merge hosted records and remote member package maps, first writer wins
/// per filename: hosted records first, then each parsed remote document in
/// member order, dropping remote records under a name a hosted member owns,
/// and records the allowlist does not admit (hosted ones too unless the list
/// is scoped `remote_only`, #5055). Shared by every per-package document a
/// virtual serves (`repodata.json`, `run_exports.json`, #4708), so the
/// ownership and allowlist rules cannot drift between them. Allowlist drops
/// are counted per member in `ak_conda_allowlist_dropped_total` under
/// `virtual_repo_key` (#4711).
fn merge_package_maps<'a>(
    virtual_repo_key: &str,
    subdir: &str,
    hosted: &'a [HostedRecord],
    parsed: &'a [(&'a str, UpstreamRepodata<'a>)],
    owned: &HashSet<String>,
    allowlist: Option<&CompiledAllowlist>,
    dropped: &mut MergeDrops,
) -> PackageMaps<'a> {
    let mut packages: BTreeMap<&str, &RawValue> = BTreeMap::new();
    let mut packages_conda: BTreeMap<&str, &RawValue> = BTreeMap::new();
    let hosted_list = hosted_allowlist(allowlist);
    let mut hosted_not_allowed: BTreeMap<&str, usize> = BTreeMap::new();
    for h in hosted {
        if let Some(list) = hosted_list {
            if !record_is_admitted(subdir, &h.filename, &h.record, list) {
                *hosted_not_allowed.entry(h.member.as_str()).or_default() += 1;
                continue;
            }
        }
        let target = if h.is_v2 {
            &mut packages_conda
        } else {
            &mut packages
        };
        target.entry(h.filename.as_str()).or_insert(&h.record);
    }
    for (member, count) in hosted_not_allowed {
        dropped.not_allowed += count;
        count_allowlist_drops(virtual_repo_key, member, count);
    }
    for (member, p) in parsed {
        let mut member_not_allowed = 0usize;
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
                    if !record_is_admitted(subdir, filename, raw, allowlist) {
                        member_not_allowed += 1;
                        continue;
                    }
                }
                target.entry(filename.as_str()).or_insert(*raw);
            }
        }
        dropped.not_allowed += member_not_allowed;
        count_allowlist_drops(virtual_repo_key, member, member_not_allowed);
    }
    (packages, packages_conda)
}

/// Parse each remote member document's package maps; a document that does not
/// parse is that member's failure.
fn parse_member_package_maps<'a>(
    remote: &'a [MemberDocument],
    what: &str,
) -> (Vec<(&'a str, UpstreamRepodata<'a>)>, Vec<MemberFailure>) {
    let mut failures = Vec::new();
    let mut parsed = Vec::with_capacity(remote.len());
    for doc in remote {
        match serde_json::from_slice::<UpstreamRepodata<'_>>(&doc.json) {
            Ok(p) => parsed.push((doc.member.as_str(), p)),
            Err(e) => failures.push(MemberFailure {
                member: doc.member.clone(),
                kind: "parse",
                reason: format!("{what} does not parse: {e}"),
            }),
        }
    }
    (parsed, failures)
}

/// A merged per-package document as it is kept.
pub(super) struct MergedBody {
    pub bytes: Vec<u8>,
    /// Length of the plain JSON document `bytes` holds (`bytes.len()` when it
    /// is plain JSON).
    pub plain_len: usize,
}

impl MergedBody {
    fn plain(bytes: Vec<u8>) -> Self {
        Self {
            plain_len: bytes.len(),
            bytes,
        }
    }
}

/// The result of a per-package merge: the document, member parse
/// failures, and the remote records it dropped.
pub(super) type PackageMerge = (Result<MergedBody, Response>, Vec<MemberFailure>, MergeDrops);

/// Merge hosted records and remote member documents into one
/// `repodata.json`, kept in its canonical zstd encoding (compact JSON); the
/// `.json` and `.bz2` a client asks for are derived from it, so one merge
/// serves every encoding (#4879). CPU-bound over upstream-sized input: run it on a blocking
/// thread. A member document that does not parse is reported as that member's
/// failure; the others still merge. Allowlist drops are counted per member in
/// `ak_conda_allowlist_dropped_total` under `virtual_repo_key` (#4711).
pub(super) fn merge_repodata(
    virtual_repo_key: &str,
    subdir: &str,
    hosted: &[HostedRecord],
    remote: &[MemberDocument],
    owned: &HashSet<String>,
    allowlist: Option<&CompiledAllowlist>,
) -> PackageMerge {
    let mut dropped = MergeDrops::default();
    let (parsed, failures) = parse_member_package_maps(remote, "repodata");
    let (packages, packages_conda) = merge_package_maps(
        virtual_repo_key,
        subdir,
        hosted,
        &parsed,
        owned,
        allowlist,
        &mut dropped,
    );
    let merged = MergedRepodata {
        info: RepodataInfo { subdir },
        packages,
        packages_conda,
        removed: [],
        repodata_version: 1,
    };
    let body = super::RepodataEncoding::encode_zst_counted(&merged)
        .map(|(bytes, plain_len)| MergedBody { bytes, plain_len });
    (body, failures, dropped)
}

// ---------------------------------------------------------------------------
// run_exports.json (CEP-12, #4708)
// ---------------------------------------------------------------------------

/// The upstream file that carries `{subdir}/run_exports.json`.
pub(super) fn run_exports_candidates(subdir: &str) -> Vec<(String, FileCodec)> {
    vec![(format!("{subdir}/run_exports.json"), FileCodec::Plain)]
}

/// The merged `run_exports.json`. Field order is the serialized key order.
#[derive(Serialize)]
struct MergedRunExports<'a> {
    info: RepodataInfo<'a>,
    packages: BTreeMap<&'a str, &'a RawValue>,
    #[serde(rename = "packages.conda")]
    packages_conda: BTreeMap<&'a str, &'a RawValue>,
}

/// Merge hosted run-export entries and remote member `run_exports.json`
/// documents into one pretty-printed `run_exports.json`, under exactly the
/// ownership and allowlist rules of [`merge_repodata`]: an entry is keyed by
/// the package filename, so a remote entry is admitted only when the matching
/// `repodata.json` record would be. A member whose upstream publishes no
/// `run_exports.json` arrives as `{}` and contributes nothing.
pub(super) fn merge_run_exports(
    virtual_repo_key: &str,
    subdir: &str,
    hosted: &[HostedRecord],
    remote: &[MemberDocument],
    owned: &HashSet<String>,
    allowlist: Option<&CompiledAllowlist>,
) -> PackageMerge {
    let mut dropped = MergeDrops::default();
    let (parsed, failures) = parse_member_package_maps(remote, "run_exports");
    let (packages, packages_conda) = merge_package_maps(
        virtual_repo_key,
        subdir,
        hosted,
        &parsed,
        owned,
        allowlist,
        &mut dropped,
    );
    let merged = MergedRunExports {
        info: RepodataInfo { subdir },
        packages,
        packages_conda,
    };
    (
        serde_json::to_vec_pretty(&merged)
            .map(MergedBody::plain)
            .map_err(internal_error),
        failures,
        dropped,
    )
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
/// across hosted members, and already filtered by the allowlist when it
/// applies to hosted members, #5055) with remote member documents into a
/// pretty-printed `channeldata.json`. Remote entries for owned names are
/// dropped, and so are remote entries whose name the allowlist (when enabled)
/// admits under no entry; a remote channeldata entry is a per-name summary,
/// so versions and subdirs do not enter into it. Returns the number of remote
/// entries the allowlist dropped, which are also counted per member in
/// `ak_conda_allowlist_dropped_total` (#4711).
pub(super) fn merge_channeldata(
    virtual_repo_key: &str,
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
            Ok(p) => parsed.push((doc.member.as_str(), p)),
            Err(e) => failures.push(MemberFailure {
                member: doc.member.clone(),
                kind: "parse",
                reason: format!("channeldata does not parse: {e}"),
            }),
        }
    }
    for (member, p) in &parsed {
        let mut member_not_allowed = 0usize;
        for (name, raw) in &p.packages {
            if owned.contains(&name.to_ascii_lowercase()) {
                continue;
            }
            if allowlist.is_some_and(|a| !a.admits_name(name)) {
                member_not_allowed += 1;
                continue;
            }
            packages.entry(name.as_str()).or_insert(*raw);
        }
        not_allowed += member_not_allowed;
        count_allowlist_drops(virtual_repo_key, member, member_not_allowed);
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
