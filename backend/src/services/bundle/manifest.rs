//! The versioned `manifest.json` codec.
//!
//! The manifest is the bundle's index: repository identities, one record per
//! artifact (logical path, digest, size, blob path, volume), optional low-side
//! scan evidence, and the reserved P2 (sequence) and P3 (signing, volume set)
//! fields. Those reserved fields are part of schema version 1 from the start,
//! so the format does not change shape when the later phases arrive; an
//! importer that cannot honour a populated reserved field refuses the bundle
//! ([`unsupported_features`]) instead of silently ignoring it.
//!
//! Decoding is two-step: the envelope (`format`, `schema_version`) is read
//! from untyped JSON first, so a newer bundle gets an explicit version error
//! rather than an opaque "unknown field". The typed decode then uses
//! `deny_unknown_fields` throughout: within a schema version, a field this
//! server does not understand is an error, never dropped. Encoding is
//! deterministic (records sorted, fixed field order), so a failed burn can be
//! re-exported byte-identically.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use super::layout::{
    self, blob_path, check_bundle_path, check_logical_path, evidence_path, is_sha256_hex,
    is_valid_repo_key, repo_file_path, RepoFile,
};
use super::{BundleError, BundleLimits};

/// Value of the manifest's `format` field.
pub const BUNDLE_FORMAT: &str = "akbundle";
/// Oldest manifest schema version this server reads.
pub const MIN_SCHEMA_VERSION: u32 = 1;
/// Newest manifest schema version this server reads, and the one it writes.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Cap on problems collected by [`validate_manifest`], so a hostile manifest
/// cannot make the report itself unbounded.
pub const MAX_REPORTED_PROBLEMS: usize = 100;

/// Who produced the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    /// Always `artifact-keeper` for bundles this product writes.
    pub product: String,
    /// Producing server version.
    pub version: String,
    /// Producing instance, when it has a stable identity.
    pub instance_id: Option<Uuid>,
}

/// What the bundle's content is relative to earlier sets (P2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BundleKind {
    /// Self-contained full export with no sequence (P1).
    Full,
    /// Periodic baseline that starts a new cumulative chain (P2, reserved).
    Baseline,
    /// Everything changed since the named baseline (P2, reserved). A lost or
    /// rejected set self-heals on the next one.
    Cumulative,
}

/// Anti-replay sequence for baseline/cumulative sets (P2, reserved). The
/// receiver keeps a per-stream high-water mark and refuses a set at or below
/// it; content is cumulative since the baseline so gaps are recoverable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SequenceInfo {
    pub stream_id: Uuid,
    /// Signed, strictly increasing per stream.
    pub sequence_number: u64,
    /// Sequence number of the baseline this set is cumulative from.
    pub baseline_sequence_number: u64,
}

/// Physical media a volume set is sized for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MediaProfile {
    /// One volume of unbounded size (disk, network transfer).
    Unbounded,
    /// DVD-R, 4.7 GB.
    DvdR,
    /// DVD-R DL, 8.5 GB.
    DvdRDl,
    /// BD-R, 25 GB.
    BdR,
    /// BD-R XL, 100 GB.
    BdRXl,
}

impl MediaProfile {
    /// Every profile, for the `/format` endpoint.
    pub const ALL: [MediaProfile; 5] = [
        MediaProfile::Unbounded,
        MediaProfile::DvdR,
        MediaProfile::DvdRDl,
        MediaProfile::BdR,
        MediaProfile::BdRXl,
    ];

    /// Nominal capacity in bytes, `None` for [`MediaProfile::Unbounded`]. The
    /// exporter (PR2) keeps headroom below this for filesystem overhead.
    pub fn capacity_bytes(self) -> Option<u64> {
        match self {
            MediaProfile::Unbounded => None,
            MediaProfile::DvdR => Some(4_700_000_000),
            MediaProfile::DvdRDl => Some(8_500_000_000),
            MediaProfile::BdR => Some(25_000_000_000),
            MediaProfile::BdRXl => Some(100_000_000_000),
        }
    }
}

/// The volume set this manifest belongs to. The total volume count is in the
/// manifest so a missing volume is detectable; the media control number is
/// for the custodian's records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VolumeSet {
    pub set_id: Uuid,
    pub media_profile: MediaProfile,
    /// Total volumes in the set (>= 1).
    pub volume_count: u32,
    pub media_control_number: Option<String>,
}

/// One repository carried by the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryEntry {
    pub key: String,
    /// Package format (`maven`, `npm`, `docker`, ...).
    pub format: String,
    /// Repository type (`local`, `remote`, `virtual`, `staging`).
    pub repo_type: String,
    /// `repos/<key>/repo.json`.
    pub metadata_path: String,
    /// `repos/<key>/artifacts.json`.
    pub artifacts_path: String,
    /// `repos/<key>/oci.json`, present for OCI repositories only.
    pub oci_path: Option<String>,
}

/// A detached signature over one record's [`record_digest`] (P3, reserved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordSignature {
    pub key_id: String,
    pub algorithm: String,
    /// Signature bytes, base64. Only the signature is encoded; content never is.
    pub value: String,
}

/// One artifact record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemEntry {
    pub repository_key: String,
    /// Path of the artifact inside its repository.
    pub logical_path: String,
    /// Lowercase hex SHA-256 of the content.
    pub sha256: String,
    pub size_bytes: u64,
    /// `blobs/<sha[0..2]>/<sha256><.ext>`.
    pub blob_path: String,
    /// 1-based volume holding the blob.
    pub volume: u32,
    pub content_type: Option<String>,
    /// Per-record signature (P3, reserved).
    pub signature: Option<RecordSignature>,
}

/// Low-side scan evidence for one artifact digest. Evidence is for a human
/// reviewer, at most a reason to reprioritise a local rescan; it is imported
/// into `bundle_scan_evidence` and NEVER into `scan_results`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanEvidenceEntry {
    pub artifact_sha256: String,
    pub scanner: String,
    pub scanner_version: Option<String>,
    /// Vulnerability database version the verdict was graded against (#3014).
    pub vulnerability_db_version: Option<String>,
    pub scanned_at: DateTime<Utc>,
    pub findings_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    /// `evidence/<sha[0..2]>/<sha256>.json`, the full report when carried.
    pub evidence_path: Option<String>,
}

/// Whole-set signing block (P3, reserved). Validity is evaluated against the
/// signed `signed_at`, not import time, and revocation against a key status
/// list carried on the media (`key_status_list_path`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SigningInfo {
    pub signed_at: DateTime<Utc>,
    pub signer_key_id: String,
    pub signer_fingerprint: String,
    pub algorithm: String,
    pub key_status_list_path: Option<String>,
}

/// `manifest.json`, schema version 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// Always [`BUNDLE_FORMAT`].
    pub format: String,
    pub schema_version: u32,
    pub bundle_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub producer: Producer,
    pub kind: BundleKind,
    /// Reserved for P2; `null` for a full bundle.
    #[serde(default)]
    pub sequence: Option<SequenceInfo>,
    pub volume_set: VolumeSet,
    pub repositories: Vec<RepositoryEntry>,
    pub items: Vec<ItemEntry>,
    #[serde(default)]
    pub scan_evidence: Vec<ScanEvidenceEntry>,
    /// Reserved for P3; `null` for an unsigned bundle.
    #[serde(default)]
    pub signing: Option<SigningInfo>,
}

/// Counts derived from a manifest that passed [`validate_manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ManifestSummary {
    pub repository_count: usize,
    pub item_count: usize,
    pub total_bytes: u64,
    pub distinct_blob_count: usize,
    pub scan_evidence_count: usize,
}

/// Read the envelope (`format`, `schema_version`) from untyped JSON and refuse
/// anything that is not a bundle manifest this server can read.
pub fn check_envelope(value: &serde_json::Value) -> Result<u32, BundleError> {
    let obj = value
        .as_object()
        .ok_or_else(|| BundleError::WrongFormat("manifest is not a JSON object".into()))?;
    match obj.get("format").and_then(|f| f.as_str()) {
        Some(BUNDLE_FORMAT) => {}
        Some(other) => {
            return Err(BundleError::WrongFormat(format!(
                "format is {other:?}, expected {BUNDLE_FORMAT:?}"
            )))
        }
        None => {
            return Err(BundleError::WrongFormat(
                "missing string field 'format'".into(),
            ))
        }
    }
    let version = obj
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            BundleError::Malformed("schema_version must be a non-negative integer".into())
        })?;
    if version < u64::from(MIN_SCHEMA_VERSION) || version > u64::from(MANIFEST_SCHEMA_VERSION) {
        return Err(BundleError::UnsupportedVersion {
            found: version,
            min: MIN_SCHEMA_VERSION,
            max: MANIFEST_SCHEMA_VERSION,
        });
    }
    Ok(version as u32)
}

/// Decode `manifest.json` bytes: size cap, envelope check, strict typed parse.
pub fn decode_manifest(bytes: &[u8], limits: &BundleLimits) -> Result<BundleManifest, BundleError> {
    if bytes.len() as u64 > limits.max_manifest_bytes {
        return Err(BundleError::LimitExceeded(format!(
            "manifest is larger than {} bytes",
            limits.max_manifest_bytes
        )));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| BundleError::Malformed(e.to_string()))?;
    check_envelope(&value)?;
    serde_json::from_value(value).map_err(|e| BundleError::Malformed(e.to_string()))
}

/// Encode a manifest deterministically: records sorted by their natural keys,
/// pretty-printed with a trailing newline (inspectable by a human reviewer).
pub fn encode_manifest(manifest: &BundleManifest) -> Result<Vec<u8>, BundleError> {
    let mut m = manifest.clone();
    m.repositories.sort_by(|a, b| a.key.cmp(&b.key));
    m.items.sort_by(|a, b| {
        (&a.repository_key, &a.logical_path).cmp(&(&b.repository_key, &b.logical_path))
    });
    m.scan_evidence.sort_by(|a, b| {
        (&a.artifact_sha256, &a.scanner, a.scanned_at).cmp(&(
            &b.artifact_sha256,
            &b.scanner,
            b.scanned_at,
        ))
    });
    let mut out =
        serde_json::to_vec_pretty(&m).map_err(|e| BundleError::Malformed(e.to_string()))?;
    out.push(b'\n');
    Ok(out)
}

/// Lowercase hex SHA-256 of `bytes` (the manifest digest recorded on a job).
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The digest a per-record signature covers (P3): SHA-256 over the RFC 8785
/// canonical JSON of the record with its own signature removed. Signing per
/// record lets one record be removed during a releasability review, or one
/// corrupt item be identified and re-shipped, without invalidating the set.
pub fn record_digest(item: &ItemEntry) -> Result<String, BundleError> {
    let unsigned = ItemEntry {
        signature: None,
        ..item.clone()
    };
    let canonical = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|e| BundleError::Malformed(e.to_string()))?;
    Ok(sha256_hex(&canonical))
}

/// Collects problems up to [`MAX_REPORTED_PROBLEMS`].
#[derive(Default)]
struct Problems(Vec<String>);

impl Problems {
    fn push(&mut self, problem: impl Into<String>) {
        if self.0.len() < MAX_REPORTED_PROBLEMS {
            self.0.push(problem.into());
        }
    }

    fn check_path(&mut self, what: &str, path: &str, expected: &str) {
        if let Err(e) = check_bundle_path(path) {
            self.push(format!("{what}: {e}"));
        } else if path != expected {
            self.push(format!(
                "{what}: path {path:?} is not canonical {expected:?}"
            ));
        }
    }
}

fn is_label(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

fn is_printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

fn validate_sequence(m: &BundleManifest, p: &mut Problems) {
    match (m.kind, &m.sequence) {
        (BundleKind::Full, None) => {}
        (BundleKind::Full, Some(_)) => p.push("a full bundle must not carry a sequence"),
        (_, None) => p.push("baseline and cumulative bundles must carry a sequence"),
        (kind, Some(seq)) => {
            if seq.sequence_number == 0 {
                p.push("sequence_number must be >= 1");
            }
            let base_ok = match kind {
                BundleKind::Baseline => seq.baseline_sequence_number == seq.sequence_number,
                _ => seq.baseline_sequence_number < seq.sequence_number,
            };
            if !base_ok {
                p.push(format!(
                    "{kind:?} bundle has inconsistent baseline_sequence_number {} for sequence {}",
                    seq.baseline_sequence_number, seq.sequence_number
                ));
            }
        }
    }
}

fn validate_repositories(m: &BundleManifest, p: &mut Problems) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    if m.repositories.is_empty() {
        p.push("bundle declares no repositories");
    }
    for repo in &m.repositories {
        if !is_valid_repo_key(&repo.key) {
            p.push(format!("repository key {:?} is not a valid key", repo.key));
            continue;
        }
        if !keys.insert(repo.key.clone()) {
            p.push(format!("repository {:?} is declared twice", repo.key));
        }
        if !is_label(&repo.format, 64) || !is_label(&repo.repo_type, 32) {
            p.push(format!(
                "repository {:?}: format and repo_type must be lowercase labels",
                repo.key
            ));
        }
        let what = format!("repository {:?}", repo.key);
        p.check_path(
            &what,
            &repo.metadata_path,
            &repo_file_path(&repo.key, RepoFile::Repo),
        );
        p.check_path(
            &what,
            &repo.artifacts_path,
            &repo_file_path(&repo.key, RepoFile::Artifacts),
        );
        if let Some(oci) = &repo.oci_path {
            p.check_path(&what, oci, &repo_file_path(&repo.key, RepoFile::Oci));
        }
    }
    keys
}

fn validate_items(
    m: &BundleManifest,
    repo_keys: &BTreeSet<String>,
    limits: &BundleLimits,
    p: &mut Problems,
) -> (u64, BTreeSet<String>) {
    let mut total: u64 = 0;
    let mut seen = BTreeSet::new();
    let mut digests = BTreeSet::new();
    if m.items.len() as u64 > limits.max_items {
        p.push(format!(
            "bundle has {} items, more than the limit of {}",
            m.items.len(),
            limits.max_items
        ));
        return (0, digests);
    }
    for (idx, item) in m.items.iter().enumerate() {
        let what = format!("item {idx}");
        if !repo_keys.contains(&item.repository_key) {
            p.push(format!(
                "{what}: repository {:?} is not declared",
                item.repository_key
            ));
        }
        if let Err(e) = check_logical_path(&item.logical_path) {
            p.push(format!("{what}: {e}"));
            continue;
        }
        if !seen.insert((&item.repository_key, &item.logical_path)) {
            p.push(format!(
                "{what}: {}/{} appears more than once",
                item.repository_key, item.logical_path
            ));
        }
        if !is_sha256_hex(&item.sha256) {
            p.push(format!("{what}: sha256 is not a lowercase hex SHA-256"));
            continue;
        }
        digests.insert(item.sha256.clone());
        p.check_path(
            &what,
            &item.blob_path,
            &blob_path(&item.sha256, &item.logical_path),
        );
        if item.volume == 0 || item.volume > m.volume_set.volume_count {
            p.push(format!(
                "{what}: volume {} is outside 1..={}",
                item.volume, m.volume_set.volume_count
            ));
        }
        if item.signature.is_some() && m.signing.is_none() {
            p.push(format!(
                "{what}: carries a record signature but the bundle has no signing block"
            ));
        }
        match total.checked_add(item.size_bytes) {
            Some(t) => total = t,
            None => p.push("total item size overflows"),
        }
    }
    (total, digests)
}

fn validate_evidence(m: &BundleManifest, digests: &BTreeSet<String>, p: &mut Problems) {
    for (idx, ev) in m.scan_evidence.iter().enumerate() {
        let what = format!("scan_evidence {idx}");
        if !digests.contains(&ev.artifact_sha256) {
            p.push(format!("{what}: artifact_sha256 matches no item"));
        }
        if !is_label(&ev.scanner, 64) {
            p.push(format!("{what}: scanner must be a lowercase label"));
        }
        if let Some(path) = &ev.evidence_path {
            match path
                .rsplit('/')
                .next()
                .and_then(|n| n.strip_suffix(".json"))
            {
                Some(sha) if is_sha256_hex(sha) => p.check_path(&what, path, &evidence_path(sha)),
                _ => p.push(format!("{what}: evidence_path {path:?} is not canonical")),
            }
        }
    }
}

fn validate_signing(m: &BundleManifest, p: &mut Problems) {
    if let Some(signing) = &m.signing {
        if !is_printable(&signing.signer_key_id, 256)
            || !is_printable(&signing.signer_fingerprint, 256)
            || !is_printable(&signing.algorithm, 64)
        {
            p.push("signing: signer_key_id, signer_fingerprint and algorithm are required");
        }
        if let Some(path) = &signing.key_status_list_path {
            match layout::classify_file(path) {
                Ok(layout::BundleEntry::Signing { .. }) => {}
                _ => p.push(format!(
                    "signing: key_status_list_path {path:?} is not under signing/"
                )),
            }
        }
    }
}

/// Check a decoded manifest for internal consistency. Returns the summary on
/// success, or every problem found (capped at [`MAX_REPORTED_PROBLEMS`]).
pub fn validate_manifest(
    m: &BundleManifest,
    limits: &BundleLimits,
) -> Result<ManifestSummary, Vec<String>> {
    let mut p = Problems::default();
    if m.format != BUNDLE_FORMAT {
        p.push(format!(
            "format is {:?}, expected {BUNDLE_FORMAT:?}",
            m.format
        ));
    }
    if !(MIN_SCHEMA_VERSION..=MANIFEST_SCHEMA_VERSION).contains(&m.schema_version) {
        p.push(format!("unsupported schema_version {}", m.schema_version));
    }
    if !is_printable(&m.producer.product, 64) || !is_printable(&m.producer.version, 64) {
        p.push("producer.product and producer.version are required");
    }
    if m.volume_set.volume_count == 0 {
        p.push("volume_set.volume_count must be >= 1");
    }
    if let Some(mcn) = &m.volume_set.media_control_number {
        if !is_printable(mcn, 64) {
            p.push("volume_set.media_control_number must be 1-64 printable characters");
        }
    }
    validate_sequence(m, &mut p);
    let repo_keys = validate_repositories(m, &mut p);
    let (total_bytes, digests) = validate_items(m, &repo_keys, limits, &mut p);
    validate_evidence(m, &digests, &mut p);
    validate_signing(m, &mut p);

    if !p.0.is_empty() {
        return Err(p.0);
    }
    let distinct_blobs: BTreeMap<&str, ()> =
        m.items.iter().map(|i| (i.blob_path.as_str(), ())).collect();
    Ok(ManifestSummary {
        repository_count: m.repositories.len(),
        item_count: m.items.len(),
        total_bytes,
        distinct_blob_count: distinct_blobs.len(),
        scan_evidence_count: m.scan_evidence.len(),
    })
}

/// Features a valid manifest uses that this server's importer cannot yet
/// honour. A non-empty list means the import must be refused: a reserved
/// field is never silently ignored (in particular, a signature is never
/// treated as verified when it was not checked).
pub fn unsupported_features(m: &BundleManifest) -> Vec<String> {
    let mut out = Vec::new();
    if m.kind != BundleKind::Full {
        out.push(format!(
            "{:?} bundles (sequenced delta sets arrive in P2)",
            m.kind
        ));
    }
    if m.signing.is_some() || m.items.iter().any(|i| i.signature.is_some()) {
        out.push("signed bundles (signature verification arrives with #2466)".to_string());
    }
    if m.volume_set.volume_count > 1 {
        out.push("multi-volume sets".to_string());
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const SHA_A: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub(crate) const SHA_B: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn limits() -> BundleLimits {
        BundleLimits::default()
    }

    pub(crate) fn item(repo: &str, path: &str, sha: &str, size: u64) -> ItemEntry {
        ItemEntry {
            repository_key: repo.into(),
            logical_path: path.into(),
            sha256: sha.into(),
            size_bytes: size,
            blob_path: blob_path(sha, path),
            volume: 1,
            content_type: None,
            signature: None,
        }
    }

    pub(crate) fn sample_manifest() -> BundleManifest {
        BundleManifest {
            format: BUNDLE_FORMAT.into(),
            schema_version: MANIFEST_SCHEMA_VERSION,
            bundle_id: Uuid::nil(),
            created_at: DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            producer: Producer {
                product: "artifact-keeper".into(),
                version: "1.11.0".into(),
                instance_id: None,
            },
            kind: BundleKind::Full,
            sequence: None,
            volume_set: VolumeSet {
                set_id: Uuid::nil(),
                media_profile: MediaProfile::Unbounded,
                volume_count: 1,
                media_control_number: Some("MCN-0001".into()),
            },
            repositories: vec![RepositoryEntry {
                key: "libs".into(),
                format: "maven".into(),
                repo_type: "local".into(),
                metadata_path: "repos/libs/repo.json".into(),
                artifacts_path: "repos/libs/artifacts.json".into(),
                oci_path: None,
            }],
            items: vec![
                item("libs", "com/acme/b/1.0/b-1.0.jar", SHA_B, 20),
                item("libs", "com/acme/a/1.0/a-1.0.jar", SHA_A, 10),
            ],
            scan_evidence: vec![],
            signing: None,
        }
    }

    fn problems(m: &BundleManifest) -> Vec<String> {
        validate_manifest(m, &limits()).expect_err("manifest should be invalid")
    }

    fn assert_problem(m: &BundleManifest, needle: &str) {
        let p = problems(m);
        assert!(
            p.iter().any(|s| s.contains(needle)),
            "expected a problem containing {needle:?}, got {p:?}"
        );
    }

    #[test]
    fn round_trip_is_deterministic_and_sorted() {
        let m = sample_manifest();
        let bytes = encode_manifest(&m).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let decoded = decode_manifest(&bytes, &limits()).unwrap();
        assert_eq!(decoded.items[0].logical_path, "com/acme/a/1.0/a-1.0.jar");
        assert_eq!(encode_manifest(&decoded).unwrap(), bytes);
        let summary = validate_manifest(&decoded, &limits()).unwrap();
        assert_eq!(summary.item_count, 2);
        assert_eq!(summary.total_bytes, 30);
        assert_eq!(summary.distinct_blob_count, 2);
        assert!(unsupported_features(&decoded).is_empty());
        assert_eq!(sha256_hex(&bytes).len(), 64);
    }

    #[test]
    fn reserved_fields_are_always_emitted() {
        let text = String::from_utf8(encode_manifest(&sample_manifest()).unwrap()).unwrap();
        for field in [
            "\"sequence\": null",
            "\"signing\": null",
            "\"scan_evidence\": []",
        ] {
            assert!(text.contains(field), "{field} missing from {text}");
        }
    }

    #[test]
    fn newer_schema_version_is_a_version_error_not_a_parse_error() {
        let doc = serde_json::json!({
            "format": BUNDLE_FORMAT,
            "schema_version": MANIFEST_SCHEMA_VERSION + 1,
            "a_field_from_the_future": true,
        });
        let err = decode_manifest(doc.to_string().as_bytes(), &limits()).unwrap_err();
        assert_eq!(
            err,
            BundleError::UnsupportedVersion {
                found: u64::from(MANIFEST_SCHEMA_VERSION + 1),
                min: MIN_SCHEMA_VERSION,
                max: MANIFEST_SCHEMA_VERSION,
            }
        );
        let zero = serde_json::json!({"format": BUNDLE_FORMAT, "schema_version": 0});
        assert!(matches!(
            decode_manifest(zero.to_string().as_bytes(), &limits()),
            Err(BundleError::UnsupportedVersion { found: 0, .. })
        ));
    }

    #[test]
    fn envelope_errors() {
        for (doc, want_format) in [
            (serde_json::json!([]), true),
            (serde_json::json!({"schema_version": 1}), true),
            (
                serde_json::json!({"format": "zip", "schema_version": 1}),
                true,
            ),
            (
                serde_json::json!({"format": BUNDLE_FORMAT, "schema_version": "1"}),
                false,
            ),
            (
                serde_json::json!({"format": BUNDLE_FORMAT, "schema_version": -1}),
                false,
            ),
        ] {
            let err = check_envelope(&doc).unwrap_err();
            assert_eq!(
                matches!(err, BundleError::WrongFormat(_)),
                want_format,
                "{doc}: {err}"
            );
        }
        assert!(matches!(
            decode_manifest(b"{not json", &limits()),
            Err(BundleError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_fields_within_a_version_are_rejected() {
        let mut value = serde_json::to_value(sample_manifest()).unwrap();
        value["items"][0]["content_base64"] = serde_json::json!("AAAA");
        let err = decode_manifest(value.to_string().as_bytes(), &limits()).unwrap_err();
        assert!(
            matches!(err, BundleError::Malformed(ref m) if m.contains("content_base64")),
            "{err}"
        );
    }

    #[test]
    fn oversized_manifest_is_refused_before_parsing() {
        let tiny = BundleLimits {
            max_manifest_bytes: 8,
            ..BundleLimits::default()
        };
        assert!(matches!(
            decode_manifest(b"{\"format\": \"akbundle\"}", &tiny),
            Err(BundleError::LimitExceeded(_))
        ));
    }

    #[test]
    fn traversal_in_manifest_paths_is_refused() {
        let mut m = sample_manifest();
        m.items[0].logical_path = "../../etc/passwd".into();
        m.items[0].blob_path = "blobs/../../etc/passwd".into();
        assert_problem(&m, "path traversal");

        let mut m = sample_manifest();
        m.items[0].blob_path = "../blobs/bb/x.jar".into();
        assert_problem(&m, "path traversal");

        let mut m = sample_manifest();
        m.repositories[0].metadata_path = "/etc/shadow".into();
        assert_problem(&m, "path traversal");

        let mut m = sample_manifest();
        m.items[0].blob_path = format!("blobs/bb/{SHA_B}.war");
        assert_problem(&m, "not canonical");
    }

    #[test]
    fn item_consistency_rules() {
        let mut m = sample_manifest();
        m.items[0].repository_key = "other".into();
        assert_problem(&m, "not declared");

        let mut m = sample_manifest();
        m.items[1].logical_path = m.items[0].logical_path.clone();
        m.items[1].blob_path = blob_path(SHA_A, &m.items[1].logical_path);
        assert_problem(&m, "more than once");

        let mut m = sample_manifest();
        m.items[0].sha256 = SHA_B.to_uppercase();
        assert_problem(&m, "lowercase hex");

        let mut m = sample_manifest();
        m.items[0].volume = 2;
        assert_problem(&m, "outside 1..=1");

        let mut m = sample_manifest();
        m.items[0].size_bytes = u64::MAX;
        assert_problem(&m, "overflows");

        let mut m = sample_manifest();
        m.items[0].signature = Some(RecordSignature {
            key_id: "k".into(),
            algorithm: "ed25519".into(),
            value: "c2ln".into(),
        });
        assert_problem(&m, "no signing block");

        let few = BundleLimits {
            max_items: 1,
            ..BundleLimits::default()
        };
        let p = validate_manifest(&sample_manifest(), &few).unwrap_err();
        assert!(p[0].contains("more than the limit"));
    }

    #[test]
    fn repository_rules() {
        let mut m = sample_manifest();
        m.repositories.clear();
        assert_problem(&m, "no repositories");

        let mut m = sample_manifest();
        m.repositories.push(m.repositories[0].clone());
        assert_problem(&m, "declared twice");

        let mut m = sample_manifest();
        m.repositories[0].key = "../x".into();
        assert_problem(&m, "not a valid key");

        let mut m = sample_manifest();
        m.repositories[0].format = "Maven!".into();
        assert_problem(&m, "lowercase labels");

        let mut m = sample_manifest();
        m.repositories[0].oci_path = Some("repos/libs/repo.json".into());
        assert_problem(&m, "not canonical");
    }

    #[test]
    fn envelope_and_volume_rules() {
        let mut m = sample_manifest();
        m.format = "other".into();
        m.schema_version = 7;
        m.producer.product.clear();
        m.volume_set.volume_count = 0;
        m.volume_set.media_control_number = Some("bad\nmcn".into());
        let p = problems(&m);
        for needle in [
            "format is",
            "schema_version 7",
            "producer",
            "volume_count",
            "media_control_number",
        ] {
            assert!(p.iter().any(|s| s.contains(needle)), "{needle}: {p:?}");
        }
    }

    #[test]
    fn sequence_rules() {
        let seq = |n, base| SequenceInfo {
            stream_id: Uuid::nil(),
            sequence_number: n,
            baseline_sequence_number: base,
        };
        let mut m = sample_manifest();
        m.sequence = Some(seq(1, 1));
        assert_problem(&m, "must not carry a sequence");

        m.kind = BundleKind::Cumulative;
        m.sequence = None;
        assert_problem(&m, "must carry a sequence");

        m.sequence = Some(seq(3, 3));
        assert_problem(&m, "inconsistent baseline");

        m.sequence = Some(seq(0, 0));
        m.kind = BundleKind::Baseline;
        assert_problem(&m, ">= 1");

        m.sequence = Some(seq(5, 2));
        m.kind = BundleKind::Cumulative;
        assert!(validate_manifest(&m, &limits()).is_ok());
        assert!(unsupported_features(&m)[0].contains("P2"));
    }

    #[test]
    fn evidence_rules() {
        let ev = |sha: &str| ScanEvidenceEntry {
            artifact_sha256: sha.into(),
            scanner: "grype".into(),
            scanner_version: Some("0.80".into()),
            vulnerability_db_version: None,
            scanned_at: Utc::now(),
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            evidence_path: Some(evidence_path(SHA_A)),
        };
        let mut m = sample_manifest();
        m.scan_evidence = vec![ev(SHA_A)];
        assert_eq!(
            validate_manifest(&m, &limits())
                .unwrap()
                .scan_evidence_count,
            1
        );

        m.scan_evidence = vec![ev(&"c".repeat(64))];
        assert_problem(&m, "matches no item");

        let mut bad = ev(SHA_A);
        bad.scanner = "Grype Scanner".into();
        bad.evidence_path = Some("evidence/../x.json".into());
        m.scan_evidence = vec![bad];
        let p = problems(&m);
        assert!(p.iter().any(|s| s.contains("lowercase label")), "{p:?}");
        assert!(p.iter().any(|s| s.contains("not canonical")), "{p:?}");

        let mut wrong_dir = ev(SHA_A);
        wrong_dir.evidence_path = Some(format!("evidence/zz/{SHA_A}.json"));
        m.scan_evidence = vec![wrong_dir];
        assert_problem(&m, "not canonical");
    }

    #[test]
    fn signed_and_multi_volume_bundles_are_valid_but_not_importable_yet() {
        let mut m = sample_manifest();
        m.signing = Some(SigningInfo {
            signed_at: Utc::now(),
            signer_key_id: "key-1".into(),
            signer_fingerprint: "ab:cd".into(),
            algorithm: "ecdsa-p384".into(),
            key_status_list_path: Some("signing/key-status.json".into()),
        });
        m.items[0].signature = Some(RecordSignature {
            key_id: "key-1".into(),
            algorithm: "ecdsa-p384".into(),
            value: "c2ln".into(),
        });
        m.volume_set.volume_count = 2;
        m.volume_set.media_profile = MediaProfile::BdR;
        m.items[1].volume = 2;
        assert!(validate_manifest(&m, &limits()).is_ok());
        let unsupported = unsupported_features(&m);
        assert!(unsupported.iter().any(|f| f.contains("signed")));
        assert!(unsupported.iter().any(|f| f.contains("multi-volume")));

        m.signing.as_mut().unwrap().key_status_list_path = Some("blobs/x".into());
        m.signing.as_mut().unwrap().algorithm.clear();
        let p = problems(&m);
        assert!(p.iter().any(|s| s.contains("not under signing/")), "{p:?}");
        assert!(p.iter().any(|s| s.contains("are required")), "{p:?}");
    }

    #[test]
    fn record_digest_ignores_the_signature_but_covers_every_other_field() {
        let mut a = item("libs", "a.jar", SHA_A, 1);
        let unsigned = record_digest(&a).unwrap();
        a.signature = Some(RecordSignature {
            key_id: "k".into(),
            algorithm: "ed25519".into(),
            value: "c2ln".into(),
        });
        assert_eq!(record_digest(&a).unwrap(), unsigned);
        a.size_bytes = 2;
        assert_ne!(record_digest(&a).unwrap(), unsigned);
    }

    #[test]
    fn problem_list_is_capped() {
        let mut m = sample_manifest();
        m.items = (0..MAX_REPORTED_PROBLEMS + 50)
            .map(|i| item("missing", &format!("f{i}.jar"), SHA_A, 1))
            .collect();
        assert_eq!(problems(&m).len(), MAX_REPORTED_PROBLEMS);
    }

    #[test]
    fn media_profiles_have_nominal_capacities() {
        assert_eq!(MediaProfile::Unbounded.capacity_bytes(), None);
        assert_eq!(MediaProfile::DvdR.capacity_bytes(), Some(4_700_000_000));
        assert_eq!(MediaProfile::DvdRDl.capacity_bytes(), Some(8_500_000_000));
        assert_eq!(MediaProfile::BdR.capacity_bytes(), Some(25_000_000_000));
        assert_eq!(MediaProfile::BdRXl.capacity_bytes(), Some(100_000_000_000));
        assert_eq!(MediaProfile::ALL.len(), 5);
    }
}
