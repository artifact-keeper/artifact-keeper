//! CEP-16 shards synthesised for Remote conda repositories whose upstream
//! publishes no shard index (#4178).
//!
//! Most private channels and older mirrors publish only `repodata.json` (and
//! its `.zst`/`.bz2`), so a CEP-16 client of such a remote downloaded the
//! whole index on every solve. Here the remote builds the shard set itself
//! from the upstream document its proxy cache already holds, and stores it
//! through the hosted path's table (`conda_shard_index`, origin
//! `'synthesized'`), so the shard index, the shard GETs and a virtual's union
//! of members (#4179) serve it exactly as they serve a hosted channel's.
//!
//! * **Freshness.** `conda_synthesized_subdirs` records which cached upstream
//!   document (path and SHA-256) the stored shards were built from. A request
//!   compares that with the proxy cache entry's checksum (a metadata read, no
//!   read of the document) and serves the stored shards while they match. Past
//!   the cache entry's TTL (the remote's metadata TTL) the document is fetched
//!   through the proxy again; an unchanged checksum is a no-op, a changed one
//!   marks the subdir stale and rebuilds it. A stale index is never served: the
//!   request waits for the rebuild (bounded by `AK_CONDA_REGEN_WAIT_SECS`, then
//!   `503` with `Retry-After` while the rebuild finishes).
//! * **Bounded memory.** The compressed document is decoded as a stream and
//!   parsed record by record ([`for_each_record`]); the plain JSON is never
//!   held, and no `serde_json::Value` tree of the document is built. Records
//!   are spilled to [`PARTITIONS`] temporary files by package name, then each
//!   partition is grouped into shards and written, so what is held at once is
//!   the compressed document, one record, and one partition's records.
//! * **One swap.** A rebuild writes every changed shard, deletes the names the
//!   upstream dropped, records the source and bumps the subdir revision in one
//!   transaction under a per-subdir advisory lock, so a reader sees the old set
//!   or the new one. Every stored shard is checked against its address when
//!   it is served (#4829), as a hosted one is.

use std::collections::BTreeMap;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::repodata_cache::{self, Prepared, Revision};
use super::{proxy_helpers, RepodataEncoding};

/// Advisory-lock class of the per-subdir synthesis lock (two-argument
/// advisory locks; the hosted materialisation lock is 0x4173).
const SYNTH_LOCK_CLASS: i32 = 0x4178;

/// Spill partitions. conda-forge `linux-64` (about 460 MiB of JSON) puts a
/// few MiB of records in each.
pub(crate) const PARTITIONS: usize = 64;

/// Shard rows written per statement.
const UPSERT_BATCH: usize = 256;

/// Decoded bytes one record (or one skipped top-level member such as
/// `removed`) may take. conda-forge's largest record is about 5 KB and its
/// largest `removed` list about 130 KB; the bound keeps a hostile upstream
/// from making one record a multi-GiB `Value`.
pub(crate) const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;

/// JSON bytes of the records one package name may carry, which is what one
/// shard holds in memory while it is encoded. conda-forge's largest
/// (`awscli`, linux-64) is about 7 MB.
pub(crate) const MAX_NAME_BYTES: usize = 64 * 1024 * 1024;

/// Why a synthesis failed: the upstream document, or this host.
#[derive(Debug)]
pub(crate) enum SynthError {
    /// The upstream document is unusable: it does not parse, or it is past
    /// a decoded, record or per-name ceiling. Answered `502`.
    Upstream(String),
    /// A local failure: the spill files in the temporary directory could not
    /// be created, written or read (a full or read-only `TMPDIR`). Answered
    /// `500`; nothing is stored.
    Local(String),
}

impl std::fmt::Display for SynthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upstream(e) => write!(f, "upstream document: {e}"),
            Self::Local(e) => write!(f, "local spill: {e}"),
        }
    }
}

/// Counts the decoded bytes read: in all, and since the last
/// [`Meter::mark`] (the start of a record or top-level member).
#[derive(Clone, Default)]
struct Meter(Arc<(std::sync::atomic::AtomicU64, std::sync::atomic::AtomicU64)>);

impl Meter {
    fn mark(&self) {
        self.0 .1.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A reader that fails once the document passes `decoded_cap` bytes, or a
/// single record or member passes `record_cap` bytes. The parser reads
/// through a 256 KiB buffer, so the record bound is that coarse.
struct Metered<R> {
    inner: R,
    meter: Meter,
    decoded_cap: u64,
    record_cap: u64,
}

impl<R: Read> Read for Metered<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.inner.read(buf)?;
        let total = self.meter.0 .0.fetch_add(n as u64, Relaxed) + n as u64;
        let since = self.meter.0 .1.fetch_add(n as u64, Relaxed) + n as u64;
        if total > self.decoded_cap {
            return Err(std::io::Error::other(format!(
                "decoded document exceeds the {}-byte ceiling ({})",
                self.decoded_cap,
                super::virtual_merge::MEMBER_MAX_DECODED_BYTES_ENV
            )));
        }
        if since > self.record_cap + 256 * 1024 {
            return Err(std::io::Error::other(format!(
                "a record exceeds {} bytes",
                self.record_cap
            )));
        }
        Ok(n)
    }
}

/// The upstream documents a synthesis reads, most compact first, as the
/// plain `repodata.json` proxy reads them (#4180).
const SOURCES: [RepodataEncoding; 3] = [
    RepodataEncoding::Zst,
    RepodataEncoding::Bz2,
    RepodataEncoding::Json,
];

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "conda shard synthesis failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
}

// ---------------------------------------------------------------------------
// Streaming parse
// ---------------------------------------------------------------------------

/// Call `sink(conda_v2, filename, record)` for every record of the
/// `repodata.json` read from `reader`, in document order, without building
/// the document: `packages` and `packages.conda` are walked entry by entry,
/// every other member is skipped. Returns the number of records. The decoded
/// document is bounded by the virtual member ceiling
/// ([`super::virtual_merge::MemberLimits`], 1 GiB by default) and each record
/// by [`MAX_RECORD_BYTES`].
pub(crate) fn for_each_record<R, F>(reader: R, sink: F) -> Result<usize, String>
where
    R: Read,
    F: FnMut(bool, String, Map<String, Value>) -> Result<(), String>,
{
    for_each_record_capped(
        reader,
        super::virtual_merge::MemberLimits::from_env().decoded as u64,
        MAX_RECORD_BYTES,
        sink,
    )
}

/// [`for_each_record`] with explicit ceilings.
pub(crate) fn for_each_record_capped<R, F>(
    reader: R,
    decoded_cap: u64,
    record_cap: u64,
    mut sink: F,
) -> Result<usize, String>
where
    R: Read,
    F: FnMut(bool, String, Map<String, Value>) -> Result<(), String>,
{
    struct Top<'a, F> {
        sink: &'a mut F,
        count: &'a mut usize,
        meter: &'a Meter,
    }
    struct Section<'a, F> {
        v2: bool,
        sink: &'a mut F,
        count: &'a mut usize,
        meter: &'a Meter,
    }
    impl<'de, F> Visitor<'de> for Top<'_, F>
    where
        F: FnMut(bool, String, Map<String, Value>) -> Result<(), String>,
    {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a repodata.json object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            while let Some(key) = map.next_key::<String>()? {
                self.meter.mark();
                let v2 = match key.as_str() {
                    "packages" => false,
                    "packages.conda" => true,
                    _ => {
                        map.next_value::<IgnoredAny>()?;
                        continue;
                    }
                };
                map.next_value_seed(Section {
                    v2,
                    sink: &mut *self.sink,
                    count: &mut *self.count,
                    meter: self.meter,
                })?;
            }
            Ok(())
        }
    }
    impl<'de, F> DeserializeSeed<'de> for Section<'_, F>
    where
        F: FnMut(bool, String, Map<String, Value>) -> Result<(), String>,
    {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de, F> Visitor<'de> for Section<'_, F>
    where
        F: FnMut(bool, String, Map<String, Value>) -> Result<(), String>,
    {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of filename to package record")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            use serde::de::Error;
            while let Some(filename) = map.next_key::<String>()? {
                let record: Map<String, Value> = map.next_value()?;
                self.meter.mark();
                (self.sink)(self.v2, filename, record).map_err(A::Error::custom)?;
                *self.count += 1;
            }
            Ok(())
        }
    }

    let mut count = 0usize;
    let meter = Meter::default();
    let reader = Metered {
        inner: reader,
        meter: meter.clone(),
        decoded_cap,
        record_cap,
    };
    let mut de =
        serde_json::Deserializer::from_reader(BufReader::with_capacity(256 * 1024, reader));
    serde::Deserializer::deserialize_map(
        &mut de,
        Top {
            sink: &mut sink,
            count: &mut count,
            meter: &meter,
        },
    )
    .map_err(|e| format!("upstream repodata.json does not parse: {e}"))?;
    de.end()
        .map_err(|e| format!("upstream repodata.json has trailing data: {e}"))?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Spill by package name
// ---------------------------------------------------------------------------

/// FNV-1a: a stable partition for a package name.
fn partition_of(name: &str) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    (h % PARTITIONS as u64) as usize
}

/// Records spilled to temporary files, one per partition of package names.
pub(crate) struct Spill {
    dir: tempfile::TempDir,
    writers: Vec<BufWriter<std::fs::File>>,
    /// Records skipped because they name no package.
    pub skipped: usize,
}

fn put_bytes(w: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)
}

fn get_bytes(r: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut out = vec![0u8; u32::from_le_bytes(len) as usize];
    r.read_exact(&mut out)?;
    Ok(Some(out))
}

impl Spill {
    /// Spill under `parent` (the process's temporary directory, `TMPDIR`,
    /// in production).
    pub(crate) fn new_in(parent: &std::path::Path) -> std::io::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("ak-conda-shard-synth-")
            .tempdir_in(parent)?;
        let writers = (0..PARTITIONS)
            .map(|i| {
                std::fs::File::create(dir.path().join(format!("{i:02}")))
                    .map(|f| BufWriter::with_capacity(64 * 1024, f))
            })
            .collect::<std::io::Result<_>>()?;
        Ok(Self {
            dir,
            writers,
            skipped: 0,
        })
    }

    /// Spill one record under the package name it carries.
    pub(crate) fn put(
        &mut self,
        v2: bool,
        filename: &str,
        record: &Map<String, Value>,
    ) -> Result<(), String> {
        let Some(name) = record.get("name").and_then(Value::as_str) else {
            self.skipped += 1;
            return Ok(());
        };
        let json = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        let w = &mut self.writers[partition_of(name)];
        (|| {
            put_bytes(w, name.as_bytes())?;
            w.write_all(&[u8::from(v2)])?;
            put_bytes(w, filename.as_bytes())?;
            put_bytes(w, &json)
        })()
        .map_err(|e| format!("spilling a record: {e}"))
    }

    /// Flush the writers and hand back the partition files.
    pub(crate) fn finish(self) -> Result<SpilledPartitions, String> {
        for mut w in self.writers {
            w.flush().map_err(|e| format!("spilling records: {e}"))?;
        }
        let paths = (0..PARTITIONS)
            .map(|i| self.dir.path().join(format!("{i:02}")))
            .collect();
        Ok(SpilledPartitions {
            _dir: self.dir,
            paths,
        })
    }
}

/// The spilled partition files; the directory is removed on drop.
pub(crate) struct SpilledPartitions {
    _dir: tempfile::TempDir,
    pub paths: Vec<PathBuf>,
}

/// One synthesised shard: package name, `.msgpack.zst` bytes, address.
pub(crate) type BuiltShard = (String, Vec<u8>, [u8; 32]);

/// Group one partition's records by package name and encode each name's
/// CEP-16 shard, in name order. Records are held as their JSON bytes until
/// their name is encoded, so the partition is never a `Value` tree; one name
/// past [`MAX_NAME_BYTES`] refuses the document.
pub(crate) fn shards_of_partition(path: &std::path::Path) -> Result<Vec<BuiltShard>, SynthError> {
    shards_of_partition_capped(path, MAX_NAME_BYTES)
}

/// [`shards_of_partition`] with an explicit per-name ceiling.
pub(crate) fn shards_of_partition_capped(
    path: &std::path::Path,
    name_cap: usize,
) -> Result<Vec<BuiltShard>, SynthError> {
    let io = |e: std::io::Error| SynthError::Local(format!("reading spilled records: {e}"));
    let local = |e: &dyn std::fmt::Display| SynthError::Local(format!("spilled records: {e}"));
    let mut r = BufReader::with_capacity(64 * 1024, std::fs::File::open(path).map_err(io)?);
    type Raw = Vec<(String, Vec<u8>)>;
    let mut by_name: BTreeMap<String, (Raw, Raw, usize)> = BTreeMap::new();
    while let Some(name) = get_bytes(&mut r).map_err(io)? {
        let mut flag = [0u8; 1];
        r.read_exact(&mut flag).map_err(io)?;
        let filename = get_bytes(&mut r)
            .map_err(io)?
            .ok_or_else(|| local(&"truncated spill"))?;
        let json = get_bytes(&mut r)
            .map_err(io)?
            .ok_or_else(|| local(&"truncated spill"))?;
        let name = String::from_utf8(name).map_err(|e| local(&e))?;
        let filename = String::from_utf8(filename).map_err(|e| local(&e))?;
        let slot = by_name.entry(name).or_default();
        slot.2 += json.len();
        if slot.2 > name_cap {
            return Err(SynthError::Upstream(format!(
                "the records of one package name exceed {name_cap} bytes"
            )));
        }
        if flag[0] == 1 {
            slot.1.push((filename, json));
        } else {
            slot.0.push((filename, json));
        }
    }
    let mut out = Vec::with_capacity(by_name.len());
    for (name, (packages, conda, _)) in by_name {
        let section = |raw: Raw| -> Result<Map<String, Value>, SynthError> {
            let mut map = Map::new();
            for (filename, json) in raw {
                // A filename listed twice keeps its last record, as a JSON
                // parser reading the upstream document would.
                map.insert(
                    filename,
                    serde_json::from_slice(&json).map_err(|e| local(&e))?,
                );
            }
            Ok(map)
        };
        let shard = serde_json::json!({
            "packages": Value::Object(section(packages)?),
            "packages.conda": Value::Object(section(conda)?),
            "removed": [],
        });
        let bytes = super::encode_shard(&shard).map_err(|_| local(&"encoding a shard"))?;
        let address = super::shard_address(&bytes);
        out.push((name, bytes, address));
    }
    Ok(out)
}

/// Decode `compressed` (the upstream `source` document with its transfer
/// coding) as a stream and spill every record under `TMPDIR`. Blocking.
pub(crate) fn spill_document(
    compressed: Bytes,
    transfer_encoding: Option<&str>,
    source: RepodataEncoding,
) -> Result<(SpilledPartitions, usize), SynthError> {
    spill_document_in(&std::env::temp_dir(), compressed, transfer_encoding, source)
}

/// [`spill_document`] under `parent`.
pub(crate) fn spill_document_in(
    parent: &std::path::Path,
    compressed: Bytes,
    transfer_encoding: Option<&str>,
    source: RepodataEncoding,
) -> Result<(SpilledPartitions, usize), SynthError> {
    let reader = super::decoded_repodata_reader(compressed, transfer_encoding, source)
        .map_err(SynthError::Upstream)?;
    let mut spill = Spill::new_in(parent)
        .map_err(|e| SynthError::Local(format!("creating the spill directory: {e}")))?;
    let mut local_failure: Option<String> = None;
    let parsed = for_each_record(reader, |v2, filename, record| {
        spill.put(v2, &filename, &record).inspect_err(|e| {
            local_failure = Some(e.clone());
        })
    });
    let records = match (parsed, local_failure) {
        (Ok(records), None) => records,
        (_, Some(local)) => return Err(SynthError::Local(local)),
        (Err(e), None) => return Err(SynthError::Upstream(e)),
    };
    let skipped = spill.skipped;
    if skipped > 0 {
        tracing::debug!(
            skipped,
            "upstream conda records without a package name skipped"
        );
    }
    Ok((
        spill.finish().map_err(SynthError::Local)?,
        records - skipped,
    ))
}

/// The response for a failed synthesis: `502` when the upstream document is
/// unusable, `500` for a local failure. Either way nothing was stored and
/// the subdir stays stale, so no index is served from it.
fn synth_failure(repo_id: Uuid, subdir: &str, e: SynthError) -> Response {
    match e {
        SynthError::Upstream(e) => {
            tracing::warn!(repo = %repo_id, subdir, error = %e, "conda shard synthesis: upstream document unusable");
            (
                StatusCode::BAD_GATEWAY,
                "Upstream conda repodata could not be read to build its shards",
            )
                .into_response()
        }
        SynthError::Local(e) => {
            tracing::error!(
                repo = %repo_id, subdir, error = %e,
                "conda shard synthesis: the spill files in the temporary directory failed"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// What the stored synthesised shards of a subdir were built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Source {
    /// Upstream document path, relative to the upstream URL.
    pub path: String,
    /// SHA-256 hex of its bytes as the proxy cache holds them.
    pub sha256: String,
}

#[derive(Debug)]
struct SubdirRow {
    source: Option<Source>,
    built: bool,
    stale: bool,
}

async fn subdir_row(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
) -> Result<Option<SubdirRow>, Response> {
    let row = sqlx::query(
        "SELECT source_path, source_sha256, built_at IS NOT NULL AS built, \
                stale_since IS NOT NULL AS stale \
           FROM conda_synthesized_subdirs WHERE repository_id = $1 AND subdir = $2",
    )
    .bind(repo_id)
    .bind(subdir)
    .fetch_optional(db)
    .await
    .map_err(internal)?;
    Ok(row.map(|r| {
        let path: Option<String> = r.get("source_path");
        let sha256: Option<String> = r.get("source_sha256");
        SubdirRow {
            source: path
                .zip(sha256)
                .map(|(path, sha256)| Source { path, sha256 }),
            built: r.get("built"),
            stale: r.get("stale"),
        }
    }))
}

/// Rebuild the synthesised shards of `(repo_id, subdir)` from the upstream
/// document `compressed` (`source` encoding, `transfer_encoding` as cached)
/// identified by `from`. A no-op when another rebuild already stored them.
pub(crate) async fn rebuild(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
    compressed: Bytes,
    transfer_encoding: Option<String>,
    source: RepodataEncoding,
    from: &Source,
) -> Result<(), Response> {
    let mut tx = db.begin().await.map_err(internal)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2 || '/' || $3))")
        .bind(SYNTH_LOCK_CLASS)
        .bind(repo_id.to_string())
        .bind(subdir)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let current: Option<(Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT source_path, source_sha256, built_at IS NOT NULL AND stale_since IS NULL \
           FROM conda_synthesized_subdirs WHERE repository_id = $1 AND subdir = $2",
    )
    .bind(repo_id)
    .bind(subdir)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    if let Some((Some(path), Some(sha), true)) = &current {
        if *path == from.path && *sha == from.sha256 {
            tx.commit().await.map_err(internal)?;
            return Ok(());
        }
    }

    let started = std::time::Instant::now();
    let (partitions, records) = tokio::task::spawn_blocking(move || {
        spill_document(compressed, transfer_encoding.as_deref(), source)
    })
    .await
    .map_err(internal)?
    .map_err(|e| synth_failure(repo_id, subdir, e))?;

    let mut names: Vec<String> = Vec::new();
    let mut written = 0u64;
    let paths = partitions.paths.clone();
    for path in paths {
        let shards = tokio::task::spawn_blocking(move || shards_of_partition(&path))
            .await
            .map_err(internal)?
            .map_err(|e| synth_failure(repo_id, subdir, e))?;
        for chunk in shards.chunks(UPSERT_BATCH) {
            let batch_names: Vec<&str> = chunk.iter().map(|(n, _, _)| n.as_str()).collect();
            let batch_shards: Vec<&[u8]> = chunk.iter().map(|(_, s, _)| s.as_slice()).collect();
            let batch_hashes: Vec<&[u8]> = chunk.iter().map(|(_, _, h)| h.as_slice()).collect();
            written += sqlx::query(
                "INSERT INTO conda_shard_index \
                   (repository_id, subdir, package_name, shard_hash, shard, origin, updated_at) \
                 SELECT $1, $2, n, h, s, 'synthesized', NOW() \
                   FROM UNNEST($3::text[], $4::bytea[], $5::bytea[]) AS t(n, h, s) \
                 ON CONFLICT (repository_id, subdir, package_name) DO UPDATE \
                   SET shard_hash = EXCLUDED.shard_hash, shard = EXCLUDED.shard, \
                       origin = 'synthesized', updated_at = NOW() \
                 WHERE conda_shard_index.shard_hash IS DISTINCT FROM EXCLUDED.shard_hash",
            )
            .bind(repo_id)
            .bind(subdir)
            .bind(&batch_names)
            .bind(&batch_hashes)
            .bind(&batch_shards)
            .execute(&mut *tx)
            .await
            .map_err(internal)?
            .rows_affected();
        }
        names.extend(shards.into_iter().map(|(n, _, _)| n));
    }
    drop(partitions);
    let removed = sqlx::query(
        "DELETE FROM conda_shard_index \
          WHERE repository_id = $1 AND subdir = $2 AND origin = 'synthesized' \
            AND NOT (package_name = ANY($3))",
    )
    .bind(repo_id)
    .bind(subdir)
    .bind(&names)
    .execute(&mut *tx)
    .await
    .map_err(internal)?
    .rows_affected();
    sqlx::query(
        "INSERT INTO conda_synthesized_subdirs \
           (repository_id, subdir, source_path, source_sha256, built_at, stale_since, checked_at) \
         VALUES ($1, $2, $3, $4, NOW(), NULL, NOW()) \
         ON CONFLICT (repository_id, subdir) DO UPDATE \
           SET source_path = EXCLUDED.source_path, source_sha256 = EXCLUDED.source_sha256, \
               built_at = NOW(), stale_since = NULL, checked_at = NOW()",
    )
    .bind(repo_id)
    .bind(subdir)
    .bind(&from.path)
    .bind(&from.sha256)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query(
        "INSERT INTO conda_subdir_revisions (repository_id, subdir, revision) VALUES ($1, $2, 1) \
         ON CONFLICT (repository_id, subdir) DO UPDATE \
           SET revision = conda_subdir_revisions.revision + 1, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(subdir)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    repodata_cache::invalidate_local(repo_id, &[subdir.to_string()]).await;
    tracing::info!(
        repo = %repo_id,
        subdir,
        source = %from.path,
        records,
        names = names.len(),
        rewritten = written,
        removed,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "synthesised CEP-16 shards from the cached upstream repodata (#4178)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Freshness and the entry points
// ---------------------------------------------------------------------------

/// The cached upstream document a synthesis reads, fetched through the
/// proxy (which revalidates it past its TTL).
struct Fetched {
    content: Bytes,
    content_encoding: Option<String>,
    source: RepodataEncoding,
    from: Source,
    _budget_permit: tokio::sync::OwnedSemaphorePermit,
}

async fn fetch_source(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    subdir: &str,
) -> Result<Option<Fetched>, Response> {
    for source in SOURCES {
        let path = format!("{subdir}/{}", source.upstream_filename());
        match proxy_helpers::proxy_fetch_capped_budgeted_with_encoding(
            proxy,
            repo_id,
            repo_key,
            upstream_url,
            &path,
            proxy_helpers::LARGE_METADATA_MAX_BYTES,
        )
        .await
        {
            Ok(proxy_helpers::CappedMetadataGet::Buffered {
                content,
                content_encoding,
                budget_permit,
                ..
            }) => {
                let sha256 = hex::encode(Sha256::digest(&content));
                return Ok(Some(Fetched {
                    content,
                    content_encoding,
                    source,
                    from: Source { path, sha256 },
                    _budget_permit: budget_permit,
                }));
            }
            Ok(proxy_helpers::CappedMetadataGet::OverCap) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "Upstream conda repodata {path} exceeds the {}-byte metadata ceiling",
                        proxy_helpers::LARGE_METADATA_MAX_BYTES
                    ),
                )
                    .into_response());
            }
            // A compressed candidate the upstream refuses with 401/403 is
            // absent, as on the plain `repodata.json` route (#4929); a refusal
            // of the plain document is still the request's failure.
            Err(response)
                if response.status() == StatusCode::NOT_FOUND
                    || (source != RepodataEncoding::Json
                        && super::optional_probe_is_absent(&response)) => {}
            Err(response) => return Err(response),
        }
    }
    Ok(None)
}

/// Make the synthesised shards of a remote's `(repo_id, subdir)` match the
/// upstream document its proxy cache holds now, and return what they were
/// built from. `Ok(None)`: the upstream publishes no `repodata.json` for the
/// subdir at all. See the module documentation.
pub(crate) async fn ensure(
    db: &PgPool,
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    subdir: &str,
) -> Result<Option<Source>, Response> {
    let row = subdir_row(db, repo_id, subdir).await?;
    if let Some(SubdirRow {
        source: Some(source),
        built: true,
        stale: false,
    }) = &row
    {
        if proxy
            .fresh_cache_validator(repo_key, &source.path)
            .await
            .as_deref()
            == Some(source.sha256.as_str())
        {
            return Ok(Some(source.clone()));
        }
    }

    let Some(fetched) = fetch_source(proxy, repo_id, repo_key, upstream_url, subdir).await? else {
        return Ok(None);
    };
    if let Some(SubdirRow {
        source: Some(source),
        built: true,
        stale: false,
    }) = &row
    {
        if *source == fetched.from {
            // A refresh that found the same upstream document: a no-op.
            sqlx::query(
                "UPDATE conda_synthesized_subdirs SET checked_at = NOW() \
                  WHERE repository_id = $1 AND subdir = $2",
            )
            .bind(repo_id)
            .bind(subdir)
            .execute(db)
            .await
            .map_err(internal)?;
            return Ok(Some(source.clone()));
        }
    }
    // The upstream index changed (or was never built): the stored shards are
    // stale until the rebuild below stores the new set.
    sqlx::query(
        "INSERT INTO conda_synthesized_subdirs (repository_id, subdir, stale_since, checked_at) \
         VALUES ($1, $2, NOW(), NOW()) \
         ON CONFLICT (repository_id, subdir) DO UPDATE \
           SET stale_since = COALESCE(conda_synthesized_subdirs.stale_since, NOW()), \
               checked_at = NOW()",
    )
    .bind(repo_id)
    .bind(subdir)
    .execute(db)
    .await
    .map_err(internal)?;

    let db = db.clone();
    let subdir_owned = subdir.to_string();
    let from = fetched.from.clone();
    repodata_cache::bounded_by(repodata_cache::regen_wait(), async move {
        repodata_cache::regen_gate()
            .run(async {
                let Fetched {
                    content,
                    content_encoding,
                    source,
                    from,
                    _budget_permit,
                } = fetched;
                rebuild(
                    &db,
                    repo_id,
                    &subdir_owned,
                    content,
                    content_encoding,
                    source,
                    &from,
                )
                .await
            })
            .await
    })
    .await?;
    Ok(Some(from))
}

/// The synthesised shard index of a remote's `subdir`, serialised from the
/// stored map and kept under the subdir revision, or `None` when the
/// upstream publishes no `repodata.json` for it.
pub(crate) async fn synthesized_index(
    db: &PgPool,
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    subdir: &str,
) -> Result<Option<Arc<Prepared>>, Response> {
    if ensure(db, proxy, repo_id, repo_key, upstream_url, subdir)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let revision: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT revision FROM conda_subdir_revisions \
                           WHERE repository_id = $1 AND subdir = $2), 0)",
    )
    .bind(repo_id)
    .bind(subdir)
    .fetch_one(db)
    .await
    .map_err(internal)?;
    repodata_cache::shard_index_cache()
        .get_or_render_scoped(repo_id, subdir, Revision(revision), || async {
            let shards = super::shard_store::stored_index(db, repo_id, subdir).await?;
            let body = super::serialize_msgpack_zst(&super::build_sharded_index(subdir, &shards))?;
            Ok::<_, Response>(Prepared::new(body))
        })
        .await
        .map(Some)
}

/// The synthesised shards of a virtual's remote member, as name to address,
/// with the cached upstream document they were built from (the merge's
/// validator), or `None` when the upstream publishes no `repodata.json`.
pub(crate) async fn member_shards(
    db: &PgPool,
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    subdir: &str,
) -> Result<Option<(BTreeMap<String, Vec<u8>>, Source)>, Response> {
    let Some(source) = ensure(db, proxy, repo_id, repo_key, upstream_url, subdir).await? else {
        return Ok(None);
    };
    let shards = super::shard_store::stored_index(db, repo_id, subdir).await?;
    Ok(Some((shards, source)))
}
