//! Cursor render of a hosted subdir's repodata documents (#4176).
//!
//! The first render of a revision used to load every live row of the
//! repository with its metadata JSON (`fetch_all`), build the whole
//! `repodata.json` as a `serde_json::Value`, and only then serialise and
//! compress it, so peak memory was several times the documents it produced.
//! This render streams instead:
//!
//! 1. one cursor over the repository's live rows, newest first, reading only
//!    the columns that decide which row each document lists (path, name, the
//!    metadata's `name` and `subdir`, the quarantine pair). It keeps a
//!    filename and an id per listed package, the same choices
//!    `repodata_document` makes over the full listing: per filename the
//!    oldest row, per package name the newest row for `current_repodata.json`;
//! 2. the listed rows, in filename order, [`ROWS_PER_CHUNK`] at a time, each
//!    record written straight into the pretty `repodata.json` (fed on into
//!    the zstd encoder chunk by chunk, so `.zst` holds the same bytes) and the
//!    pretty `current_repodata.json`.
//!
//! What is held is the output plus one chunk of rows, so peak memory is
//! bounded by the encoded documents, not by the row set. The bytes are the
//! ones the `serde_json::Value` render produces (asserted by the tests).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use sqlx::PgPool;
use uuid::Uuid;

use super::{build_artifact_entry, is_conda_package, is_conda_v2, is_withdrawn, CondaArtifact};

/// Rows fetched and written per chunk of the second pass.
const ROWS_PER_CHUNK: usize = 512;

/// The documents one render produces.
pub(crate) struct RenderedSubdir {
    /// `repodata.json` as served: pretty-printed.
    pub json: Vec<u8>,
    /// `repodata.json.zst`: zstd (level 3) of exactly the `json` bytes.
    pub zst: Vec<u8>,
    /// `current_repodata.json`, pretty-printed.
    pub current: Vec<u8>,
    /// `run_exports.json`, pretty-printed.
    pub run_exports: Vec<u8>,
}

fn failed(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "conda repodata render failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
}

/// What the first pass reads per row.
#[derive(sqlx::FromRow)]
struct ListingRow {
    id: Uuid,
    path: String,
    name: String,
    meta_name: Option<String>,
    meta_subdir: Option<String>,
    quarantine_status: Option<String>,
    quarantine_until: Option<DateTime<Utc>>,
}

/// The rows each document lists, by filename.
#[derive(Default)]
struct Listing {
    /// `repodata.json` and `run_exports.json`: per filename, the oldest
    /// visible row (later inserts of the newest-first listing overwrite).
    full: BTreeMap<String, Uuid>,
    /// `current_repodata.json`: per package name the newest visible row,
    /// then per filename (a later name overwrites, as the map insert did).
    current: BTreeMap<String, Uuid>,
    /// Filenames of rows a scan policy blocks (#4978 item 6) that no listed
    /// row carries: they join the `removed` array, like withdrawn rows.
    refused: BTreeSet<String>,
}

/// Pass 1: decide which row each document lists, streaming the repository's
/// live rows newest first. Mirrors `list_conda_artifacts_at` (visibility at
/// `now`), `artifacts_for_subdir` and `repodata_document`.
async fn listing(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
    now: DateTime<Utc>,
) -> Result<Listing, Response> {
    let prefix = format!("{subdir}/");
    let mut rows = sqlx::query_as::<_, ListingRow>(
        "SELECT a.id, a.path, a.name, \
                CASE WHEN jsonb_typeof(am.metadata -> 'name') = 'string' \
                     THEN am.metadata ->> 'name' END AS meta_name, \
                CASE WHEN jsonb_typeof(am.metadata -> 'subdir') = 'string' \
                     THEN am.metadata ->> 'subdir' END AS meta_subdir, \
                a.quarantine_status, a.quarantine_until \
           FROM artifacts a \
           LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
          WHERE a.repository_id = $1 AND a.is_deleted = false \
          ORDER BY a.created_at DESC",
    )
    .bind(repo_id)
    .fetch(db);
    // The subdir's visible rows, newest first: `(id, filename, name)`.
    let mut visible: Vec<(Uuid, String, String)> = Vec::new();
    while let Some(row) = rows.try_next().await.map_err(failed)? {
        if is_withdrawn(row.quarantine_status.as_deref(), row.quarantine_until, now) {
            continue;
        }
        let in_subdir = match row.meta_subdir.as_deref() {
            Some(s) => s == subdir,
            None => row.path.starts_with(&prefix),
        };
        if !in_subdir {
            continue;
        }
        let filename = row.path.rsplit('/').next().unwrap_or(&row.path).to_string();
        visible.push((row.id, filename, row.meta_name.unwrap_or(row.name)));
    }
    drop(rows);
    // #4288 item 1 / #4978 item 6: a row a scan policy blocks is refused by
    // the download gate, so it is not listed either.
    let ids: Vec<Uuid> = visible.iter().map(|(id, _, _)| *id).collect();
    let refused = super::policy_refused(db, repo_id, &ids).await?;

    let mut out = Listing::default();
    let mut latest: BTreeMap<String, (String, Uuid)> = BTreeMap::new();
    for (id, filename, name) in visible {
        if refused.contains(&id) {
            if is_conda_package(&filename) {
                out.refused.insert(filename);
            }
            continue;
        }
        let row_id = id;
        latest
            .entry(name)
            .or_insert_with(|| (filename.clone(), row_id));
        if is_conda_package(&filename) {
            out.full.insert(filename, row_id);
        }
    }
    for (filename, id) in latest.into_values() {
        if is_conda_package(&filename) {
            out.current.insert(filename, id);
        }
    }
    out.refused.retain(|f| !out.full.contains_key(f));
    Ok(out)
}

/// A pretty-printed `repodata.json` written member by member, byte for
/// byte what `serde_json::to_vec_pretty` makes of the whole document.
struct PrettyDoc {
    out: Vec<u8>,
    /// Members written into the open section.
    in_section: usize,
}

/// Indent every line after the first of a pretty-printed value by `by`
/// spaces, so it can be placed `by` deeper than it was rendered. A pretty
/// JSON value has no raw newline inside a string, so every `\n` is a line
/// break.
fn indented(pretty: &[u8], by: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(pretty.len() + pretty.len() / 8);
    for &b in pretty {
        out.push(b);
        if b == b'\n' {
            out.extend(std::iter::repeat_n(b' ', by));
        }
    }
    out
}

impl PrettyDoc {
    fn new(subdir: &str) -> Result<Self, Response> {
        let info =
            serde_json::to_vec_pretty(&serde_json::json!({ "subdir": subdir })).map_err(failed)?;
        let mut out = b"{\n  \"info\": ".to_vec();
        out.extend(indented(&info, 2));
        Ok(Self { out, in_section: 0 })
    }

    fn open_section(&mut self, key: &str) -> Result<(), Response> {
        self.out.extend_from_slice(b",\n  ");
        self.out.extend(serde_json::to_vec(key).map_err(failed)?);
        self.out.extend_from_slice(b": ");
        self.in_section = 0;
        Ok(())
    }

    fn member(&mut self, filename: &str, entry: &serde_json::Value) -> Result<(), Response> {
        self.out.extend_from_slice(if self.in_section == 0 {
            b"{\n    "
        } else {
            b",\n    "
        });
        self.out
            .extend(serde_json::to_vec(filename).map_err(failed)?);
        self.out.extend_from_slice(b": ");
        self.out.extend(indented(
            &serde_json::to_vec_pretty(entry).map_err(failed)?,
            4,
        ));
        self.in_section += 1;
        Ok(())
    }

    fn close_section(&mut self) {
        if self.in_section == 0 {
            self.out.extend_from_slice(b"{}");
        } else {
            self.out.extend_from_slice(b"\n  }");
        }
    }

    fn finish(mut self, removed: &serde_json::Value) -> Result<Vec<u8>, Response> {
        self.out.extend_from_slice(b",\n  \"removed\": ");
        self.out.extend(indented(
            &serde_json::to_vec_pretty(removed).map_err(failed)?,
            2,
        ));
        self.out
            .extend_from_slice(b",\n  \"repodata_version\": 1\n}");
        Ok(self.out)
    }
}

/// `repodata.json.zst`: the pretty `repodata.json` bytes fed into zstd as
/// they are written, so the compressed document decompresses to exactly the
/// bytes `repodata.json` serves. A JLAP client hashes whichever encoding it
/// downloaded, and the JLAP chain names that one hash (#4175).
struct ZstTee {
    encoder: zstd::stream::write::Encoder<'static, Vec<u8>>,
    /// Bytes of the pretty document already written into the encoder.
    fed: usize,
}

impl ZstTee {
    fn new() -> Result<Self, Response> {
        Ok(Self {
            encoder: zstd::stream::write::Encoder::new(Vec::new(), 3).map_err(failed)?,
            fed: 0,
        })
    }

    /// Feed what `json` gained since the last call.
    fn feed(&mut self, json: &[u8]) -> Result<(), Response> {
        self.encoder.write_all(&json[self.fed..]).map_err(failed)?;
        self.fed = json.len();
        Ok(())
    }

    fn finish(mut self, json: &[u8]) -> Result<Vec<u8>, Response> {
        self.feed(json)?;
        self.encoder.finish().map_err(failed)
    }
}

/// The three streamed documents, moved onto the blocking pool per chunk.
struct Writers {
    json: PrettyDoc,
    zst: ZstTee,
    current: PrettyDoc,
}

/// Rows of `ids`, as the full listing carries them.
async fn rows_by_id(db: &PgPool, ids: &[Uuid]) -> Result<HashMap<Uuid, CondaArtifact>, Response> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        path: String,
        name: String,
        version: Option<String>,
        size_bytes: i64,
        checksum_sha256: String,
        storage_key: String,
        metadata: Option<serde_json::Value>,
        created_at: DateTime<Utc>,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256, \
                a.storage_key, am.metadata, a.created_at \
           FROM artifacts a \
           LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
          WHERE a.id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(db)
    .await
    .map_err(failed)?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.id,
                CondaArtifact {
                    id: r.id,
                    path: r.path,
                    name: r.name,
                    version: r.version,
                    size_bytes: r.size_bytes,
                    checksum_sha256: r.checksum_sha256,
                    storage_key: r.storage_key,
                    metadata: r.metadata,
                    indexed_at: Some(r.created_at),
                },
            )
        })
        .collect())
}

/// The documents of a subdir no row has ever named: the bytes
/// [`render_subdir`] produces for it, without reading the catalog.
pub(crate) fn render_empty(subdir: &str) -> Result<RenderedSubdir, Response> {
    let removed = serde_json::json!([]);
    let mut json = PrettyDoc::new(subdir)?;
    let mut current = PrettyDoc::new(subdir)?;
    for section in ["packages", "packages.conda"] {
        json.open_section(section)?;
        current.open_section(section)?;
        json.close_section();
        current.close_section();
    }
    let json = json.finish(&removed)?;
    let zst = ZstTee::new()?.finish(&json)?;
    let run_exports = serde_json::json!({
        "info": { "subdir": subdir },
        "packages": {},
    });
    Ok(RenderedSubdir {
        json,
        zst,
        current: current.finish(&removed)?,
        run_exports: serde_json::to_vec_pretty(&run_exports).map_err(failed)?,
    })
}

/// Render `repodata.json` (pretty), its compact zstd encoding,
/// `current_repodata.json` and `run_exports.json` of hosted `(repo_id,
/// subdir)` with visibility decided at `now`, and `removed` the filenames of
/// the `removed` array.
pub(crate) async fn render_subdir(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
    now: DateTime<Utc>,
    removed: &[String],
) -> Result<RenderedSubdir, Response> {
    render_subdir_chunked(db, repo_id, subdir, now, removed, ROWS_PER_CHUNK).await
}

/// [`render_subdir`] reading `rows_per_chunk` rows per chunk.
pub(crate) async fn render_subdir_chunked(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
    now: DateTime<Utc>,
    removed: &[String],
    rows_per_chunk: usize,
) -> Result<RenderedSubdir, Response> {
    let listing = listing(db, repo_id, subdir, now).await?;
    let removed = if listing.refused.is_empty() {
        serde_json::json!(removed)
    } else {
        let mut all: Vec<&str> = removed
            .iter()
            .map(String::as_str)
            .chain(listing.refused.iter().map(String::as_str))
            .collect();
        all.sort_unstable();
        all.dedup();
        serde_json::json!(all)
    };
    let mut writers = Writers {
        json: PrettyDoc::new(subdir)?,
        zst: ZstTee::new()?,
        current: PrettyDoc::new(subdir)?,
    };
    let mut run_exports = serde_json::Map::new();

    for (section, v2) in [("packages", false), ("packages.conda", true)] {
        writers.json.open_section(section)?;
        writers.current.open_section(section)?;
        // Filename order, the order a sorted map serialises in; a filename
        // may be listed by one document and not the other.
        let mut filenames: Vec<&String> = listing
            .full
            .keys()
            .chain(listing.current.keys())
            .filter(|f| is_conda_v2(f) == v2)
            .collect();
        filenames.sort();
        filenames.dedup();
        for chunk in filenames.chunks(rows_per_chunk.max(1)) {
            let mut ids: HashSet<Uuid> = HashSet::new();
            for f in chunk {
                ids.extend(listing.full.get(*f));
                ids.extend(listing.current.get(*f));
            }
            let ids: Vec<Uuid> = ids.into_iter().collect();
            let rows = rows_by_id(db, &ids).await?;
            let mut entries = Vec::with_capacity(chunk.len());
            for f in chunk {
                let entry_of = |id: Option<&Uuid>| {
                    id.and_then(|id| rows.get(id))
                        .map(|a| build_artifact_entry(a, f, subdir))
                };
                let full = entry_of(listing.full.get(*f));
                if let Some(a) = listing.full.get(*f).and_then(|id| rows.get(id)) {
                    run_exports.insert((*f).clone(), super::run_exports_entry(a.metadata.as_ref()));
                }
                entries.push(((*f).clone(), full, entry_of(listing.current.get(*f))));
            }
            writers = tokio::task::spawn_blocking(move || -> Result<Writers, Response> {
                for (filename, full, current) in &entries {
                    if let Some(entry) = full {
                        writers.json.member(filename, entry)?;
                    }
                    if let Some(entry) = current {
                        writers.current.member(filename, entry)?;
                    }
                }
                writers.zst.feed(&writers.json.out)?;
                Ok(writers)
            })
            .await
            .map_err(failed)??;
        }
        writers.json.close_section();
        writers.current.close_section();
    }

    let subdir = subdir.to_string();
    tokio::task::spawn_blocking(move || -> Result<RenderedSubdir, Response> {
        let run_exports = serde_json::json!({
            "info": { "subdir": subdir },
            "packages": run_exports,
        });
        let json = writers.json.finish(&removed)?;
        let zst = writers.zst.finish(&json)?;
        Ok(RenderedSubdir {
            json,
            zst,
            current: writers.current.finish(&removed)?,
            run_exports: serde_json::to_vec_pretty(&run_exports).map_err(failed)?,
        })
    })
    .await
    .map_err(failed)?
}
