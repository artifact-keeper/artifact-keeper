//! JLAP from stored repodata revisions for hosted conda channels (#4175).
//!
//! Every render of a hosted subdir revision ([`super::repodata_cache`]) ends
//! here before its documents are kept and served. In one transaction, under
//! the lock of the subdir's `conda_repodata_jlap` row, [`record`]:
//!
//! 1. compares the BLAKE2b-256 of the rendered `repodata.json` with the hash
//!    the stored JLAP's footer names. Equal: nothing changes (a revision
//!    whose documents did not move, or a second replica rendering the same
//!    revision);
//! 2. otherwise reads the newest stored revision document, computes the
//!    RFC 6902 patch from it to the new document ([`diff_documents`]), and
//!    appends one patch line to the stored JLAP in place of its footer. The
//!    BLAKE2b chain continues from the stored bytes, so every line a client
//!    already holds keeps its offset and checksum and a `Range` request from
//!    the client's saved position returns only the new lines;
//! 3. stores the new document as a revision, keeps the newest
//!    [`JLAP_REVISIONS_ENV`] of them, and keeps one patch line fewer in the
//!    JLAP (the IV absorbs a trimmed line, so the chain values of the lines
//!    that stay do not change).
//!
//! The JLAP a revision's documents carry is therefore the stored JLAP whose
//! footer is that revision's `repodata.json` hash, written before that
//! `repodata.json` is served anywhere. A withdrawal moves the
//! subdir revision (the catalog trigger marks it in the writer's
//! transaction); the next render diffs the document without the package and
//! appends its `remove` before the new `repodata.json` exists for any
//! client, so the JLAP tail never lists what `repodata.json` no longer does.
//!
//! A render that lost a race to a newer revision (another replica already
//! recorded a later revision) leaves the stored JLAP as it is and carries it:
//! appending an older document after a newer one would put a withdrawn
//! package back in the tail.
//!
//! So does a render of the revision already recorded whose bytes differ (two
//! renders that decided visibility at different instants, #5167). Appending
//! would have them take turns restoring each other's document, stepping the
//! tail back. The cost is one mismatched pair until the revision next moves:
//! this render's `repodata.json` is not the document the footer names, so a
//! client holding it finds no patch and downloads the index.
//!
//! The documents are hashed as served: `repodata.json` and the uncompressed
//! bytes of `repodata.json.zst` and `.bz2` are the same bytes, so a client
//! that downloaded any encoding computes the hash the chain names.

use std::sync::OnceLock;

use serde_json::value::RawValue;
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::{blake2_256, blake2_256_keyed, escape_json_pointer, sorted_compact_json};

/// Number of `repodata.json` revisions kept per subdir, and so one more than
/// the patch lines the JLAP keeps (#4175).
pub(crate) const JLAP_REVISIONS_ENV: &str = "AK_CONDA_JLAP_REVISIONS";
/// Default of [`JLAP_REVISIONS_ENV`]: a client that refreshes at least once
/// every seven channel changes never downloads the whole index again.
const DEFAULT_JLAP_REVISIONS: usize = 8;
/// Upper bound of [`JLAP_REVISIONS_ENV`]: each kept revision is a compressed
/// copy of the subdir's index.
const MAX_JLAP_REVISIONS: usize = 1024;

/// A patch with more operations than this is not written: the client falls
/// back to downloading the whole document, which is cheaper than applying
/// it (the limit conda's own JLAP writer uses).
pub(crate) const JLAP_PATCH_STEPS_LIMIT: usize = 8192;

/// Parse [`JLAP_REVISIONS_ENV`]: an integer from 1 (keep only the current
/// document: the JLAP carries no patches) to [`MAX_JLAP_REVISIONS`], else
/// the default.
pub(crate) fn parse_jlap_revisions(raw: Option<&str>) -> usize {
    match raw.map(str::trim) {
        None | Some("") => DEFAULT_JLAP_REVISIONS,
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (1..=MAX_JLAP_REVISIONS).contains(&n) => n,
            _ => {
                tracing::warn!(
                    value = v,
                    default = DEFAULT_JLAP_REVISIONS,
                    "{JLAP_REVISIONS_ENV} is not an integer from 1 to {MAX_JLAP_REVISIONS}; \
                     using the default"
                );
                DEFAULT_JLAP_REVISIONS
            }
        },
    }
}

fn jlap_revisions() -> usize {
    static KEEP: OnceLock<usize> = OnceLock::new();
    *KEEP.get_or_init(|| parse_jlap_revisions(std::env::var(JLAP_REVISIONS_ENV).ok().as_deref()))
}

/// The footer's `url`: the document the hashes describe.
const JLAP_URL: &str = "repodata.json";

/// A JLAP file split into its parts: the IV, the patch lines, the hash the
/// footer names. Rendering recomputes the footer and the trailing checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Jlap {
    pub iv: [u8; 32],
    pub lines: Vec<String>,
    pub latest: [u8; 32],
}

impl Jlap {
    /// A JLAP with no patches naming `latest`.
    pub fn fresh(latest: [u8; 32]) -> Self {
        Self {
            iv: [0u8; 32],
            lines: Vec::new(),
            latest,
        }
    }

    /// Parse stored JLAP bytes, verifying the checksum chain.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        super::verify_jlap_chain(bytes)?;
        let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
        let lines: Vec<&str> = text.split('\n').collect();
        // verify_jlap_chain guarantees at least three lines and a 32-byte IV.
        let iv: [u8; 32] = hex::decode(lines[0])
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "IV must be 32 bytes".to_string())?;
        let footer: Value =
            serde_json::from_str(lines[lines.len() - 2]).map_err(|e| e.to_string())?;
        let latest: [u8; 32] = footer
            .get("latest")
            .and_then(Value::as_str)
            .and_then(|h| hex::decode(h).ok())
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| "footer has no 32-byte `latest` hash".to_string())?;
        Ok(Self {
            iv,
            lines: lines[1..lines.len() - 2]
                .iter()
                .map(|l| l.to_string())
                .collect(),
            latest,
        })
    }

    /// Append the patch line `from -> to` and name `to` in the footer.
    pub fn append(&mut self, from: &[u8; 32], ops: Vec<Value>, to: [u8; 32]) {
        self.lines.push(patch_line(from, ops, &to));
        self.latest = to;
    }

    /// Keep at most `keep` patch lines, dropping the oldest. The IV becomes
    /// the chain value after the dropped lines, so every kept line keeps its
    /// chain value.
    pub fn trim(&mut self, keep: usize) {
        if self.lines.len() <= keep {
            return;
        }
        let drop = self.lines.len() - keep;
        for line in self.lines.drain(..drop) {
            self.iv = blake2_256_keyed(line.as_bytes(), &self.iv);
        }
    }

    /// The JLAP file: IV, patch lines, footer, trailing checksum, joined by
    /// `\n` with no trailing newline.
    pub fn render(&self) -> Vec<u8> {
        let footer = sorted_compact_json(&serde_json::json!({
            "latest": hex::encode(self.latest),
            "url": JLAP_URL,
        }));
        let mut checksum = self.iv;
        let mut out = hex::encode(self.iv).into_bytes();
        for line in self.lines.iter().chain(std::iter::once(&footer)) {
            checksum = blake2_256_keyed(line.as_bytes(), &checksum);
            out.push(b'\n');
            out.extend_from_slice(line.as_bytes());
        }
        out.push(b'\n');
        out.extend_from_slice(hex::encode(checksum).as_bytes());
        out
    }
}

/// One patch line: compact JSON with sorted keys, as conda's writer makes it.
fn patch_line(from: &[u8; 32], ops: Vec<Value>, to: &[u8; 32]) -> String {
    sorted_compact_json(&serde_json::json!({
        "from": hex::encode(from),
        "patch": ops,
        "to": hex::encode(to),
    }))
}

/// The JLAP of a document with no stored history: no patches.
pub(crate) fn bootstrap(json: &[u8]) -> Vec<u8> {
    Jlap::fresh(blake2_256(json)).render()
}

/// Whether two raw JSON values are the same value. Raw bytes decide when
/// they are equal (the render is deterministic, so they almost always are);
/// otherwise both are parsed, so a whitespace or key-order difference is not
/// a change.
fn same_value(a: &RawValue, b: &RawValue) -> Result<bool, serde_json::Error> {
    if a.get() == b.get() {
        return Ok(true);
    }
    let a: Value = serde_json::from_str(a.get())?;
    let b: Value = serde_json::from_str(b.get())?;
    Ok(a == b)
}

fn is_object(v: &RawValue) -> bool {
    v.get().trim_start().starts_with('{')
}

fn op(kind: &str, path: String, value: Option<&RawValue>) -> Result<Value, serde_json::Error> {
    let mut op = serde_json::Map::new();
    op.insert("op".into(), Value::String(kind.into()));
    op.insert("path".into(), Value::String(path));
    if let Some(v) = value {
        op.insert("value".into(), serde_json::from_str(v.get())?);
    }
    Ok(Value::Object(op))
}

/// Append to `ops` the operations that turn the object `old` into `new`
/// member by member under `prefix` (a JSON pointer).
fn diff_members(
    prefix: &str,
    old: &RawValue,
    new: &RawValue,
    ops: &mut Vec<Value>,
) -> Result<(), serde_json::Error> {
    let old: std::collections::BTreeMap<String, &RawValue> = serde_json::from_str(old.get())?;
    let new: std::collections::BTreeMap<String, &RawValue> = serde_json::from_str(new.get())?;
    for key in old.keys() {
        if !new.contains_key(key) {
            ops.push(op(
                "remove",
                format!("{prefix}/{}", escape_json_pointer(key)),
                None,
            )?);
        }
    }
    for (key, value) in &new {
        let path = format!("{prefix}/{}", escape_json_pointer(key));
        match old.get(key) {
            None => ops.push(op("add", path, Some(value))?),
            Some(prev) if !same_value(prev, value)? => ops.push(op("replace", path, Some(value))?),
            Some(_) => {}
        }
    }
    Ok(())
}

/// The RFC 6902 operations that turn the `repodata.json` document `old` into
/// `new`, or `None` when they are equal or the patch would exceed
/// [`JLAP_PATCH_STEPS_LIMIT`].
///
/// Every top-level member is covered: an object present in both (`info`,
/// `packages`, `packages.conda`) is diffed record by record, anything else
/// (`removed`, `repodata_version`) is added, replaced or removed whole, so
/// applying the patch to `old` gives a document equal to `new`. The
/// documents are read as raw slices, never as a whole `serde_json::Value`
/// tree: only the records that changed are parsed.
pub(crate) fn diff_documents(
    old: &[u8],
    new: &[u8],
) -> Result<Option<Vec<Value>>, serde_json::Error> {
    let old_top: std::collections::BTreeMap<String, &RawValue> = serde_json::from_slice(old)?;
    let new_top: std::collections::BTreeMap<String, &RawValue> = serde_json::from_slice(new)?;
    let mut ops = Vec::new();
    for key in old_top.keys() {
        if !new_top.contains_key(key) {
            ops.push(op(
                "remove",
                format!("/{}", escape_json_pointer(key)),
                None,
            )?);
        }
    }
    for (key, value) in &new_top {
        let path = format!("/{}", escape_json_pointer(key));
        match old_top.get(key) {
            None => ops.push(op("add", path, Some(value))?),
            Some(prev) if is_object(prev) && is_object(value) => {
                diff_members(&path, prev, value, &mut ops)?
            }
            Some(prev) if !same_value(prev, value)? => ops.push(op("replace", path, Some(value))?),
            Some(_) => {}
        }
        if ops.len() > JLAP_PATCH_STEPS_LIMIT {
            break;
        }
    }
    if ops.is_empty() {
        Ok(None)
    } else if ops.len() > JLAP_PATCH_STEPS_LIMIT {
        tracing::debug!(
            ops = ops.len(),
            limit = JLAP_PATCH_STEPS_LIMIT,
            "conda JLAP patch exceeds the step limit; not written"
        );
        Ok(None)
    } else {
        Ok(Some(ops))
    }
}

/// The next JLAP after `stored` for the new document `json` (hash `to`),
/// given the previous document `prev` (its hash `from` and its bytes).
/// Pure: [`record`] runs it on the blocking pool inside its transaction.
fn advance(
    stored: Option<Jlap>,
    prev: Option<([u8; 32], Vec<u8>)>,
    json: &[u8],
    to: [u8; 32],
    keep_lines: usize,
) -> Jlap {
    let mut jlap = stored.unwrap_or_else(|| Jlap::fresh(to));
    if let Some((from, prev_json)) = prev {
        // A stored document that does not hash to its recorded hash is not
        // patched from: a client holding that hash would end at a document
        // that differs from `json`.
        if blake2_256(&prev_json) == from && from == jlap.latest {
            match diff_documents(&prev_json, json) {
                Ok(Some(ops)) => jlap.append(&from, ops, to),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "conda JLAP: could not diff repodata revisions")
                }
            }
        } else {
            tracing::warn!("conda JLAP: stored revision does not match its hash; no patch written");
        }
    }
    jlap.latest = to;
    jlap.trim(keep_lines);
    jlap
}

/// Record the rendered `repodata.json` of hosted `(repo_id, subdir)` at
/// `revision` (with its `.zst` encoding, the bytes stored) and return the
/// JLAP to serve with it. See the module documentation.
pub(crate) async fn record(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
    revision: i64,
    json: &bytes::Bytes,
    zst: &bytes::Bytes,
) -> Result<Vec<u8>, String> {
    record_keeping(db, repo_id, subdir, revision, json, zst, jlap_revisions()).await
}

/// [`record`] keeping `keep` revisions.
pub(crate) async fn record_keeping(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
    revision: i64,
    json: &bytes::Bytes,
    zst: &bytes::Bytes,
    keep: usize,
) -> Result<Vec<u8>, String> {
    let keep = keep.max(1);
    let to = {
        let json = json.clone();
        tokio::task::spawn_blocking(move || blake2_256(&json))
            .await
            .map_err(|e| e.to_string())?
    };
    let err = |e: sqlx::Error| e.to_string();
    let mut tx = db.begin().await.map_err(err)?;
    sqlx::query(
        "INSERT INTO conda_repodata_jlap (repository_id, subdir) VALUES ($1, $2) \
         ON CONFLICT (repository_id, subdir) DO NOTHING",
    )
    .bind(repo_id)
    .bind(subdir)
    .execute(&mut *tx)
    .await
    .map_err(err)?;
    let row = sqlx::query(
        "SELECT jlap, latest_revision, latest_hash FROM conda_repodata_jlap \
          WHERE repository_id = $1 AND subdir = $2 FOR UPDATE",
    )
    .bind(repo_id)
    .bind(subdir)
    .fetch_one(&mut *tx)
    .await
    .map_err(err)?;
    let stored_bytes: Option<Vec<u8>> = row.get("jlap");
    let latest_revision: Option<i64> = row.get("latest_revision");
    let latest_hash: Option<Vec<u8>> = row.get("latest_hash");

    if let Some(bytes) = &stored_bytes {
        if latest_hash.as_deref() == Some(&to[..]) {
            // Same document: the stored JLAP already ends at it.
            if latest_revision.is_some_and(|r| r < revision) {
                sqlx::query(
                    "UPDATE conda_repodata_jlap SET latest_revision = $3, updated_at = NOW() \
                      WHERE repository_id = $1 AND subdir = $2",
                )
                .bind(repo_id)
                .bind(subdir)
                .bind(revision)
                .execute(&mut *tx)
                .await
                .map_err(err)?;
            }
            tx.commit().await.map_err(err)?;
            return Ok(bytes.clone());
        }
        if latest_revision.is_some_and(|r| r >= revision) {
            // This revision or a newer one is already recorded with other
            // bytes: appending this render could move the tail backwards.
            tx.rollback().await.map_err(err)?;
            return Ok(bytes.clone());
        }
    }

    let stored = match stored_bytes.as_deref().map(Jlap::parse) {
        Some(Ok(jlap)) => Some(jlap),
        Some(Err(e)) => {
            tracing::warn!(
                repo = %repo_id, subdir, error = %e,
                "conda JLAP: stored file does not verify; starting a new one"
            );
            None
        }
        None => None,
    };
    let prev = if stored.is_some() {
        sqlx::query(
            "SELECT blake2b, document FROM conda_repodata_revisions \
              WHERE repository_id = $1 AND subdir = $2 ORDER BY id DESC LIMIT 1",
        )
        .bind(repo_id)
        .bind(subdir)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err)?
        .map(|r| {
            (
                r.get::<Vec<u8>, _>("blake2b"),
                r.get::<Vec<u8>, _>("document"),
            )
        })
    } else {
        None
    };

    let json_c = json.clone();
    let jlap = tokio::task::spawn_blocking(move || -> Result<Jlap, String> {
        let prev = match prev {
            Some((hash, document)) => match (
                <[u8; 32]>::try_from(hash.as_slice()),
                zstd::stream::decode_all(document.as_slice()),
            ) {
                (Ok(hash), Ok(document)) => Some((hash, document)),
                _ => None,
            },
            None => None,
        };
        Ok(advance(stored, prev, &json_c, to, keep - 1))
    })
    .await
    .map_err(|e| e.to_string())??;
    let body = jlap.render();

    sqlx::query(
        "INSERT INTO conda_repodata_revisions (repository_id, subdir, revision, blake2b, document) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(repo_id)
    .bind(subdir)
    .bind(revision)
    .bind(&to[..])
    .bind(zst.as_ref())
    .execute(&mut *tx)
    .await
    .map_err(err)?;
    sqlx::query(
        "DELETE FROM conda_repodata_revisions \
          WHERE repository_id = $1 AND subdir = $2 \
            AND id NOT IN (SELECT id FROM conda_repodata_revisions \
                            WHERE repository_id = $1 AND subdir = $2 \
                            ORDER BY id DESC LIMIT $3)",
    )
    .bind(repo_id)
    .bind(subdir)
    .bind(keep as i64)
    .execute(&mut *tx)
    .await
    .map_err(err)?;
    sqlx::query(
        "UPDATE conda_repodata_jlap \
            SET jlap = $3, latest_revision = $4, latest_hash = $5, updated_at = NOW() \
          WHERE repository_id = $1 AND subdir = $2",
    )
    .bind(repo_id)
    .bind(subdir)
    .bind(&body)
    .bind(revision)
    .bind(&to[..])
    .execute(&mut *tx)
    .await
    .map_err(err)?;
    tx.commit().await.map_err(err)?;
    Ok(body)
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    /// Apply RFC 6902 `add`, `remove` and `replace` operations (the ones
    /// [`diff_documents`] writes) the way a JSON Patch library does.
    pub(crate) fn apply(doc: &mut Value, ops: &[Value]) {
        for op in ops {
            let path = op["path"].as_str().unwrap();
            let tokens: Vec<String> = path
                .split('/')
                .skip(1)
                .map(|t| t.replace("~1", "/").replace("~0", "~"))
                .collect();
            let (last, parents) = tokens.split_last().unwrap();
            let mut target = &mut *doc;
            for t in parents {
                target = target.get_mut(t.as_str()).expect("parent exists");
            }
            let map = target.as_object_mut().expect("parent is an object");
            match op["op"].as_str().unwrap() {
                "add" => {
                    map.insert(last.clone(), op["value"].clone());
                }
                "replace" => {
                    assert!(map.contains_key(last), "replace of a missing member {path}");
                    map.insert(last.clone(), op["value"].clone());
                }
                "remove" => {
                    assert!(
                        map.remove(last).is_some(),
                        "remove of a missing member {path}"
                    );
                }
                other => panic!("unexpected op {other}"),
            }
        }
    }

    fn doc(packages: Value, conda: Value, removed: Value) -> Vec<u8> {
        serde_json::to_vec_pretty(&serde_json::json!({
            "info": {"subdir": "noarch"},
            "packages": packages,
            "packages.conda": conda,
            "removed": removed,
            "repodata_version": 1,
        }))
        .unwrap()
    }

    #[test]
    fn a_patch_turns_the_old_document_into_the_new_one_4175() {
        let old = doc(
            serde_json::json!({
                "a-1.0-0.tar.bz2": {"name": "a", "version": "1.0"},
                "b/x-1.0-0.tar.bz2": {"name": "b", "version": "1.0"},
                "c~1.0-0.tar.bz2": {"name": "c", "version": "1.0"},
            }),
            serde_json::json!({}),
            serde_json::json!([]),
        );
        let new = doc(
            serde_json::json!({
                "b/x-1.0-0.tar.bz2": {"name": "b", "version": "1.0", "depends": ["z"]},
                "d-1.0-0.tar.bz2": {"name": "d", "version": "1.0"},
            }),
            serde_json::json!({"e-1.0-0.conda": {"name": "e"}}),
            serde_json::json!(["a-1.0-0.tar.bz2", "c~1.0-0.tar.bz2"]),
        );
        let ops = diff_documents(&old, &new).unwrap().unwrap();
        let mut patched: Value = serde_json::from_slice(&old).unwrap();
        apply(&mut patched, &ops);
        assert_eq!(patched, serde_json::from_slice::<Value>(&new).unwrap());
        assert!(diff_documents(&new, &new).unwrap().is_none());
        // Key order and whitespace are not changes.
        let compact = serde_json::to_vec(&serde_json::from_slice::<Value>(&new).unwrap()).unwrap();
        assert!(diff_documents(&new, &compact).unwrap().is_none());
    }

    #[test]
    fn top_level_members_are_covered_whole_4175() {
        let old = br#"{"info":{"subdir":"noarch"},"packages":{},"removed":[],"x":1}"#;
        let new = br#"{"info":{"subdir":"noarch","extra":true},"packages":{},"packages.conda":{},"repodata_version":1}"#;
        let ops = diff_documents(old, new).unwrap().unwrap();
        let mut patched: Value = serde_json::from_slice(old).unwrap();
        apply(&mut patched, &ops);
        assert_eq!(patched, serde_json::from_slice::<Value>(new).unwrap());
    }

    #[test]
    fn appended_lines_keep_the_bytes_and_chain_of_the_stored_ones_4175() {
        let h = |b: &[u8]| blake2_256(b);
        let mut jlap = Jlap::fresh(h(b"r1"));
        let first = jlap.render();
        super::super::verify_jlap_chain(&first).unwrap();
        jlap.append(&h(b"r1"), vec![serde_json::json!({"op": "add"})], h(b"r2"));
        let second = jlap.render();
        super::super::verify_jlap_chain(&second).unwrap();
        // The client saved the offset of the footer line of `first`; the new
        // file has the same bytes before it.
        let footer_at = first.iter().rposition(|b| *b == b'\n').unwrap();
        let footer_at = first[..footer_at]
            .iter()
            .rposition(|b| *b == b'\n')
            .unwrap()
            + 1;
        assert_eq!(first[..footer_at], second[..footer_at]);
        assert_eq!(Jlap::parse(&second).unwrap(), jlap);

        // Trimming keeps the chain value of every kept line: a range request
        // read from the kept line's predecessor checksum still verifies.
        jlap.append(
            &h(b"r2"),
            vec![serde_json::json!({"op": "remove"})],
            h(b"r3"),
        );
        let full = jlap.render();
        let mut trimmed = jlap.clone();
        trimmed.trim(1);
        assert_eq!(trimmed.lines, jlap.lines[1..]);
        let trimmed_bytes = trimmed.render();
        super::super::verify_jlap_chain(&trimmed_bytes).unwrap();
        assert_eq!(
            full.rsplit(|b| *b == b'\n').next(),
            trimmed_bytes.rsplit(|b| *b == b'\n').next(),
            "the trailing checksum is unchanged by a trim"
        );
    }

    #[test]
    fn advance_writes_a_patch_only_from_the_document_the_footer_names_4175() {
        let r1 = doc(
            serde_json::json!({"a-1.0-0.tar.bz2": {"name": "a"}}),
            serde_json::json!({}),
            serde_json::json!([]),
        );
        let r2 = doc(
            serde_json::json!({}),
            serde_json::json!({}),
            serde_json::json!(["a-1.0-0.tar.bz2"]),
        );
        let (h1, h2) = (blake2_256(&r1), blake2_256(&r2));
        let stored = Jlap::fresh(h1);
        let next = advance(Some(stored.clone()), Some((h1, r1.clone())), &r2, h2, 7);
        assert_eq!(next.lines.len(), 1);
        assert_eq!(next.latest, h2);
        // A previous document whose bytes do not hash to the recorded hash.
        let next = advance(Some(stored), Some((h1, r2.clone())), &r2, h2, 7);
        assert!(next.lines.is_empty());
        assert_eq!(next.latest, h2);
        // keep 1 revision: no patch lines at all.
        let next = advance(Some(Jlap::fresh(h1)), Some((h1, r1)), &r2, h2, 0);
        assert!(next.lines.is_empty());
    }

    #[test]
    fn revisions_env_is_bounded_4175() {
        assert_eq!(parse_jlap_revisions(None), DEFAULT_JLAP_REVISIONS);
        assert_eq!(parse_jlap_revisions(Some("3")), 3);
        assert_eq!(parse_jlap_revisions(Some("1")), 1);
        assert_eq!(parse_jlap_revisions(Some("0")), DEFAULT_JLAP_REVISIONS);
        assert_eq!(parse_jlap_revisions(Some("x")), DEFAULT_JLAP_REVISIONS);
        assert_eq!(parse_jlap_revisions(Some("100000")), DEFAULT_JLAP_REVISIONS);
    }

    fn listing(names: &[&str]) -> bytes::Bytes {
        let packages: serde_json::Map<String, Value> = names
            .iter()
            .map(|n| (format!("{n}-1.0-0.tar.bz2"), serde_json::json!({"name": n})))
            .collect();
        doc(
            Value::Object(packages),
            serde_json::json!({}),
            serde_json::json!([]),
        )
        .into()
    }

    async fn record_doc(
        fx: &tdh::Fixture,
        revision: i64,
        json: &bytes::Bytes,
        keep: usize,
    ) -> Jlap {
        let zst = bytes::Bytes::from(zstd::stream::encode_all(json.as_ref(), 3).unwrap());
        let body = record_keeping(&fx.pool, fx.repo_id, "noarch", revision, json, &zst, keep)
            .await
            .unwrap();
        Jlap::parse(&body).unwrap()
    }

    async fn kept_revisions(fx: &tdh::Fixture) -> Vec<i64> {
        sqlx::query_scalar(
            "SELECT revision FROM conda_repodata_revisions \
              WHERE repository_id = $1 AND subdir = 'noarch' ORDER BY id",
        )
        .bind(fx.repo_id)
        .fetch_all(&fx.pool)
        .await
        .unwrap()
    }

    /// #4175: the stored JLAP grows by one line per changed revision, keeps
    /// N revisions and N - 1 lines, and its stored bytes always verify; an
    /// unchanged document and a render behind a newer revision write nothing.
    #[tokio::test]
    async fn the_stored_jlap_keeps_n_revisions_and_never_moves_back_4175() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let docs: Vec<bytes::Bytes> = (1..=5)
            .map(|i| listing(&["a", "b", "c", "d", "e"][..i]))
            .collect();
        let first = record_doc(&fx, 1, &docs[0], 3).await;
        assert!(first.lines.is_empty());
        assert_eq!(first.latest, blake2_256(&docs[0]));

        let mut prev_bytes = first.render();
        for (i, json) in docs.iter().enumerate().skip(1) {
            let jlap = record_doc(&fx, i as i64 + 1, json, 3).await;
            assert_eq!(jlap.latest, blake2_256(json));
            assert_eq!(jlap.lines.len(), i.min(2), "at most N - 1 lines");
            let bytes = jlap.render();
            if i < 3 {
                // Untrimmed: the old bytes up to the old footer are a prefix.
                let footer = prev_bytes[..prev_bytes.len() - 65]
                    .iter()
                    .rposition(|b| *b == b'\n')
                    .unwrap();
                assert_eq!(prev_bytes[..=footer], bytes[..=footer]);
            }
            prev_bytes = bytes;
        }
        assert_eq!(kept_revisions(&fx).await, vec![3, 4, 5]);
        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT jlap FROM conda_repodata_jlap WHERE repository_id = $1 AND subdir = 'noarch'",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        super::super::verify_jlap_chain(&stored).unwrap();
        assert_eq!(stored, prev_bytes);

        // The same document at a later revision: nothing appended.
        let same = record_doc(&fx, 6, &docs[4], 3).await;
        assert_eq!(same.render(), prev_bytes);
        assert_eq!(kept_revisions(&fx).await, vec![3, 4, 5]);
        // A render of an older revision with other bytes: the stored JLAP is
        // carried unchanged.
        let behind = record_doc(&fx, 2, &docs[0], 3).await;
        assert_eq!(behind.render(), prev_bytes);
        assert_eq!(kept_revisions(&fx).await, vec![3, 4, 5]);
    }

    /// #5167: two renders of one revision that decided visibility at different
    /// instants do not take turns appending each other's document. The tail
    /// stays where the first left it, and the next revision patches from it.
    #[tokio::test]
    async fn renders_of_one_revision_do_not_step_the_tail_back_5167() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let first = listing(&["a"]);
        let second = listing(&["a", "b"]);
        let other = listing(&["a", "c"]);
        let later = listing(&["a", "b", "c"]);

        record_doc(&fx, 1, &first, 8).await;
        let stored = record_doc(&fx, 2, &second, 8).await;
        assert_eq!(stored.lines.len(), 1);

        // The other render of revision 2, then the first again, then the
        // other: the stored JLAP is carried each time and nothing is kept.
        for json in [&other, &second, &other] {
            let carried = record_doc(&fx, 2, json, 8).await;
            assert_eq!(carried, stored);
            assert_eq!(kept_revisions(&fx).await, vec![1, 2]);
        }

        // The next revision patches from the document the footer names.
        let next = record_doc(&fx, 3, &later, 8).await;
        assert_eq!(next.lines[..1], stored.lines[..]);
        assert_eq!(next.lines.len(), 2);
        let mut patched: Value = serde_json::from_slice(&first).unwrap();
        for line in &next.lines {
            let line: Value = serde_json::from_str(line).unwrap();
            apply(&mut patched, line["patch"].as_array().unwrap());
        }
        assert_eq!(patched, serde_json::from_slice::<Value>(&later).unwrap());
        assert_eq!(next.latest, blake2_256(&later));
        assert_eq!(kept_revisions(&fx).await, vec![1, 2, 3]);
    }
}
