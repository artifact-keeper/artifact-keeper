//! Unpack a stored OCI / Docker image into the root filesystem it describes
//! (#6000).
//!
//! The OpenSCAP scanner evaluates a container image's configuration, so it
//! needs the image's files laid out as the container would see them: every
//! layer applied in manifest order, with whiteouts honoured. Before #6000 the
//! scanner wrote the manifest bytes into the workspace as one file and the
//! sidecar, finding no `etc/` there, evaluated its own filesystem instead.
//!
//! The layers come from this repository's own blob store (`oci_blobs`), never
//! from the network. Unpacking runs in process with the `tar` crate and is
//! hardened the same way the other scan-workspace extractors are, plus what a
//! full root filesystem adds:
//!
//! * every path is resolved inside the root with chroot semantics: a symlink
//!   an earlier layer created (`etc -> /`, `x -> ../../..`) is followed the
//!   way the container would follow it, re-rooted at the image root, so no
//!   entry is ever written outside it;
//! * symlinks are written with a RELATIVE target that resolves to the same
//!   place inside the root (`/usr/share/zoneinfo/UTC` becomes
//!   `../usr/share/zoneinfo/UTC`), so a reader that does not chroot cannot
//!   be led out of the tree either;
//! * hard links must name an existing regular file inside the root;
//! * device nodes, FIFOs and sockets are skipped; setuid and setgid bits are
//!   dropped (the tree sits on a shared volume); ownership cannot be kept,
//!   because the backend does not run as root, so every file is owned by the
//!   scanning UID;
//! * the decoded bytes of all layers together, the number of entries, and the
//!   compressed input are bounded by the scan-workspace ceilings
//!   ([`max_scan_extracted_bytes`], [`MAX_SCAN_EXTRACTED_ENTRIES`],
//!   [`MAX_SCAN_INPUT_BYTES`]);
//! * the job's cancellation flag is checked once per entry.
//!
//! Directory modes are applied after the last layer, deepest first, so a
//! read-only directory in a lower layer does not stop a higher one from
//! writing beneath it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::scanner_service::{
    max_scan_extracted_bytes, parse_oci_manifest_path, resolve_scan_reference,
    ScanReferenceResolution, WorkspaceExtraction, WorkspaceExtractor, MAX_SCAN_EXTRACTED_ENTRIES,
    MAX_SCAN_INPUT_BYTES,
};
use crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX;
use crate::storage::StorageBackend;

/// Directory under the job workspace the image is unpacked into.
pub(crate) const ROOTFS_DIR: &str = "rootfs";

/// Most symlinks followed while resolving one path, as Linux's `MAXSYMLINKS`.
const MAX_SYMLINK_HOPS: usize = 40;

/// How one image layer is compressed, from its descriptor's `mediaType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerCoding {
    Plain,
    Gzip,
    Zstd,
}

impl LayerCoding {
    /// The coding of a layer media type, or `None` when it is not a
    /// filesystem layer this unpacker reads.
    pub(crate) fn from_media_type(media_type: &str) -> Option<Self> {
        let mt = media_type.trim().to_ascii_lowercase();
        let is_layer = mt.starts_with("application/vnd.oci.image.layer.")
            || mt.starts_with("application/vnd.docker.image.rootfs.");
        if !is_layer {
            return None;
        }
        if mt.ends_with("+gzip") || mt.ends_with(".tar.gzip") {
            Some(Self::Gzip)
        } else if mt.ends_with("+zstd") {
            Some(Self::Zstd)
        } else if mt.ends_with(".tar") || mt.ends_with(".diff.tar") {
            Some(Self::Plain)
        } else {
            None
        }
    }
}

/// One filesystem layer, in manifest order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageLayer {
    pub digest: String,
    pub coding: LayerCoding,
    pub size: u64,
}

/// Why an image cannot be unpacked into a root filesystem. Every variant is a
/// "this artifact cannot be evaluated" answer, recorded `not_applicable`, not
/// a scan error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotUnpackable {
    NotAnImageManifest,
    UnsupportedLayer(String),
    MissingLayer(String),
    UnresolvableIndex,
    NoStorage,
}

impl std::fmt::Display for NotUnpackable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnImageManifest => {
                write!(f, "the manifest lists no filesystem layers to unpack")
            }
            Self::UnsupportedLayer(mt) => write!(f, "layer media type {mt} is not a tar layer"),
            Self::MissingLayer(d) => {
                write!(f, "layer {d} is not stored in this repository, so the image cannot be unpacked locally")
            }
            Self::UnresolvableIndex => {
                write!(f, "the image index has no runnable platform manifest")
            }
            Self::NoStorage => write!(
                f,
                "no repository storage is available to read the layers from"
            ),
        }
    }
}

impl From<NotUnpackable> for AppError {
    fn from(e: NotUnpackable) -> Self {
        AppError::ScannerEngineUnavailable(format!("OpenSCAP: {e}"))
    }
}

/// Read the ordered filesystem layers from an image manifest body.
pub(crate) fn parse_image_layers(
    body: &[u8],
) -> std::result::Result<Vec<ImageLayer>, NotUnpackable> {
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| NotUnpackable::NotAnImageManifest)?;
    let layers = json
        .get("layers")
        .and_then(|l| l.as_array())
        .filter(|l| !l.is_empty())
        .ok_or(NotUnpackable::NotAnImageManifest)?;
    layers
        .iter()
        .map(|layer| {
            let media_type = layer
                .get("mediaType")
                .and_then(|m| m.as_str())
                .unwrap_or_default();
            let coding = LayerCoding::from_media_type(media_type)
                .ok_or_else(|| NotUnpackable::UnsupportedLayer(media_type.to_string()))?;
            let digest = layer
                .get("digest")
                .and_then(|d| d.as_str())
                .filter(|d| is_sha256_digest(d))
                .ok_or(NotUnpackable::NotAnImageManifest)?
                .to_string();
            let size = layer.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            Ok(ImageLayer {
                digest,
                coding,
                size,
            })
        })
        .collect()
}

fn is_sha256_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Extracts a stored image's root filesystem into `<workspace>/rootfs`.
pub(crate) struct OciRootfsExtractor<'a> {
    pub db: Option<&'a PgPool>,
    pub storage: Option<&'a dyn StorageBackend>,
    pub repository_id: Uuid,
}

#[async_trait]
impl WorkspaceExtractor for OciRootfsExtractor<'_> {
    async fn extract(&self, job: WorkspaceExtraction<'_>) -> Result<PathBuf> {
        let (Some(db), Some(storage)) = (self.db, self.storage) else {
            return Err(NotUnpackable::NoStorage.into());
        };
        let manifest = resolve_image_manifest(job.content, &job.artifact.path, storage).await?;
        let layers = parse_image_layers(&manifest)?;
        let keys = layer_storage_keys(db, self.repository_id, &layers).await?;
        unpack_layers(storage, &layers, &keys, job.workspace, job.cancel).await
    }
}

/// The single-platform image manifest to unpack: the artifact's own body, or
/// for an image index the child [`resolve_scan_reference`] selects, read from
/// local storage.
async fn resolve_image_manifest(
    content: &Bytes,
    artifact_path: &str,
    storage: &dyn StorageBackend,
) -> Result<Bytes> {
    let reference = parse_oci_manifest_path(artifact_path)
        .map(|(_, r)| r)
        .unwrap_or("latest");
    match resolve_scan_reference(content, reference) {
        ScanReferenceResolution::Passthrough(_) => Ok(content.clone()),
        ScanReferenceResolution::UnresolvableIndex(_) => {
            Err(NotUnpackable::UnresolvableIndex.into())
        }
        ScanReferenceResolution::ResolvedIndexChild(digest) => {
            if !is_sha256_digest(&digest) {
                return Err(NotUnpackable::UnresolvableIndex.into());
            }
            storage
                .get(&format!("{OCI_MANIFEST_STORAGE_PREFIX}{digest}"))
                .await
                .map_err(|_| NotUnpackable::MissingLayer(digest).into())
        }
    }
}

/// Map each layer digest to its storage key in this repository.
async fn layer_storage_keys(
    db: &PgPool,
    repository_id: Uuid,
    layers: &[ImageLayer],
) -> Result<HashMap<String, String>> {
    let digests: Vec<String> = layers.iter().map(|l| l.digest.clone()).collect();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT digest, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = ANY($2)",
    )
    .bind(repository_id)
    .bind(&digests)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(format!("Failed to load OCI layer blobs: {e}")))?;
    let keys: HashMap<String, String> = rows.into_iter().collect();
    if let Some(missing) = layers.iter().find(|l| !keys.contains_key(&l.digest)) {
        return Err(NotUnpackable::MissingLayer(missing.digest.clone()).into());
    }
    Ok(keys)
}

/// Copy every layer out of storage, then apply them in order into
/// `<workspace>/rootfs` on a blocking thread. Returns the rootfs path.
pub(crate) async fn unpack_layers(
    storage: &dyn StorageBackend,
    layers: &[ImageLayer],
    keys: &HashMap<String, String>,
    workspace: &Path,
    cancel: std::sync::Arc<AtomicBool>,
) -> Result<PathBuf> {
    let declared: u64 = layers.iter().map(|l| l.size).sum();
    if declared > MAX_SCAN_INPUT_BYTES {
        return Err(AppError::Internal(format!(
            "image layers total {declared} bytes, over the {MAX_SCAN_INPUT_BYTES}-byte scan input limit"
        )));
    }

    let blob_dir = workspace.join("layers");
    tokio::fs::create_dir_all(&blob_dir)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create layer staging dir: {e}")))?;
    let mut input_budget = MAX_SCAN_INPUT_BYTES;
    let mut staged = Vec::with_capacity(layers.len());
    for (i, layer) in layers.iter().enumerate() {
        let key = keys
            .get(&layer.digest)
            .ok_or_else(|| AppError::from(NotUnpackable::MissingLayer(layer.digest.clone())))?;
        let path = blob_dir.join(format!("{i}.blob"));
        copy_blob_capped(storage, key, &path, &mut input_budget).await?;
        staged.push((path, layer.coding));
    }

    let root = workspace.join(ROOTFS_DIR);
    let root_for_task = root.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        std::fs::create_dir_all(&root_for_task)
            .map_err(|e| AppError::Internal(format!("Failed to create rootfs dir: {e}")))?;
        let mut builder = RootfsBuilder::new(
            root_for_task,
            max_scan_extracted_bytes(),
            MAX_SCAN_EXTRACTED_ENTRIES,
        )?;
        for (path, coding) in staged {
            let file = std::fs::File::open(&path)
                .map_err(|e| AppError::Internal(format!("Failed to open staged layer: {e}")))?;
            builder.apply_layer(file, coding, &cancel)?;
            let _ = std::fs::remove_file(&path);
        }
        builder.finish()
    })
    .await
    .map_err(|e| AppError::Internal(format!("Rootfs extraction task failed: {e}")))??;
    let _ = tokio::fs::remove_dir_all(&blob_dir).await;
    Ok(root)
}

async fn copy_blob_capped(
    storage: &dyn StorageBackend,
    key: &str,
    path: &Path,
    budget: &mut u64,
) -> Result<()> {
    let mut stream = storage
        .get_stream(key)
        .await
        .map_err(|e| AppError::Storage(format!("Failed to open layer blob {key}: {e}")))?;
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| AppError::Storage(format!("Failed to stage layer blob: {e}")))?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| AppError::Storage(format!("Failed to read layer blob {key}: {e}")))?;
        let len = chunk.len() as u64;
        if len > *budget {
            return Err(AppError::Internal(format!(
                "image layers exceed the {MAX_SCAN_INPUT_BYTES}-byte scan input limit"
            )));
        }
        *budget -= len;
        file.write_all(&chunk)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to stage layer blob: {e}")))?;
    }
    file.flush()
        .await
        .map_err(|e| AppError::Storage(format!("Failed to stage layer blob: {e}")))
}

/// A reader that fails once more than `remaining` bytes have been read.
struct Capped<R> {
    inner: R,
    remaining: u64,
    breached: bool,
}

const BUDGET_BREACH: &str = "rootfs extraction budget exceeded";

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.remaining {
            self.breached = true;
            return Err(std::io::Error::other(BUDGET_BREACH));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn budget_error() -> AppError {
    AppError::Internal(
        "Image expands beyond the extraction budget; refusing to scan suspected decompression bomb"
            .to_string(),
    )
}

fn io_err(what: &str, path: &Path, e: std::io::Error) -> AppError {
    AppError::Internal(format!("{what} {}: {e}", path.display()))
}

/// Applies image layers into one root directory. Blocking.
pub(crate) struct RootfsBuilder {
    root: PathBuf,
    remaining_bytes: u64,
    entries: u64,
    max_entries: u64,
    /// Final directory modes, applied by [`Self::finish`].
    dir_modes: BTreeMap<PathBuf, u32>,
}

impl RootfsBuilder {
    pub(crate) fn new(root: PathBuf, max_bytes: u64, max_entries: u64) -> Result<Self> {
        let root = std::fs::canonicalize(&root).map_err(|e| io_err("Failed to open", &root, e))?;
        Ok(Self {
            root,
            remaining_bytes: max_bytes,
            entries: 0,
            max_entries,
            dir_modes: BTreeMap::new(),
        })
    }

    /// Apply one layer's tar stream on top of what is already unpacked.
    pub(crate) fn apply_layer<R: Read>(
        &mut self,
        reader: R,
        coding: LayerCoding,
        cancel: &AtomicBool,
    ) -> Result<()> {
        match coding {
            LayerCoding::Plain => self.apply_tar(reader, cancel),
            LayerCoding::Gzip => self.apply_tar(flate2::read::MultiGzDecoder::new(reader), cancel),
            LayerCoding::Zstd => {
                let decoder = zstd::Decoder::new(reader)
                    .map_err(|e| AppError::Internal(format!("Failed to open zstd layer: {e}")))?;
                self.apply_tar(decoder, cancel)
            }
        }
    }

    fn apply_tar<R: Read>(&mut self, reader: R, cancel: &AtomicBool) -> Result<()> {
        let mut archive = tar::Archive::new(Capped {
            inner: reader,
            remaining: self.remaining_bytes,
            breached: false,
        });
        // Paths this layer created: an opaque whiteout removes only what LOWER
        // layers put in its directory.
        let mut created: HashSet<PathBuf> = HashSet::new();
        let walk_err = |e: std::io::Error| {
            if e.to_string().contains(BUDGET_BREACH) {
                budget_error()
            } else {
                AppError::Internal(format!("Image layer is not a readable tar: {e}"))
            }
        };
        let entries = archive.entries().map_err(walk_err)?;
        for entry in entries {
            if cancel.load(Ordering::SeqCst) {
                return Err(AppError::Internal(
                    "Rootfs extraction cancelled: the scan was abandoned".to_string(),
                ));
            }
            let mut entry = entry.map_err(walk_err)?;
            self.entries += 1;
            if self.entries > self.max_entries {
                return Err(AppError::Internal(format!(
                    "Image contains too many entries (> {}); refusing to scan suspected decompression bomb",
                    self.max_entries
                )));
            }
            let raw_path = entry
                .path()
                .map_err(|e| AppError::Internal(format!("Bad tar entry path: {e}")))?
                .into_owned();
            let Some(rel) = normalize_entry_path(&raw_path) else {
                continue;
            };
            let header = entry.header();
            let kind = header.entry_type();
            let mode = header.mode().unwrap_or(0o644);
            let link_name = entry.link_name().ok().flatten().map(|l| l.into_owned());
            self.apply_entry(&rel, kind, mode, link_name, &mut entry, &mut created)?;
        }
        self.remaining_bytes = archive.into_inner().remaining;
        Ok(())
    }

    fn apply_entry<R: Read>(
        &mut self,
        rel: &[OsString],
        kind: tar::EntryType,
        mode: u32,
        link_name: Option<PathBuf>,
        data: &mut R,
        created: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        let (name, parent_rel) = rel.split_last().expect("normalized path is non-empty");
        let name_str = name.to_string_lossy();

        // Whiteouts (OCI image-spec layer.md).
        if let Some(hidden) = name_str.strip_prefix(".wh.") {
            let Some(parent) = self.resolve(parent_rel, true, false)? else {
                return Ok(());
            };
            if hidden == ".wh..opq" {
                self.clear_lower(&parent, created)?;
            } else if !hidden.is_empty() && hidden != "." && hidden != ".." {
                remove_any(&parent.join(hidden))?;
            }
            return Ok(());
        }

        let Some(parent) = self.resolve(parent_rel, true, true)? else {
            return Ok(());
        };
        let target = parent.join(name);
        self.mark_created(&target, created);

        if kind.is_dir() {
            match std::fs::symlink_metadata(&target) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => {
                    remove_any(&target)?;
                    create_dir(&target)?;
                }
                Err(_) => create_dir(&target)?,
            }
            if let Ok(rel_dir) = target.strip_prefix(&self.root) {
                self.dir_modes.insert(rel_dir.to_path_buf(), mode & 0o1777);
            }
            return Ok(());
        }

        if kind.is_symlink() {
            let Some(link) = link_name else {
                return Ok(());
            };
            let rewritten = self.confined_link_target(&parent, &link);
            remove_any(&target)?;
            std::os::unix::fs::symlink(&rewritten, &target)
                .map_err(|e| io_err("Failed to create symlink", &target, e))?;
            return Ok(());
        }

        if kind.is_hard_link() {
            let Some(link) = link_name else {
                return Ok(());
            };
            let Some(link_rel) = normalize_entry_path(&link) else {
                return Ok(());
            };
            let Some(source) = self.resolve(&link_rel, false, false)? else {
                return Ok(());
            };
            match std::fs::symlink_metadata(&source) {
                Ok(m) if m.is_file() && source != target => {
                    remove_any(&target)?;
                    std::fs::hard_link(&source, &target)
                        .map_err(|e| io_err("Failed to create hard link", &target, e))?;
                }
                _ => {}
            }
            return Ok(());
        }

        if kind.is_file() || kind == tar::EntryType::Continuous {
            remove_any(&target)?;
            use std::os::unix::fs::OpenOptionsExt;
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc_o_nofollow())
                .open(&target)
                .map_err(|e| io_err("Failed to create", &target, e))?;
            std::io::copy(data, &mut out).map_err(|e| {
                if e.to_string().contains(BUDGET_BREACH) {
                    budget_error()
                } else {
                    io_err("Failed to write", &target, e)
                }
            })?;
            drop(out);
            set_mode(&target, mode & 0o0777)?;
        }
        // Character and block devices, FIFOs and anything else: skipped.
        Ok(())
    }

    fn mark_created(&self, path: &Path, created: &mut HashSet<PathBuf>) {
        let mut p = path.to_path_buf();
        while p.starts_with(&self.root) && p != self.root {
            if !created.insert(p.clone()) {
                break;
            }
            if !p.pop() {
                break;
            }
        }
    }

    /// Opaque whiteout: drop every child of `dir` this layer did not create.
    fn clear_lower(&self, dir: &Path, created: &HashSet<PathBuf>) -> Result<()> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Ok(());
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !created.contains(&path) {
                remove_any(&path)?;
            }
        }
        Ok(())
    }

    /// Resolve `rel` (normal components) inside the root, following symlinks
    /// with chroot semantics. `follow_final` follows a symlink in the last
    /// component; `create` makes missing directories (and replaces a
    /// non-directory standing where a directory must be). Returns `None` when
    /// a component is missing and `create` is off, or the link chain is too
    /// deep. The result is always inside the root.
    pub(crate) fn resolve(
        &self,
        rel: &[OsString],
        follow_final: bool,
        create: bool,
    ) -> Result<Option<PathBuf>> {
        let mut pending: Vec<OsString> = rel.iter().rev().cloned().collect();
        let mut resolved: Vec<OsString> = Vec::new();
        let mut hops = 0usize;
        while let Some(part) = pending.pop() {
            if part == ".." {
                resolved.pop();
                continue;
            }
            if part == "." || part.is_empty() {
                continue;
            }
            let is_final = pending.is_empty();
            let candidate = self.join(&resolved).join(&part);
            match std::fs::symlink_metadata(&candidate) {
                Ok(m) if m.file_type().is_symlink() && (!is_final || follow_final) => {
                    hops += 1;
                    if hops > MAX_SYMLINK_HOPS {
                        return Ok(None);
                    }
                    let target = std::fs::read_link(&candidate)
                        .map_err(|e| io_err("Failed to read symlink", &candidate, e))?;
                    if target.is_absolute() {
                        resolved.clear();
                    }
                    for c in target.components().rev() {
                        match c {
                            Component::Normal(s) => pending.push(s.to_os_string()),
                            Component::ParentDir => pending.push(OsString::from("..")),
                            _ => {}
                        }
                    }
                }
                Ok(m) if m.is_dir() || (is_final && !create) => resolved.push(part),
                Ok(_) => {
                    // A file or a (final-unfollowed) link where a directory
                    // must be.
                    if !create {
                        return Ok(None);
                    }
                    remove_any(&candidate)?;
                    create_dir(&candidate)?;
                    resolved.push(part);
                }
                Err(_) if is_final && !create => resolved.push(part),
                Err(_) if create => {
                    create_dir(&candidate)?;
                    resolved.push(part);
                }
                Err(_) => return Ok(None),
            }
        }
        Ok(Some(self.join(&resolved)))
    }

    fn join(&self, comps: &[OsString]) -> PathBuf {
        let mut p = self.root.clone();
        for c in comps {
            p.push(c);
        }
        p
    }

    /// The relative symlink target, from `link_dir` (a directory inside the
    /// root), that names what `target` names when the root is `/`.
    pub(crate) fn confined_link_target(&self, link_dir: &Path, target: &Path) -> PathBuf {
        let base: Vec<OsString> = link_dir
            .strip_prefix(&self.root)
            .map(|p| p.iter().map(|c| c.to_os_string()).collect())
            .unwrap_or_default();
        let mut dest: Vec<OsString> = if target.is_absolute() {
            Vec::new()
        } else {
            base.clone()
        };
        for c in target.components() {
            match c {
                Component::Normal(s) => dest.push(s.to_os_string()),
                Component::ParentDir => {
                    dest.pop();
                }
                _ => {}
            }
        }
        let common = base.iter().zip(&dest).take_while(|(a, b)| a == b).count();
        let mut out = PathBuf::new();
        for _ in common..base.len() {
            out.push("..");
        }
        for c in &dest[common..] {
            out.push(c);
        }
        if out.as_os_str().is_empty() {
            out.push(".");
        }
        out
    }

    /// Apply the recorded directory modes, deepest first, and mark the tree
    /// as a container filesystem.
    pub(crate) fn finish(self) -> Result<()> {
        // SCAP content (scap-security-guide) tells a container from a machine
        // by `/.dockerenv` or `/run/.containerenv`, which the container
        // runtime creates at run time and an image does not carry. Without one
        // every machine-only rule (boot loader, partitions, kernel modules)
        // applies to the image and fails.
        let marker = self.root.join(".dockerenv");
        remove_any(&marker)?;
        std::fs::write(&marker, b"").map_err(|e| io_err("Failed to write", &marker, e))?;

        let mut dirs: Vec<(&PathBuf, &u32)> = self.dir_modes.iter().collect();
        dirs.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
        for (rel, mode) in dirs {
            let path = self.root.join(rel);
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                set_mode(&path, *mode)?;
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn libc_o_nofollow() -> i32 {
    libc::O_NOFOLLOW
}

#[cfg(not(target_os = "linux"))]
fn libc_o_nofollow() -> i32 {
    0
}

/// Turn a tar entry path into normal components: a leading `/` and `.`
/// components are dropped, an entry naming `..` anywhere is refused (`None`),
/// as is the root itself.
pub(crate) fn normalize_entry_path(path: &Path) -> Option<Vec<OsString>> {
    let mut out = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => out.push(s.to_os_string()),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    (!out.is_empty()).then_some(out)
}

fn create_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(path)
        .map_err(|e| io_err("Failed to create directory", path, e))
}

/// Remove whatever is at `path` without following a symlink there.
fn remove_any(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => {
            // A lower layer may have left it unwritable; its final mode is
            // only applied by `finish`, so it is still owner-writable here
            // unless it came from this tree's previous run, which never
            // happens (each job has a fresh workspace).
            std::fs::remove_dir_all(path).map_err(|e| io_err("Failed to remove", path, e))
        }
        Ok(_) => std::fs::remove_file(path).map_err(|e| io_err("Failed to remove", path, e)),
        Err(_) => Ok(()),
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| io_err("Failed to set mode on", path, e))
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// Build a tar in memory with raw headers, so entries the `tar` crate's
    /// builder would refuse (`..`, absolute paths) can be written.
    struct TarBuf(Vec<u8>);

    impl TarBuf {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn entry(&mut self, path: &str, kind: tar::EntryType, mode: u32, link: &str, data: &[u8]) {
            let mut h = tar::Header::new_ustar();
            {
                let raw = h.as_old_mut();
                raw.name[..path.len()].copy_from_slice(path.as_bytes());
                raw.linkname[..link.len()].copy_from_slice(link.as_bytes());
            }
            h.set_entry_type(kind);
            h.set_mode(mode);
            h.set_size(data.len() as u64);
            h.set_cksum();
            self.0.extend_from_slice(h.as_bytes());
            self.0.extend_from_slice(data);
            let pad = (512 - data.len() % 512) % 512;
            self.0.extend(vec![0u8; pad]);
        }
        fn file(&mut self, path: &str, mode: u32, data: &[u8]) -> &mut Self {
            self.entry(path, tar::EntryType::Regular, mode, "", data);
            self
        }
        fn dir(&mut self, path: &str, mode: u32) -> &mut Self {
            self.entry(path, tar::EntryType::Directory, mode, "", b"");
            self
        }
        fn symlink(&mut self, path: &str, target: &str) -> &mut Self {
            self.entry(path, tar::EntryType::Symlink, 0o777, target, b"");
            self
        }
        fn hardlink(&mut self, path: &str, target: &str) -> &mut Self {
            self.entry(path, tar::EntryType::Link, 0o644, target, b"");
            self
        }
        fn fifo(&mut self, path: &str) -> &mut Self {
            self.entry(path, tar::EntryType::Fifo, 0o644, "", b"");
            self
        }
        fn bytes(&self) -> Vec<u8> {
            let mut v = self.0.clone();
            v.extend(vec![0u8; 1024]);
            v
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        outside: PathBuf,
        builder: RootfsBuilder,
    }

    fn fixture() -> Fixture {
        fixture_with(1 << 30, 10_000)
    }

    fn fixture_with(max_bytes: u64, max_entries: u64) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws").join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let builder = RootfsBuilder::new(root, max_bytes, max_entries).unwrap();
        Fixture {
            _dir: dir,
            outside,
            builder,
        }
    }

    fn apply(f: &mut Fixture, tar: &TarBuf) -> Result<()> {
        f.builder.apply_layer(
            &tar.bytes()[..],
            LayerCoding::Plain,
            &AtomicBool::new(false),
        )
    }

    fn root(f: &Fixture) -> PathBuf {
        f.builder.root.clone()
    }

    fn outside_is_empty(f: &Fixture) -> bool {
        std::fs::read_dir(&f.outside).unwrap().next().is_none()
            && !f.outside.parent().unwrap().join("pwned").exists()
    }

    #[test]
    fn media_types() {
        use LayerCoding::*;
        for (mt, want) in [
            ("application/vnd.oci.image.layer.v1.tar+gzip", Some(Gzip)),
            ("application/vnd.oci.image.layer.v1.tar+zstd", Some(Zstd)),
            ("application/vnd.oci.image.layer.v1.tar", Some(Plain)),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                Some(Gzip),
            ),
            (
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                Some(Gzip),
            ),
            ("application/vnd.docker.image.rootfs.diff.tar", Some(Plain)),
            ("application/vnd.cncf.helm.chart.content.v1.tar+gzip", None),
            ("application/vnd.dev.cosign.simplesigning.v1+json", None),
        ] {
            assert_eq!(LayerCoding::from_media_type(mt), want, "{mt}");
        }
    }

    #[test]
    fn parse_layers_in_manifest_order() {
        let d1 = format!("sha256:{}", "a".repeat(64));
        let d2 = format!("sha256:{}", "b".repeat(64));
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": d1, "size": 1},
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d2, "size": 10},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": d1, "size": 20},
            ]
        });
        let layers = parse_image_layers(body.to_string().as_bytes()).unwrap();
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].digest, d2);
        assert_eq!(layers[0].coding, LayerCoding::Gzip);
        assert_eq!(layers[1].size, 20);

        let index = serde_json::json!({"manifests": []});
        assert_eq!(
            parse_image_layers(index.to_string().as_bytes()),
            Err(NotUnpackable::NotAnImageManifest)
        );
        let bad = serde_json::json!({"layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:../../x"}]});
        assert_eq!(
            parse_image_layers(bad.to_string().as_bytes()),
            Err(NotUnpackable::NotAnImageManifest)
        );
    }

    #[test]
    fn layers_apply_in_order_with_whiteouts() {
        let mut f = fixture();
        apply(
            &mut f,
            TarBuf::new()
                .dir("etc/", 0o755)
                .file("etc/os-release", 0o644, b"ID=rhel\n")
                .file("etc/gone", 0o644, b"x")
                .dir("var/cache/", 0o755)
                .file("var/cache/a", 0o644, b"a")
                .file("var/cache/b", 0o644, b"b"),
        )
        .unwrap();
        apply(
            &mut f,
            TarBuf::new()
                .file("etc/os-release", 0o644, b"ID=centos\n")
                .file("etc/.wh.gone", 0o644, b"")
                .file("var/cache/new", 0o644, b"n")
                .file("var/cache/.wh..wh..opq", 0o644, b""),
        )
        .unwrap();
        let r = root(&f);
        assert_eq!(
            std::fs::read_to_string(r.join("etc/os-release")).unwrap(),
            "ID=centos\n"
        );
        assert!(!r.join("etc/gone").exists());
        assert!(
            r.join("var/cache/new").exists(),
            "same-layer entry survives opaque"
        );
        assert!(!r.join("var/cache/a").exists());
        assert!(!r.join("var/cache/b").exists());
    }

    #[test]
    fn symlinked_parent_is_followed_inside_the_root() {
        // A lower layer makes `etc` a link to the host root (absolute) and
        // `up` a link that climbs out (relative). Writing through either must
        // land inside the image root, never outside it.
        let mut f = fixture();
        apply(
            &mut f,
            TarBuf::new()
                .symlink("etc", "/")
                .symlink("up", "../../../../outside"),
        )
        .unwrap();
        apply(
            &mut f,
            TarBuf::new()
                .file("etc/pwned", 0o644, b"x")
                .file("up/pwned", 0o644, b"y")
                .file("../pwned", 0o644, b"z")
                .file("/abs-ok", 0o644, b"ok"),
        )
        .unwrap();
        let r = root(&f);
        assert!(outside_is_empty(&f));
        assert!(
            r.join("pwned").exists(),
            "etc -> / re-rooted at the image root"
        );
        assert!(
            r.join("outside/pwned").exists(),
            "climbing link clamped at the root"
        );
        assert!(r.join("abs-ok").exists());
        // The links themselves were rewritten to relative, confined targets.
        assert_eq!(
            std::fs::read_link(r.join("etc")).unwrap(),
            PathBuf::from(".")
        );
        assert_eq!(
            std::fs::read_link(r.join("up")).unwrap(),
            PathBuf::from("outside")
        );
    }

    #[test]
    fn absolute_symlinks_become_relative() {
        let mut f = fixture();
        apply(
            &mut f,
            TarBuf::new()
                .file("usr/lib/os-release", 0o644, b"ID=rhel\n")
                .symlink("etc/os-release", "/usr/lib/os-release")
                .symlink("etc/alternatives/x", "../../../../../usr/bin/x"),
        )
        .unwrap();
        let r = root(&f);
        assert_eq!(
            std::fs::read_link(r.join("etc/os-release")).unwrap(),
            PathBuf::from("../usr/lib/os-release")
        );
        assert_eq!(
            std::fs::read_to_string(r.join("etc/os-release")).unwrap(),
            "ID=rhel\n"
        );
        assert_eq!(
            std::fs::read_link(r.join("etc/alternatives/x")).unwrap(),
            PathBuf::from("../../usr/bin/x")
        );
    }

    #[test]
    fn final_symlink_is_replaced_not_written_through() {
        let mut f = fixture();
        let victim = f.outside.join("victim");
        std::fs::write(&victim, b"original").unwrap();
        apply(
            &mut f,
            TarBuf::new().symlink("etc/passwd", "../../../outside/victim"),
        )
        .unwrap();
        apply(
            &mut f,
            TarBuf::new().file("etc/passwd", 0o644, b"root:x:0:0"),
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "original");
        let r = root(&f);
        assert!(!std::fs::symlink_metadata(r.join("etc/passwd"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn hard_links_must_stay_inside() {
        let mut f = fixture();
        std::fs::write(f.outside.join("secret"), b"s").unwrap();
        apply(
            &mut f,
            TarBuf::new()
                .file("bin/a", 0o755, b"elf")
                .hardlink("bin/b", "bin/a")
                .hardlink("bin/c", "../../outside/secret")
                .hardlink("bin/d", "/missing"),
        )
        .unwrap();
        let r = root(&f);
        assert_eq!(std::fs::read(r.join("bin/b")).unwrap(), b"elf");
        assert!(!r.join("bin/c").exists());
        assert!(!r.join("bin/d").exists());
    }

    #[test]
    fn modes_kept_setuid_dropped_devices_skipped() {
        let mut f = fixture();
        apply(
            &mut f,
            TarBuf::new()
                .dir("root/", 0o550)
                .file("root/.bashrc", 0o644, b"umask 022")
                .file("etc/shadow", 0o000, b"root:!!:")
                .file("usr/bin/su", 0o4755, b"elf")
                .dir("tmp/", 0o1777)
                .fifo("run/initctl"),
        )
        .unwrap();
        let r = root(&f);
        let mode = |p: &str| {
            std::fs::symlink_metadata(r.join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        f.builder.finish().unwrap();
        assert_eq!(mode("etc/shadow"), 0o000);
        assert_eq!(mode("usr/bin/su"), 0o755);
        assert_eq!(mode("root"), 0o550);
        assert_eq!(mode("tmp"), 0o1777);
        assert!(!r.join("run/initctl").exists());
        assert!(r.join(".dockerenv").exists());
        // Let the tempdir clean up.
        std::fs::set_permissions(r.join("root"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(r.join("etc/shadow"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
    }

    #[test]
    fn entry_budget_is_enforced_across_layers() {
        let mut f = fixture_with(1 << 30, 3);
        apply(
            &mut f,
            TarBuf::new().file("a", 0o644, b"").file("b", 0o644, b""),
        )
        .unwrap();
        let err = apply(
            &mut f,
            TarBuf::new().file("c", 0o644, b"").file("d", 0o644, b""),
        )
        .unwrap_err();
        assert!(err.to_string().contains("too many entries"), "{err}");
    }

    #[test]
    fn byte_budget_is_enforced_across_layers() {
        let mut f = fixture_with(8 * 1024, 1000);
        let big = vec![b'x'; 3000];
        apply(&mut f, TarBuf::new().file("a", 0o644, &big)).unwrap();
        let err = apply(
            &mut f,
            TarBuf::new().file("b", 0o644, &big).file("c", 0o644, &big),
        )
        .unwrap_err();
        assert!(err.to_string().contains("extraction budget"), "{err}");
    }

    #[test]
    fn gzip_layer_and_cancellation() {
        let mut f = fixture();
        let tar = TarBuf::new()
            .file("etc/os-release", 0o644, b"ID=rhel\n")
            .bytes();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        f.builder
            .apply_layer(&gz[..], LayerCoding::Gzip, &AtomicBool::new(false))
            .unwrap();
        assert!(root(&f).join("etc/os-release").exists());
        let err = f
            .builder
            .apply_layer(&gz[..], LayerCoding::Gzip, &AtomicBool::new(true))
            .unwrap_err();
        assert!(err.to_string().contains("cancelled"), "{err}");
    }

    #[test]
    fn symlink_loop_does_not_hang() {
        let mut f = fixture();
        apply(
            &mut f,
            TarBuf::new()
                .symlink("a", "b")
                .symlink("b", "a")
                .file("a/x", 0o644, b"x"),
        )
        .unwrap();
        assert!(outside_is_empty(&f));
    }

    #[test]
    fn normalize_refuses_parent_components() {
        assert_eq!(normalize_entry_path(Path::new("./etc/x")).unwrap().len(), 2);
        assert_eq!(normalize_entry_path(Path::new("/etc/x")).unwrap().len(), 2);
        assert!(normalize_entry_path(Path::new("etc/../../x")).is_none());
        assert!(normalize_entry_path(Path::new("./")).is_none());
    }
}
