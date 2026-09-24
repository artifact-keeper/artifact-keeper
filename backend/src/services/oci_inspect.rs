//! Describe a container image without pulling it: the manifest (or the
//! platform manifest behind an index), its config blob — what a container
//! starts with — the per-layer build history, and, when the image carries
//! a BuildKit SLSA provenance attestation built in `mode=max`, the actual
//! Dockerfile that produced it.
//!
//! Everything here reads from the registry's own storage (the manifests and
//! blobs already pushed), so inspection costs two or three storage reads
//! and never touches the network. The parsing is pure functions over bytes
//! so it is unit-tested without storage; `inspect` orchestrates the reads.
//!
//! The output shape is deliberately the same document the Bifrost console
//! renders for its image catalog (`ImageInspect` in bifrost-api), so one
//! viewer serves both products.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::handlers::oci_v2::{blob_storage_key, manifest_storage_key};
use crate::error::{AppError, Result};
use crate::storage::StorageBackend;

pub const MEDIA_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const MEDIA_DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const ATTESTATION_REFERENCE_TYPE: &str = "attestation-manifest";
const MAX_BLOB_BYTES: usize = 8 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ImagePlatform {
    pub os: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ImageConfig {
    pub env: BTreeMap<String, String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub user: String,
    pub working_dir: String,
    pub exposed_ports: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

/// One `history` row of the image config: the instruction that produced a
/// layer, joined to that layer when it produced one. This is the closest an
/// image gets to its Dockerfile when no provenance attestation carries the
/// real one.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ImageHistoryEntry {
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub empty_layer: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ImageLayer {
    pub digest: String,
    pub media_type: String,
    pub size_bytes: u64,
}

/// What a BuildKit SLSA provenance attestation says about how the image
/// was built. `dockerfile` is present only for `mode=max` attestations,
/// which embed the source; the image builder always emits those.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ImageProvenance {
    pub attestation_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImageInspect {
    /// The reference that was inspected (`repo/image:tag`).
    pub reference: String,
    /// Digest of the manifest the details describe (the platform manifest
    /// when `reference` resolved to an index).
    pub digest: String,
    /// Digest of the index the reference points at, when it is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_digest: Option<String>,
    pub platforms: Vec<ImagePlatform>,
    pub size_bytes: u64,
    pub config: ImageConfig,
    pub history: Vec<ImageHistoryEntry>,
    pub layers: Vec<ImageLayer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ImageProvenance>,
    /// Which producer filled the document: `registry` (read from storage).
    pub source: String,
}

// ---------------------------------------------------------------------------
// Wire shapes of the OCI documents we read
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    platform: Option<PlatformJson>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct PlatformJson {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ManifestJson {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
    #[serde(default)]
    manifests: Vec<Descriptor>,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigJson {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    config: ContainerConfigJson,
    #[serde(default)]
    history: Vec<HistoryJson>,
}

#[derive(Debug, Default, Deserialize)]
struct ContainerConfigJson {
    #[serde(rename = "Env", default)]
    env: Vec<String>,
    #[serde(rename = "Entrypoint", default)]
    entrypoint: Vec<String>,
    #[serde(rename = "Cmd", default)]
    cmd: Vec<String>,
    #[serde(rename = "User", default)]
    user: String,
    #[serde(rename = "WorkingDir", default)]
    working_dir: String,
    #[serde(rename = "ExposedPorts", default)]
    exposed_ports: BTreeMap<String, serde_json::Value>,
    #[serde(rename = "Labels", default)]
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default, Deserialize)]
struct HistoryJson {
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    created_by: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    empty_layer: bool,
}

// ---------------------------------------------------------------------------
// Pure parsing
// ---------------------------------------------------------------------------

/// The manifests an index offers, resolved to what inspection needs: the
/// platform manifest to describe (linux/amd64 when present, else the first
/// real image), every platform listed, and the attestation manifest that
/// refers to the chosen one, when any.
#[derive(Debug, PartialEq, Eq)]
pub struct IndexChoice {
    pub manifest_digest: String,
    pub platforms: Vec<ImagePlatform>,
    pub attestation_digest: Option<String>,
}

pub fn is_index_media_type(media_type: &str) -> bool {
    media_type == MEDIA_OCI_INDEX || media_type == MEDIA_DOCKER_LIST
}

fn parse_manifest_json(bytes: &[u8]) -> Result<ManifestJson> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("manifest is not valid JSON: {e}")))
}

/// Whether `bytes` is an index (manifest list) rather than an image manifest.
pub fn manifest_is_index(bytes: &[u8]) -> Result<bool> {
    let m = parse_manifest_json(bytes)?;
    Ok(is_index_media_type(&m.media_type) || (!m.manifests.is_empty() && m.config.is_none()))
}

/// Pick the platform manifest an index describes. `None` when the index
/// lists no image manifests at all.
pub fn choose_from_index(index_bytes: &[u8]) -> Result<Option<IndexChoice>> {
    let index = parse_manifest_json(index_bytes)?;
    let is_attestation = |d: &Descriptor| {
        d.annotations
            .get("vnd.docker.reference.type")
            .map(|t| t == ATTESTATION_REFERENCE_TYPE)
            .unwrap_or(false)
            || d.platform
                .as_ref()
                .map(|p| p.os == "unknown" && p.architecture == "unknown")
                .unwrap_or(false)
    };
    let mut platforms = Vec::new();
    let mut chosen: Option<&Descriptor> = None;
    for d in index.manifests.iter().filter(|d| !is_attestation(d)) {
        if let Some(p) = &d.platform {
            platforms.push(ImagePlatform {
                os: p.os.clone(),
                architecture: p.architecture.clone(),
                variant: p.variant.clone().filter(|v| !v.is_empty()),
            });
            if p.os == "linux" && p.architecture == "amd64" {
                chosen = Some(d);
            }
        }
        if chosen.is_none() && d.platform.is_none() {
            chosen = Some(d);
        }
    }
    let chosen = match chosen.or_else(|| index.manifests.iter().find(|d| !is_attestation(d))) {
        Some(c) => c,
        None => return Ok(None),
    };
    let attestation_digest = index
        .manifests
        .iter()
        .filter(|d| is_attestation(d))
        .find(|d| {
            d.annotations
                .get("vnd.docker.reference.digest")
                .map(|r| r == &chosen.digest)
                .unwrap_or(false)
        })
        .map(|d| d.digest.clone());
    Ok(Some(IndexChoice {
        manifest_digest: chosen.digest.clone(),
        platforms,
        attestation_digest,
    }))
}

/// The layers and config descriptor of an image manifest.
pub struct ParsedManifest {
    pub config_digest: String,
    pub layers: Vec<ImageLayer>,
    pub size_bytes: u64,
}

pub fn parse_image_manifest(bytes: &[u8]) -> Result<ParsedManifest> {
    let m = parse_manifest_json(bytes)?;
    let config = m.config.ok_or_else(|| {
        AppError::UnprocessableEntity(
            "manifest has no config descriptor (schema 1 manifests are not supported)".to_string(),
        )
    })?;
    let layers: Vec<ImageLayer> = m
        .layers
        .iter()
        .map(|l| ImageLayer {
            digest: l.digest.clone(),
            media_type: l.media_type.clone(),
            size_bytes: l.size,
        })
        .collect();
    let size_bytes = layers.iter().map(|l| l.size_bytes).sum();
    Ok(ParsedManifest {
        config_digest: config.digest,
        layers,
        size_bytes,
    })
}

/// The container config and the history joined to `layers` in order:
/// every non-empty history step consumes the next layer.
pub fn parse_config(
    bytes: &[u8],
    layers: &[ImageLayer],
) -> Result<(ImageConfig, Vec<ImageHistoryEntry>, Option<ImagePlatform>)> {
    let cfg: ConfigJson = serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("image config is not valid JSON: {e}")))?;
    let mut env = BTreeMap::new();
    for kv in &cfg.config.env {
        let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
        env.insert(k.to_string(), v.to_string());
    }
    let config = ImageConfig {
        env,
        entrypoint: cfg.config.entrypoint.clone(),
        cmd: cfg.config.cmd.clone(),
        user: cfg.config.user.clone(),
        working_dir: cfg.config.working_dir.clone(),
        exposed_ports: cfg.config.exposed_ports.keys().cloned().collect(),
        labels: cfg.config.labels.clone().unwrap_or_default(),
    };
    let mut layer_index = 0usize;
    let history = cfg
        .history
        .iter()
        .map(|h| {
            let mut entry = ImageHistoryEntry {
                created_by: h.created_by.clone(),
                created: h.created.clone(),
                comment: h.comment.clone().filter(|c| !c.is_empty()),
                empty_layer: h.empty_layer,
                layer_digest: None,
                size_bytes: None,
            };
            if !h.empty_layer {
                if let Some(layer) = layers.get(layer_index) {
                    entry.layer_digest = Some(layer.digest.clone());
                    entry.size_bytes = Some(layer.size_bytes);
                }
                layer_index += 1;
            }
            entry
        })
        .collect();
    let platform = if cfg.os.is_empty() && cfg.architecture.is_empty() {
        None
    } else {
        Some(ImagePlatform {
            os: cfg.os,
            architecture: cfg.architecture,
            variant: cfg.variant.filter(|v| !v.is_empty()),
        })
    };
    Ok((config, history, platform))
}

/// Read an in-toto statement carrying SLSA provenance and pull out what the
/// viewer shows. Handles both the SLSA v1 layout BuildKit emits today
/// (`runDetails.metadata.buildkit_metadata.source.infos`) and the v0.2
/// layout (`metadata."https://mobyproject.org/buildkit@v1#metadata"`).
pub fn provenance_from_attestation(bytes: &[u8], attestation_digest: &str) -> ImageProvenance {
    let mut out = ImageProvenance {
        attestation_digest: attestation_digest.to_string(),
        ..Default::default()
    };
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return out;
    };
    out.predicate_type = doc
        .get("predicateType")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let predicate = doc.get("predicate").cloned().unwrap_or_default();
    out.build_type = predicate
        .pointer("/buildDefinition/buildType")
        .or_else(|| predicate.get("buildType"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    out.builder_id = predicate
        .pointer("/runDetails/builder/id")
        .or_else(|| predicate.pointer("/builder/id"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let infos = predicate
        .pointer("/runDetails/metadata/buildkit_metadata/source/infos")
        .or_else(|| {
            predicate
                .get("metadata")
                .and_then(|m| m.get("https://mobyproject.org/buildkit@v1#metadata"))
                .and_then(|m| m.pointer("/source/infos"))
        })
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for info in infos {
        let filename = info
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("Dockerfile");
        let Some(data) = info.get("data").and_then(|v| v.as_str()) else {
            continue;
        };
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(data) {
            if let Ok(text) = String::from_utf8(decoded) {
                out.dockerfile = Some(text);
                out.dockerfile_name = Some(filename.to_string());
                break;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Distribution family, from what the image says about itself
// ---------------------------------------------------------------------------

/// The system package manager an image most likely carries, read from its
/// own build history (the newest step that ran a package manager wins) and,
/// failing that, its labels (Red Hat's UBI images name their component).
/// None when nothing in the image says.
pub fn detect_system_manager(
    history: &[ImageHistoryEntry],
    labels: &BTreeMap<String, String>,
) -> Option<&'static str> {
    for h in history.iter().rev() {
        let c = h.created_by.as_str();
        if c.contains("microdnf ") {
            return Some("microdnf");
        }
        if c.contains("dnf ") {
            return Some("dnf");
        }
        if c.contains("yum ") {
            return Some("yum");
        }
        if c.contains("apk add") || c.contains("apk ") {
            return Some("apk");
        }
        if c.contains("apt-get ") || c.contains("apt ") || c.contains("dpkg ") {
            return Some("apt");
        }
    }
    let component = labels
        .get("com.redhat.component")
        .or_else(|| labels.get("name"))
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    let vendor = labels
        .get("org.opencontainers.image.vendor")
        .or_else(|| labels.get("vendor"))
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    if vendor.contains("red hat") || component.starts_with("ubi") {
        return Some(
            if component.contains("minimal") || component.contains("micro") {
                "microdnf"
            } else {
                "dnf"
            },
        );
    }
    if vendor.contains("alpine") || component.contains("alpine") {
        return Some("apk");
    }
    if vendor.contains("debian") || vendor.contains("ubuntu") || vendor.contains("canonical") {
        return Some("apt");
    }
    None
}

// ---------------------------------------------------------------------------
// Orchestration over storage
// ---------------------------------------------------------------------------

async fn read_capped(storage: &dyn StorageBackend, key: &str, what: &str) -> Result<Vec<u8>> {
    let bytes = storage
        .get(key)
        .await
        .map_err(|e| AppError::NotFound(format!("{what} is not in storage ({key}): {e}")))?;
    if bytes.len() > MAX_BLOB_BYTES {
        return Err(AppError::UnprocessableEntity(format!(
            "{what} is larger than {} bytes",
            MAX_BLOB_BYTES
        )));
    }
    Ok(bytes.to_vec())
}

/// Describe the image whose manifest (or index) has `manifest_digest`,
/// reading everything from `storage`.
pub async fn inspect(
    storage: &dyn StorageBackend,
    reference: &str,
    manifest_digest: &str,
) -> Result<ImageInspect> {
    let top = read_capped(storage, &manifest_storage_key(manifest_digest), "manifest").await?;
    let mut index_digest = None;
    let mut platforms = Vec::new();
    let mut attestation_digest = None;
    let (manifest_bytes, digest) = if manifest_is_index(&top)? {
        let choice = choose_from_index(&top)?.ok_or_else(|| {
            AppError::UnprocessableEntity("index lists no image manifests".to_string())
        })?;
        index_digest = Some(manifest_digest.to_string());
        platforms = choice.platforms;
        attestation_digest = choice.attestation_digest;
        let bytes = read_capped(
            storage,
            &manifest_storage_key(&choice.manifest_digest),
            "platform manifest",
        )
        .await?;
        (bytes, choice.manifest_digest)
    } else {
        (top, manifest_digest.to_string())
    };
    let parsed = parse_image_manifest(&manifest_bytes)?;
    let config_bytes = read_capped(
        storage,
        &blob_storage_key(&parsed.config_digest),
        "image config",
    )
    .await?;
    let (config, history, platform) = parse_config(&config_bytes, &parsed.layers)?;
    if platforms.is_empty() {
        platforms.extend(platform);
    }
    let mut provenance = None;
    if let Some(att) = attestation_digest {
        if let Ok(att_manifest) =
            read_capped(storage, &manifest_storage_key(&att), "attestation").await
        {
            if let Ok(m) = parse_manifest_json(&att_manifest) {
                if let Some(layer) = m.layers.first() {
                    if let Ok(blob) = read_capped(
                        storage,
                        &blob_storage_key(&layer.digest),
                        "attestation blob",
                    )
                    .await
                    {
                        provenance = Some(provenance_from_attestation(&blob, &att));
                    }
                }
            }
        }
    }
    Ok(ImageInspect {
        reference: reference.to_string(),
        digest,
        index_digest,
        platforms,
        size_bytes: parsed.size_bytes,
        config,
        history,
        layers: parsed.layers,
        provenance,
        source: "registry".to_string(),
    })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn index_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": MEDIA_OCI_INDEX,
            "manifests": [
                {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:arm","size":1,"platform":{"os":"linux","architecture":"arm64","variant":"v8"}},
                {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:amd","size":1,"platform":{"os":"linux","architecture":"amd64"}},
                {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:att","size":1,"platform":{"os":"unknown","architecture":"unknown"},
                 "annotations":{"vnd.docker.reference.type":"attestation-manifest","vnd.docker.reference.digest":"sha256:amd"}}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn index_choice_prefers_amd64_and_finds_its_attestation() {
        let choice = choose_from_index(&index_json()).unwrap().unwrap();
        assert_eq!(choice.manifest_digest, "sha256:amd");
        assert_eq!(choice.attestation_digest.as_deref(), Some("sha256:att"));
        assert_eq!(choice.platforms.len(), 2);
        assert_eq!(choice.platforms[0].variant.as_deref(), Some("v8"));
        assert!(manifest_is_index(&index_json()).unwrap());
    }

    #[test]
    fn manifest_and_config_join_history_to_layers() {
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cfg","size":10},
            "layers":[
                {"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l1","size":100},
                {"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l2","size":900}
            ]
        }))
        .unwrap();
        assert!(!manifest_is_index(&manifest).unwrap());
        let parsed = parse_image_manifest(&manifest).unwrap();
        assert_eq!(parsed.config_digest, "sha256:cfg");
        assert_eq!(parsed.size_bytes, 1000);
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture":"amd64","os":"linux",
            "config":{"Env":["PATH=/bin","A=1=2"],"Cmd":["/bin/bash"],"User":"app","WorkingDir":"/home/app",
                      "ExposedPorts":{"8265/tcp":{}},"Labels":{"team":"a"}},
            "history":[
                {"created_by":"FROM ubuntu","empty_layer":false},
                {"created_by":"/bin/sh -c #(nop) ENV A=1","empty_layer":true},
                {"created_by":"RUN pip install numpy","empty_layer":false}
            ]
        }))
        .unwrap();
        let (cfg, history, platform) = parse_config(&config, &parsed.layers).unwrap();
        assert_eq!(cfg.env.get("A").map(String::as_str), Some("1=2"));
        assert_eq!(cfg.user, "app");
        assert_eq!(cfg.exposed_ports, vec!["8265/tcp"]);
        assert_eq!(cfg.labels.get("team").map(String::as_str), Some("a"));
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].layer_digest.as_deref(), Some("sha256:l1"));
        assert_eq!(history[0].size_bytes, Some(100));
        assert!(history[1].empty_layer && history[1].layer_digest.is_none());
        assert_eq!(history[2].layer_digest.as_deref(), Some("sha256:l2"));
        assert_eq!(platform.unwrap().architecture, "amd64");
    }

    /// An index → amd64 manifest → config, plus the attestation manifest and
    /// its provenance blob, written into a filesystem store the way the
    /// registry lays them out; `inspect` reads it all back.
    #[tokio::test]
    async fn inspect_reads_index_manifest_config_and_provenance_from_storage() {
        use crate::storage::StorageBackend;
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::filesystem::FilesystemStorage::new(dir.path());
        let put = |key: String, bytes: Vec<u8>| {
            let storage = &storage;
            async move { storage.put(&key, bytes.into()).await.unwrap() }
        };
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cfg","size":10},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l1","size":100}]
        }))
        .unwrap();
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture":"amd64","os":"linux",
            "config":{"Env":["PATH=/bin"],"User":"app","Labels":{"team":"a"}},
            "history":[{"created_by":"RUN pip install numpy","empty_layer":false}]
        }))
        .unwrap();
        let dockerfile = "FROM python:3.12-slim\nRUN pip install numpy\n";
        let provenance = serde_json::to_vec(&serde_json::json!({
            "predicateType":"https://slsa.dev/provenance/v1",
            "predicate":{"runDetails":{"builder":{"id":"buildkit"},"metadata":{"buildkit_metadata":{"source":{"infos":[
                {"filename":"Dockerfile","data": base64::engine::general_purpose::STANDARD.encode(dockerfile)}]}}}}}
        }))
        .unwrap();
        let att_manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:attcfg","size":1},
            "layers":[{"mediaType":"application/vnd.in-toto+json","digest":"sha256:prov","size":1}]
        }))
        .unwrap();
        put(manifest_storage_key("sha256:idx"), index_json()).await;
        put(manifest_storage_key("sha256:amd"), manifest).await;
        put(blob_storage_key("sha256:cfg"), config).await;
        put(manifest_storage_key("sha256:att"), att_manifest).await;
        put(blob_storage_key("sha256:prov"), provenance).await;

        let doc = inspect(&storage, "images/spike:0.1", "sha256:idx")
            .await
            .unwrap();
        assert_eq!(doc.reference, "images/spike:0.1");
        assert_eq!(doc.digest, "sha256:amd");
        assert_eq!(doc.index_digest.as_deref(), Some("sha256:idx"));
        assert_eq!(doc.platforms.len(), 2, "from the index, not the config");
        assert_eq!(doc.size_bytes, 100, "layers only");
        assert_eq!(doc.config.user, "app");
        assert_eq!(doc.history[0].layer_digest.as_deref(), Some("sha256:l1"));
        assert_eq!(doc.layers.len(), 1);
        let p = doc.provenance.expect("provenance");
        assert_eq!(p.dockerfile.as_deref(), Some(dockerfile));
        assert_eq!(p.attestation_digest, "sha256:att");

        // A plain manifest (no index) takes its platform from the config and
        // carries no provenance; a missing manifest is a 404.
        let doc = inspect(&storage, "images/spike:0.1", "sha256:amd")
            .await
            .unwrap();
        assert!(doc.index_digest.is_none());
        assert_eq!(doc.platforms[0].architecture, "amd64");
        assert!(doc.provenance.is_none());
        let err = inspect(&storage, "images/x:1", "sha256:missing")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "{err}");
    }

    #[test]
    fn system_manager_comes_from_history_then_labels() {
        let h = |steps: &[&str]| -> Vec<ImageHistoryEntry> {
            steps
                .iter()
                .map(|c| ImageHistoryEntry {
                    created: None,
                    created_by: c.to_string(),
                    comment: None,
                    empty_layer: false,
                    layer_digest: None,
                    size_bytes: None,
                })
                .collect()
        };
        let none = BTreeMap::new();
        assert_eq!(
            detect_system_manager(
                &h(&["RUN /bin/sh -c apt-get update && apt-get install -y git"]),
                &none
            ),
            Some("apt")
        );
        assert_eq!(
            detect_system_manager(
                &h(&["RUN microdnf install -y git && microdnf clean all"]),
                &none
            ),
            Some("microdnf")
        );
        assert_eq!(
            detect_system_manager(&h(&["RUN dnf install -y git"]), &none),
            Some("dnf")
        );
        assert_eq!(
            detect_system_manager(&h(&["RUN yum install -y git"]), &none),
            Some("yum")
        );
        assert_eq!(
            detect_system_manager(&h(&["RUN apk add --no-cache curl"]), &none),
            Some("apk")
        );
        // The newest step wins: a UBI base later customised with microdnf.
        assert_eq!(
            detect_system_manager(
                &h(&["RUN dnf install -y x", "RUN microdnf install -y y"]),
                &none
            ),
            Some("microdnf")
        );
        assert_eq!(
            detect_system_manager(&h(&["ENV A=1", "CMD [\"bash\"]"]), &none),
            None
        );
        let ubi = BTreeMap::from([(
            "com.redhat.component".to_string(),
            "ubi9-minimal-container".to_string(),
        )]);
        assert_eq!(detect_system_manager(&[], &ubi), Some("microdnf"));
        let rh = BTreeMap::from([(
            "org.opencontainers.image.vendor".to_string(),
            "Red Hat, Inc.".to_string(),
        )]);
        assert_eq!(detect_system_manager(&[], &rh), Some("dnf"));
        let ubuntu = BTreeMap::from([("vendor".to_string(), "Canonical".to_string())]);
        assert_eq!(detect_system_manager(&[], &ubuntu), Some("apt"));
    }

    #[test]
    fn provenance_extracts_the_dockerfile_from_slsa_v1_and_v02() {
        let dockerfile = "FROM alpine\nRUN echo hi\n";
        let data = base64::engine::general_purpose::STANDARD.encode(dockerfile);
        let v1 = serde_json::to_vec(&serde_json::json!({
            "predicateType":"https://slsa.dev/provenance/v1",
            "predicate":{
                "buildDefinition":{"buildType":"https://mobyproject.org/buildkit@v1"},
                "runDetails":{"builder":{"id":"buildkit"},"metadata":{"buildkit_metadata":{"source":{"infos":[{"filename":"Dockerfile","data":data}]}}}}
            }
        }))
        .unwrap();
        let p = provenance_from_attestation(&v1, "sha256:att");
        assert_eq!(p.dockerfile.as_deref(), Some(dockerfile));
        assert_eq!(p.dockerfile_name.as_deref(), Some("Dockerfile"));
        assert_eq!(
            p.build_type.as_deref(),
            Some("https://mobyproject.org/buildkit@v1")
        );
        assert_eq!(p.builder_id.as_deref(), Some("buildkit"));
        let v02 = serde_json::to_vec(&serde_json::json!({
            "predicateType":"https://slsa.dev/provenance/v0.2",
            "predicate":{"buildType":"x","builder":{"id":"b"},
                "metadata":{"https://mobyproject.org/buildkit@v1#metadata":{"source":{"infos":[{"filename":"Containerfile","data":data}]}}}}
        }))
        .unwrap();
        let p = provenance_from_attestation(&v02, "sha256:att2");
        assert_eq!(p.dockerfile.as_deref(), Some(dockerfile));
        assert_eq!(p.dockerfile_name.as_deref(), Some("Containerfile"));
        // Garbage in: the digest is still recorded, nothing else.
        let p = provenance_from_attestation(b"not json", "sha256:x");
        assert_eq!(p.attestation_digest, "sha256:x");
        assert!(p.dockerfile.is_none());
    }
}
