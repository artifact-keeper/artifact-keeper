//! Format-native finalize for a chunked upload completion (#1846).
//!
//! `PUT /api/v1/uploads/{id}/complete` resolves the session's repository
//! format and, when that format has a native upload route that indexes the
//! artifact (Maven, npm, PyPI, RPM, Incus, Debian), runs the same parsers and
//! records the same rows that route does, so the artifact appears in the
//! format's own index (`maven-metadata.xml`, the npm packument, the PyPI
//! simple index, RPM `primary.xml`, `images.json`, `Packages`) exactly as a
//! single upload through the native route would make it appear.
//!
//! Three steps, each shared with the native route where the route exposes it:
//!
//! 1. [`native_target`]: the `(name, version)` the native route writes for the
//!    path, and what the parser needs to read: nothing (a Maven jar is indexed
//!    from its path), a byte stream (a Maven POM, an npm tarball's
//!    `package.json`), or a local file (a zip wheel, an RPM header, a Debian or
//!    Incus archive). Paths the native route would not index (a Maven checksum
//!    sidecar, a debian file outside `pool/`) keep the generic behaviour.
//! 2. [`stage`]: the parse, run before any byte is stored, so a package the
//!    native route refuses (a `package.json` or wheel `METADATA` that names a
//!    different project or version than the file) is refused here too.
//! 3. [`record`]: after the artifact row commits, the `artifact_metadata`
//!    document, catalog row, install-script analysis and index cache
//!    invalidation the native route performs. Silent: the completion emits its
//!    own `artifact.uploaded`.
//!
//! The artifact keeps the content-addressed storage key every chunked upload
//! uses; every format's download route reads the row's `storage_key`, so rows
//! committed before this change stay readable as they are.

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use uuid::Uuid;

use crate::api::SharedState;
use crate::models::repository::RepositoryFormat;
use crate::services::package_service::PackageService;
use crate::services::upload_service::UploadSession;

/// Largest POM a chunked Maven completion reads into memory for its metadata.
/// A POM is a small XML document; anything larger is indexed from its path
/// alone, as the native route indexes a POM it cannot parse.
const MAX_POM_BYTES: usize = 8 * 1024 * 1024;

/// What a format's finalize parser reads from the uploaded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalizeInput {
    /// Nothing: the native route indexes the file from its path.
    PathOnly,
    /// A forward-only byte stream: the completion can feed it the staged
    /// chunks without assembling a local file.
    Stream,
    /// A local file (the parser seeks, or reads a header by offset).
    LocalFile,
}

/// The coordinates a format's native route writes for a path, and what its
/// parser needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeTarget {
    pub name: String,
    pub version: String,
    pub input: FinalizeInput,
}

/// Where [`stage`] reads the uploaded bytes from.
pub(crate) enum FinalizeSource<'a> {
    /// No bytes are needed (`FinalizeInput::PathOnly`).
    None,
    /// The locally assembled, verified file.
    File(&'a std::path::Path),
    /// The verified staged chunks, in order.
    Stream(BoxStream<'static, crate::error::Result<Bytes>>),
}

/// What the native route derives from the bytes, recorded against the
/// artifact row once it exists.
pub(crate) enum StagedNativeFinalize {
    /// An Incus image's `artifact_metadata` document (arch/os/release), which
    /// `streams_images` reads.
    Incus(serde_json::Value),
    /// A parsed and validated Debian package (control metadata, maintainer
    /// scripts), which `Packages` renders.
    Debian(Box<crate::api::handlers::debian::StagedDebianPackage>),
    /// A Maven file's `artifact_metadata` document and catalog entry, which
    /// `maven-metadata.xml` and the grouped listings read.
    Maven(Box<StagedMaven>),
    /// An npm tarball's `package.json`, which the packument serves as the
    /// version document.
    Npm(Box<StagedNpm>),
    /// A PyPI distribution's parsed core metadata and content analysis.
    Pypi(Box<StagedPypi>),
    /// An RPM's install scriptlets and its filename-derived identity (the
    /// header metadata itself is recorded by the completion's RPM parse).
    Rpm(Box<StagedRpm>),
}

pub(crate) struct StagedMaven {
    coords: crate::formats::maven::MavenCoordinates,
    metadata: serde_json::Value,
    package_name: String,
    package_description: Option<String>,
    package_metadata: Option<serde_json::Value>,
}

pub(crate) struct StagedNpm {
    package_name: String,
    version: String,
    version_data: serde_json::Value,
}

pub(crate) struct StagedPypi {
    metadata: serde_json::Value,
    summary: Option<String>,
    catalog: serde_json::Value,
    analysis: crate::services::pypi_analysis::PypiAnalysis,
}

pub(crate) struct StagedRpm {
    scripts: crate::api::handlers::rpm::ExtractedScripts,
}

/// The `artifact_metadata` document a native finalize records, ready to write
/// inside the artifact-row transaction (#5002).
pub(crate) struct NativeMetadata {
    pub format: &'static str,
    pub metadata: serde_json::Value,
    pub properties: serde_json::Value,
}

/// The `artifact_metadata` row a native finalize writes, derived from the
/// staged parse.
///
/// The completion writes this in the same transaction as the `artifacts` row,
/// so a failure after the row commits cannot leave an indexed artifact without
/// its format metadata. Everything else the native route does (catalog rows,
/// script analysis, cache invalidation, the Debian/RPM extra tables) stays in
/// [`record`] after the commit.
pub(crate) fn metadata_document(
    staged: &StagedNativeFinalize,
    _target: &NativeTarget,
    session: &UploadSession,
    rpm_metadata: Option<&serde_json::Value>,
) -> Result<Option<NativeMetadata>, String> {
    let document = match staged {
        StagedNativeFinalize::Incus(metadata) => NativeMetadata {
            format: "incus",
            metadata: metadata.clone(),
            properties: serde_json::json!({}),
        },
        StagedNativeFinalize::Debian(package) => NativeMetadata {
            format: "debian",
            metadata: package.control_document().clone(),
            properties: serde_json::json!({}),
        },
        StagedNativeFinalize::Maven(maven) => NativeMetadata {
            format: "maven",
            metadata: maven.metadata.clone(),
            properties: serde_json::json!({}),
        },
        StagedNativeFinalize::Npm(npm) => NativeMetadata {
            format: "npm",
            metadata: serde_json::json!({
                "name": npm.package_name,
                "version": npm.version,
                "version_data": npm.version_data,
            }),
            properties: serde_json::json!({}),
        },
        StagedNativeFinalize::Pypi(pypi) => NativeMetadata {
            format: "pypi",
            metadata: pypi.metadata.clone(),
            properties: serde_json::json!({}),
        },
        StagedNativeFinalize::Rpm(_) => {
            // The header parse normally supplies the document; when it did not
            // parse, the native route falls back to the NEVRA in the file
            // name, and so does this completion.
            let metadata = match rpm_metadata {
                Some(metadata) => metadata.clone(),
                None => {
                    let filename = basename(&session.artifact_path);
                    let (name, version, release, arch) =
                        crate::api::handlers::rpm::parse_rpm_filename(filename)
                            .ok_or_else(|| "not an RPM package file name".to_string())?;
                    crate::api::handlers::rpm::build_rpm_metadata(
                        &name, &version, &release, &arch, filename,
                    )
                }
            };
            NativeMetadata {
                format: "rpm",
                metadata,
                properties: serde_json::json!({}),
            }
        }
    };
    Ok(Some(document))
}

/// Whether `format` has a dedicated finalize above. A format that does keeps
/// the generic behaviour for a path [`native_target`] declined (a Maven
/// checksum sidecar); the generic dispatch below is only for formats with no
/// native finalize at all.
pub(crate) fn has_native_finalize(format: &RepositoryFormat) -> bool {
    matches!(
        format,
        RepositoryFormat::Incus
            | RepositoryFormat::Lxc
            | RepositoryFormat::Debian
            | RepositoryFormat::Maven
            | RepositoryFormat::Gradle
            | RepositoryFormat::Npm
            | RepositoryFormat::Pypi
            | RepositoryFormat::Rpm
    )
}

/// The `artifact_metadata` document a format handler derives from the upload
/// path alone, for the formats with no native finalize above (#5002).
///
/// Most handlers index a chunked upload from its path (a Terraform provider's
/// platform, a Helm chart's name and version, a Chef cookbook's coordinates);
/// this runs the same `parse_metadata` the native route's handler exposes, with
/// an empty body. A path the handler does not recognise, or a generic handler
/// whose document is just the path, yields `None` and the upload keeps the
/// generic behaviour. The document is written inside the artifact transaction
/// by the completion, like the native ones.
pub(crate) async fn generic_metadata_document(
    format: &RepositoryFormat,
    artifact_path: &str,
) -> Option<NativeMetadata> {
    let format_key = format.handler_key();
    if format_key == "generic" || has_native_finalize(format) {
        return None;
    }
    let handler = crate::formats::get_handler_for_format(format);
    let metadata = crate::formats::FormatHandler::parse_metadata(
        handler.as_ref(),
        artifact_path,
        &Bytes::new(),
    )
    .await
    .ok()?;
    if metadata.as_object().is_some_and(|object| object.is_empty()) {
        return None;
    }
    Some(NativeMetadata {
        format: format_key,
        metadata,
        properties: serde_json::json!({}),
    })
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The native target for `artifact_path` in a repository of `format`, or
/// `None` to keep the generic chunked behaviour.
pub(crate) fn native_target(
    format: &RepositoryFormat,
    artifact_path: &str,
) -> Option<NativeTarget> {
    use crate::formats::maven::MavenHandler;
    let target = |(name, version): (String, String), input| NativeTarget {
        name,
        version,
        input,
    };
    match format {
        RepositoryFormat::Incus | RepositoryFormat::Lxc => {
            crate::api::handlers::incus::image_coordinates_from_path(artifact_path)
                .map(|c| target(c, FinalizeInput::LocalFile))
        }
        RepositoryFormat::Debian => {
            crate::api::handlers::debian::package_coordinates_from_path(artifact_path)
                .map(|c| target(c, FinalizeInput::LocalFile))
        }
        RepositoryFormat::Maven | RepositoryFormat::Gradle => {
            // Checksum sidecars and `maven-metadata.xml` are row-less objects
            // on the native route; a chunked upload of one keeps its generic
            // row rather than being indexed as a version.
            if crate::api::handlers::maven::is_rowless_maven_path(artifact_path) {
                return None;
            }
            let coords = MavenHandler::parse_coordinates(artifact_path).ok()?;
            let input = if MavenHandler::is_pom(artifact_path) {
                FinalizeInput::Stream
            } else {
                FinalizeInput::PathOnly
            };
            Some(target((coords.artifact_id, coords.version), input))
        }
        RepositoryFormat::Npm => {
            // `{package}/{version}/{file}.tgz`, the layout the native publish
            // writes and the tarball route resolves. The registry URL layout
            // `{package}/-/{file}.tgz` names no version in the path; such an
            // upload keeps the generic behaviour, as before.
            if !artifact_path.ends_with(".tgz") {
                return None;
            }
            let package =
                crate::api::handlers::npm::npm_package_name_from_artifact_path(artifact_path)?;
            let version = super::version_from_artifact_path(artifact_path)
                .filter(|version| *version != "-")?;
            Some(target(
                (package.to_string(), version.to_string()),
                FinalizeInput::Stream,
            ))
        }
        RepositoryFormat::Pypi => {
            let filename = basename(artifact_path);
            let info = crate::formats::pypi::PypiHandler::parse_filename(filename).ok()?;
            let name = crate::formats::pypi_name::NormalizedProjectName::parse(&info.name?)?;
            let version = info.version.filter(|v| !v.is_empty())?;
            // A wheel is a zip archive (the parser seeks), so it needs a file.
            Some(target(
                (name.as_str().to_string(), version),
                FinalizeInput::LocalFile,
            ))
        }
        RepositoryFormat::Rpm => {
            let filename = basename(artifact_path);
            let (name, version, release, _arch) =
                crate::api::handlers::rpm::parse_rpm_filename(filename)?;
            Some(target(
                (
                    name,
                    crate::api::handlers::rpm::build_rpm_full_version(&version, &release),
                ),
                // The header parse reads the file's leading bytes by offset.
                FinalizeInput::LocalFile,
            ))
        }
        _ => None,
    }
}

/// The content type the format's native route stores for `artifact_path`.
pub(crate) fn native_content_type(
    format: &RepositoryFormat,
    artifact_path: &str,
) -> Option<&'static str> {
    match format {
        RepositoryFormat::Maven | RepositoryFormat::Gradle => Some(
            crate::api::handlers::maven::content_type_for_path(artifact_path),
        ),
        RepositoryFormat::Npm => Some("application/gzip"),
        RepositoryFormat::Pypi => Some(crate::api::handlers::pypi::pypi_content_type(basename(
            artifact_path,
        ))),
        RepositoryFormat::Rpm => Some("application/x-rpm"),
        _ => None,
    }
}

/// A blocking [`std::io::Read`] over an async byte stream, for the archive
/// parsers that run on the blocking pool. A pump task forwards the stream
/// through a small bounded channel, so at most a few chunks are in memory;
/// when the reader is dropped early (the parser found what it needed) the
/// pump stops at its next send. Never read it from an async worker.
struct BlockingStreamReader {
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>,
    current: Bytes,
}

impl BlockingStreamReader {
    /// Start the pump. Call from async context; read from a blocking thread.
    fn spawn(mut stream: BoxStream<'static, crate::error::Result<Bytes>>) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
        tokio::spawn(async move {
            while let Some(chunk) = stream.next().await {
                let item = chunk.map_err(|e| std::io::Error::other(e.to_string()));
                let stop = item.is_err();
                if tx.send(item).await.is_err() || stop {
                    break;
                }
            }
        });
        Self {
            rx,
            current: Bytes::new(),
        }
    }
}

impl std::io::Read for BlockingStreamReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.current.is_empty() {
            match self.rx.blocking_recv() {
                Some(Ok(chunk)) => self.current = chunk,
                Some(Err(e)) => return Err(e),
                // The pump finished: end of stream.
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.current.len());
        buf[..n].copy_from_slice(&self.current[..n]);
        let _ = self.current.split_to(n);
        Ok(n)
    }
}

/// Open `source` as a byte stream (a local file is streamed from disk).
async fn source_stream(
    source: FinalizeSource<'_>,
) -> Result<BoxStream<'static, crate::error::Result<Bytes>>, String> {
    match source {
        FinalizeSource::Stream(stream) => Ok(stream),
        FinalizeSource::File(path) => {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|e| format!("could not read the assembled upload: {e}"))?;
            Ok(tokio_util::io::ReaderStream::new(file)
                .map(|chunk| chunk.map_err(crate::error::AppError::from))
                .boxed())
        }
        FinalizeSource::None => Ok(futures::stream::empty().boxed()),
    }
}

/// Run the native finalize's read of the uploaded bytes. Called only for a
/// path [`native_target`] accepted. `Err` is a client-facing reason the upload
/// is refused (400), with nothing stored.
pub(crate) async fn stage(
    format: &RepositoryFormat,
    artifact_path: &str,
    target: &NativeTarget,
    source: FinalizeSource<'_>,
) -> Result<StagedNativeFinalize, String> {
    match format {
        RepositoryFormat::Incus | RepositoryFormat::Lxc => {
            let FinalizeSource::File(file) = source else {
                return Err("an Incus image finalize needs the assembled file".to_string());
            };
            let (path, file) = (artifact_path.to_string(), file.to_path_buf());
            let metadata = tokio::task::spawn_blocking(move || {
                crate::api::handlers::incus::extract_image_metadata(&path, &file)
            })
            .await
            .unwrap_or_else(|_| serde_json::json!({"file_type": "unknown"}));
            Ok(StagedNativeFinalize::Incus(metadata))
        }
        RepositoryFormat::Debian => {
            let FinalizeSource::File(file) = source else {
                return Err("a Debian package finalize needs the assembled file".to_string());
            };
            // `native_target` accepted the path through the same
            // `staged_package_target` check, so `Ok(None)` (not a pool
            // package) is unreachable.
            crate::api::handlers::debian::finalize_from_staged(artifact_path, file)
                .await?
                .map(|staged| StagedNativeFinalize::Debian(Box::new(staged)))
                .ok_or_else(|| "not a Debian pool package".to_string())
        }
        RepositoryFormat::Maven | RepositoryFormat::Gradle => stage_maven(artifact_path, source)
            .await
            .map(|staged| StagedNativeFinalize::Maven(Box::new(staged))),
        RepositoryFormat::Npm => stage_npm(target, source)
            .await
            .map(|staged| StagedNativeFinalize::Npm(Box::new(staged))),
        RepositoryFormat::Pypi => {
            let FinalizeSource::File(file) = source else {
                return Err("a PyPI distribution finalize needs the assembled file".to_string());
            };
            stage_pypi(artifact_path, target, file)
                .await
                .map(|staged| StagedNativeFinalize::Pypi(Box::new(staged)))
        }
        RepositoryFormat::Rpm => {
            let FinalizeSource::File(file) = source else {
                return Err("an RPM finalize needs the assembled file".to_string());
            };
            let prefix = super::read_rpm_header_prefix(file)
                .await
                .map_err(|e| format!("could not read the RPM header: {e}"))?;
            let scripts = tokio::task::spawn_blocking(move || {
                crate::api::handlers::rpm::extract_rpm_scriptlets(&prefix)
            })
            .await
            .map_err(|e| format!("RPM header parse failed: {e}"))?;
            Ok(StagedNativeFinalize::Rpm(Box::new(StagedRpm { scripts })))
        }
        _ => Err("this repository format has no native finalize".to_string()),
    }
}

/// The native Maven route's metadata for one file: the POM's fields for a
/// `.pom`, otherwise the coordinates alone, with the coordinate fields always
/// taken from the path (`maven.rs` `upload`).
async fn stage_maven(
    artifact_path: &str,
    source: FinalizeSource<'_>,
) -> Result<StagedMaven, String> {
    use crate::formats::maven::MavenHandler;
    let coords = MavenHandler::parse_coordinates(artifact_path)
        .map_err(|e| format!("Invalid Maven path: {e}"))?;
    let is_pom = MavenHandler::is_pom(artifact_path);
    let pom_bytes = if is_pom {
        let mut stream = source_stream(source).await?;
        let mut pom = Vec::new();
        let mut oversized = false;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("could not read the uploaded POM: {e}"))?;
            if pom.len() + chunk.len() > MAX_POM_BYTES {
                oversized = true;
                break;
            }
            pom.extend_from_slice(&chunk);
        }
        if oversized {
            Bytes::new()
        } else {
            Bytes::from(pom)
        }
    } else {
        Bytes::new()
    };
    let handler = MavenHandler::new();
    let mut metadata =
        crate::formats::FormatHandler::parse_metadata(&handler, artifact_path, &pom_bytes)
            .await
            .unwrap_or_else(|_| {
                serde_json::json!({
                    "groupId": coords.group_id,
                    "artifactId": coords.artifact_id,
                    "version": coords.version,
                    "extension": coords.extension,
                })
            });
    let package_name = crate::api::handlers::maven::maven_package_name(&coords);
    let (package_description, package_metadata) = if is_pom {
        (
            crate::api::handlers::maven::maven_package_description(&metadata),
            Some(
                crate::api::handlers::maven::build_maven_package_catalog_metadata(
                    &coords, &metadata,
                ),
            ),
        )
    } else {
        (None, None)
    };
    metadata["groupId"] = serde_json::Value::String(coords.group_id.clone());
    metadata["artifactId"] = serde_json::Value::String(coords.artifact_id.clone());
    metadata["version"] = serde_json::Value::String(coords.version.clone());
    metadata["extension"] = serde_json::Value::String(coords.extension.clone());
    if let Some(classifier) = &coords.classifier {
        metadata["classifier"] = serde_json::Value::String(classifier.clone());
    }
    Ok(StagedMaven {
        coords,
        metadata,
        package_name,
        package_description,
        package_metadata,
    })
}

/// The npm tarball's `package.json`, which must name the package and version
/// the path does (the native publish binds the tarball to the packument entry
/// it is attached to the same way).
async fn stage_npm(target: &NativeTarget, source: FinalizeSource<'_>) -> Result<StagedNpm, String> {
    let reader = BlockingStreamReader::spawn(source_stream(source).await?);
    let package_json = crate::util::bounded_archive::with_ingest_extraction_async(|| {
        tokio::task::spawn_blocking(move || {
            crate::util::bounded_archive::read_metadata_from_tar_gz(reader, is_root_package_json)
        })
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("npm tarball could not be read: {e}"))?
    .map_err(|e| format!("npm tarball could not be read: {e}"))?
    .ok_or_else(|| "npm tarball has no package.json".to_string())?;
    let version_data: serde_json::Value = serde_json::from_slice(&package_json)
        .map_err(|e| format!("npm tarball package.json is not valid JSON: {e}"))?;
    let declared_name = version_data
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim);
    let declared_version = version_data.get("version").and_then(|v| v.as_str());
    // npm names are lowercase by construction; a legacy mixed-case name is
    // compared case-insensitively, as the tarball identity check of the npm
    // proxy does (#3003).
    if !declared_name.is_some_and(|name| name.eq_ignore_ascii_case(&target.name)) {
        return Err(format!(
            "npm tarball package.json names package {:?}, but the upload path names {:?}",
            declared_name.unwrap_or(""),
            target.name
        ));
    }
    if declared_version.map(clean_npm_version) != Some(clean_npm_version(&target.version)) {
        return Err(format!(
            "npm tarball package.json declares version {:?}, but the upload path names {:?}",
            declared_version.unwrap_or(""),
            target.version
        ));
    }
    // The version document carries the identity npm publishes it under (the
    // path's), not a `v`-prefixed or mixed-case spelling from the file.
    let mut version_data = version_data;
    if let Some(doc) = version_data.as_object_mut() {
        doc.insert("name".to_string(), target.name.clone().into());
        doc.insert("version".to_string(), target.version.clone().into());
    }
    Ok(StagedNpm {
        package_name: target.name.clone(),
        version: target.version.clone(),
        version_data,
    })
}

/// The tarball's root `package.json`: `package/package.json` as `npm pack`
/// writes it, or the same file under another top-level directory. A nested
/// one (a bundled dependency's, or a `dist/cjs/package.json` type marker)
/// does not describe the package.
fn is_root_package_json(path: &std::path::Path) -> bool {
    let mut components = path
        .components()
        .filter(|component| !matches!(component, std::path::Component::CurDir));
    matches!(
        (components.next(), components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), Some(std::path::Component::Normal(file)), None)
            if file == "package.json"
    )
}

/// A version as npm normalizes it when it publishes (`semver.clean`):
/// surrounding whitespace, a leading `=` or `v`, and build metadata dropped.
/// The tarball keeps the `package.json` as written, the path carries the
/// published version.
fn clean_npm_version(version: &str) -> &str {
    let version = version
        .trim()
        .trim_start_matches(['=', 'v', 'V'])
        .trim_start();
    version.split('+').next().unwrap_or(version)
}

/// The PyPI identity gate and content analysis the native upload runs: the
/// wheel's `METADATA` (or the sdist's `PKG-INFO`) must name the project and
/// version the file name does.
async fn stage_pypi(
    artifact_path: &str,
    target: &NativeTarget,
    file: &std::path::Path,
) -> Result<StagedPypi, String> {
    use crate::formats::pypi::PypiHandler;
    let filename = basename(artifact_path).to_string();
    let pkg_info = {
        let file = file.to_path_buf();
        let (name, version, filename) = (
            target.name.clone(),
            target.version.clone(),
            filename.clone(),
        );
        crate::util::bounded_archive::with_ingest_extraction_async(|| {
            tokio::task::spawn_blocking(move || {
                let file = std::fs::File::open(&file).map_err(|e| {
                    crate::error::AppError::Internal(format!("re-open assembled upload: {e}"))
                })?;
                PypiHandler::validate_upload_file(&name, &version, &filename, file)
            })
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("upload validation task failed: {e}"))?
        .map_err(|e| e.to_string())?
    };
    let raw_name = pkg_info
        .as_ref()
        .map(|info| info.name.clone())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| target.name.clone());
    let summary = pkg_info.as_ref().and_then(|info| info.summary.clone());
    let requires_python = pkg_info
        .as_ref()
        .and_then(|info| info.requires_python.clone());
    let analysis =
        crate::api::handlers::pypi::analyze_pypi_upload(file.to_path_buf(), filename.clone()).await;
    let mut metadata = serde_json::json!({
        "name": raw_name,
        "normalized_name": target.name,
        "version": target.version,
        "filename": filename,
    });
    if let Some(pkg_info) = crate::api::handlers::pypi::build_upload_pkg_info(
        pkg_info,
        None,
        None,
        &serde_json::Map::new(),
    ) {
        metadata["pkg_info"] = pkg_info;
    }
    let catalog = crate::api::handlers::pypi::build_pypi_package_catalog_metadata(
        &filename,
        requires_python.as_deref(),
    );
    Ok(StagedPypi {
        metadata,
        summary,
        catalog,
        analysis,
    })
}

/// Record a natively finalized chunked upload's non-metadata format records
/// against its committed artifact row: catalog entries, script analysis and
/// cache invalidation. The `artifact_metadata` document itself is written by
/// the completion inside the artifact-row transaction (#5002).
/// `rpm_metadata` is the header metadata the completion's RPM parse produced
/// (RPM only).
pub(crate) async fn record(
    state: &SharedState,
    session: &UploadSession,
    artifact_id: Uuid,
    target: &NativeTarget,
    staged: StagedNativeFinalize,
    rpm_metadata: Option<&serde_json::Value>,
) -> Result<(), String> {
    let catalog = PackageService::new(state.db.clone());
    match staged {
        StagedNativeFinalize::Incus(_) => {
            catalog
                .try_create_or_update_from_artifact(
                    session.repository_id,
                    &target.name,
                    &target.version,
                    session.total_size,
                    &session.checksum_sha256,
                    None,
                    Some(serde_json::json!({ "format": "incus" })),
                )
                .await;
            Ok(())
        }
        StagedNativeFinalize::Debian(package) => {
            let (upload, deb_head) = package.parts();
            crate::api::handlers::debian::record_debian_package_extras(
                &state.db,
                session.repository_id,
                artifact_id,
                session.total_size,
                &session.checksum_sha256,
                upload,
                deb_head,
            )
            .await;
            Ok(())
        }
        StagedNativeFinalize::Maven(maven) => {
            let StagedMaven {
                coords,
                metadata: _,
                package_name,
                package_description,
                package_metadata,
            } = *maven;
            catalog
                .try_create_or_update_from_artifact(
                    session.repository_id,
                    &package_name,
                    &coords.version,
                    session.total_size,
                    &session.checksum_sha256,
                    package_description.as_deref(),
                    package_metadata,
                )
                .await;
            // #4633: a version's size is the total of its files.
            if let Some(directory) =
                crate::api::handlers::maven::maven_version_directory(&session.artifact_path)
            {
                catalog
                    .try_set_version_size_to_directory_total(
                        session.repository_id,
                        &package_name,
                        &coords.version,
                        directory,
                    )
                    .await;
            }
            crate::api::handlers::maven::invalidate_maven_metadata_cache(
                session.repository_id,
                &coords.group_id,
                &coords.artifact_id,
            )
            .await;
            crate::api::handlers::maven::invalidate_maven_prefixes_cache(session.repository_id)
                .await;
            Ok(())
        }
        StagedNativeFinalize::Npm(npm) => {
            let StagedNpm {
                package_name,
                version,
                version_data,
            } = *npm;
            crate::api::handlers::npm::record_npm_install_script_analysis(
                state,
                artifact_id,
                &version_data,
            )
            .await;
            let description = version_data
                .get("description")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            catalog
                .try_create_or_update_from_artifact(
                    session.repository_id,
                    &package_name,
                    &version,
                    session.total_size,
                    &session.checksum_sha256,
                    description.as_deref(),
                    Some(serde_json::json!({ "format": "npm" })),
                )
                .await;
            crate::api::handlers::npm::invalidate_packument_caches(
                state,
                session.repository_id,
                &session.repository_key,
                &package_name,
            )
            .await;
            Ok(())
        }
        StagedNativeFinalize::Pypi(pypi) => {
            let StagedPypi {
                metadata: _,
                summary,
                catalog: catalog_metadata,
                analysis,
            } = *pypi;
            crate::api::handlers::pypi::record_pypi_package_analysis(state, artifact_id, analysis)
                .await;
            catalog
                .try_create_or_update_from_artifact(
                    session.repository_id,
                    &target.name,
                    &target.version,
                    session.total_size,
                    &session.checksum_sha256,
                    summary.as_deref(),
                    Some(catalog_metadata),
                )
                .await;
            Ok(())
        }
        StagedNativeFinalize::Rpm(rpm) => {
            let StagedRpm {
                scripts: (scripts, unanalyzed, completeness),
            } = *rpm;
            // The header document (or the filename-derived fallback) is
            // written in the artifact transaction by the completion; only the
            // scriptlet analysis and catalog entry remain here.
            if let Err(e) = crate::services::package_analysis_service::record_install_scripts(
                &state.db,
                artifact_id,
                "rpm",
                scripts,
                unanalyzed,
                completeness,
            )
            .await
            {
                tracing::warn!(artifact_id = %artifact_id, error = %e, "rpm scriptlet analysis could not be recorded");
            }
            let description = rpm_metadata
                .and_then(|metadata| metadata.get("summary"))
                .and_then(|v| v.as_str())
                .filter(|d| !d.is_empty());
            catalog
                .try_create_or_update_from_artifact(
                    session.repository_id,
                    &target.name,
                    &target.version,
                    session.total_size,
                    &session.checksum_sha256,
                    description,
                    Some(serde_json::json!({ "format": "rpm" })),
                )
                .await;
            Ok(())
        }
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;

    fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = tar::Builder::new(&mut gz);
            for (path, body) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        gz.flush().unwrap();
        gz.finish().unwrap()
    }

    /// #5002: a format without a native finalize still dispatches its handler
    /// on chunked completion, deriving the document from the upload path. The
    /// native formats keep their own parsers (and their path-declined cases
    /// stay generic).
    #[tokio::test]
    async fn generic_metadata_document_dispatches_non_native_formats() {
        let document = generic_metadata_document(
            &RepositoryFormat::Terraform,
            "hashicorp/aws/5.0.0/download/linux/amd64",
        )
        .await
        .expect("Terraform provider path must dispatch");
        assert_eq!(document.format, "terraform");
        assert_eq!(document.metadata["namespace"], "hashicorp");
        assert_eq!(document.metadata["name"], "aws");
        assert_eq!(document.metadata["version"], "5.0.0");
        assert_eq!(document.metadata["os"], "linux");
        assert_eq!(document.metadata["arch"], "amd64");

        // A format with a native finalize never takes the generic path, even
        // when its own parser declines this particular path.
        assert!(has_native_finalize(&RepositoryFormat::Maven));
        assert!(generic_metadata_document(
            &RepositoryFormat::Maven,
            "com/example/1.0/a.jar.sha256"
        )
        .await
        .is_none());
        // The generic handler's document is just the path, so it adds nothing.
        assert!(
            generic_metadata_document(&RepositoryFormat::Generic, "a/b.bin")
                .await
                .is_none()
        );
    }

    fn npm_tgz(name: &str, version: &str) -> Vec<u8> {
        let package_json = serde_json::json!({
            "name": name,
            "version": version,
            "description": "chunked npm package",
            "dependencies": { "left-pad": "^1.3.0" },
        })
        .to_string();
        tgz(&[
            ("package/package.json", package_json.as_bytes()),
            ("package/index.js", b"module.exports = 1;\n"),
        ])
    }

    fn wheel(name: &str, version: &str) -> Vec<u8> {
        use std::io::Write;
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, '_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file(format!("{name}-{version}.dist-info/METADATA"), options)
                .unwrap();
            write!(
                zip,
                "Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\
                 Summary: chunked wheel\nRequires-Python: >=3.9\n"
            )
            .unwrap();
            zip.finish().unwrap();
        }
        cursor.into_inner()
    }

    async fn body_text(router: axum::Router, uri: String) -> (StatusCode, String) {
        let (status, body) = tdh::send(router, tdh::get(uri)).await;
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn row(f: &tdh::Fixture, path: &str) -> (Uuid, String, Option<String>, String) {
        sqlx::query_as(
            "SELECT id, name, version, content_type FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(f.repo_id)
        .bind(path)
        .fetch_one(&f.pool)
        .await
        .expect("chunked artifact row")
    }

    async fn catalog_version(f: &tdh::Fixture, name: &str) -> Option<String> {
        sqlx::query_scalar(
            "SELECT pv.version FROM packages p JOIN package_versions pv ON pv.package_id = p.id \
             WHERE p.repository_id = $1 AND p.name = $2",
        )
        .bind(f.repo_id)
        .bind(name)
        .fetch_optional(&f.pool)
        .await
        .expect("catalog lookup")
    }

    /// #1846: a Maven jar and its POM pushed through the chunked flow are
    /// indexed as the native PUT indexes them: `maven-metadata.xml` lists the
    /// version, the row is named after the artifactId and the catalog entry
    /// is `groupId:artifactId` with the POM's description. Before the fix the
    /// rows had no `maven` metadata document, so the generated
    /// `maven-metadata.xml` did not exist (404).
    #[tokio::test]
    async fn chunked_maven_jar_and_pom_appear_in_maven_metadata_1846() {
        let Some(f) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let pom = br#"<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme.chunked</groupId>
  <artifactId>demo</artifactId>
  <version>1.4.2</version>
  <description>chunked maven artifact</description>
</project>
"#;
        let base = "com/acme/chunked/demo/1.4.2";
        for (file, bytes) in [
            ("demo-1.4.2.jar", b"PK\x03\x04 chunked jar body".to_vec()),
            ("demo-1.4.2.pom", pom.to_vec()),
        ] {
            let path = format!("{base}/{file}");
            let (status, body) = f
                .chunked_upload(&path, &bytes, serde_json::json!({}), false)
                .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{path}: {}",
                String::from_utf8_lossy(&body)
            );
        }

        let (status, xml) = body_text(
            f.router_with_auth(crate::api::handlers::maven::router()),
            format!("/{}/com/acme/chunked/demo/maven-metadata.xml", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "maven-metadata.xml: {xml}");
        assert!(xml.contains("<version>1.4.2</version>"), "{xml}");
        assert!(xml.contains("<artifactId>demo</artifactId>"), "{xml}");

        let (_, name, version, content_type) = row(&f, &format!("{base}/demo-1.4.2.jar")).await;
        assert_eq!(name, "demo");
        assert_eq!(version.as_deref(), Some("1.4.2"));
        assert_eq!(content_type, "application/java-archive");
        let (pom_id, ..) = row(&f, &format!("{base}/demo-1.4.2.pom")).await;
        let metadata: serde_json::Value = sqlx::query_scalar(
            "SELECT metadata FROM artifact_metadata WHERE artifact_id = $1 AND format = 'maven'",
        )
        .bind(pom_id)
        .fetch_one(&f.pool)
        .await
        .expect("maven metadata document for the POM");
        assert_eq!(metadata["groupId"], "com.acme.chunked");
        assert_eq!(metadata["description"], "chunked maven artifact");
        assert_eq!(
            catalog_version(&f, "com.acme.chunked:demo")
                .await
                .as_deref(),
            Some("1.4.2")
        );
        f.teardown().await;
    }

    /// #1846: an npm tarball pushed through the chunked flow appears in the
    /// packument with its `package.json` as the version document (so its
    /// dependencies reach `npm install`). Before the fix the row was named
    /// after the file, so the packument did not list it (404).
    #[tokio::test]
    async fn chunked_npm_tarball_appears_in_packument_1846() {
        let Some(f) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let path = "chunked-pkg/2.0.0/chunked-pkg-2.0.0.tgz";
        let (status, body) = f
            .chunked_upload(
                path,
                &npm_tgz("chunked-pkg", "2.0.0"),
                serde_json::json!({}),
                false,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        let (status, packument) = body_text(
            f.router_with_auth(crate::api::handlers::npm::router()),
            format!("/{}/chunked-pkg", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "packument: {packument}");
        let doc: serde_json::Value = serde_json::from_str(&packument).expect("packument json");
        let version = &doc["versions"]["2.0.0"];
        assert_eq!(version["dependencies"]["left-pad"], "^1.3.0", "{packument}");
        assert!(
            version["dist"]["tarball"]
                .as_str()
                .is_some_and(|t| t.ends_with("/chunked-pkg/-/chunked-pkg-2.0.0.tgz")),
            "{packument}"
        );
        assert_eq!(doc["dist-tags"]["latest"], "2.0.0");
        let (_, name, _, content_type) = row(&f, path).await;
        assert_eq!(name, "chunked-pkg");
        assert_eq!(content_type, "application/gzip");
        assert_eq!(
            catalog_version(&f, "chunked-pkg").await.as_deref(),
            Some("2.0.0")
        );
        f.teardown().await;
    }

    /// #1846: a tarball whose `package.json` names another package than its
    /// path is refused, as the native publish binds the two, and nothing is
    /// stored.
    #[tokio::test]
    async fn chunked_npm_tarball_naming_another_package_is_refused_1846() {
        let Some(f) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let path = "chunked-pkg/2.0.0/chunked-pkg-2.0.0.tgz";
        let (status, body) = f
            .chunked_upload(
                path,
                &npm_tgz("other-pkg", "2.0.0"),
                serde_json::json!({}),
                false,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(f.repo_id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(rows, 0);
        f.teardown().await;
    }

    /// #1846: a wheel pushed through the chunked flow appears in its
    /// project's simple index with `data-requires-python`, as a twine upload
    /// makes it appear. Before the fix the row was named after the file, so
    /// `/simple/<project>/` did not list it.
    #[tokio::test]
    async fn chunked_pypi_wheel_appears_in_simple_index_1846() {
        let Some(f) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };
        let file = "chunked_dist-0.3.1-py3-none-any.whl";
        let path = format!("chunked-dist/0.3.1/{file}");
        let (status, body) = f
            .chunked_upload(
                &path,
                &wheel("chunked_dist", "0.3.1"),
                serde_json::json!({}),
                false,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        let (status, html) = body_text(
            f.router_with_auth(crate::api::handlers::pypi::router()),
            format!("/{}/simple/chunked-dist/", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "simple index: {html}");
        assert!(html.contains(file), "{html}");
        assert!(html.contains("data-requires-python=\"&gt;=3.9\""), "{html}");
        let (_, name, version, _) = row(&f, &path).await;
        assert_eq!(name, "chunked-dist");
        assert_eq!(version.as_deref(), Some("0.3.1"));
        assert_eq!(
            catalog_version(&f, "chunked-dist").await.as_deref(),
            Some("0.3.1")
        );
        f.teardown().await;
    }

    /// #1846: a wheel whose `METADATA` names another project than its file
    /// name is refused (the native upload's identity gate), and nothing is
    /// stored.
    #[tokio::test]
    async fn chunked_pypi_wheel_with_mismatched_metadata_is_refused_1846() {
        let Some(f) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };
        let path = "chunked-dist/0.3.1/chunked_dist-0.3.1-py3-none-any.whl";
        let (status, body) = f
            .chunked_upload(
                path,
                &wheel("someone_else", "0.3.1"),
                serde_json::json!({}),
                false,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(f.repo_id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(rows, 0);
        f.teardown().await;
    }

    /// #1846: an RPM pushed through the chunked flow is named and versioned
    /// by its NEVRA, listed in `primary.xml` and registered in the catalog as
    /// the native PUT registers it. Before the fix the row was named after
    /// the file and no catalog entry was written.
    #[tokio::test]
    async fn chunked_rpm_is_indexed_like_a_native_put_1846() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let rpm = crate::api::handlers::proxy_scan_archive::test_support::minimal_rpm(
            "chunked-tool",
            None,
            "3.1",
            "2",
            "x86_64",
            &[],
        );
        let path = "packages/chunked-tool-3.1-2.x86_64.rpm";
        let (status, body) = f
            .chunked_upload(path, &rpm, serde_json::json!({}), false)
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

        let (status, gz) = tdh::send(
            f.router_with_auth(crate::api::handlers::rpm::router()),
            tdh::get(format!("/{}/repodata/primary.xml.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let mut primary = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut primary)
            .expect("primary.xml.gz");
        assert!(primary.contains("<name>chunked-tool</name>"), "{primary}");
        assert!(primary.contains(r#"ver="3.1" rel="2""#), "{primary}");

        let (_, name, version, content_type) = row(&f, path).await;
        assert_eq!(name, "chunked-tool");
        assert_eq!(version.as_deref(), Some("3.1-2"));
        assert_eq!(content_type, "application/x-rpm");
        assert_eq!(
            catalog_version(&f, "chunked-tool").await.as_deref(),
            Some("3.1-2")
        );
        f.teardown().await;
    }

    /// #1846: `Prefer: respond-async` answers the completion with 202 and the
    /// session as the poll location; polling it reports `completed` with the
    /// committed artifact, which the format index then lists. Before the
    /// change the completion always answered 200 in the request.
    #[tokio::test]
    async fn respond_async_completion_answers_202_and_polls_to_completed_1846() {
        use axum::body::Body;
        use axum::http::Request;
        use sha2::{Digest, Sha256};
        let Some(f) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let payload = npm_tgz("async-pkg", "1.0.0");
        let path = "async-pkg/1.0.0/async-pkg-1.0.0.tgz";
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = || {
            crate::api::handlers::upload::router()
                .with_state(f.state.clone())
                .layer(axum::Extension::<crate::api::middleware::auth::AuthExtension>(auth.clone()))
        };
        let create = serde_json::json!({
            "repository_key": f.repo_key,
            "artifact_path": path,
            "total_size": payload.len() as i64,
            "checksum_sha256": hex::encode(Sha256::digest(&payload)),
        });
        let (status, resp) = tdh::send(
            app(),
            tdh::post(
                "/".to_string(),
                "application/json",
                Bytes::from(serde_json::to_vec(&create).unwrap()),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&resp)
        );
        let session: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        let session_id = session["session_id"].as_str().unwrap().to_string();
        let chunk = Request::builder()
            .method("PATCH")
            .uri(format!("/{session_id}"))
            .header(
                "content-range",
                format!("bytes 0-{}/{}", payload.len() - 1, payload.len()),
            )
            .body(Body::from(payload.clone()))
            .unwrap();
        let (status, _) = tdh::send(app(), chunk).await;
        assert_eq!(status, StatusCode::OK);

        let complete = Request::builder()
            .method("PUT")
            .uri(format!("/{session_id}/complete"))
            .header("prefer", "wait=5, respond-async")
            .body(Body::empty())
            .unwrap();
        let response = tower::ServiceExt::oneshot(app(), complete).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok()),
            Some(format!("/api/v1/uploads/{session_id}").as_str())
        );
        assert_eq!(
            response
                .headers()
                .get("preference-applied")
                .and_then(|v| v.to_str().ok()),
            Some("respond-async")
        );

        let mut polled = serde_json::Value::Null;
        for _ in 0..100 {
            let (status, body) = tdh::send(app(), tdh::get(format!("/{session_id}"))).await;
            assert_eq!(status, StatusCode::OK);
            polled = serde_json::from_slice(&body).unwrap();
            if polled["status"] != "committing" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(polled["status"], "completed", "{polled}");
        let (artifact_id, ..) = row(&f, path).await;
        assert_eq!(polled["artifact_id"], artifact_id.to_string());

        let (status, packument) = body_text(
            f.router_with_auth(crate::api::handlers::npm::router()),
            format!("/{}/async-pkg", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{packument}");
        assert!(packument.contains("\"1.0.0\""), "{packument}");
        f.teardown().await;
    }

    #[test]
    fn prefer_header_parsing_1846() {
        let headers = |v: &str| {
            let mut h = axum::http::HeaderMap::new();
            h.insert("prefer", axum::http::HeaderValue::from_str(v).unwrap());
            h
        };
        assert!(super::super::prefers_respond_async(&headers(
            "respond-async"
        )));
        assert!(super::super::prefers_respond_async(&headers(
            "wait=10, Respond-Async"
        )));
        assert!(super::super::prefers_respond_async(&headers(
            "respond-async; x=1"
        )));
        assert!(!super::super::prefers_respond_async(&headers(
            "return=minimal"
        )));
        assert!(!super::super::prefers_respond_async(
            &axum::http::HeaderMap::new()
        ));
    }

    /// A blocking reader over a byte stream yields exactly the stream's
    /// bytes, across chunk boundaries.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_stream_reader_yields_the_stream_bytes() {
        let chunks: Vec<crate::error::Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"hello ")),
            Ok(Bytes::new()),
            Ok(Bytes::from_static(b"chunked world")),
        ];
        let reader = BlockingStreamReader::spawn(futures::stream::iter(chunks).boxed());
        let read = tokio::task::spawn_blocking(move || {
            let mut reader = reader;
            let mut out = String::new();
            std::io::Read::read_to_string(&mut reader, &mut out).map(|_| out)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(read, "hello chunked world");
    }

    /// A fixture whose repository sits on the in-memory "cloud" backend
    /// (native streaming), so the completion assembles on the backend and the
    /// stream parsers read the staged chunks.
    async fn cloud_fixture(
        format: &str,
    ) -> Option<(tdh::Fixture, std::sync::Arc<tdh::MemStorage>)> {
        let pool = tdh::try_pool().await?;
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "local", format).await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        sqlx::query(
            "UPDATE repositories SET storage_backend = 's3', storage_path = '' WHERE id = $1",
        )
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("cloud backend");
        let (state, mem) = tdh::build_state_with_cloud(pool.clone(), "s3");
        Some((
            tdh::Fixture {
                pool,
                user_id,
                username,
                repo_id,
                repo_key,
                storage_dir,
                state,
            },
            mem,
        ))
    }

    /// #1846 on a native-streaming backend: the POM and the npm tarball are
    /// parsed from the staged chunks (no local assembly), the artifacts are
    /// indexed, and a refused tarball leaves neither its content-addressed
    /// object nor its assembled staging object behind.
    #[tokio::test]
    async fn stream_parsers_read_the_staged_chunks_on_object_storage_1846() {
        let Some((f, mem)) = cloud_fixture("npm").await else {
            return;
        };
        let path = "cloud-pkg/1.0.0/cloud-pkg-1.0.0.tgz";
        let (status, body) = f
            .chunked_upload(
                path,
                &npm_tgz("cloud-pkg", "1.0.0"),
                serde_json::json!({}),
                false,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let (status, packument) = body_text(
            f.router_with_auth(crate::api::handlers::npm::router()),
            format!("/{}/cloud-pkg", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "packument: {packument}");
        assert!(packument.contains("\"1.0.0\""), "{packument}");

        let refused_path = "cloud-pkg/2.0.0/cloud-pkg-2.0.0.tgz";
        let refused = npm_tgz("someone-else", "2.0.0");
        let (status, body) = f
            .chunked_upload(refused_path, &refused, serde_json::json!({}), false)
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let session_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM upload_sessions WHERE repository_id = $1 AND artifact_path = $2",
        )
        .bind(f.repo_id)
        .bind(refused_path)
        .fetch_one(&f.pool)
        .await
        .expect("refused session");
        let cas_key =
            crate::services::artifact_service::ArtifactService::storage_key_from_checksum(&{
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&refused))
            });
        {
            let objects = mem.objects.lock().unwrap();
            assert!(
                !objects.contains_key(&cas_key),
                "a refused package stores nothing"
            );
            assert!(
                !objects.contains_key(&crate::services::upload_service::staged_assembly_key(
                    session_id
                )),
                "the assembled staging object is deleted"
            );
        }
        f.teardown().await;

        let Some((f, _mem)) = cloud_fixture("maven").await else {
            return;
        };
        let pom = br#"<project><modelVersion>4.0.0</modelVersion><groupId>com.acme.cloud</groupId><artifactId>lib</artifactId><version>0.9</version><description>parsed from the staged chunks</description></project>"#;
        let pom_path = "com/acme/cloud/lib/0.9/lib-0.9.pom";
        let (status, body) = f
            .chunked_upload(pom_path, pom, serde_json::json!({}), false)
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let (pom_id, name, ..) = row(&f, pom_path).await;
        assert_eq!(name, "lib");
        let description: Option<String> = sqlx::query_scalar(
            "SELECT metadata->>'description' FROM artifact_metadata \
             WHERE artifact_id = $1 AND format = 'maven'",
        )
        .bind(pom_id)
        .fetch_one(&f.pool)
        .await
        .expect("maven metadata");
        assert_eq!(
            description.as_deref(),
            Some("parsed from the staged chunks")
        );
        f.teardown().await;
    }

    /// #1846: an artifact the chunked flow committed into a format repository
    /// before this change (a generic row named after its file, with no format
    /// metadata, under the content-addressed key) stays downloadable through
    /// the format's own route.
    #[tokio::test]
    async fn rows_committed_before_the_dispatch_stay_downloadable_1846() {
        let Some(f) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let bytes = format!("pre-1846 chunked jar {}", Uuid::new_v4()).into_bytes();
        let sha = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&bytes))
        };
        let key =
            crate::services::artifact_service::ArtifactService::storage_key_from_checksum(&sha);
        let storage = f
            .state
            .storage_for_repo(&crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: f.storage_dir.to_string_lossy().into_owned(),
            })
            .unwrap();
        storage.put(&key, Bytes::from(bytes.clone())).await.unwrap();
        let path = "com/acme/old/old/1.0/old-1.0.jar";
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'old-1.0.jar', '1.0', $3, $4, 'application/octet-stream', $5)",
        )
        .bind(f.repo_id)
        .bind(path)
        .bind(bytes.len() as i64)
        .bind(&sha)
        .bind(&key)
        .execute(&f.pool)
        .await
        .unwrap();
        let (status, body) = tdh::send(
            f.router_with_auth(crate::api::handlers::maven::router()),
            tdh::get(format!("/{}/{path}", f.repo_key)),
        )
        .await;
        f.teardown().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), bytes.as_slice());
    }

    #[test]
    fn npm_identity_helpers_1846() {
        use std::path::Path;
        assert!(is_root_package_json(Path::new("package/package.json")));
        assert!(is_root_package_json(Path::new("./package/package.json")));
        assert!(is_root_package_json(Path::new("my-lib-1.0.0/package.json")));
        assert!(!is_root_package_json(Path::new("package.json")));
        assert!(!is_root_package_json(Path::new(
            "package/node_modules/dep/package.json"
        )));
        assert!(!is_root_package_json(Path::new(
            "package/dist/cjs/package.json"
        )));
        assert_eq!(clean_npm_version("1.2.3"), "1.2.3");
        assert_eq!(clean_npm_version(" v1.2.3 "), "1.2.3");
        assert_eq!(clean_npm_version("=1.2.3"), "1.2.3");
        assert_eq!(clean_npm_version("1.2.3+build.7"), "1.2.3");
        assert_eq!(clean_npm_version("1.2.3-beta.1"), "1.2.3-beta.1");
    }

    /// #1846: a legitimate tarball is not refused for what npm itself
    /// accepts: a bundled dependency's `package.json` ahead of the root one in
    /// tar order, a `v`-prefixed version in `package.json`, a mixed-case
    /// name. And an upload under the registry URL layout `{pkg}/-/{file}`
    /// keeps the generic behaviour instead of a 400.
    #[tokio::test]
    async fn chunked_npm_tarballs_npm_accepts_are_not_refused_1846() {
        let Some(f) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let root = serde_json::json!({ "name": "Bundler-Pkg", "version": "v3.0.0" }).to_string();
        let nested = serde_json::json!({ "name": "dep", "version": "9.9.9" }).to_string();
        let tarball = tgz(&[
            ("package/node_modules/dep/package.json", nested.as_bytes()),
            ("package/dist/cjs/package.json", br#"{"type":"commonjs"}"#),
            ("package/package.json", root.as_bytes()),
        ]);
        let path = "bundler-pkg/3.0.0/bundler-pkg-3.0.0.tgz";
        let (status, body) = f
            .chunked_upload(path, &tarball, serde_json::json!({}), false)
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let (_, name, version, _) = row(&f, path).await;
        assert_eq!(name, "bundler-pkg");
        assert_eq!(version.as_deref(), Some("3.0.0"));
        let (status, packument) = body_text(
            f.router_with_auth(crate::api::handlers::npm::router()),
            format!("/{}/bundler-pkg", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "packument: {packument}");
        let doc: serde_json::Value = serde_json::from_str(&packument).unwrap();
        assert_eq!(doc["versions"]["3.0.0"]["version"], "3.0.0", "{packument}");
        assert_eq!(
            doc["versions"]["3.0.0"]["name"], "bundler-pkg",
            "{packument}"
        );

        let dash = "dash-pkg/-/dash-pkg-1.0.0.tgz";
        let (status, body) = f
            .chunked_upload(
                dash,
                &npm_tgz("dash-pkg", "1.0.0"),
                serde_json::json!({}),
                false,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let (_, name, ..) = row(&f, dash).await;
        assert_eq!(name, "dash-pkg-1.0.0.tgz", "generic row, as before");
        f.teardown().await;
    }

    #[test]
    fn native_target_table_1846() {
        use RepositoryFormat as F;
        let t = |f: &F, p: &str| native_target(f, p).map(|t| (t.name, t.version, t.input));
        assert_eq!(
            t(&F::Maven, "com/acme/demo/1.0/demo-1.0.jar"),
            Some(("demo".into(), "1.0".into(), FinalizeInput::PathOnly))
        );
        assert_eq!(
            t(&F::Maven, "com/acme/demo/1.0/demo-1.0.pom"),
            Some(("demo".into(), "1.0".into(), FinalizeInput::Stream))
        );
        assert_eq!(t(&F::Maven, "com/acme/demo/1.0/demo-1.0.jar.sha1"), None);
        assert_eq!(t(&F::Maven, "com/acme/demo/maven-metadata.xml"), None);
        assert_eq!(
            t(&F::Npm, "@scope/pkg/1.2.3/pkg-1.2.3.tgz"),
            Some(("@scope/pkg".into(), "1.2.3".into(), FinalizeInput::Stream))
        );
        assert_eq!(t(&F::Npm, "pkg/1.2.3/README.md"), None);
        // The registry URL layout names no version: generic, as before.
        assert_eq!(t(&F::Npm, "pkg/-/pkg-1.2.3.tgz"), None);
        assert_eq!(t(&F::Npm, "@scope/pkg/-/pkg-1.2.3.tgz"), None);
        assert_eq!(
            t(&F::Pypi, "anything/My_Pkg-1.0-py3-none-any.whl"),
            Some(("my-pkg".into(), "1.0".into(), FinalizeInput::LocalFile))
        );
        assert_eq!(t(&F::Pypi, "notes.txt"), None);
        assert_eq!(
            t(&F::Rpm, "packages/hello-2.10-1.el8.noarch.rpm"),
            Some((
                "hello".into(),
                "2.10-1.el8".into(),
                FinalizeInput::LocalFile
            ))
        );
        assert_eq!(t(&F::Generic, "a/1.0/a.bin"), None);
    }
}
