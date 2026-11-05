//! Format-native finalize for the single-request generic upload (#5254).
//!
//! `PUT /api/v1/repositories/{repo}/artifacts/{path}` (and the multipart
//! variants that share its tail) used to name a package after the first two
//! path segments and record no format metadata (except an RPM header, #3801),
//! so a package uploaded that way was listed in its format's index under the
//! wrong identity, without its fields, or not at all.
//!
//! For a package at its format's native layout path (Alpine, Debian,
//! Maven/Gradle, npm, PyPI, RPM, Incus/LXC) this module runs the parse helpers
//! the format's own upload route runs, before anything is stored, and records
//! the rows that route records once the artifact row exists:
//!
//! 1. [`native_target`]: the `(name, version)` the native route writes for the
//!    path, and what its parser reads. `None` keeps the generic behaviour (a
//!    Maven checksum sidecar, a Debian file outside `pool/`, any other file).
//! 2. [`stage`]: the parse. `Err` is a client-facing reason the native route
//!    would refuse the package (400, nothing stored).
//! 3. [`record`]: the `artifact_metadata` document, catalog entry,
//!    install-script analysis and index cache invalidation. Silent: the
//!    generic upload emits its own `artifact.uploaded`.
//!
//! The artifact keeps the content-addressed storage key every generic upload
//! uses; every format's download route reads the row's `storage_key`.

use uuid::Uuid;

use crate::api::SharedState;
use crate::models::repository::RepositoryFormat;
use crate::services::artifact_service::ArtifactService;
use crate::services::package_service::PackageService;

/// Largest POM read into memory for its metadata. A POM is a small XML
/// document; anything larger is indexed from its path alone, as the native
/// route indexes a POM it cannot parse.
const MAX_POM_BYTES: u64 = 8 * 1024 * 1024;

/// What a format's parser reads from the uploaded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalizeInput {
    /// Nothing: the native route indexes the file from its path (a Maven jar).
    PathOnly,
    /// The package's leading bytes (an `.apk` control segment). Read from the
    /// staging object when the body is staged on the storage backend.
    Head,
    /// The whole body as a local file (the parser seeks, or walks an archive).
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
    /// No bytes are needed ([`FinalizeInput::PathOnly`]).
    None,
    /// The staged body as a local file.
    File(&'a std::path::Path),
    /// The body's leading bytes ([`FinalizeInput::Head`]).
    Head(Vec<u8>),
}

/// What the native route derives from the bytes, recorded against the
/// artifact row once it exists.
pub(crate) enum StagedNativeFinalize {
    Incus(serde_json::Value),
    Debian(Box<super::debian::StagedDebianPackage>),
    Maven(Box<StagedMaven>),
    Npm(Box<StagedNpm>),
    Pypi(Box<StagedPypi>),
    Rpm(Box<super::rpm::ExtractedScripts>),
    Alpine(Box<StagedAlpine>),
}

pub(crate) struct StagedMaven {
    coords: crate::formats::maven::MavenCoordinates,
    metadata: serde_json::Value,
    package_name: String,
    package_description: Option<String>,
    package_metadata: Option<serde_json::Value>,
}

pub(crate) struct StagedNpm {
    version_data: serde_json::Value,
}

pub(crate) struct StagedPypi {
    metadata: serde_json::Value,
    summary: Option<String>,
    catalog: serde_json::Value,
    analysis: crate::services::pypi_analysis::PypiAnalysis,
}

pub(crate) struct StagedAlpine {
    document: serde_json::Value,
    description: Option<String>,
}

/// The committed artifact a finalize records against.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FinalizeContext<'a> {
    pub repository_id: Uuid,
    pub repository_key: &'a str,
    pub artifact_path: &'a str,
    pub size_bytes: i64,
    pub checksum_sha256: &'a str,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The native target for `artifact_path` in a repository of `format`, or
/// `None` to keep the generic behaviour.
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
            super::incus::image_coordinates_from_path(artifact_path)
                .map(|c| target(c, FinalizeInput::LocalFile))
        }
        RepositoryFormat::Debian => super::debian::package_coordinates_from_path(artifact_path)
            .map(|c| target(c, FinalizeInput::LocalFile)),
        RepositoryFormat::Maven | RepositoryFormat::Gradle => {
            // Checksum sidecars and `maven-metadata.xml` are row-less objects
            // on the native route; they keep their generic row here.
            if super::maven::is_rowless_maven_path(artifact_path) {
                return None;
            }
            let coords = MavenHandler::parse_coordinates(artifact_path).ok()?;
            let input = if MavenHandler::is_pom(artifact_path) {
                FinalizeInput::LocalFile
            } else {
                FinalizeInput::PathOnly
            };
            Some(target((coords.artifact_id, coords.version), input))
        }
        RepositoryFormat::Npm => {
            // `{package}/{version}/{file}.tgz`, the layout the native publish
            // writes, or the registry URL layout `{package}/-/{file}.tgz`,
            // whose version is the one npm puts in the tarball's file name.
            if !artifact_path.ends_with(".tgz") {
                return None;
            }
            if let Some((package, file)) = artifact_path.rsplit_once("/-/") {
                return npm_registry_layout_coordinates(package, file)
                    .map(|c| target(c, FinalizeInput::LocalFile));
            }
            let package = super::npm::npm_package_name_from_artifact_path(artifact_path)?;
            let mut segments = artifact_path.rsplit('/');
            let _file = segments.next()?;
            let version = segments.next().filter(|v| !v.is_empty() && *v != "-")?;
            Some(target(
                (package.to_string(), version.to_string()),
                FinalizeInput::LocalFile,
            ))
        }
        RepositoryFormat::Pypi => {
            let info =
                crate::formats::pypi::PypiHandler::parse_filename(basename(artifact_path)).ok()?;
            let name = crate::formats::pypi_name::NormalizedProjectName::parse(&info.name?)?;
            let version = info.version.filter(|v| !v.is_empty())?;
            Some(target(
                (name.as_str().to_string(), version),
                FinalizeInput::LocalFile,
            ))
        }
        RepositoryFormat::Rpm => {
            let (name, version, release, _arch) =
                super::rpm::parse_rpm_filename(basename(artifact_path))?;
            Some(target(
                (name, super::rpm::build_rpm_full_version(&version, &release)),
                FinalizeInput::LocalFile,
            ))
        }
        // `{branch}/{repository}/{arch}/{name}-{version}.apk`.
        RepositoryFormat::Alpine => super::alpine::package_coordinates_from_path(artifact_path)
            .map(|c| target(c, FinalizeInput::Head)),
        _ => None,
    }
}

/// Whether a generic upload of `artifact_path` into a `format` repository
/// needs its body as a local file: the path's [`native_target`] reads a
/// [`FinalizeInput::LocalFile`]. A path not known yet (a multipart form can
/// name it after the file) is treated as possibly such a package for every
/// format whose finalize reads one.
pub(crate) fn needs_local_file(format: &RepositoryFormat, artifact_path: Option<&str>) -> bool {
    match artifact_path {
        Some(path) => native_target(format, path)
            .is_some_and(|target| target.input == FinalizeInput::LocalFile),
        None => matches!(
            format,
            RepositoryFormat::Incus
                | RepositoryFormat::Lxc
                | RepositoryFormat::Debian
                | RepositoryFormat::Maven
                | RepositoryFormat::Gradle
                | RepositoryFormat::Npm
                | RepositoryFormat::Pypi
                | RepositoryFormat::Rpm
        ),
    }
}

/// The `(package, version)` of an npm tarball at the registry URL layout
/// `{package}/-/{file}`: `file` is `{name}-{version}.tgz`, `name` being the
/// package's unscoped part. `None` for anything else.
fn npm_registry_layout_coordinates(package: &str, file: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = package.split('/').collect();
    let unscoped = match segments.as_slice() {
        [name] if !name.starts_with('@') => *name,
        [scope, name] if scope.len() > 1 && scope.starts_with('@') => *name,
        _ => return None,
    };
    if unscoped.is_empty() || file.contains('/') {
        return None;
    }
    let version = file
        .strip_suffix(".tgz")?
        .strip_prefix(unscoped)?
        .strip_prefix('-')?;
    (!version.is_empty()).then(|| (package.to_string(), version.to_string()))
}

/// The content type the format's native route stores for `artifact_path`.
pub(crate) fn native_content_type(
    format: &RepositoryFormat,
    artifact_path: &str,
) -> Option<&'static str> {
    match format {
        RepositoryFormat::Maven | RepositoryFormat::Gradle => {
            Some(super::maven::content_type_for_path(artifact_path))
        }
        RepositoryFormat::Npm => Some("application/gzip"),
        RepositoryFormat::Pypi => Some(super::pypi::pypi_content_type(basename(artifact_path))),
        RepositoryFormat::Rpm => Some("application/x-rpm"),
        RepositoryFormat::Alpine => Some("application/vnd.alpine.package"),
        RepositoryFormat::Debian => Some(super::debian::DEBIAN_BINARY_CONTENT_TYPE),
        _ => None,
    }
}

/// Up to `limit` leading bytes of the local file at `path`.
pub(crate) async fn read_file_head(path: &std::path::Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await?;
    let mut head = Vec::new();
    file.take(limit).read_to_end(&mut head).await?;
    Ok(head)
}

fn needs_file(source: FinalizeSource<'_>, what: &str) -> Result<std::path::PathBuf, String> {
    match source {
        FinalizeSource::File(file) => Ok(file.to_path_buf()),
        _ => Err(format!("{what} finalize needs the staged file")),
    }
}

/// Run the native route's parse of the uploaded bytes. Called only for a path
/// [`native_target`] accepted. Returns the target the row is stored under (an
/// Alpine package takes its `.PKGINFO` identity, as the native route stores
/// it) and what [`record`] writes. `Err` is a client-facing reason the upload
/// is refused (400), with nothing stored.
pub(crate) async fn stage(
    format: &RepositoryFormat,
    artifact_path: &str,
    target: NativeTarget,
    source: FinalizeSource<'_>,
) -> Result<(NativeTarget, StagedNativeFinalize), String> {
    match format {
        RepositoryFormat::Incus | RepositoryFormat::Lxc => {
            let file = needs_file(source, "an Incus image")?;
            let path = artifact_path.to_string();
            let metadata = tokio::task::spawn_blocking(move || {
                super::incus::extract_image_metadata(&path, &file)
            })
            .await
            .unwrap_or_else(|_| serde_json::json!({"file_type": "unknown"}));
            Ok((target, StagedNativeFinalize::Incus(metadata)))
        }
        RepositoryFormat::Debian => {
            let file = needs_file(source, "a Debian package")?;
            // `native_target` accepted the path through the same
            // `staged_package_target` check, so `Ok(None)` is unreachable.
            let staged = super::debian::finalize_from_staged(artifact_path, &file)
                .await?
                .ok_or_else(|| "not a Debian pool package".to_string())?;
            Ok((target, StagedNativeFinalize::Debian(Box::new(staged))))
        }
        RepositoryFormat::Maven | RepositoryFormat::Gradle => {
            let staged = stage_maven(artifact_path, source).await?;
            Ok((target, StagedNativeFinalize::Maven(Box::new(staged))))
        }
        RepositoryFormat::Npm => {
            let file = needs_file(source, "an npm tarball")?;
            let staged = stage_npm(&target, file).await?;
            Ok((target, StagedNativeFinalize::Npm(Box::new(staged))))
        }
        RepositoryFormat::Pypi => {
            let file = needs_file(source, "a PyPI distribution")?;
            let staged = stage_pypi(artifact_path, &target, file).await?;
            Ok((target, StagedNativeFinalize::Pypi(Box::new(staged))))
        }
        RepositoryFormat::Rpm => {
            let file = needs_file(source, "an RPM")?;
            let prefix = super::upload::read_rpm_header_prefix(&file)
                .await
                .map_err(|e| format!("could not read the RPM header: {e}"))?;
            let scripts =
                tokio::task::spawn_blocking(move || super::rpm::extract_rpm_scriptlets(&prefix))
                    .await
                    .map_err(|e| format!("RPM header parse failed: {e}"))?;
            Ok((target, StagedNativeFinalize::Rpm(Box::new(scripts))))
        }
        RepositoryFormat::Alpine => {
            // An unreadable package is stored unindexed, as the native route
            // stores it: only a read failure of the upload itself is refused.
            let head = match source {
                FinalizeSource::Head(head) => head,
                FinalizeSource::File(file) => {
                    read_file_head(file, super::alpine::FINALIZE_HEAD_BYTES as u64)
                        .await
                        .map_err(|e| format!("could not read the uploaded package: {e}"))?
                }
                FinalizeSource::None => Vec::new(),
            };
            let (path, name, version) = (
                artifact_path.to_string(),
                target.name.clone(),
                target.version.clone(),
            );
            let (identity, document, description) = tokio::task::spawn_blocking(move || {
                super::alpine::finalize_document(&path, &name, &version, &head)
            })
            .await
            .map_err(|e| format!("Alpine package parse failed: {e}"))?;
            Ok((
                NativeTarget {
                    name: identity.0,
                    version: identity.1,
                    input: target.input,
                },
                StagedNativeFinalize::Alpine(Box::new(StagedAlpine {
                    document,
                    description,
                })),
            ))
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
    let pom_bytes = match source {
        FinalizeSource::File(file) if is_pom => {
            let pom = read_file_head(file, MAX_POM_BYTES + 1)
                .await
                .map_err(|e| format!("could not read the uploaded POM: {e}"))?;
            if pom.len() as u64 > MAX_POM_BYTES {
                bytes::Bytes::new()
            } else {
                bytes::Bytes::from(pom)
            }
        }
        _ => bytes::Bytes::new(),
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
    let package_name = super::maven::maven_package_name(&coords);
    let (package_description, package_metadata) = if is_pom {
        (
            super::maven::maven_package_description(&metadata),
            Some(super::maven::build_maven_package_catalog_metadata(
                &coords, &metadata,
            )),
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
async fn stage_npm(target: &NativeTarget, file: std::path::PathBuf) -> Result<StagedNpm, String> {
    let package_json = tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&file)
            .map_err(|e| crate::error::AppError::Internal(format!("re-open staged upload: {e}")))?;
        crate::util::bounded_archive::read_metadata_from_tar_gz(
            std::io::BufReader::new(file),
            is_root_package_json,
        )
    })
    .await
    .map_err(|e| format!("npm tarball could not be read: {e}"))?
    .map_err(|e| format!("npm tarball could not be read: {e}"))?
    .ok_or_else(|| "npm tarball has no package.json".to_string())?;
    let mut version_data: serde_json::Value = serde_json::from_slice(&package_json)
        .map_err(|e| format!("npm tarball package.json is not valid JSON: {e}"))?;
    let declared_name = version_data
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim);
    let declared_version = version_data.get("version").and_then(|v| v.as_str());
    // npm names are lowercase by construction; a legacy mixed-case name is
    // compared case-insensitively.
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
    if let Some(doc) = version_data.as_object_mut() {
        doc.insert("name".to_string(), target.name.clone().into());
        doc.insert("version".to_string(), target.version.clone().into());
    }
    Ok(StagedNpm { version_data })
}

/// The tarball's root `package.json`: `package/package.json` as `npm pack`
/// writes it, or the same file under another top-level directory. A nested
/// one (a bundled dependency's) does not describe the package.
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
    file: std::path::PathBuf,
) -> Result<StagedPypi, String> {
    use crate::formats::pypi::PypiHandler;
    let filename = basename(artifact_path).to_string();
    let pkg_info = {
        let file = file.clone();
        let (name, version, filename) = (
            target.name.clone(),
            target.version.clone(),
            filename.clone(),
        );
        crate::util::bounded_archive::with_ingest_extraction_async(|| {
            tokio::task::spawn_blocking(move || {
                let file = std::fs::File::open(&file).map_err(|e| {
                    crate::error::AppError::Internal(format!("re-open staged upload: {e}"))
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
    let analysis = super::pypi::analyze_pypi_upload(file, filename.clone()).await;
    let mut metadata = serde_json::json!({
        "name": raw_name,
        "normalized_name": target.name,
        "version": target.version,
        "filename": filename,
    });
    if let Some(pkg_info) =
        super::pypi::build_upload_pkg_info(pkg_info, None, None, &serde_json::Map::new())
    {
        metadata["pkg_info"] = pkg_info;
    }
    let catalog =
        super::pypi::build_pypi_package_catalog_metadata(&filename, requires_python.as_deref());
    Ok(StagedPypi {
        metadata,
        summary,
        catalog,
        analysis,
    })
}

/// Record a natively finalized generic upload's format rows against its
/// committed artifact: the `artifact_metadata` document, then the catalog
/// entry, install-script analysis and index cache invalidation the native
/// route performs. `rpm_metadata` is the header document the generic upload's
/// RPM parse (#3801) produced. The artifact is already committed, so a failure
/// is logged rather than failing the upload, as the RPM metadata write on
/// this path always was.
pub(crate) async fn record(
    state: &SharedState,
    artifact_service: &ArtifactService,
    context: &FinalizeContext<'_>,
    artifact_id: Uuid,
    target: &NativeTarget,
    staged: StagedNativeFinalize,
    rpm_metadata: Option<&serde_json::Value>,
) {
    let catalog = PackageService::new(state.db.clone());
    let set_metadata = |format: &'static str, metadata: serde_json::Value| async move {
        if let Err(e) = artifact_service
            .set_metadata(artifact_id, format, metadata, serde_json::json!({}))
            .await
        {
            tracing::warn!(artifact_id = %artifact_id, error = %e, "format metadata could not be recorded");
        }
    };
    match staged {
        StagedNativeFinalize::Incus(metadata) => {
            if let Err(e) =
                super::incus::store_image_metadata(&state.db, artifact_id, &metadata).await
            {
                tracing::warn!(artifact_id = %artifact_id, error = %e, "format metadata could not be recorded");
            }
            catalog
                .try_create_or_update_from_artifact(
                    context.repository_id,
                    &target.name,
                    &target.version,
                    context.size_bytes,
                    context.checksum_sha256,
                    None,
                    Some(serde_json::json!({ "format": "incus" })),
                )
                .await;
        }
        StagedNativeFinalize::Debian(package) => {
            let (upload, deb_head) = package.parts();
            if let Err(e) = super::debian::record_debian_package(
                state,
                artifact_service,
                context.repository_id,
                artifact_id,
                context.size_bytes,
                context.checksum_sha256,
                upload,
                deb_head,
            )
            .await
            {
                tracing::warn!(artifact_id = %artifact_id, error = %e, "format metadata could not be recorded");
            }
        }
        StagedNativeFinalize::Maven(maven) => {
            let StagedMaven {
                coords,
                metadata,
                package_name,
                package_description,
                package_metadata,
            } = *maven;
            set_metadata("maven", metadata).await;
            catalog
                .try_create_or_update_from_artifact(
                    context.repository_id,
                    &package_name,
                    &coords.version,
                    context.size_bytes,
                    context.checksum_sha256,
                    package_description.as_deref(),
                    package_metadata,
                )
                .await;
            // #4633: a version's size is the total of its files.
            if let Some(directory) = super::maven::maven_version_directory(context.artifact_path) {
                catalog
                    .try_set_version_size_to_directory_total(
                        context.repository_id,
                        &package_name,
                        &coords.version,
                        directory,
                    )
                    .await;
            }
            super::maven::invalidate_maven_metadata_cache(
                context.repository_id,
                &coords.group_id,
                &coords.artifact_id,
            )
            .await;
            super::maven::invalidate_maven_prefixes_cache(context.repository_id).await;
        }
        StagedNativeFinalize::Npm(npm) => {
            let version_data = npm.version_data;
            let description = version_data
                .get("description")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            set_metadata(
                "npm",
                serde_json::json!({
                    "name": target.name,
                    "version": target.version,
                    "version_data": version_data,
                }),
            )
            .await;
            super::npm::record_npm_install_script_analysis(state, artifact_id, &version_data).await;
            catalog
                .try_create_or_update_from_artifact(
                    context.repository_id,
                    &target.name,
                    &target.version,
                    context.size_bytes,
                    context.checksum_sha256,
                    description.as_deref(),
                    Some(serde_json::json!({ "format": "npm" })),
                )
                .await;
            super::npm::invalidate_packument_caches(
                state,
                context.repository_id,
                context.repository_key,
                &target.name,
            )
            .await;
        }
        StagedNativeFinalize::Pypi(pypi) => {
            let StagedPypi {
                metadata,
                summary,
                catalog: catalog_metadata,
                analysis,
            } = *pypi;
            set_metadata("pypi", metadata).await;
            super::pypi::record_pypi_package_analysis(state, artifact_id, analysis).await;
            catalog
                .try_create_or_update_from_artifact(
                    context.repository_id,
                    &target.name,
                    &target.version,
                    context.size_bytes,
                    context.checksum_sha256,
                    summary.as_deref(),
                    Some(catalog_metadata),
                )
                .await;
        }
        StagedNativeFinalize::Rpm(scripts) => {
            // The header document when it parsed, else the NEVRA in the file
            // name, as the native route falls back to.
            let fallback;
            let metadata = match rpm_metadata {
                Some(metadata) => metadata,
                None => {
                    let filename = basename(context.artifact_path);
                    let Some((name, version, release, arch)) =
                        super::rpm::parse_rpm_filename(filename)
                    else {
                        return;
                    };
                    fallback =
                        super::rpm::build_rpm_metadata(&name, &version, &release, &arch, filename);
                    &fallback
                }
            };
            if let Err(e) = super::rpm::record_rpm_metadata(
                &state.db,
                artifact_id,
                context.repository_id,
                metadata,
            )
            .await
            {
                tracing::warn!(artifact_id = %artifact_id, error = %e, "RPM metadata could not be recorded");
            }
            let (scripts, unanalyzed, completeness) = *scripts;
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
            let description = metadata
                .get("summary")
                .and_then(|v| v.as_str())
                .filter(|d| !d.is_empty());
            catalog
                .try_create_or_update_from_artifact(
                    context.repository_id,
                    &target.name,
                    &target.version,
                    context.size_bytes,
                    context.checksum_sha256,
                    description,
                    Some(serde_json::json!({ "format": "rpm" })),
                )
                .await;
        }
        StagedNativeFinalize::Alpine(alpine) => {
            let StagedAlpine {
                document,
                description,
            } = *alpine;
            set_metadata("alpine", document).await;
            // The package catalog entry the native route registers (#3659).
            catalog
                .try_create_or_update_from_artifact(
                    context.repository_id,
                    &target.name,
                    &target.version,
                    context.size_bytes,
                    context.checksum_sha256,
                    description.as_deref(),
                    Some(serde_json::json!({ "format": "alpine" })),
                )
                .await;
        }
    }
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;
    use bytes::Bytes;

    /// A real `.apk` built by `abuild -F` (the Alpine handler's fixture).
    const MARKER_APK: &[u8] = include_bytes!("../../../tests/fixtures/dtf-marker-1.0-r0.apk");
    /// Real minimal noarch RPM built with rpmbuild (Summary set).
    const TEST_RPM: &[u8] = include_bytes!("../../../tests/fixtures/ak-meta-test-1.0-1.noarch.rpm");

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

    fn npm_package_json(name: &str, version: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "description": "generic npm package",
            "dependencies": { "left-pad": "^1.3.0" },
        })
    }

    fn npm_tgz(name: &str, version: &str) -> Vec<u8> {
        let package_json = npm_package_json(name, version).to_string();
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
                 Summary: generic wheel\nRequires-Python: >=3.9\n"
            )
            .unwrap();
            zip.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn minimal_deb(package: &str, version: &str) -> Vec<u8> {
        crate::api::handlers::debian::upload_db_tests::minimal_deb(
            package,
            version,
            "amd64",
            "generic deb",
        )
    }

    async fn body_text(router: axum::Router, uri: String) -> (StatusCode, String) {
        let (status, body) = tdh::send(router, tdh::get(uri)).await;
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn row(f: &tdh::Fixture, path: &str) -> (String, Option<String>, String) {
        sqlx::query_as(
            "SELECT name, version, content_type FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(f.repo_id)
        .bind(path)
        .fetch_one(&f.pool)
        .await
        .expect("artifact row")
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

    /// `PUT /api/v1/repositories/{repo}/artifacts/{path}` as the fixture user.
    async fn generic_put(f: &tdh::Fixture, path: &str, body: &[u8]) -> (StatusCode, Bytes) {
        generic_put_with(f, path, body, &[]).await
    }

    async fn generic_put_with(
        f: &tdh::Fixture,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> (StatusCode, Bytes) {
        let mut req = tdh::put(
            format!("/{}/artifacts/{path}", f.repo_key),
            Bytes::from(body.to_vec()),
        );
        for (name, value) in headers {
            req.headers_mut().insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        tdh::send(
            f.router_with_auth(crate::api::handlers::repositories::router()),
            req,
        )
        .await
    }

    fn assert_status(want: StatusCode, (status, body): (StatusCode, Bytes)) -> Bytes {
        assert_eq!(status, want, "{}", String::from_utf8_lossy(&body));
        body
    }

    /// `PUT {uri}` on a native `router`, which must succeed.
    async fn native_put(
        f: &tdh::Fixture,
        router: axum::Router<SharedState>,
        uri: String,
        body: &[u8],
    ) {
        let (status, text) = tdh::send(
            f.router_with_auth(router),
            tdh::put(uri, Bytes::from(body.to_vec())),
        )
        .await;
        assert!(
            status.is_success(),
            "{status}: {}",
            String::from_utf8_lossy(&text)
        );
    }

    /// The `artifact_metadata` row (format, document) at `path`, if any.
    async fn metadata_at(f: &tdh::Fixture, path: &str) -> Option<(String, serde_json::Value)> {
        sqlx::query_as(
            "SELECT am.format, am.metadata FROM artifact_metadata am \
             JOIN artifacts a ON a.id = am.artifact_id \
             WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false",
        )
        .bind(f.repo_id)
        .bind(path)
        .fetch_optional(&f.pool)
        .await
        .expect("metadata lookup")
    }

    async fn artifact_count(f: &tdh::Fixture) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
            .bind(f.repo_id)
            .fetch_one(&f.pool)
            .await
            .unwrap()
    }

    /// Two fixtures of `format`: the native route's and the generic PUT's.
    async fn pair(format: &str) -> Option<(tdh::Fixture, tdh::Fixture)> {
        Some((
            tdh::Fixture::setup("local", format).await?,
            tdh::Fixture::setup("local", format).await?,
        ))
    }

    /// The two repositories hold the same row identity and format document
    /// at `path`.
    async fn assert_parity(native: &tdh::Fixture, generic: &tdh::Fixture, path: &str) {
        assert_eq!(
            row(generic, path).await,
            row(native, path).await,
            "row at {path}"
        );
        assert_eq!(
            metadata_at(generic, path).await.expect("generic document"),
            metadata_at(native, path).await.expect("native document"),
            "document at {path}"
        );
    }

    /// The `APKINDEX` text of an unsigned `APKINDEX.tar.gz`.
    fn apkindex_text(tar_gz: &[u8]) -> String {
        let mut archive = tar::Archive::new(flate2::read::MultiGzDecoder::new(tar_gz));
        for entry in archive.entries().expect("APKINDEX tar") {
            let mut entry = entry.expect("APKINDEX tar entry");
            if entry.path().unwrap().to_string_lossy() == "APKINDEX" {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut entry, &mut text).unwrap();
                return text;
            }
        }
        panic!("no APKINDEX entry");
    }

    /// #5254: an `.apk` PUT through the generic endpoint at its native layout
    /// path is named, documented and indexed exactly as the native Alpine
    /// upload records it. Before the fix the row was `v3.24`/`main`.
    #[tokio::test]
    async fn generic_put_apk_matches_the_native_alpine_upload_5254() {
        let Some((native, generic)) = pair("alpine").await else {
            return;
        };
        let path = "v3.24/main/aarch64/dtf-marker-1.0-r0.apk";
        native_put(
            &native,
            crate::api::handlers::alpine::router(),
            format!("/{}/{path}", native.repo_key),
            MARKER_APK,
        )
        .await;
        assert_status(
            StatusCode::CREATED,
            generic_put(&generic, path, MARKER_APK).await,
        );
        let (name, version, _) = row(&generic, path).await;
        assert_eq!(
            (name.as_str(), version.as_deref()),
            ("dtf-marker", Some("1.0-r0"))
        );
        assert_parity(&native, &generic, path).await;
        let (_, doc) = metadata_at(&generic, path).await.unwrap();
        assert!(doc["apk_checksum"].is_string(), "{doc}");

        let index = |f: &tdh::Fixture| {
            let router = f.router_with_auth(crate::api::handlers::alpine::router());
            let uri = format!("/{}/v3.24/main/aarch64/APKINDEX.tar.gz", f.repo_key);
            async move {
                let (status, body) = tdh::send(router, tdh::get(uri)).await;
                assert_eq!(status, StatusCode::OK);
                apkindex_text(&body)
            }
        };
        let generic_index = index(&generic).await;
        assert!(generic_index.contains("P:dtf-marker\n"), "{generic_index}");
        assert!(generic_index.contains("V:1.0-r0\n"), "{generic_index}");
        assert_eq!(generic_index, index(&native).await);
        assert_eq!(
            catalog_version(&generic, "dtf-marker").await.as_deref(),
            Some("1.0-r0")
        );
        native.teardown().await;
        generic.teardown().await;
    }

    /// #5254: an `.apk` whose file name misstates its identity is stored, and
    /// answered, under its `.PKGINFO` `pkgname`/`pkgver`, as the native route
    /// stores it.
    #[tokio::test]
    async fn generic_put_apk_takes_its_pkginfo_identity_like_the_native_route_5254() {
        let Some((native, generic)) = pair("alpine").await else {
            return;
        };
        let path = "v3.24/main/aarch64/dtf-9.9-r9.apk";
        native_put(
            &native,
            crate::api::handlers::alpine::router(),
            format!("/{}/{path}", native.repo_key),
            MARKER_APK,
        )
        .await;
        let body = assert_status(
            StatusCode::CREATED,
            generic_put(&generic, path, MARKER_APK).await,
        );
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response["name"], "dtf-marker");
        assert_eq!(response["version"], "1.0-r0");
        assert_parity(&native, &generic, path).await;
        assert_eq!(
            catalog_version(&generic, "dtf-marker").await.as_deref(),
            Some("1.0-r0")
        );
        native.teardown().await;
        generic.teardown().await;
    }

    /// #5254: an unreadable `.apk` is stored, as the native route stores it,
    /// with its file-name identity and no apk checksum (so `APKINDEX` leaves
    /// it out); the upload is not refused.
    #[tokio::test]
    async fn generic_put_unreadable_apk_is_stored_unindexed_5254() {
        let Some(f) = tdh::Fixture::setup("local", "alpine").await else {
            return;
        };
        let path = "edge/main/x86_64/broken-2.0-r1.apk";
        assert_status(
            StatusCode::CREATED,
            generic_put(&f, path, b"not an apk at all").await,
        );
        let (name, version, _) = row(&f, path).await;
        assert_eq!(
            (name.as_str(), version.as_deref()),
            ("broken", Some("2.0-r1"))
        );
        let (format, doc) = metadata_at(&f, path).await.expect("alpine document");
        assert_eq!(format, "alpine");
        assert_eq!(doc["name"], "broken");
        assert!(doc.get("apk_checksum").is_none(), "{doc}");
        f.teardown().await;
    }

    /// #5254: a `.deb` PUT through the generic endpoint at its pool path gets
    /// the native Debian upload's row, control document and `Packages`
    /// stanza (with `Depends`).
    #[tokio::test]
    async fn generic_put_deb_matches_the_native_debian_upload_5254() {
        let Some((native, generic)) = pair("debian").await else {
            return;
        };
        let (package, version) = ("ak-generic-deb", "1.4.0-2");
        let deb = minimal_deb(package, version);
        let path = format!("pool/main/a/{package}/{package}_{version}_amd64.deb");
        native_put(
            &native,
            crate::api::handlers::debian::router(),
            format!("/{}/{path}", native.repo_key),
            &deb,
        )
        .await;
        assert_status(
            StatusCode::CREATED,
            generic_put(&generic, &path, &deb).await,
        );
        let (name, row_version, _) = row(&generic, &path).await;
        assert_eq!(
            (name.as_str(), row_version.as_deref()),
            (package, Some(version))
        );
        assert_parity(&native, &generic, &path).await;

        let packages = |f: &tdh::Fixture| {
            let router = f.router_with_auth(crate::api::handlers::debian::router());
            let uri = format!("/{}/dists/bookworm/main/binary-amd64/Packages", f.repo_key);
            async move {
                let (status, text) = body_text(router, uri).await;
                assert_eq!(status, StatusCode::OK);
                text
            }
        };
        let generic_packages = packages(&generic).await;
        assert!(
            generic_packages.contains("Depends: libc6 (>= 2.36)\n"),
            "{generic_packages}"
        );
        assert_eq!(generic_packages, packages(&native).await);
        assert_eq!(
            catalog_version(&generic, package).await.as_deref(),
            Some(version)
        );
        native.teardown().await;
        generic.teardown().await;
    }

    /// #5254: a `.deb` whose control file names another package than its
    /// pool file name is refused (400) as the native route refuses it, and
    /// nothing is stored.
    #[tokio::test]
    async fn generic_put_deb_disagreeing_with_its_file_name_is_refused_5254() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let deb = minimal_deb("someone-else", "1.0");
        assert_status(
            StatusCode::BAD_REQUEST,
            generic_put(&f, "pool/main/a/ak-deb/ak-deb_1.0_amd64.deb", &deb).await,
        );
        assert_eq!(artifact_count(&f).await, 0);
        f.teardown().await;
    }

    /// #5254: a Maven jar and POM PUT through the generic endpoint produce the
    /// native Maven upload's rows, documents and `maven-metadata.xml`. Before
    /// the fix the rows were `com`/`acme` and `maven-metadata.xml` was 404.
    #[tokio::test]
    async fn generic_put_maven_jar_and_pom_match_the_native_maven_upload_5254() {
        let Some((native, generic)) = pair("maven").await else {
            return;
        };
        let pom = br#"<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme.generic</groupId>
  <artifactId>demo</artifactId>
  <version>2.3.4</version>
  <description>generic maven artifact</description>
</project>
"#;
        let base = "com/acme/generic/demo/2.3.4";
        let files = [
            (
                format!("{base}/demo-2.3.4.jar"),
                b"PK\x03\x04 jar body".to_vec(),
            ),
            (format!("{base}/demo-2.3.4.pom"), pom.to_vec()),
        ];
        for (path, bytes) in &files {
            native_put(
                &native,
                crate::api::handlers::maven::router(),
                format!("/{}/{path}", native.repo_key),
                bytes,
            )
            .await;
            assert_status(
                StatusCode::CREATED,
                generic_put(&generic, path, bytes).await,
            );
        }
        for (path, _) in &files {
            let (name, version, _) = row(&generic, path).await;
            assert_eq!((name.as_str(), version.as_deref()), ("demo", Some("2.3.4")));
            assert_parity(&native, &generic, path).await;
        }
        let metadata_xml = |f: &tdh::Fixture| {
            let router = f.router_with_auth(crate::api::handlers::maven::router());
            let uri = format!("/{}/com/acme/generic/demo/maven-metadata.xml", f.repo_key);
            async move {
                let (status, xml) = body_text(router, uri).await;
                assert_eq!(status, StatusCode::OK, "{xml}");
                // `lastUpdated` is the generation time.
                xml.lines()
                    .filter(|line| !line.contains("<lastUpdated>"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        };
        let generic_xml = metadata_xml(&generic).await;
        assert!(
            generic_xml.contains("<version>2.3.4</version>"),
            "{generic_xml}"
        );
        assert_eq!(generic_xml, metadata_xml(&native).await);
        assert_eq!(
            catalog_version(&generic, "com.acme.generic:demo")
                .await
                .as_deref(),
            Some("2.3.4")
        );
        // A checksum sidecar keeps the generic behaviour (no Maven document).
        let sha1 = format!("{base}/demo-2.3.4.jar.sha1");
        assert_status(
            StatusCode::CREATED,
            generic_put(&generic, &sha1, b"0123").await,
        );
        assert!(metadata_at(&generic, &sha1).await.is_none());
        native.teardown().await;
        generic.teardown().await;
    }

    /// #5254: an npm tarball PUT through the generic endpoint at
    /// `{package}/{version}/{file}.tgz` is in the packument with its
    /// `package.json` as the version document (dependencies included).
    #[tokio::test]
    async fn generic_put_npm_tarball_is_in_the_packument_5254() {
        let Some(f) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let path = "generic-pkg/1.2.0/generic-pkg-1.2.0.tgz";
        assert_status(
            StatusCode::CREATED,
            generic_put(&f, path, &npm_tgz("generic-pkg", "1.2.0")).await,
        );
        let (name, version, content_type) = row(&f, path).await;
        assert_eq!(
            (name.as_str(), version.as_deref(), content_type.as_str()),
            ("generic-pkg", Some("1.2.0"), "application/gzip")
        );
        let (format, doc) = metadata_at(&f, path).await.expect("npm document");
        assert_eq!(format, "npm");
        assert_eq!(
            doc,
            serde_json::json!({
                "name": "generic-pkg",
                "version": "1.2.0",
                "version_data": npm_package_json("generic-pkg", "1.2.0"),
            })
        );
        let (status, packument) = body_text(
            f.router_with_auth(crate::api::handlers::npm::router()),
            format!("/{}/generic-pkg", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{packument}");
        let doc: serde_json::Value = serde_json::from_str(&packument).unwrap();
        assert_eq!(
            doc["versions"]["1.2.0"]["dependencies"]["left-pad"], "^1.3.0",
            "{packument}"
        );
        assert_eq!(
            catalog_version(&f, "generic-pkg").await.as_deref(),
            Some("1.2.0")
        );
        f.teardown().await;
    }

    /// #5254: an npm tarball PUT through the generic endpoint at the registry
    /// URL layout `{package}/-/{file}.tgz` gets the packument entry a native
    /// `npm publish` of the same tarball gets.
    #[tokio::test]
    async fn generic_put_npm_registry_layout_matches_the_native_publish_5254() {
        use base64::Engine as _;
        let Some((native, generic)) = pair("npm").await else {
            return;
        };
        let tarball = npm_tgz("layout-pkg", "3.1.4");
        let file = "layout-pkg-3.1.4.tgz";
        let mut version = npm_package_json("layout-pkg", "3.1.4");
        version["dist"] = serde_json::json!({ "tarball": format!("http://x/{file}") });
        let publish = serde_json::json!({
            "_id": "layout-pkg",
            "name": "layout-pkg",
            "dist-tags": { "latest": "3.1.4" },
            "versions": { "3.1.4": version },
            "_attachments": { file: {
                "content_type": "application/octet-stream",
                "data": base64::engine::general_purpose::STANDARD.encode(&tarball),
                "length": tarball.len(),
            }},
        });
        let (status, body) = tdh::send(
            native.router_with_auth(crate::api::handlers::npm::router()),
            tdh::put_json(
                format!("/{}/layout-pkg", native.repo_key),
                Bytes::from(serde_json::to_vec(&publish).unwrap()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "{status}: {}",
            String::from_utf8_lossy(&body)
        );
        let path = format!("layout-pkg/-/{file}");
        assert_status(
            StatusCode::CREATED,
            generic_put(&generic, &path, &tarball).await,
        );

        let packument = |f: &tdh::Fixture| {
            let router = f.router_with_auth(crate::api::handlers::npm::router());
            let uri = format!("/{}/layout-pkg", f.repo_key);
            let key = f.repo_key.clone();
            async move {
                let (status, text) = body_text(router, uri).await;
                assert_eq!(status, StatusCode::OK, "{text}");
                let doc: serde_json::Value =
                    serde_json::from_str(&text.replace(&key, "<repo>")).unwrap();
                (doc["versions"]["3.1.4"].clone(), doc["dist-tags"].clone())
            }
        };
        let generic_entry = packument(&generic).await;
        assert_eq!(generic_entry.0["dependencies"]["left-pad"], "^1.3.0");
        assert_eq!(generic_entry, packument(&native).await);
        let (name, version, _) = row(&generic, &path).await;
        assert_eq!(
            (name.as_str(), version.as_deref()),
            ("layout-pkg", Some("3.1.4"))
        );
        native.teardown().await;
        generic.teardown().await;
    }

    /// #5254: a tarball naming another package, or another version, than its
    /// path is refused, as the native publish refuses it, and nothing is
    /// stored.
    #[tokio::test]
    async fn generic_put_npm_tarball_naming_another_package_is_refused_5254() {
        let Some(f) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let path = "generic-pkg/1.2.0/generic-pkg-1.2.0.tgz";
        for tarball in [
            npm_tgz("other-pkg", "1.2.0"),
            npm_tgz("generic-pkg", "9.9.9"),
            tgz(&[("package/index.js", b"1")]),
            tgz(&[("package/package.json", b"not json")]),
            b"not a tarball".to_vec(),
        ] {
            assert_status(
                StatusCode::BAD_REQUEST,
                generic_put(&f, path, &tarball).await,
            );
        }
        assert_eq!(artifact_count(&f).await, 0);
        // A `v`-prefixed `package.json` version is the version npm publishes.
        let path = "generic-pkg/1.3.0/generic-pkg-1.3.0.tgz";
        assert_status(
            StatusCode::CREATED,
            generic_put(&f, path, &npm_tgz("generic-pkg", "v1.3.0")).await,
        );
        let (_, doc) = metadata_at(&f, path).await.unwrap();
        assert_eq!(doc["version_data"]["version"], "1.3.0");
        f.teardown().await;
    }

    /// #5254: a wheel PUT through the generic endpoint is in its project's
    /// simple index with `data-requires-python`; one whose `METADATA` names
    /// another version is refused.
    #[tokio::test]
    async fn generic_put_pypi_wheel_is_in_the_simple_index_5254() {
        let Some(f) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };
        let file = "generic_dist-0.9.0-py3-none-any.whl";
        let path = format!("generic-dist/0.9.0/{file}");
        assert_status(
            StatusCode::CREATED,
            generic_put(&f, &path, &wheel("generic_dist", "0.9.0")).await,
        );
        let (name, version, content_type) = row(&f, &path).await;
        assert_eq!(
            (name.as_str(), version.as_deref(), content_type.as_str()),
            ("generic-dist", Some("0.9.0"), "application/zip")
        );
        let (format, doc) = metadata_at(&f, &path).await.expect("pypi document");
        assert_eq!(format, "pypi");
        assert_eq!(doc["name"], "generic_dist");
        assert_eq!(doc["normalized_name"], "generic-dist");
        assert_eq!(doc["pkg_info"]["requires_python"], ">=3.9", "{doc}");
        let (status, html) = body_text(
            f.router_with_auth(crate::api::handlers::pypi::router()),
            format!("/{}/simple/generic-dist/", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{html}");
        assert!(html.contains(file), "{html}");
        assert!(html.contains("data-requires-python=\"&gt;=3.9\""), "{html}");
        assert_eq!(
            catalog_version(&f, "generic-dist").await.as_deref(),
            Some("0.9.0")
        );

        let mismatched = "generic-dist/1.0.0/generic_dist-1.0.0-py3-none-any.whl";
        assert_status(
            StatusCode::BAD_REQUEST,
            generic_put(&f, mismatched, &wheel("generic_dist", "0.9.0")).await,
        );
        assert_eq!(artifact_count(&f).await, 1);
        f.teardown().await;
    }

    /// #5254: an RPM PUT through the generic endpoint is named by its NEVRA,
    /// keeps its header document (#3801) and is registered in the catalog and
    /// `primary.xml`, as the native upload records it.
    #[tokio::test]
    async fn generic_put_rpm_matches_the_native_rpm_upload_5254() {
        let Some((native, generic)) = pair("rpm").await else {
            return;
        };
        let path = "packages/ak-meta-test-1.0-1.noarch.rpm";
        native_put(
            &native,
            crate::api::handlers::rpm::router(),
            format!("/{}/{path}", native.repo_key),
            TEST_RPM,
        )
        .await;
        assert_status(
            StatusCode::CREATED,
            generic_put(&generic, path, TEST_RPM).await,
        );
        let (name, version, content_type) = row(&generic, path).await;
        assert_eq!(
            (name.as_str(), version.as_deref(), content_type.as_str()),
            ("ak-meta-test", Some("1.0-1"), "application/x-rpm")
        );
        assert_parity(&native, &generic, path).await;
        assert_eq!(
            catalog_version(&generic, "ak-meta-test").await.as_deref(),
            Some("1.0-1")
        );
        let (status, gz) = tdh::send(
            generic.router_with_auth(crate::api::handlers::rpm::router()),
            tdh::get(format!("/{}/repodata/primary.xml.gz", generic.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let mut primary = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut primary)
            .unwrap();
        assert!(primary.contains("<name>ak-meta-test</name>"), "{primary}");

        // An RPM whose header does not parse keeps the file-name NEVRA.
        let broken = "broken-tool-2.0-3.x86_64.rpm";
        assert_status(
            StatusCode::CREATED,
            generic_put(&generic, broken, b"not an rpm").await,
        );
        let (name, version, _) = row(&generic, broken).await;
        assert_eq!(
            (name.as_str(), version.as_deref()),
            ("broken-tool", Some("2.0-3"))
        );
        let (_, doc) = metadata_at(&generic, broken).await.expect("rpm document");
        assert_eq!(doc["name"], "broken-tool");
        native.teardown().await;
        generic.teardown().await;
    }

    /// #5254: an Incus image PUT through the generic endpoint is named after
    /// its product and listed in `images.json` with its `metadata.yaml`
    /// fields, as a chunked upload is.
    #[tokio::test]
    async fn generic_put_incus_image_matches_the_chunked_upload_5254() {
        let Some((chunked, generic)) = pair("incus").await else {
            return;
        };
        let yaml = b"architecture: x86_64\nproperties:\n  os: Debian\n  release: trixie\n";
        let image = tgz(&[("metadata.yaml", &yaml[..])]);
        let path = "debian-trixie/20261101/incus.tar.gz";
        let (status, body) = chunked
            .chunked_upload(path, &image, serde_json::json!({}), false)
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_status(
            StatusCode::CREATED,
            generic_put(&generic, path, &image).await,
        );
        let (name, version, _) = row(&generic, path).await;
        assert_eq!(
            (name.as_str(), version.as_deref()),
            ("debian-trixie", Some("20261101"))
        );
        assert_eq!(
            metadata_at(&generic, path).await.expect("generic document"),
            metadata_at(&chunked, path).await.expect("chunked document")
        );
        let (status, body) = tdh::send(
            generic.router_with_auth(crate::api::handlers::incus::router()),
            tdh::get(format!("/{}/streams/v1/images.json", generic.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let catalog: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            catalog["products"]["debian-trixie"]["os"], "Debian",
            "{catalog}"
        );
        assert_eq!(
            catalog_version(&generic, "debian-trixie").await.as_deref(),
            Some("20261101")
        );
        chunked.teardown().await;
        generic.teardown().await;
    }

    /// #5254: a file that is not a package at its format's layout path keeps
    /// the generic behaviour: path-derived coordinates, the declared content
    /// type, no format document, never refused.
    #[tokio::test]
    async fn generic_put_of_a_non_package_file_keeps_the_generic_behaviour_5254() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let path = "docs/1.0/readme.txt";
        assert_status(
            StatusCode::CREATED,
            generic_put_with(&f, path, b"plain text", &[("content-type", "text/plain")]).await,
        );
        let (name, version, content_type) = row(&f, path).await;
        assert_eq!(
            (name.as_str(), version.as_deref(), content_type.as_str()),
            ("docs", Some("1.0"), "text/plain")
        );
        assert!(metadata_at(&f, path).await.is_none());
        f.teardown().await;
    }

    /// #5254: a TRUSTED replication push is stored as sent, as it skips the
    /// #3801 RPM header parse; nothing is derived or refused.
    #[tokio::test]
    async fn generic_put_trusted_replication_skips_the_native_finalize_5254() {
        let Some(f) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let path = "repl-pkg/1.0.0/repl-pkg-1.0.0.tgz";
        let mut req = tdh::put(
            format!("/{}/artifacts/{path}", f.repo_key),
            Bytes::from(npm_tgz("not-repl-pkg", "9.9.9")),
        );
        req.headers_mut().insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_static("true"),
        );
        let router = tdh::router_with_auth(
            crate::api::handlers::repositories::router(),
            f.state.clone(),
            tdh::admin_auth(f.user_id, &f.username),
        );
        assert_status(StatusCode::CREATED, tdh::send(router, req).await);
        let (name, version, _) = row(&f, path).await;
        assert_eq!(
            (name.as_str(), version.as_deref()),
            ("repl-pkg", Some("1.0.0"))
        );
        assert!(metadata_at(&f, path).await.is_none());
        f.teardown().await;
    }

    /// #5254: on an object-storage repository the Alpine finalize reads the
    /// package head from the staging object, and a package read as a file
    /// (npm, Debian) is spooled locally; all are indexed.
    #[tokio::test]
    async fn generic_put_on_object_storage_runs_the_native_finalize_5254() {
        for (format, path, bytes, name) in [
            (
                "npm",
                "cloud-pkg/1.0.0/cloud-pkg-1.0.0.tgz",
                npm_tgz("cloud-pkg", "1.0.0"),
                "cloud-pkg",
            ),
            (
                "alpine",
                "v3.24/main/aarch64/dtf-marker-1.0-r0.apk",
                MARKER_APK.to_vec(),
                "dtf-marker",
            ),
            (
                "alpine",
                "v3.24/main/aarch64/empty-1.0-r0.apk",
                Vec::new(),
                "empty",
            ),
            (
                "debian",
                "pool/main/c/cloud-deb/cloud-deb_1.0_amd64.deb",
                minimal_deb("cloud-deb", "1.0"),
                "cloud-deb",
            ),
        ] {
            let Some(mut f) = tdh::Fixture::setup("local", format).await else {
                return;
            };
            sqlx::query(
                "UPDATE repositories SET storage_backend = 's3', storage_path = key WHERE id = $1",
            )
            .bind(f.repo_id)
            .execute(&f.pool)
            .await
            .unwrap();
            let (state, _mem) = tdh::build_state_with_cloud(f.pool.clone(), "s3");
            f.state = state;
            assert_status(StatusCode::CREATED, generic_put(&f, path, &bytes).await);
            let (row_name, ..) = row(&f, path).await;
            assert_eq!(row_name, name, "{format}");
            let (document_format, _) = metadata_at(&f, path).await.expect("format document");
            assert_eq!(document_format, format);
            f.teardown().await;
        }
    }

    #[test]
    fn native_target_table_5254() {
        use RepositoryFormat as F;
        let t =
            |format: &F, p: &str| native_target(format, p).map(|t| (t.name, t.version, t.input));
        let some = |n: &str, v: &str, i| Some((n.to_string(), v.to_string(), i));
        use FinalizeInput::{Head, LocalFile, PathOnly};
        for (format, path, want) in [
            (
                F::Alpine,
                "v3.24/main/x86_64/nginx-1.30.6-r0.apk",
                some("nginx", "1.30.6-r0", Head),
            ),
            (F::Alpine, "v3.24/main/x86_64/APKINDEX.tar.gz", None),
            (F::Alpine, "main/x86_64/nginx-1.30.6-r0.apk", None),
            (F::Alpine, "v3.24//x86_64/nginx-1.30.6-r0.apk", None),
            (
                F::Alpine,
                "v3.24/main/x86_64/extra/nginx-1.30.6-r0.apk",
                None,
            ),
            (
                F::Debian,
                "pool/main/h/hello/hello_1.0-1_amd64.deb",
                some("hello", "1.0-1", LocalFile),
            ),
            (F::Debian, "dists/stable/Release", None),
            (
                F::Maven,
                "com/acme/demo/1.0/demo-1.0.jar",
                some("demo", "1.0", PathOnly),
            ),
            (
                F::Gradle,
                "com/acme/demo/1.0/demo-1.0.pom",
                some("demo", "1.0", LocalFile),
            ),
            (F::Maven, "com/acme/demo/1.0/demo-1.0.jar.sha1", None),
            (F::Maven, "com/acme/demo/maven-metadata.xml", None),
            (
                F::Npm,
                "left-pad/1.3.0/left-pad-1.3.0.tgz",
                some("left-pad", "1.3.0", LocalFile),
            ),
            (
                F::Npm,
                "@scope/pkg/2.1.0/pkg-2.1.0.tgz",
                some("@scope/pkg", "2.1.0", LocalFile),
            ),
            (
                F::Npm,
                "left-pad/-/left-pad-1.3.0.tgz",
                some("left-pad", "1.3.0", LocalFile),
            ),
            (
                F::Npm,
                "@scope/pkg/-/pkg-2.1.0.tgz",
                some("@scope/pkg", "2.1.0", LocalFile),
            ),
            (F::Npm, "left-pad/-/other-1.3.0.tgz", None),
            (F::Npm, "@/pkg/-/pkg-2.1.0.tgz", None),
            (F::Npm, "a/b/c/-/c-1.0.0.tgz", None),
            (F::Npm, "left-pad/-/left-pad-.tgz", None),
            (F::Npm, "left-pad/1.3.0/readme.md", None),
            (F::Npm, "left-pad.tgz", None),
            (
                F::Pypi,
                "demo/1.0/demo-1.0-py3-none-any.whl",
                some("demo", "1.0", LocalFile),
            ),
            (F::Pypi, "demo/1.0/notes.txt", None),
            (
                F::Rpm,
                "x/hello-2.10-1.el8.noarch.rpm",
                some("hello", "2.10-1.el8", LocalFile),
            ),
            (F::Rpm, "bad.rpm", None),
            (
                F::Incus,
                "ubuntu/2024/incus.tar.gz",
                some("ubuntu", "2024", LocalFile),
            ),
            (F::Lxc, "ubuntu/2024/SHA256SUMS", None),
            (F::Generic, "a/1.0/a.tgz", None),
        ] {
            assert_eq!(t(&format, path), want, "{format:?} {path}");
        }
        assert!(needs_local_file(
            &F::Debian,
            Some("pool/main/a/a/a_1_all.deb")
        ));
        assert!(!needs_local_file(&F::Debian, Some("dists/x/Release")));
        assert!(!needs_local_file(&F::Alpine, Some("a/b/c/d-1-r0.apk")));
        assert!(!needs_local_file(
            &F::Maven,
            Some("com/acme/demo/1.0/demo-1.0.jar")
        ));
        for format in [F::Pypi, F::Rpm, F::Npm, F::Maven, F::Incus, F::Debian] {
            assert!(needs_local_file(&format, None), "{format:?}");
        }
        assert!(!needs_local_file(&F::Alpine, None));
        assert!(!needs_local_file(&F::Generic, None));
        for (format, path, want) in [
            (
                F::Alpine,
                "a/b/c/d-1-r0.apk",
                Some("application/vnd.alpine.package"),
            ),
            (F::Maven, "a/b/1/b-1.jar", Some("application/java-archive")),
            (F::Npm, "a/1/a-1.tgz", Some("application/gzip")),
            (F::Pypi, "a-1.tar.gz", Some("application/gzip")),
            (F::Rpm, "a-1-1.x86_64.rpm", Some("application/x-rpm")),
            (
                F::Debian,
                "pool/main/a/a/a_1_all.deb",
                Some("application/vnd.debian.binary-package"),
            ),
            (F::Incus, "a/1/incus.tar.gz", None),
        ] {
            assert_eq!(native_content_type(&format, path), want, "{format:?}");
        }
    }

    #[test]
    fn npm_identity_helpers_5254() {
        assert_eq!(clean_npm_version(" v1.2.3+build.5 "), "1.2.3");
        assert_eq!(clean_npm_version("=1.0.0"), "1.0.0");
        assert!(is_root_package_json(std::path::Path::new(
            "package/package.json"
        )));
        assert!(is_root_package_json(std::path::Path::new(
            "./other/package.json"
        )));
        assert!(!is_root_package_json(std::path::Path::new(
            "package/dist/package.json"
        )));
        assert!(!is_root_package_json(std::path::Path::new("package.json")));
    }

    /// A finalize that reads a file refuses a source without one, and the
    /// Alpine finalize reads only the head and takes the `.PKGINFO` identity.
    #[tokio::test]
    async fn stage_sources_and_alpine_identity_5254() {
        let target = |name: &str, version: &str, input| NativeTarget {
            name: name.into(),
            version: version.into(),
            input,
        };
        for format in [
            RepositoryFormat::Incus,
            RepositoryFormat::Debian,
            RepositoryFormat::Npm,
            RepositoryFormat::Pypi,
            RepositoryFormat::Rpm,
        ] {
            assert!(stage(
                &format,
                "a/1/a-1.tgz",
                target("a", "1", FinalizeInput::LocalFile),
                FinalizeSource::None
            )
            .await
            .is_err());
        }
        assert!(stage(
            &RepositoryFormat::Generic,
            "a",
            target("a", "1", FinalizeInput::PathOnly),
            FinalizeSource::None
        )
        .await
        .is_err());

        // A file name that misreads the identity is corrected by `.PKGINFO`.
        let (resolved, staged) = stage(
            &RepositoryFormat::Alpine,
            "v3.24/main/aarch64/dtf-marker-1.0-r0.apk",
            target("dtf", "marker-1.0-r0", FinalizeInput::Head),
            FinalizeSource::Head(MARKER_APK.to_vec()),
        )
        .await
        .unwrap();
        assert_eq!(
            (resolved.name.as_str(), resolved.version.as_str()),
            ("dtf-marker", "1.0-r0")
        );
        let StagedNativeFinalize::Alpine(alpine) = staged else {
            panic!("an Alpine finalize");
        };
        assert_eq!(alpine.document["name"], "dtf-marker");
        assert_eq!(alpine.document["arch"], "aarch64");
        assert_eq!(alpine.document["branch"], "v3.24");

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pkg.apk");
        std::fs::write(&file, MARKER_APK).unwrap();
        assert_eq!(read_file_head(&file, 4).await.unwrap(), &MARKER_APK[..4]);
        let (resolved, _) = stage(
            &RepositoryFormat::Alpine,
            "v3.24/main/aarch64/dtf-marker-1.0-r0.apk",
            target("dtf-marker", "1.0-r0", FinalizeInput::Head),
            FinalizeSource::File(&file),
        )
        .await
        .unwrap();
        assert_eq!(resolved.name, "dtf-marker");
    }
}
