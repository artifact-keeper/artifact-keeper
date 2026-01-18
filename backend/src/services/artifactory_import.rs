//! Artifactory Export Import Service
//!
//! This module handles importing from JFrog Artifactory export directories or archives.
//! Artifactory exports typically contain:
//! - repositories/ - Repository configurations and artifacts
//! - etc/security/ - Users, groups, and permissions
//! - etc/artifactory/ - System configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zip::ZipArchive;

/// Errors that can occur during import
#[derive(Error, Debug)]
pub enum ImportError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON parsing error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("ZIP archive error: {0}")]
    ZipError(#[from] zip::result::ZipError),

    #[error("Invalid export format: {0}")]
    InvalidFormat(String),

    #[error("Missing required file: {0}")]
    MissingFile(String),

    #[error("Unsupported export version: {0}")]
    UnsupportedVersion(String),
}

/// Artifactory export metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    pub version: String,
    pub export_time: Option<String>,
    pub artifactory_version: Option<String>,
    pub repositories: Vec<String>,
    pub has_security: bool,
    pub total_artifacts: u64,
    pub total_size_bytes: u64,
}

/// Repository configuration from export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedRepository {
    pub key: String,
    pub repo_type: String,
    pub package_type: String,
    pub description: Option<String>,
    pub includes_pattern: Option<String>,
    pub excludes_pattern: Option<String>,
    pub handle_releases: bool,
    pub handle_snapshots: bool,
    pub layout: Option<String>,
}

/// Artifact entry from export
#[derive(Debug, Clone)]
pub struct ImportedArtifact {
    pub repo_key: String,
    pub path: String,
    pub name: String,
    pub file_path: PathBuf,
    pub size: u64,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub properties: HashMap<String, Vec<String>>,
}

/// User from export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedUser {
    pub username: String,
    pub email: Option<String>,
    pub admin: bool,
    pub enabled: bool,
    pub groups: Vec<String>,
    pub realm: Option<String>,
}

/// Group from export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedGroup {
    pub name: String,
    pub description: Option<String>,
    pub auto_join: bool,
    pub realm: Option<String>,
    pub admin_privileges: bool,
}

/// Permission target from export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedPermission {
    pub name: String,
    pub repositories: Vec<String>,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub users: HashMap<String, Vec<String>>,
    pub groups: HashMap<String, Vec<String>>,
}

/// Import progress callback
pub type ProgressCallback = Box<dyn Fn(ImportProgress) + Send + Sync>;

/// Import progress update
#[derive(Debug, Clone, Serialize)]
pub struct ImportProgress {
    pub phase: String,
    pub current: u64,
    pub total: u64,
    pub current_item: Option<String>,
    pub message: String,
}

/// Artifactory export importer
pub struct ArtifactoryImporter {
    /// Root path of the export (directory or extracted archive)
    root_path: PathBuf,
    /// Temporary directory for extracted archives
    temp_dir: Option<PathBuf>,
    /// Progress callback
    progress_callback: Option<ProgressCallback>,
}

impl ArtifactoryImporter {
    /// Create a new importer for a directory export
    pub fn from_directory(path: &Path) -> Result<Self, ImportError> {
        if !path.is_dir() {
            return Err(ImportError::InvalidFormat(
                "Path is not a directory".to_string(),
            ));
        }

        // Validate it looks like an Artifactory export
        Self::validate_export_structure(path)?;

        Ok(Self {
            root_path: path.to_path_buf(),
            temp_dir: None,
            progress_callback: None,
        })
    }

    /// Create a new importer from a ZIP archive
    pub fn from_archive(archive_path: &Path) -> Result<Self, ImportError> {
        if !archive_path.is_file() {
            return Err(ImportError::InvalidFormat(
                "Archive path is not a file".to_string(),
            ));
        }

        // Create temp directory for extraction
        let temp_dir = tempfile::tempdir()
            .map_err(|e| ImportError::Io(io::Error::new(io::ErrorKind::Other, e)))?;
        let temp_path = temp_dir.path().to_path_buf();

        // Extract archive
        let file = File::open(archive_path)?;
        let reader = BufReader::new(file);
        let mut archive = ZipArchive::new(reader)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = match file.enclosed_name() {
                Some(path) => temp_path.join(path),
                None => continue,
            };

            if file.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        fs::create_dir_all(p)?;
                    }
                }
                let mut outfile = File::create(&outpath)?;
                io::copy(&mut file, &mut outfile)?;
            }
        }

        // Find the actual export root (may be nested in the archive)
        let export_root = Self::find_export_root(&temp_path)?;

        // Keep the temp directory so it's not deleted when the function returns
        let temp_path_owned = temp_dir
            .keep()
            .map_err(|e| ImportError::Io(io::Error::other(e.to_string())))?;

        Ok(Self {
            root_path: export_root,
            temp_dir: Some(temp_path_owned),
            progress_callback: None,
        })
    }

    /// Set progress callback
    pub fn with_progress_callback(mut self, callback: ProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// Find the export root directory (handles nested structures)
    fn find_export_root(path: &Path) -> Result<PathBuf, ImportError> {
        // Check if current path is a valid export
        if Self::is_valid_export(path) {
            return Ok(path.to_path_buf());
        }

        // Check one level down
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            if entry_path.is_dir() && Self::is_valid_export(&entry_path) {
                return Ok(entry_path);
            }
        }

        Err(ImportError::InvalidFormat(
            "Could not find valid Artifactory export structure".to_string(),
        ))
    }

    /// Check if a path looks like a valid Artifactory export
    fn is_valid_export(path: &Path) -> bool {
        // Must have repositories directory
        path.join("repositories").exists()
    }

    /// Validate export structure
    fn validate_export_structure(path: &Path) -> Result<(), ImportError> {
        if !path.join("repositories").exists() {
            return Err(ImportError::InvalidFormat(
                "Missing 'repositories' directory".to_string(),
            ));
        }
        Ok(())
    }

    /// Report progress
    fn report_progress(&self, progress: ImportProgress) {
        if let Some(ref callback) = self.progress_callback {
            callback(progress);
        }
    }

    /// Get export metadata
    pub fn get_metadata(&self) -> Result<ExportMetadata, ImportError> {
        let mut metadata = ExportMetadata {
            version: "unknown".to_string(),
            export_time: None,
            artifactory_version: None,
            repositories: Vec::new(),
            has_security: false,
            total_artifacts: 0,
            total_size_bytes: 0,
        };

        // Check for artifactory.config.xml or similar
        let config_path = self
            .root_path
            .join("etc/artifactory/artifactory.config.xml");
        if config_path.exists() {
            // Parse for version info if needed
            metadata.artifactory_version = Some("detected".to_string());
        }

        // List repositories
        let repos_path = self.root_path.join("repositories");
        if repos_path.exists() {
            for entry in fs::read_dir(&repos_path)? {
                let entry = entry?;
                if entry.path().is_dir() {
                    let repo_name = entry.file_name().to_string_lossy().to_string();
                    // Skip metadata directories
                    if !repo_name.starts_with('.') && repo_name != "_index" {
                        metadata.repositories.push(repo_name);
                    }
                }
            }
        }

        // Check for security data
        let security_path = self.root_path.join("etc/security");
        metadata.has_security = security_path.exists();

        // Count artifacts and calculate size
        for repo in &metadata.repositories {
            let repo_path = repos_path.join(repo);
            if let Ok((count, size)) = Self::count_artifacts_in_dir(&repo_path) {
                metadata.total_artifacts += count;
                metadata.total_size_bytes += size;
            }
        }

        Ok(metadata)
    }

    /// Count artifacts in a directory recursively
    fn count_artifacts_in_dir(path: &Path) -> Result<(u64, u64), ImportError> {
        let mut count = 0u64;
        let mut size = 0u64;

        if !path.exists() {
            return Ok((0, 0));
        }

        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                // Skip metadata files
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default();
                if !name.ends_with(".properties") && !name.starts_with('.') {
                    count += 1;
                    size += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }

        Ok((count, size))
    }

    /// List repositories from export
    pub fn list_repositories(&self) -> Result<Vec<ImportedRepository>, ImportError> {
        let mut repositories = Vec::new();
        let repos_path = self.root_path.join("repositories");

        self.report_progress(ImportProgress {
            phase: "scanning".to_string(),
            current: 0,
            total: 0,
            current_item: None,
            message: "Scanning repositories...".to_string(),
        });

        for entry in fs::read_dir(&repos_path)? {
            let entry = entry?;
            if entry.path().is_dir() {
                let repo_name = entry.file_name().to_string_lossy().to_string();
                if repo_name.starts_with('.') || repo_name == "_index" {
                    continue;
                }

                // Try to read repository config
                let repo = self.read_repository_config(&entry.path(), &repo_name)?;
                repositories.push(repo);
            }
        }

        Ok(repositories)
    }

    /// Read repository configuration from export
    fn read_repository_config(
        &self,
        repo_path: &Path,
        repo_name: &str,
    ) -> Result<ImportedRepository, ImportError> {
        // Try to find repo-config.xml or similar
        let config_path = repo_path.join(".meta/repo-config.xml");

        if config_path.exists() {
            // Parse XML config
            let content = fs::read_to_string(&config_path)?;
            return Self::parse_repo_config_xml(&content, repo_name);
        }

        // Try JSON config
        let json_config_path = repo_path.join(".meta/repo-config.json");
        if json_config_path.exists() {
            let content = fs::read_to_string(&json_config_path)?;
            let repo: ImportedRepository = serde_json::from_str(&content)?;
            return Ok(repo);
        }

        // Infer from directory structure
        Ok(ImportedRepository {
            key: repo_name.to_string(),
            repo_type: Self::infer_repo_type(repo_name),
            package_type: Self::infer_package_type(repo_path, repo_name),
            description: None,
            includes_pattern: None,
            excludes_pattern: None,
            handle_releases: true,
            handle_snapshots: true,
            layout: None,
        })
    }

    /// Parse repository config from XML
    fn parse_repo_config_xml(
        content: &str,
        repo_name: &str,
    ) -> Result<ImportedRepository, ImportError> {
        // Simple XML parsing using quick-xml
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut repo = ImportedRepository {
            key: repo_name.to_string(),
            repo_type: "local".to_string(),
            package_type: "generic".to_string(),
            description: None,
            includes_pattern: None,
            excludes_pattern: None,
            handle_releases: true,
            handle_snapshots: true,
            layout: None,
        };

        let mut current_tag = String::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                }
                Ok(Event::Text(e)) => {
                    let text = String::from_utf8_lossy(&e).to_string();
                    match current_tag.as_str() {
                        "key" => repo.key = text,
                        "type" | "rclass" => repo.repo_type = text,
                        "packageType" => repo.package_type = text,
                        "description" => repo.description = Some(text),
                        "includesPattern" => repo.includes_pattern = Some(text),
                        "excludesPattern" => repo.excludes_pattern = Some(text),
                        "handleReleases" => repo.handle_releases = text == "true",
                        "handleSnapshots" => repo.handle_snapshots = text == "true",
                        "repoLayoutRef" => repo.layout = Some(text),
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ImportError::InvalidFormat(format!(
                        "XML parse error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(repo)
    }

    /// Infer repository type from name conventions
    fn infer_repo_type(name: &str) -> String {
        if name.contains("-remote") || name.ends_with("-cache") {
            "remote".to_string()
        } else if name.contains("-virtual") {
            "virtual".to_string()
        } else {
            "local".to_string()
        }
    }

    /// Infer package type from repository content
    fn infer_package_type(repo_path: &Path, name: &str) -> String {
        // Check name patterns
        let name_lower = name.to_lowercase();
        if name_lower.contains("maven") || name_lower.contains("libs-") {
            return "maven".to_string();
        }
        if name_lower.contains("npm") {
            return "npm".to_string();
        }
        if name_lower.contains("docker") {
            return "docker".to_string();
        }
        if name_lower.contains("pypi") || name_lower.contains("python") {
            return "pypi".to_string();
        }
        if name_lower.contains("nuget") {
            return "nuget".to_string();
        }
        if name_lower.contains("helm") {
            return "helm".to_string();
        }
        if name_lower.contains("cargo") || name_lower.contains("rust") {
            return "cargo".to_string();
        }
        if name_lower.contains("go") || name_lower.contains("golang") {
            return "go".to_string();
        }

        // Check directory contents for common patterns
        if repo_path.exists() {
            // Maven: has pom.xml files
            for entry in walkdir::WalkDir::new(repo_path)
                .max_depth(5)
                .into_iter()
                .filter_map(|e| e.ok())
                .take(100)
            {
                let name = entry.file_name().to_string_lossy();
                if name.ends_with(".pom") || name == "pom.xml" {
                    return "maven".to_string();
                }
                if name == "package.json" {
                    return "npm".to_string();
                }
                if name.ends_with(".whl") || name == "setup.py" {
                    return "pypi".to_string();
                }
                if name.ends_with(".nupkg") {
                    return "nuget".to_string();
                }
            }
        }

        "generic".to_string()
    }

    /// Iterate over artifacts in a repository
    pub fn list_artifacts(
        &self,
        repo_key: &str,
    ) -> Result<impl Iterator<Item = Result<ImportedArtifact, ImportError>> + '_, ImportError> {
        let repo_path = self.root_path.join("repositories").join(repo_key);

        if !repo_path.exists() {
            return Err(ImportError::MissingFile(format!(
                "Repository not found: {}",
                repo_key
            )));
        }

        let walker = walkdir::WalkDir::new(&repo_path).into_iter();
        let repo_key = repo_key.to_string();

        Ok(walker.filter_map(move |entry| {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => return Some(Err(ImportError::Io(e.into()))),
            };

            let path = entry.path();

            // Skip directories and metadata files
            if !path.is_file() {
                return None;
            }

            let name = path.file_name()?.to_string_lossy().to_string();

            // Skip metadata files
            if name.ends_with(".properties")
                || name.starts_with('.')
                || name.ends_with(".xml")
                || name.ends_with(".sha1")
                || name.ends_with(".sha256")
                || name.ends_with(".md5")
            {
                return None;
            }

            // Get relative path within repository
            let relative_path = path.strip_prefix(&repo_path).ok()?;
            let parent_path = relative_path.parent().unwrap_or(Path::new(""));

            // Read properties if available
            let properties_path = path.with_extension(format!(
                "{}.properties",
                path.extension().unwrap_or_default().to_string_lossy()
            ));

            let mut artifact = ImportedArtifact {
                repo_key: repo_key.clone(),
                path: parent_path.to_string_lossy().to_string(),
                name: name.clone(),
                file_path: path.to_path_buf(),
                size: entry.metadata().ok()?.len(),
                sha1: None,
                sha256: None,
                md5: None,
                created: None,
                modified: None,
                properties: HashMap::new(),
            };

            // Try to read checksums
            if let Ok(sha1) = fs::read_to_string(path.with_extension(format!(
                "{}.sha1",
                path.extension().unwrap_or_default().to_string_lossy()
            ))) {
                artifact.sha1 = Some(sha1.trim().to_string());
            }

            if let Ok(sha256) = fs::read_to_string(path.with_extension(format!(
                "{}.sha256",
                path.extension().unwrap_or_default().to_string_lossy()
            ))) {
                artifact.sha256 = Some(sha256.trim().to_string());
            }

            if let Ok(md5) = fs::read_to_string(path.with_extension(format!(
                "{}.md5",
                path.extension().unwrap_or_default().to_string_lossy()
            ))) {
                artifact.md5 = Some(md5.trim().to_string());
            }

            // Try to read properties
            if properties_path.exists() {
                if let Ok(props) = Self::read_properties_file(&properties_path) {
                    artifact.properties = props;
                    artifact.created = artifact
                        .properties
                        .get("artifactory.created")
                        .and_then(|v| v.first().cloned());
                    artifact.modified = artifact
                        .properties
                        .get("artifactory.modified")
                        .and_then(|v| v.first().cloned());
                }
            }

            Some(Ok(artifact))
        }))
    }

    /// Read a properties file
    fn read_properties_file(path: &Path) -> Result<HashMap<String, Vec<String>>, ImportError> {
        let content = fs::read_to_string(path)?;
        let mut properties = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();
                properties.entry(key).or_insert_with(Vec::new).push(value);
            }
        }

        Ok(properties)
    }

    /// Read artifact file content
    pub fn read_artifact(&self, artifact: &ImportedArtifact) -> Result<Vec<u8>, ImportError> {
        fs::read(&artifact.file_path).map_err(ImportError::from)
    }

    /// Read artifact file as stream
    pub fn open_artifact(&self, artifact: &ImportedArtifact) -> Result<File, ImportError> {
        File::open(&artifact.file_path).map_err(ImportError::from)
    }

    /// List users from export
    pub fn list_users(&self) -> Result<Vec<ImportedUser>, ImportError> {
        let users_path = self.root_path.join("etc/security/users.xml");

        if !users_path.exists() {
            // Try alternative location
            let alt_path = self.root_path.join("security/users.xml");
            if !alt_path.exists() {
                return Ok(Vec::new());
            }
            return self.parse_users_xml(&alt_path);
        }

        self.parse_users_xml(&users_path)
    }

    /// Parse users.xml
    fn parse_users_xml(&self, path: &Path) -> Result<Vec<ImportedUser>, ImportError> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let content = fs::read_to_string(path)?;
        let mut reader = Reader::from_str(&content);
        reader.config_mut().trim_text(true);

        let mut users = Vec::new();
        let mut current_user: Option<ImportedUser> = None;
        let mut current_tag = String::new();
        let mut in_groups = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    current_tag = tag.clone();

                    if tag == "user" {
                        current_user = Some(ImportedUser {
                            username: String::new(),
                            email: None,
                            admin: false,
                            enabled: true,
                            groups: Vec::new(),
                            realm: None,
                        });
                    } else if tag == "groups" {
                        in_groups = true;
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag == "user" {
                        if let Some(user) = current_user.take() {
                            if !user.username.is_empty() {
                                users.push(user);
                            }
                        }
                    } else if tag == "groups" {
                        in_groups = false;
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = String::from_utf8_lossy(&e).to_string();
                    if let Some(ref mut user) = current_user {
                        match current_tag.as_str() {
                            "username" | "name" => user.username = text,
                            "email" => user.email = Some(text),
                            "admin" => user.admin = text == "true",
                            "enabled" => user.enabled = text == "true",
                            "realm" => user.realm = Some(text),
                            "group" | "groupName" if in_groups => {
                                user.groups.push(text);
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ImportError::InvalidFormat(format!(
                        "XML parse error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(users)
    }

    /// List groups from export
    pub fn list_groups(&self) -> Result<Vec<ImportedGroup>, ImportError> {
        let groups_path = self.root_path.join("etc/security/groups.xml");

        if !groups_path.exists() {
            let alt_path = self.root_path.join("security/groups.xml");
            if !alt_path.exists() {
                return Ok(Vec::new());
            }
            return self.parse_groups_xml(&alt_path);
        }

        self.parse_groups_xml(&groups_path)
    }

    /// Parse groups.xml
    fn parse_groups_xml(&self, path: &Path) -> Result<Vec<ImportedGroup>, ImportError> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let content = fs::read_to_string(path)?;
        let mut reader = Reader::from_str(&content);
        reader.config_mut().trim_text(true);

        let mut groups = Vec::new();
        let mut current_group: Option<ImportedGroup> = None;
        let mut current_tag = String::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    current_tag = tag.clone();

                    if tag == "group" {
                        current_group = Some(ImportedGroup {
                            name: String::new(),
                            description: None,
                            auto_join: false,
                            realm: None,
                            admin_privileges: false,
                        });
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag == "group" {
                        if let Some(group) = current_group.take() {
                            if !group.name.is_empty() {
                                groups.push(group);
                            }
                        }
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = String::from_utf8_lossy(&e).to_string();
                    if let Some(ref mut group) = current_group {
                        match current_tag.as_str() {
                            "name" | "groupName" => group.name = text,
                            "description" => group.description = Some(text),
                            "autoJoin" => group.auto_join = text == "true",
                            "realm" => group.realm = Some(text),
                            "adminPrivileges" => group.admin_privileges = text == "true",
                            _ => {}
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ImportError::InvalidFormat(format!(
                        "XML parse error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(groups)
    }

    /// List permissions from export
    pub fn list_permissions(&self) -> Result<Vec<ImportedPermission>, ImportError> {
        let perms_path = self.root_path.join("etc/security/permissions.xml");

        if !perms_path.exists() {
            let alt_path = self.root_path.join("security/permissions.xml");
            if !alt_path.exists() {
                return Ok(Vec::new());
            }
            return self.parse_permissions_xml(&alt_path);
        }

        self.parse_permissions_xml(&perms_path)
    }

    /// Parse permissions.xml
    fn parse_permissions_xml(&self, path: &Path) -> Result<Vec<ImportedPermission>, ImportError> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let content = fs::read_to_string(path)?;
        let mut reader = Reader::from_str(&content);
        reader.config_mut().trim_text(true);

        let mut permissions = Vec::new();
        let mut current_perm: Option<ImportedPermission> = None;
        let mut current_tag = String::new();
        let mut in_repositories = false;
        let mut in_users = false;
        let mut in_groups = false;
        let mut current_principal = String::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    current_tag = tag.clone();

                    if tag == "permissionTarget" || tag == "permission" {
                        current_perm = Some(ImportedPermission {
                            name: String::new(),
                            repositories: Vec::new(),
                            include_patterns: Vec::new(),
                            exclude_patterns: Vec::new(),
                            users: HashMap::new(),
                            groups: HashMap::new(),
                        });
                    } else if tag == "repositories" {
                        in_repositories = true;
                    } else if tag == "users" {
                        in_users = true;
                    } else if tag == "groups" {
                        in_groups = true;
                    } else if (tag == "user" || tag == "group") && (in_users || in_groups) {
                        // Get name attribute
                        for attr in e.attributes().filter_map(|a| a.ok()) {
                            if attr.key.as_ref() == b"name" {
                                current_principal =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag == "permissionTarget" || tag == "permission" {
                        if let Some(perm) = current_perm.take() {
                            if !perm.name.is_empty() {
                                permissions.push(perm);
                            }
                        }
                    } else if tag == "repositories" {
                        in_repositories = false;
                    } else if tag == "users" {
                        in_users = false;
                    } else if tag == "groups" {
                        in_groups = false;
                    } else if tag == "user" || tag == "group" {
                        current_principal.clear();
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = String::from_utf8_lossy(&e).to_string();
                    if let Some(ref mut perm) = current_perm {
                        match current_tag.as_str() {
                            "name" if !in_users && !in_groups => perm.name = text,
                            "repo" | "repository" if in_repositories => {
                                perm.repositories.push(text);
                            }
                            "includePattern" => perm.include_patterns.push(text),
                            "excludePattern" => perm.exclude_patterns.push(text),
                            "permission" if in_users && !current_principal.is_empty() => {
                                perm.users
                                    .entry(current_principal.clone())
                                    .or_default()
                                    .push(text);
                            }
                            "permission" if in_groups && !current_principal.is_empty() => {
                                perm.groups
                                    .entry(current_principal.clone())
                                    .or_default()
                                    .push(text);
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ImportError::InvalidFormat(format!(
                        "XML parse error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(permissions)
    }
}

impl Drop for ArtifactoryImporter {
    fn drop(&mut self) {
        // Clean up temp directory if we extracted an archive
        if let Some(ref temp_dir) = self.temp_dir {
            let _ = fs::remove_dir_all(temp_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_export() -> TempDir {
        let temp = TempDir::new().unwrap();

        // Create basic structure
        fs::create_dir_all(temp.path().join("repositories/libs-release")).unwrap();
        fs::create_dir_all(temp.path().join("repositories/libs-snapshot")).unwrap();
        fs::create_dir_all(temp.path().join("etc/security")).unwrap();

        // Create a test artifact
        let artifact_path = temp
            .path()
            .join("repositories/libs-release/com/example/test/1.0/test-1.0.jar");
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, b"test artifact content").unwrap();

        // Create checksum files
        fs::write(artifact_path.with_extension("jar.sha1"), "abc123").unwrap();

        // Create users.xml
        let users_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user>
        <username>admin</username>
        <email>admin@example.com</email>
        <admin>true</admin>
        <enabled>true</enabled>
        <groups>
            <group>readers</group>
        </groups>
    </user>
    <user>
        <username>developer</username>
        <email>dev@example.com</email>
        <admin>false</admin>
        <enabled>true</enabled>
    </user>
</users>"#;
        fs::write(temp.path().join("etc/security/users.xml"), users_xml).unwrap();

        // Create groups.xml
        let groups_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<groups>
    <group>
        <name>readers</name>
        <description>Read-only users</description>
        <autoJoin>false</autoJoin>
    </group>
    <group>
        <name>deployers</name>
        <description>Can deploy artifacts</description>
        <autoJoin>false</autoJoin>
    </group>
</groups>"#;
        fs::write(temp.path().join("etc/security/groups.xml"), groups_xml).unwrap();

        temp
    }

    #[test]
    fn test_create_importer_from_directory() {
        let temp = create_test_export();
        let importer = ArtifactoryImporter::from_directory(temp.path()).unwrap();
        assert!(importer.root_path.exists());
    }

    #[test]
    fn test_get_metadata() {
        let temp = create_test_export();
        let importer = ArtifactoryImporter::from_directory(temp.path()).unwrap();
        let metadata = importer.get_metadata().unwrap();

        assert!(metadata.repositories.contains(&"libs-release".to_string()));
        assert!(metadata.repositories.contains(&"libs-snapshot".to_string()));
        assert!(metadata.has_security);
    }

    #[test]
    fn test_list_repositories() {
        let temp = create_test_export();
        let importer = ArtifactoryImporter::from_directory(temp.path()).unwrap();
        let repos = importer.list_repositories().unwrap();

        assert_eq!(repos.len(), 2);
        let repo_names: Vec<_> = repos.iter().map(|r| r.key.as_str()).collect();
        assert!(repo_names.contains(&"libs-release"));
        assert!(repo_names.contains(&"libs-snapshot"));
    }

    #[test]
    fn test_list_artifacts() {
        let temp = create_test_export();
        let importer = ArtifactoryImporter::from_directory(temp.path()).unwrap();
        let artifacts: Vec<_> = importer
            .list_artifacts("libs-release")
            .unwrap()
            .filter_map(|a| a.ok())
            .collect();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "test-1.0.jar");
        assert_eq!(artifacts[0].sha1, Some("abc123".to_string()));
    }

    #[test]
    fn test_list_users() {
        let temp = create_test_export();
        let importer = ArtifactoryImporter::from_directory(temp.path()).unwrap();
        let users = importer.list_users().unwrap();

        assert_eq!(users.len(), 2);
        let admin = users.iter().find(|u| u.username == "admin").unwrap();
        assert!(admin.admin);
        assert_eq!(admin.email, Some("admin@example.com".to_string()));
    }

    #[test]
    fn test_list_groups() {
        let temp = create_test_export();
        let importer = ArtifactoryImporter::from_directory(temp.path()).unwrap();
        let groups = importer.list_groups().unwrap();

        assert_eq!(groups.len(), 2);
        let readers = groups.iter().find(|g| g.name == "readers").unwrap();
        assert_eq!(readers.description, Some("Read-only users".to_string()));
    }

    #[test]
    fn test_infer_repo_type() {
        assert_eq!(
            ArtifactoryImporter::infer_repo_type("libs-release"),
            "local"
        );
        assert_eq!(
            ArtifactoryImporter::infer_repo_type("jcenter-remote"),
            "remote"
        );
        assert_eq!(
            ArtifactoryImporter::infer_repo_type("libs-virtual"),
            "virtual"
        );
    }
}
