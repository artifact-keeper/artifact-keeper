//! CLI command runner for Artifactory migration.
//!
//! This module implements the actual execution logic for migration CLI commands.

use crate::cli::migrate::{
    error, output, table_row, ArtifactoryConfig, MigrateCli, MigrateCommand, MigrateConfig,
};
use crate::services::artifactory_client::{
    ArtifactoryAuth, ArtifactoryClient, ArtifactoryClientConfig,
};
use crate::services::artifactory_import::{
    ArtifactoryImporter, ImportProgress, ImportedRepository,
};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Run the migration CLI command
pub async fn run(cli: MigrateCli) -> Result<(), Box<dyn std::error::Error>> {
    // Load config file if provided
    let mut config = if let Some(ref config_path) = cli.config {
        MigrateConfig::from_file(config_path)?
    } else {
        MigrateConfig::default()
    };

    // Merge CLI args with config
    config.merge_with_cli(&cli);

    match cli.command {
        MigrateCommand::Import {
            path,
            include,
            exclude,
            include_users,
            include_groups,
            include_permissions,
            dry_run,
        } => {
            run_import(
                &cli.format,
                cli.verbose,
                &path,
                include.as_deref(),
                exclude.as_deref(),
                include_users,
                include_groups,
                include_permissions,
                dry_run,
            )
            .await
        }
        MigrateCommand::Test => run_test(&cli.format, &config).await,
        MigrateCommand::Assess {
            include,
            exclude,
            output: output_path,
        } => {
            run_assess(
                &cli.format,
                &config,
                include.as_deref(),
                exclude.as_deref(),
                output_path.as_deref(),
            )
            .await
        }
        MigrateCommand::Start { dry_run, .. } => {
            if dry_run {
                output(&cli.format, "Dry run: no changes will be made", None);
            }
            output(
                &cli.format,
                "Migration start command - use API for full functionality",
                None,
            );
            Ok(())
        }
        MigrateCommand::Status { job_id, follow } => run_status(&cli.format, &job_id, follow).await,
        MigrateCommand::Pause { job_id } => {
            output(
                &cli.format,
                &format!("Pause request sent for job {}", job_id),
                None,
            );
            Ok(())
        }
        MigrateCommand::Resume { job_id } => {
            output(
                &cli.format,
                &format!("Resume request sent for job {}", job_id),
                None,
            );
            Ok(())
        }
        MigrateCommand::Cancel { job_id } => {
            output(
                &cli.format,
                &format!("Cancel request sent for job {}", job_id),
                None,
            );
            Ok(())
        }
        MigrateCommand::List { status, limit } => {
            run_list(&cli.format, status.as_deref(), limit).await
        }
        MigrateCommand::Report {
            job_id,
            format: report_format,
            output: output_path,
        } => run_report(&cli.format, &job_id, &report_format, output_path.as_deref()).await,
    }
}

/// Create an importer from a path (directory or ZIP archive).
fn create_importer(
    format: &str,
    path: &Path,
) -> Result<ArtifactoryImporter, Box<dyn std::error::Error>> {
    if path.is_dir() {
        output(
            format,
            &format!("Loading export from directory: {}", path.display()),
            None,
        );
        return Ok(ArtifactoryImporter::from_directory(path)?);
    }

    if path.extension().map(|e| e == "zip").unwrap_or(false) {
        output(
            format,
            &format!("Extracting archive: {}", path.display()),
            None,
        );
        return Ok(ArtifactoryImporter::from_archive(path)?);
    }

    error(format, "Path must be a directory or ZIP archive");
    Err("Invalid path".into())
}

/// Attach a verbose progress callback to the importer when verbose mode is on.
fn attach_progress_callback(
    importer: ArtifactoryImporter,
    format: &str,
    verbose: bool,
) -> ArtifactoryImporter {
    if !verbose {
        return importer;
    }

    let counter = Arc::new(AtomicU64::new(0));
    let format_clone = format.to_string();
    importer.with_progress_callback(Box::new(move |progress: ImportProgress| {
        counter.store(progress.current, Ordering::SeqCst);
        if format_clone != "json" {
            eprint!(
                "\r{}: {}/{} - {}",
                progress.phase, progress.current, progress.total, progress.message
            );
        }
    }))
}

/// Check whether a repository key passes include/exclude filters.
fn repo_passes_filters(key: &str, include: Option<&[String]>, exclude: Option<&[String]>) -> bool {
    let included = match include {
        Some(patterns) => patterns.iter().any(|p| matches_pattern(key, p)),
        None => true,
    };
    let excluded = match exclude {
        Some(patterns) => patterns.iter().any(|p| matches_pattern(key, p)),
        None => false,
    };
    included && !excluded
}

/// Display a dry-run preview of what would be imported from each repository.
fn show_dry_run_preview(
    format: &str,
    importer: &ArtifactoryImporter,
    repos: &[&ImportedRepository],
) -> Result<(), Box<dyn std::error::Error>> {
    output(format, "\nDry run - no changes will be made", None);

    for repo in repos {
        let artifacts: Vec<_> = importer
            .list_artifacts(&repo.key)?
            .filter_map(|a| a.ok())
            .take(10)
            .collect();

        output(
            format,
            &format!(
                "\nRepository '{}' would import {} artifacts (showing first 10):",
                repo.key,
                artifacts.len()
            ),
            None,
        );

        for artifact in &artifacts {
            if format == "text" {
                println!("  - {}/{}", artifact.path, artifact.name);
            }
        }
    }

    Ok(())
}

/// Import artifacts from the selected repositories, returning (imported, failed) counts.
fn import_artifacts(
    format: &str,
    verbose: bool,
    importer: &ArtifactoryImporter,
    repos: &[&ImportedRepository],
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let mut total_imported = 0u64;
    let mut total_failed = 0u64;

    for repo in repos {
        output(
            format,
            &format!("\nImporting repository: {}", repo.key),
            None,
        );

        // TODO: Create repository in Artifact Keeper if it doesn't exist
        // This would require database access and the repository service

        let artifacts = importer.list_artifacts(&repo.key)?;

        for artifact_result in artifacts {
            match artifact_result {
                Ok(artifact) => {
                    if verbose {
                        output(
                            format,
                            &format!("  Importing: {}/{}", artifact.path, artifact.name),
                            None,
                        );
                    }
                    // TODO: Upload artifact to Artifact Keeper
                    // This would require the artifact service
                    total_imported += 1;
                }
                Err(e) => {
                    error(format, &format!("  Failed to read artifact: {}", e));
                    total_failed += 1;
                }
            }
        }
    }

    Ok((total_imported, total_failed))
}

/// Import security data (users, groups, permissions) when requested.
fn import_security_data(
    format: &str,
    verbose: bool,
    importer: &ArtifactoryImporter,
    include_users: bool,
    include_groups: bool,
    include_permissions: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if include_users {
        output(format, "\nImporting users...", None);
        let users = importer.list_users()?;
        output(format, &format!("  Found {} users", users.len()), None);

        for user in &users {
            if verbose {
                output(
                    format,
                    &format!(
                        "  - {} ({})",
                        user.username,
                        user.email.as_deref().unwrap_or("no email")
                    ),
                    None,
                );
            }
            // TODO: Create user in Artifact Keeper
        }
    }

    if include_groups {
        output(format, "\nImporting groups...", None);
        let groups = importer.list_groups()?;
        output(format, &format!("  Found {} groups", groups.len()), None);

        for group in &groups {
            if verbose {
                output(format, &format!("  - {}", group.name), None);
            }
            // TODO: Create group in Artifact Keeper
        }
    }

    if include_permissions {
        output(format, "\nImporting permissions...", None);
        let permissions = importer.list_permissions()?;
        output(
            format,
            &format!("  Found {} permission targets", permissions.len()),
            None,
        );

        for perm in &permissions {
            if verbose {
                output(
                    format,
                    &format!(
                        "  - {} (repos: {})",
                        perm.name,
                        perm.repositories.join(", ")
                    ),
                    None,
                );
            }
            // TODO: Create permission in Artifact Keeper
        }
    }

    Ok(())
}

/// Build an authenticated Artifactory client from the migration config.
fn build_client(
    format: &str,
    config: &MigrateConfig,
) -> Result<(ArtifactoryClient, String), Box<dyn std::error::Error>> {
    let artifactory = config
        .artifactory
        .as_ref()
        .ok_or("No Artifactory configuration provided")?;

    let url = artifactory
        .url
        .as_ref()
        .ok_or("No Artifactory URL provided")?;

    let auth = build_auth(format, artifactory)?;
    let client_config = ArtifactoryClientConfig {
        base_url: url.clone(),
        auth,
        ..Default::default()
    };

    let client = ArtifactoryClient::new(client_config)?;
    Ok((client, url.clone()))
}

/// Build authentication credentials from the Artifactory config.
fn build_auth(
    format: &str,
    artifactory: &ArtifactoryConfig,
) -> Result<ArtifactoryAuth, Box<dyn std::error::Error>> {
    if let Some(ref token) = artifactory.token {
        return Ok(ArtifactoryAuth::ApiToken(token.clone()));
    }
    if let (Some(ref username), Some(ref password)) = (&artifactory.username, &artifactory.password)
    {
        return Ok(ArtifactoryAuth::BasicAuth {
            username: username.clone(),
            password: password.clone(),
        });
    }
    error(format, "No authentication credentials provided");
    Err("No authentication credentials".into())
}

/// Filter repositories by include/exclude patterns and display the table.
fn filter_repositories<'a>(
    format: &str,
    repositories: &'a [ImportedRepository],
    include: Option<&[String]>,
    exclude: Option<&[String]>,
) -> Vec<&'a ImportedRepository> {
    if format == "text" {
        println!("\nRepositories:");
        table_row(&["Key", "Type", "Package Type"]);
        table_row(&["---", "----", "------------"]);
    }

    let mut selected = Vec::new();
    for repo in repositories {
        if !repo_passes_filters(&repo.key, include, exclude) {
            continue;
        }
        selected.push(repo);
        if format == "text" {
            table_row(&[&repo.key, &repo.repo_type, &repo.package_type]);
        }
    }
    selected
}

/// Run import from Artifactory export directory
#[allow(clippy::too_many_arguments, unused_variables)]
async fn run_import(
    format: &str,
    verbose: bool,
    path: &Path,
    include: Option<&[String]>,
    exclude: Option<&[String]>,
    include_users: bool,
    include_groups: bool,
    include_permissions: bool,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let importer = create_importer(format, path)?;
    let importer = attach_progress_callback(importer, format, verbose);

    // Get metadata
    let metadata = importer.get_metadata()?;
    output(
        format,
        &format!(
            "Export contains {} repositories, {} artifacts ({} bytes)",
            metadata.repositories.len(),
            metadata.total_artifacts,
            metadata.total_size_bytes
        ),
        Some(serde_json::json!({
            "repositories": metadata.repositories.len(),
            "artifacts": metadata.total_artifacts,
            "size_bytes": metadata.total_size_bytes,
            "has_security": metadata.has_security
        })),
    );

    // List and filter repositories
    let repositories = importer.list_repositories()?;
    let repos_to_import = filter_repositories(format, &repositories, include, exclude);

    output(
        format,
        &format!(
            "\n{} repositories selected for import",
            repos_to_import.len()
        ),
        Some(serde_json::json!({
            "selected_repositories": repos_to_import.iter().map(|r| &r.key).collect::<Vec<_>>()
        })),
    );

    if dry_run {
        return show_dry_run_preview(format, &importer, &repos_to_import);
    }

    error(
        format,
        "Migration import is not yet implemented. \
         Repository creation, artifact upload, and security data import \
         are planned for a future release. \
         Use 'ak migrate analyze' to preview what would be imported.",
    );
    return Err("Migration import is not yet implemented".into());

    #[allow(unreachable_code)]
    let (total_imported, total_failed) =
        import_artifacts(format, verbose, &importer, &repos_to_import)?;

    // Import security data if the export contains it
    if metadata.has_security {
        import_security_data(
            format,
            verbose,
            &importer,
            include_users,
            include_groups,
            include_permissions,
        )?;
    }

    // Summary
    output(
        format,
        &format!(
            "\nImport complete: {} imported, {} failed",
            total_imported, total_failed
        ),
        Some(serde_json::json!({
            "imported": total_imported,
            "failed": total_failed
        })),
    );

    Ok(())
}

/// Run connection test
async fn run_test(format: &str, config: &MigrateConfig) -> Result<(), Box<dyn std::error::Error>> {
    let (client, url) = build_client(format, config)?;
    output(format, &format!("Testing connection to {}...", url), None);

    match client.ping().await {
        Ok(true) => {
            output(
                format,
                "Connection successful!",
                Some(serde_json::json!({"status": "success"})),
            );

            // Get version info
            if let Ok(version) = client.get_version().await {
                output(
                    format,
                    &format!("Artifactory version: {}", version.version),
                    Some(serde_json::json!({
                        "version": version.version,
                        "revision": version.revision,
                        "license": version.license
                    })),
                );
            }

            Ok(())
        }
        Ok(false) => {
            error(
                format,
                "Connection failed: server returned non-success status",
            );
            Err("Connection failed".into())
        }
        Err(e) => {
            error(format, &format!("Connection failed: {}", e));
            Err(e.into())
        }
    }
}

/// Run pre-migration assessment
async fn run_assess(
    format: &str,
    config: &MigrateConfig,
    include: Option<&[String]>,
    exclude: Option<&[String]>,
    output_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (client, url) = build_client(format, config)?;
    output(
        format,
        &format!("Running assessment against {}...", url),
        None,
    );

    // List repositories
    let repositories = client.list_repositories().await?;

    let mut selected_repos = Vec::new();
    let mut total_artifacts = 0i64;

    for repo in &repositories {
        if !repo_passes_filters(&repo.key, include, exclude) {
            continue;
        }

        // Get artifact count for this repo
        let aql_result = client.list_artifacts(&repo.key, 0, 1).await;
        let artifact_count = aql_result.map(|r| r.range.total).unwrap_or(0);
        total_artifacts += artifact_count;

        selected_repos.push(serde_json::json!({
            "key": repo.key,
            "type": repo.repo_type,
            "package_type": repo.package_type,
            "artifact_count": artifact_count
        }));
    }

    let assessment = serde_json::json!({
        "source_url": url,
        "total_repositories": selected_repos.len(),
        "total_artifacts": total_artifacts,
        "repositories": selected_repos
    });

    // Output or save report
    if let Some(path) = output_path {
        std::fs::write(path, serde_json::to_string_pretty(&assessment)?)?;
        output(
            format,
            &format!("Assessment report saved to: {}", path.display()),
            None,
        );
    } else {
        output(
            format,
            &format!(
                "Assessment: {} repositories, {} artifacts",
                selected_repos.len(),
                total_artifacts
            ),
            Some(assessment),
        );
    }

    Ok(())
}

/// Run status check
async fn run_status(
    format: &str,
    job_id: &str,
    follow: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    output(
        format,
        &format!("Status for job {}: use API for real-time status", job_id),
        Some(serde_json::json!({
            "job_id": job_id,
            "follow": follow,
            "message": "Use the web UI or API for real-time job status"
        })),
    );
    Ok(())
}

/// Run list jobs
async fn run_list(
    format: &str,
    status: Option<&str>,
    limit: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    output(
        format,
        &format!(
            "List jobs (status: {:?}, limit: {}): use API for job listing",
            status, limit
        ),
        Some(serde_json::json!({
            "status_filter": status,
            "limit": limit,
            "message": "Use the web UI or API for job listing"
        })),
    );
    Ok(())
}

/// Run report generation
async fn run_report(
    format: &str,
    job_id: &str,
    report_format: &str,
    output_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    output(
        format,
        &format!("Generate {} report for job {}", report_format, job_id),
        Some(serde_json::json!({
            "job_id": job_id,
            "format": report_format,
            "output": output_path.map(|p| p.display().to_string()),
            "message": "Use the web UI or API for report generation"
        })),
    );
    Ok(())
}

/// Simple pattern matching (supports * wildcard)
fn matches_pattern(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') {
        // Simple glob matching
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let (prefix, suffix) = (parts[0], parts[1]);
            return value.starts_with(prefix) && value.ends_with(suffix);
        }
    }

    value == pattern
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::artifactory_client::ArtifactoryAuth;
    use crate::services::artifactory_import::ImportedRepository;

    // ---- matches_pattern ----

    #[test]
    fn test_matches_pattern_exact() {
        assert!(matches_pattern("libs-release", "libs-release"));
        assert!(!matches_pattern("libs-release", "libs-snapshot"));
    }

    #[test]
    fn test_matches_pattern_star_wildcard() {
        assert!(matches_pattern("anything", "*"));
        assert!(matches_pattern("", "*"));
    }

    #[test]
    fn test_matches_pattern_prefix_wildcard() {
        assert!(matches_pattern("libs-release", "libs-*"));
        assert!(matches_pattern("libs-snapshot", "libs-*"));
        assert!(!matches_pattern("maven-central", "libs-*"));
    }

    #[test]
    fn test_matches_pattern_suffix_wildcard() {
        assert!(matches_pattern("maven-central-cache", "*-cache"));
        assert!(matches_pattern("npm-remote-cache", "*-cache"));
        assert!(!matches_pattern("maven-central", "*-cache"));
    }

    #[test]
    fn test_matches_pattern_infix_wildcard() {
        assert!(matches_pattern("libs-release-local", "libs-*-local"));
        assert!(!matches_pattern("libs-release-remote", "libs-*-local"));
    }

    #[test]
    fn test_matches_pattern_empty_prefix_suffix() {
        assert!(matches_pattern("release", "*release"));
        assert!(matches_pattern("release", "release*"));
        assert!(matches_pattern("release", "*"));
    }

    #[test]
    fn test_matches_pattern_no_wildcard_no_match() {
        assert!(!matches_pattern("foo", "bar"));
        assert!(!matches_pattern("", "bar"));
    }

    #[test]
    fn test_matches_pattern_multiple_wildcards_falls_through() {
        // With more than one * (3+ parts after split), the function falls through
        // to exact match since only two-part splits are handled.
        assert!(!matches_pattern("a-b-c", "a-*-*"));
        assert!(!matches_pattern("a-b-c", "*-*-c"));
    }

    // ---- repo_passes_filters ----

    #[test]
    fn test_repo_passes_filters_no_filters() {
        assert!(repo_passes_filters("any-repo", None, None));
    }

    #[test]
    fn test_repo_passes_filters_include_only() {
        let include = vec!["libs-*".to_string()];
        assert!(repo_passes_filters("libs-release", Some(&include), None));
        assert!(!repo_passes_filters("maven-central", Some(&include), None));
    }

    #[test]
    fn test_repo_passes_filters_exclude_only() {
        let exclude = vec!["*-cache".to_string()];
        assert!(repo_passes_filters("libs-release", None, Some(&exclude)));
        assert!(!repo_passes_filters(
            "maven-central-cache",
            None,
            Some(&exclude)
        ));
    }

    #[test]
    fn test_repo_passes_filters_include_and_exclude() {
        let include = vec!["libs-*".to_string()];
        let exclude = vec!["libs-snapshot".to_string()];

        assert!(repo_passes_filters(
            "libs-release",
            Some(&include),
            Some(&exclude)
        ));
        assert!(!repo_passes_filters(
            "libs-snapshot",
            Some(&include),
            Some(&exclude)
        ));
        // Not in include list at all
        assert!(!repo_passes_filters(
            "maven-central",
            Some(&include),
            Some(&exclude)
        ));
    }

    #[test]
    fn test_repo_passes_filters_exclude_overrides_include() {
        let include = vec!["*".to_string()];
        let exclude = vec!["secret-repo".to_string()];

        assert!(repo_passes_filters(
            "public-repo",
            Some(&include),
            Some(&exclude)
        ));
        assert!(!repo_passes_filters(
            "secret-repo",
            Some(&include),
            Some(&exclude)
        ));
    }

    #[test]
    fn test_repo_passes_filters_multiple_patterns() {
        let include = vec!["libs-*".to_string(), "maven-*".to_string()];
        let exclude = vec!["*-cache".to_string(), "*-snapshot".to_string()];

        assert!(repo_passes_filters(
            "libs-release",
            Some(&include),
            Some(&exclude)
        ));
        assert!(repo_passes_filters(
            "maven-local",
            Some(&include),
            Some(&exclude)
        ));
        assert!(!repo_passes_filters(
            "libs-snapshot",
            Some(&include),
            Some(&exclude)
        ));
        assert!(!repo_passes_filters(
            "maven-central-cache",
            Some(&include),
            Some(&exclude)
        ));
        assert!(!repo_passes_filters(
            "npm-remote",
            Some(&include),
            Some(&exclude)
        ));
    }

    #[test]
    fn test_repo_passes_filters_empty_include_rejects_all() {
        let include: Vec<String> = vec![];
        assert!(!repo_passes_filters("anything", Some(&include), None));
    }

    #[test]
    fn test_repo_passes_filters_empty_exclude_allows_all() {
        let exclude: Vec<String> = vec![];
        assert!(repo_passes_filters("anything", None, Some(&exclude)));
    }

    // ---- build_auth ----

    #[test]
    fn test_build_auth_with_token() {
        let config = ArtifactoryConfig {
            token: Some("my-token".to_string()),
            username: None,
            password: None,
            url: None,
        };
        let auth = build_auth("text", &config).unwrap();
        match auth {
            ArtifactoryAuth::ApiToken(token) => assert_eq!(token, "my-token"),
            _ => panic!("Expected ApiToken variant"),
        }
    }

    #[test]
    fn test_build_auth_with_basic_auth() {
        let config = ArtifactoryConfig {
            token: None,
            username: Some("admin".to_string()),
            password: Some("secret".to_string()),
            url: None,
        };
        let auth = build_auth("text", &config).unwrap();
        match auth {
            ArtifactoryAuth::BasicAuth { username, password } => {
                assert_eq!(username, "admin");
                assert_eq!(password, "secret");
            }
            _ => panic!("Expected BasicAuth variant"),
        }
    }

    #[test]
    fn test_build_auth_token_takes_precedence_over_basic() {
        let config = ArtifactoryConfig {
            token: Some("my-token".to_string()),
            username: Some("admin".to_string()),
            password: Some("secret".to_string()),
            url: None,
        };
        let auth = build_auth("text", &config).unwrap();
        match auth {
            ArtifactoryAuth::ApiToken(token) => assert_eq!(token, "my-token"),
            _ => panic!("Expected ApiToken when both token and basic auth are provided"),
        }
    }

    #[test]
    fn test_build_auth_no_credentials() {
        let config = ArtifactoryConfig {
            token: None,
            username: None,
            password: None,
            url: None,
        };
        let result = build_auth("text", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_auth_username_without_password() {
        let config = ArtifactoryConfig {
            token: None,
            username: Some("admin".to_string()),
            password: None,
            url: None,
        };
        let result = build_auth("text", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_auth_password_without_username() {
        let config = ArtifactoryConfig {
            token: None,
            username: None,
            password: Some("secret".to_string()),
            url: None,
        };
        let result = build_auth("text", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_auth_json_format_no_credentials() {
        let config = ArtifactoryConfig::default();
        let result = build_auth("json", &config);
        assert!(result.is_err());
    }

    // ---- build_client ----

    #[test]
    fn test_build_client_no_artifactory_config() {
        let config = MigrateConfig::default();
        let result = build_client("text", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_client_no_url() {
        let config = MigrateConfig {
            artifactory: Some(ArtifactoryConfig {
                url: None,
                token: Some("my-token".to_string()),
                username: None,
                password: None,
            }),
            ..Default::default()
        };
        let result = build_client("text", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_client_no_auth() {
        let config = MigrateConfig {
            artifactory: Some(ArtifactoryConfig {
                url: Some("https://artifactory.example.com".to_string()),
                token: None,
                username: None,
                password: None,
            }),
            ..Default::default()
        };
        let result = build_client("text", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_client_with_valid_token_config() {
        let config = MigrateConfig {
            artifactory: Some(ArtifactoryConfig {
                url: Some("https://artifactory.example.com".to_string()),
                token: Some("my-token".to_string()),
                username: None,
                password: None,
            }),
            ..Default::default()
        };
        let result = build_client("text", &config);
        assert!(result.is_ok());
        let (_client, url) = result.unwrap();
        assert_eq!(url, "https://artifactory.example.com");
    }

    #[test]
    fn test_build_client_with_valid_basic_auth_config() {
        let config = MigrateConfig {
            artifactory: Some(ArtifactoryConfig {
                url: Some("https://artifactory.example.com".to_string()),
                token: None,
                username: Some("admin".to_string()),
                password: Some("pass".to_string()),
            }),
            ..Default::default()
        };
        let result = build_client("text", &config);
        assert!(result.is_ok());
    }

    // ---- filter_repositories ----

    fn make_repo(key: &str, repo_type: &str, package_type: &str) -> ImportedRepository {
        ImportedRepository {
            key: key.to_string(),
            repo_type: repo_type.to_string(),
            package_type: package_type.to_string(),
            description: None,
            includes_pattern: None,
            excludes_pattern: None,
            handle_releases: true,
            handle_snapshots: false,
            layout: None,
        }
    }

    #[test]
    fn test_filter_repositories_no_filters() {
        let repos = vec![
            make_repo("libs-release", "local", "maven"),
            make_repo("npm-remote", "remote", "npm"),
        ];
        let result = filter_repositories("json", &repos, None, None);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_repositories_include_filter() {
        let repos = vec![
            make_repo("libs-release", "local", "maven"),
            make_repo("libs-snapshot", "local", "maven"),
            make_repo("npm-remote", "remote", "npm"),
        ];
        let include = vec!["libs-*".to_string()];
        let result = filter_repositories("json", &repos, Some(&include), None);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].key, "libs-release");
        assert_eq!(result[1].key, "libs-snapshot");
    }

    #[test]
    fn test_filter_repositories_exclude_filter() {
        let repos = vec![
            make_repo("libs-release", "local", "maven"),
            make_repo("libs-snapshot", "local", "maven"),
            make_repo("npm-remote", "remote", "npm"),
        ];
        let exclude = vec!["*-snapshot".to_string()];
        let result = filter_repositories("json", &repos, None, Some(&exclude));
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].key, "libs-release");
        assert_eq!(result[1].key, "npm-remote");
    }

    #[test]
    fn test_filter_repositories_include_and_exclude() {
        let repos = vec![
            make_repo("libs-release", "local", "maven"),
            make_repo("libs-snapshot", "local", "maven"),
            make_repo("npm-remote", "remote", "npm"),
        ];
        let include = vec!["libs-*".to_string()];
        let exclude = vec!["*-snapshot".to_string()];
        let result = filter_repositories("json", &repos, Some(&include), Some(&exclude));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].key, "libs-release");
    }

    #[test]
    fn test_filter_repositories_empty_list() {
        let repos: Vec<ImportedRepository> = vec![];
        let result = filter_repositories("json", &repos, None, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_repositories_all_excluded() {
        let repos = vec![
            make_repo("libs-release", "local", "maven"),
            make_repo("npm-remote", "remote", "npm"),
        ];
        let exclude = vec!["*".to_string()];
        let result = filter_repositories("json", &repos, None, Some(&exclude));
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_repositories_preserves_order() {
        let repos = vec![
            make_repo("z-repo", "local", "maven"),
            make_repo("a-repo", "local", "maven"),
            make_repo("m-repo", "local", "maven"),
        ];
        let result = filter_repositories("json", &repos, None, None);
        assert_eq!(result[0].key, "z-repo");
        assert_eq!(result[1].key, "a-repo");
        assert_eq!(result[2].key, "m-repo");
    }

    #[test]
    fn test_filter_repositories_text_format_does_not_panic() {
        let repos = vec![make_repo("libs-release", "local", "maven")];
        let result = filter_repositories("text", &repos, None, None);
        assert_eq!(result.len(), 1);
    }
}
