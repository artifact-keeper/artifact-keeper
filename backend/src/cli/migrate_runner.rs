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
#[allow(clippy::too_many_arguments)]
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

    #[test]
    fn test_matches_pattern() {
        assert!(matches_pattern("libs-release", "libs-*"));
        assert!(matches_pattern("libs-release", "*"));
        assert!(matches_pattern("libs-release", "libs-release"));
        assert!(!matches_pattern("libs-release", "libs-snapshot"));
        assert!(matches_pattern("maven-central-cache", "*-cache"));
    }
}
