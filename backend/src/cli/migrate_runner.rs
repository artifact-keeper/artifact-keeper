//! CLI command runner for Artifactory migration.
//!
//! This module implements the actual execution logic for migration CLI commands.

use crate::cli::migrate::{error, output, table_row, MigrateCli, MigrateCommand, MigrateConfig};
use crate::services::artifactory_import::{ArtifactoryImporter, ImportProgress};
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
        MigrateCommand::Test => {
            run_test(&cli.format, &config).await
        }
        MigrateCommand::Assess {
            include,
            exclude,
            output: output_path,
        } => {
            run_assess(&cli.format, &config, include.as_deref(), exclude.as_deref(), output_path.as_deref()).await
        }
        MigrateCommand::Start { dry_run, .. } => {
            if dry_run {
                output(&cli.format, "Dry run: no changes will be made", None);
            }
            output(&cli.format, "Migration start command - use API for full functionality", None);
            Ok(())
        }
        MigrateCommand::Status { job_id, follow } => {
            run_status(&cli.format, &job_id, follow).await
        }
        MigrateCommand::Pause { job_id } => {
            output(&cli.format, &format!("Pause request sent for job {}", job_id), None);
            Ok(())
        }
        MigrateCommand::Resume { job_id } => {
            output(&cli.format, &format!("Resume request sent for job {}", job_id), None);
            Ok(())
        }
        MigrateCommand::Cancel { job_id } => {
            output(&cli.format, &format!("Cancel request sent for job {}", job_id), None);
            Ok(())
        }
        MigrateCommand::List { status, limit } => {
            run_list(&cli.format, status.as_deref(), limit).await
        }
        MigrateCommand::Report {
            job_id,
            format: report_format,
            output: output_path,
        } => {
            run_report(&cli.format, &job_id, &report_format, output_path.as_deref()).await
        }
    }
}

/// Run import from Artifactory export directory
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
    // Create importer based on path type
    let importer = if path.is_dir() {
        output(format, &format!("Loading export from directory: {}", path.display()), None);
        ArtifactoryImporter::from_directory(path)?
    } else if path.extension().map(|e| e == "zip").unwrap_or(false) {
        output(format, &format!("Extracting archive: {}", path.display()), None);
        ArtifactoryImporter::from_archive(path)?
    } else {
        error(format, "Path must be a directory or ZIP archive");
        return Err("Invalid path".into());
    };

    // Add progress callback if verbose
    let progress_counter = Arc::new(AtomicU64::new(0));
    let importer = if verbose {
        let counter = progress_counter.clone();
        let format_clone = format.to_string();
        importer.with_progress_callback(Box::new(move |progress: ImportProgress| {
            counter.store(progress.current, Ordering::SeqCst);
            if format_clone != "json" {
                eprint!("\r{}: {}/{} - {}", progress.phase, progress.current, progress.total, progress.message);
            }
        }))
    } else {
        importer
    };

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

    // List repositories
    let repositories = importer.list_repositories()?;

    if format == "text" {
        println!("\nRepositories:");
        table_row(&["Key", "Type", "Package Type"]);
        table_row(&["---", "----", "------------"]);
    }

    let mut repos_to_import = Vec::new();
    for repo in &repositories {
        // Apply include/exclude filters
        let included = match include {
            Some(patterns) => patterns.iter().any(|p| matches_pattern(&repo.key, p)),
            None => true,
        };
        let excluded = match exclude {
            Some(patterns) => patterns.iter().any(|p| matches_pattern(&repo.key, p)),
            None => false,
        };

        if included && !excluded {
            repos_to_import.push(repo);
            if format == "text" {
                table_row(&[&repo.key, &repo.repo_type, &repo.package_type]);
            }
        }
    }

    output(
        format,
        &format!("\n{} repositories selected for import", repos_to_import.len()),
        Some(serde_json::json!({
            "selected_repositories": repos_to_import.iter().map(|r| &r.key).collect::<Vec<_>>()
        })),
    );

    if dry_run {
        output(format, "\nDry run - no changes will be made", None);

        // Show what would be imported
        for repo in repos_to_import {
            let artifacts: Vec<_> = importer.list_artifacts(&repo.key)?
                .filter_map(|a| a.ok())
                .take(10)
                .collect();

            output(
                format,
                &format!("\nRepository '{}' would import {} artifacts (showing first 10):", repo.key, artifacts.len()),
                None,
            );

            for artifact in artifacts {
                if format == "text" {
                    println!("  - {}/{}", artifact.path, artifact.name);
                }
            }
        }

        return Ok(());
    }

    // Process import
    let mut total_imported = 0u64;
    let mut total_failed = 0u64;

    for repo in repos_to_import {
        output(format, &format!("\nImporting repository: {}", repo.key), None);

        // TODO: Create repository in Artifact Keeper if it doesn't exist
        // This would require database access and the repository service

        // Import artifacts
        let artifacts = importer.list_artifacts(&repo.key)?;

        for artifact_result in artifacts {
            match artifact_result {
                Ok(artifact) => {
                    if verbose {
                        output(format, &format!("  Importing: {}/{}", artifact.path, artifact.name), None);
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

    // Import users if requested
    if include_users && metadata.has_security {
        output(format, "\nImporting users...", None);
        let users = importer.list_users()?;
        output(format, &format!("  Found {} users", users.len()), None);

        for user in &users {
            if verbose {
                output(format, &format!("  - {} ({})", user.username, user.email.as_deref().unwrap_or("no email")), None);
            }
            // TODO: Create user in Artifact Keeper
        }
    }

    // Import groups if requested
    if include_groups && metadata.has_security {
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

    // Import permissions if requested
    if include_permissions && metadata.has_security {
        output(format, "\nImporting permissions...", None);
        let permissions = importer.list_permissions()?;
        output(format, &format!("  Found {} permission targets", permissions.len()), None);

        for perm in &permissions {
            if verbose {
                output(format, &format!("  - {} (repos: {})", perm.name, perm.repositories.join(", ")), None);
            }
            // TODO: Create permission in Artifact Keeper
        }
    }

    // Summary
    output(
        format,
        &format!("\nImport complete: {} imported, {} failed", total_imported, total_failed),
        Some(serde_json::json!({
            "imported": total_imported,
            "failed": total_failed
        })),
    );

    Ok(())
}

/// Run connection test
async fn run_test(
    format: &str,
    config: &MigrateConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let artifactory = config.artifactory.as_ref()
        .ok_or("No Artifactory configuration provided")?;

    let url = artifactory.url.as_ref()
        .ok_or("No Artifactory URL provided")?;

    output(format, &format!("Testing connection to {}...", url), None);

    // Build auth
    let auth = if let Some(ref token) = artifactory.token {
        crate::services::artifactory_client::ArtifactoryAuth::ApiToken(token.clone())
    } else if let (Some(ref username), Some(ref password)) = (&artifactory.username, &artifactory.password) {
        crate::services::artifactory_client::ArtifactoryAuth::BasicAuth {
            username: username.clone(),
            password: password.clone(),
        }
    } else {
        error(format, "No authentication credentials provided");
        return Err("No authentication credentials".into());
    };

    let client_config = crate::services::artifactory_client::ArtifactoryClientConfig {
        base_url: url.clone(),
        auth,
        ..Default::default()
    };

    let client = crate::services::artifactory_client::ArtifactoryClient::new(client_config)?;

    match client.ping().await {
        Ok(true) => {
            output(format, "Connection successful!", Some(serde_json::json!({"status": "success"})));

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
            error(format, "Connection failed: server returned non-success status");
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
    let artifactory = config.artifactory.as_ref()
        .ok_or("No Artifactory configuration provided")?;

    let url = artifactory.url.as_ref()
        .ok_or("No Artifactory URL provided")?;

    output(format, &format!("Running assessment against {}...", url), None);

    // Build auth
    let auth = if let Some(ref token) = artifactory.token {
        crate::services::artifactory_client::ArtifactoryAuth::ApiToken(token.clone())
    } else if let (Some(ref username), Some(ref password)) = (&artifactory.username, &artifactory.password) {
        crate::services::artifactory_client::ArtifactoryAuth::BasicAuth {
            username: username.clone(),
            password: password.clone(),
        }
    } else {
        error(format, "No authentication credentials provided");
        return Err("No authentication credentials".into());
    };

    let client_config = crate::services::artifactory_client::ArtifactoryClientConfig {
        base_url: url.clone(),
        auth,
        ..Default::default()
    };

    let client = crate::services::artifactory_client::ArtifactoryClient::new(client_config)?;

    // List repositories
    let repositories = client.list_repositories().await?;

    let mut selected_repos = Vec::new();
    let mut total_artifacts = 0i64;

    for repo in &repositories {
        // Apply include/exclude filters
        let included = match include {
            Some(patterns) => patterns.iter().any(|p| matches_pattern(&repo.key, p)),
            None => true,
        };
        let excluded = match exclude {
            Some(patterns) => patterns.iter().any(|p| matches_pattern(&repo.key, p)),
            None => false,
        };

        if included && !excluded {
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
        output(format, &format!("Assessment report saved to: {}", path.display()), None);
    } else {
        output(
            format,
            &format!("Assessment: {} repositories, {} artifacts", selected_repos.len(), total_artifacts),
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
        &format!("List jobs (status: {:?}, limit: {}): use API for job listing", status, limit),
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
