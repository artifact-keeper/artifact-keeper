//! CLI commands for Artifactory migration.
//!
//! Provides command-line interface for running migrations, assessments,
//! and managing migration jobs without the web UI.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Artifactory to Artifact Keeper migration CLI
#[derive(Parser, Debug)]
#[command(name = "ak-migrate")]
#[command(about = "Migrate from JFrog Artifactory to Artifact Keeper", long_about = None)]
pub struct MigrateCli {
    #[command(subcommand)]
    pub command: MigrateCommand,

    /// Path to config file (YAML)
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Artifactory URL (can also be set via ARTIFACTORY_URL env var)
    #[arg(long, env = "ARTIFACTORY_URL", global = true)]
    pub url: Option<String>,

    /// API token for authentication (can also be set via ARTIFACTORY_TOKEN env var)
    #[arg(long, env = "ARTIFACTORY_TOKEN", global = true)]
    pub token: Option<String>,

    /// Username for basic auth
    #[arg(long, env = "ARTIFACTORY_USERNAME", global = true)]
    pub username: Option<String>,

    /// Password for basic auth (can also be set via ARTIFACTORY_PASSWORD env var)
    #[arg(long, env = "ARTIFACTORY_PASSWORD", global = true)]
    pub password: Option<String>,

    /// Database URL (can also be set via DATABASE_URL env var)
    #[arg(long, env = "DATABASE_URL", global = true)]
    pub database_url: Option<String>,

    /// Output format (json, text)
    #[arg(long, default_value = "text", global = true)]
    pub format: String,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum MigrateCommand {
    /// Run a pre-migration assessment
    Assess {
        /// Repository patterns to include (e.g., "libs-*", "maven-local")
        #[arg(short, long)]
        include: Option<Vec<String>>,

        /// Repository patterns to exclude
        #[arg(short, long)]
        exclude: Option<Vec<String>>,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Start a new migration
    Start {
        /// Repository patterns to include
        #[arg(short, long)]
        include: Option<Vec<String>>,

        /// Repository patterns to exclude
        #[arg(short, long)]
        exclude: Option<Vec<String>>,

        /// Path patterns to exclude from artifacts
        #[arg(long)]
        exclude_paths: Option<Vec<String>>,

        /// Include users in migration
        #[arg(long)]
        include_users: bool,

        /// Include groups in migration
        #[arg(long)]
        include_groups: bool,

        /// Include permissions in migration
        #[arg(long)]
        include_permissions: bool,

        /// Conflict resolution strategy (skip, overwrite, rename)
        #[arg(long, default_value = "skip")]
        conflict_resolution: String,

        /// Dry run - show what would be migrated without making changes
        #[arg(long)]
        dry_run: bool,

        /// Run in background and return job ID
        #[arg(long)]
        background: bool,

        /// Verify checksums after transfer
        #[arg(long, default_value = "true")]
        verify_checksums: bool,

        /// Incremental migration - only migrate changes since last sync
        #[arg(long)]
        incremental: bool,

        /// Only migrate artifacts modified after this date (ISO 8601)
        #[arg(long)]
        modified_after: Option<String>,

        /// Only migrate artifacts modified before this date (ISO 8601)
        #[arg(long)]
        modified_before: Option<String>,
    },

    /// Check status of a migration job
    Status {
        /// Job ID to check
        job_id: String,

        /// Follow progress (like tail -f)
        #[arg(short, long)]
        follow: bool,
    },

    /// Pause a running migration
    Pause {
        /// Job ID to pause
        job_id: String,
    },

    /// Resume a paused migration
    Resume {
        /// Job ID to resume
        job_id: String,
    },

    /// Cancel a migration job
    Cancel {
        /// Job ID to cancel
        job_id: String,
    },

    /// List migration jobs
    List {
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,

        /// Number of jobs to show
        #[arg(short, long, default_value = "10")]
        limit: i64,
    },

    /// Generate migration report
    Report {
        /// Job ID
        job_id: String,

        /// Output format (json, html)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Import from Artifactory export directory
    Import {
        /// Path to Artifactory export directory or archive
        path: PathBuf,

        /// Repository patterns to include
        #[arg(short, long)]
        include: Option<Vec<String>>,

        /// Repository patterns to exclude
        #[arg(short, long)]
        exclude: Option<Vec<String>>,

        /// Include users
        #[arg(long)]
        include_users: bool,

        /// Include groups
        #[arg(long)]
        include_groups: bool,

        /// Include permissions
        #[arg(long)]
        include_permissions: bool,

        /// Dry run
        #[arg(long)]
        dry_run: bool,
    },

    /// Test connection to Artifactory
    Test,
}

/// Configuration loaded from YAML file
#[derive(Debug, serde::Deserialize, Default)]
pub struct MigrateConfig {
    pub artifactory: Option<ArtifactoryConfig>,
    pub migration: Option<MigrationOptions>,
    pub database: Option<DatabaseConfig>,
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct ArtifactoryConfig {
    pub url: Option<String>,
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct MigrationOptions {
    pub include_repositories: Option<Vec<String>>,
    pub exclude_repositories: Option<Vec<String>>,
    pub exclude_paths: Option<Vec<String>>,
    pub include_users: Option<bool>,
    pub include_groups: Option<bool>,
    pub include_permissions: Option<bool>,
    pub conflict_resolution: Option<String>,
    pub verify_checksums: Option<bool>,
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct DatabaseConfig {
    pub url: Option<String>,
}

impl MigrateConfig {
    /// Load config from YAML file
    pub fn from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: MigrateConfig = serde_yaml::from_str(&contents)?;
        Ok(config)
    }

    /// Merge CLI args with config file
    pub fn merge_with_cli(&mut self, cli: &MigrateCli) {
        // CLI args override config file
        if let Some(ref url) = cli.url {
            if self.artifactory.is_none() {
                self.artifactory = Some(ArtifactoryConfig::default());
            }
            self.artifactory.as_mut().unwrap().url = Some(url.clone());
        }

        if let Some(ref token) = cli.token {
            if self.artifactory.is_none() {
                self.artifactory = Some(ArtifactoryConfig::default());
            }
            self.artifactory.as_mut().unwrap().token = Some(token.clone());
        }

        if let Some(ref username) = cli.username {
            if self.artifactory.is_none() {
                self.artifactory = Some(ArtifactoryConfig::default());
            }
            self.artifactory.as_mut().unwrap().username = Some(username.clone());
        }

        if let Some(ref password) = cli.password {
            if self.artifactory.is_none() {
                self.artifactory = Some(ArtifactoryConfig::default());
            }
            self.artifactory.as_mut().unwrap().password = Some(password.clone());
        }

        if let Some(ref db_url) = cli.database_url {
            if self.database.is_none() {
                self.database = Some(DatabaseConfig::default());
            }
            self.database.as_mut().unwrap().url = Some(db_url.clone());
        }
    }
}

/// Print message based on output format
pub fn output(format: &str, message: &str, json_value: Option<serde_json::Value>) {
    match format {
        "json" => {
            if let Some(value) = json_value {
                println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            } else {
                println!(r#"{{"message": "{}"}}"#, message);
            }
        }
        _ => {
            println!("{}", message);
        }
    }
}

/// Print error message
pub fn error(format: &str, message: &str) {
    match format {
        "json" => {
            eprintln!(r#"{{"error": "{}"}}"#, message);
        }
        _ => {
            eprintln!("Error: {}", message);
        }
    }
}

/// Print table row
pub fn table_row(cells: &[&str]) {
    println!("{}", cells.join("\t"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = MigrateConfig::default();
        assert!(config.artifactory.is_none());
        assert!(config.migration.is_none());
        assert!(config.database.is_none());
    }

    #[test]
    fn test_output_text() {
        // Just test that it doesn't panic
        output("text", "test message", None);
    }

    #[test]
    fn test_output_json() {
        // Just test that it doesn't panic
        output("json", "test message", Some(serde_json::json!({"key": "value"})));
    }
}
