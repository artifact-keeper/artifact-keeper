//! HTTP request handlers.

/// Remove any soft-deleted artifact at the given `(repository_id, path)` so
/// that a subsequent INSERT won't violate the UNIQUE constraint.  This is a
/// fire-and-forget cleanup: if the DELETE fails or finds nothing we just
/// continue with the INSERT.
pub async fn cleanup_soft_deleted_artifact(
    db: &sqlx::PgPool,
    repository_id: uuid::Uuid,
    path: &str,
) {
    let _ = sqlx::query(
        "DELETE FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = true",
    )
    .bind(repository_id)
    .bind(path)
    .execute(db)
    .await;
}

/// Escape SQL `LIKE` wildcards (`%`, `_`) and the escape character (`\`) in
/// user-supplied input that will be concatenated into a `LIKE` pattern.
///
/// Use together with an `ESCAPE '\'` clause on the SQL side. Without this
/// helper, a user-supplied path component containing `%` or `_` would act
/// as a wildcard rather than a literal, leaking other artifact paths inside
/// the same repository (info disclosure / wrong-artifact serving).
pub fn escape_like_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Escape a user-supplied filename from a URL path segment for safe
/// `LIKE '%/' || $n ESCAPE '\'` suffix matching. Strips a single leading
/// slash (URL extractors often hand us one) and escapes `%`, `_`, `\`.
pub fn escape_filename_for_like(file_path: &str) -> String {
    escape_like_literal(file_path.trim_start_matches('/'))
}

/// Build a `/`-joined path prefix from user-supplied components, escaping
/// each component for safe `LIKE $n || '%' ESCAPE '\'` prefix matching.
/// A trailing `/` is appended. Empty input produces an empty string.
pub fn escape_path_prefix(components: &[&str]) -> String {
    let mut out = String::new();
    for c in components {
        out.push_str(&escape_like_literal(c));
        out.push('/');
    }
    out
}

pub mod error_helpers;

pub mod admin;
pub mod alpine;
pub mod analytics;
pub mod ansible;
pub mod approval;
pub mod artifact_labels;
pub mod artifacts;
pub mod auth;
pub mod builds;
pub mod cargo;
pub mod chef;
pub mod cocoapods;
pub mod composer;
pub mod conan;
pub mod conda;
pub mod cran;
pub mod curation;
pub mod debian;
pub mod dependency_track;
pub mod events;
pub mod gitlfs;
pub mod goproxy;
pub mod groups;
pub mod health;
pub mod helm;
pub mod hex;
pub mod huggingface;
pub mod incus;
pub mod jetbrains;
pub mod lifecycle;
pub mod maven;
pub mod migration;
pub mod monitoring;
pub mod notifications;
pub mod npm;
pub mod nuget;
pub mod oci_v2;
pub mod packages;
pub mod peer;
pub mod peer_instance_labels;
pub mod peers;
pub mod permissions;
pub mod plugins;
pub mod profile;
pub mod promotion;
pub mod promotion_rules;
pub mod protobuf;
pub mod proxy_helpers;
pub mod pub_registry;
pub mod puppet;
pub mod pypi;
pub mod quality_gates;
pub mod quarantine;
pub mod remote_instances;
pub mod repo_tokens;
pub mod repositories;
pub mod repository_labels;
pub mod rpm;
pub mod rubygems;
pub mod sbom;
pub mod sbt;
pub mod search;
pub mod security;
pub mod service_accounts;
pub mod signing;
pub mod smtp;
pub mod sso;
pub mod sso_admin;
pub mod storage_gc;
pub mod swift;
pub mod sync_policies;
pub mod system_config;
pub mod telemetry;
pub mod terraform;
pub mod totp;
pub mod transfer;
pub mod tree;
pub mod upload;
pub mod users;
pub mod vscode;
pub mod wasm_proxy;
pub mod webhooks;

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // escape_like_literal — SQL LIKE wildcard escape for user-supplied input
    // -----------------------------------------------------------------------

    #[test]
    fn test_escape_like_literal_passes_safe_chars_through() {
        assert_eq!(escape_like_literal("foo-1.0.0.tgz"), "foo-1.0.0.tgz");
        assert_eq!(escape_like_literal(""), "");
        assert_eq!(escape_like_literal("@types/mdurl"), "@types/mdurl");
    }

    #[test]
    fn test_escape_like_literal_escapes_percent() {
        // SECURITY: a `%` from user input must not act as a LIKE wildcard.
        assert_eq!(escape_like_literal("%"), r"\%");
        assert_eq!(escape_like_literal("%.gem"), r"\%.gem");
        assert_eq!(escape_like_literal("foo%bar%baz"), r"foo\%bar\%baz");
    }

    #[test]
    fn test_escape_like_literal_escapes_underscore() {
        // SECURITY: a `_` from user input must not act as a LIKE single-char wildcard.
        assert_eq!(escape_like_literal("_"), r"\_");
        assert_eq!(escape_like_literal("foo_bar"), r"foo\_bar");
    }

    #[test]
    fn test_escape_like_literal_escapes_backslash() {
        // SECURITY: a `\` must be escaped so it doesn't itself act as the LIKE
        // escape character (we use `ESCAPE '\'` on the SQL side).
        assert_eq!(escape_like_literal(r"\"), r"\\");
        assert_eq!(escape_like_literal(r"foo\bar"), r"foo\\bar");
    }

    #[test]
    fn test_escape_like_literal_combined_payload() {
        // Adversarial filename mixing all special chars.
        assert_eq!(escape_like_literal(r"%_\evil"), r"\%\_\\evil");
    }

    // -----------------------------------------------------------------------
    // escape_filename_for_like — strip leading slash + escape
    // -----------------------------------------------------------------------

    #[test]
    fn test_escape_filename_strips_leading_slash() {
        assert_eq!(escape_filename_for_like("/foo.tgz"), "foo.tgz");
        assert_eq!(escape_filename_for_like("//foo.tgz"), "foo.tgz");
        assert_eq!(escape_filename_for_like("foo.tgz"), "foo.tgz");
        assert_eq!(escape_filename_for_like(""), "");
    }

    #[test]
    fn test_escape_filename_escapes_wildcards() {
        // SECURITY: a `%` or `_` in a download URL filename must not
        // broaden the LIKE match to other artifacts in the repository.
        assert_eq!(escape_filename_for_like("/%.whl"), r"\%.whl");
        assert_eq!(escape_filename_for_like("foo_bar.gem"), r"foo\_bar.gem");
        assert_eq!(escape_filename_for_like(r"/%_\evil"), r"\%\_\\evil");
    }

    #[test]
    fn test_escape_filename_preserves_internal_slashes() {
        // `/` is not a LIKE special char; internal path separators in
        // a filename are matched literally.
        assert_eq!(
            escape_filename_for_like("/v3/files/foo-1.0.0.tar.gz"),
            "v3/files/foo-1.0.0.tar.gz"
        );
    }

    // -----------------------------------------------------------------------
    // escape_path_prefix — multi-component path prefix
    // -----------------------------------------------------------------------

    #[test]
    fn test_escape_path_prefix_two_components() {
        assert_eq!(
            escape_path_prefix(&["bert-base", "main"]),
            "bert-base/main/"
        );
    }

    #[test]
    fn test_escape_path_prefix_three_components() {
        // SECURITY: alpine paths use `branch/repository/arch/` from URL;
        // `_` in `x86_64` must be escaped so it's matched literally.
        assert_eq!(
            escape_path_prefix(&["v3.18", "main", "x86_64"]),
            r"v3.18/main/x86\_64/"
        );
    }

    #[test]
    fn test_escape_path_prefix_escapes_each_component() {
        // SECURITY: every component is escaped independently before the
        // separator is emitted, so a `/` in user input would be a literal
        // (which is fine; `/` isn't a LIKE wildcard) but `%` and `_`
        // become escaped in place.
        assert_eq!(escape_path_prefix(&["%", "_evil"]), r"\%/\_evil/");
    }

    #[test]
    fn test_escape_path_prefix_empty_inputs() {
        assert_eq!(escape_path_prefix(&[]), "");
        assert_eq!(escape_path_prefix(&[""]), "/");
    }
}
