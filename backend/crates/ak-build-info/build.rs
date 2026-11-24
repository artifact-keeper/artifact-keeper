//! Bakes the build metadata `src/lib.rs` exports into `$OUT_DIR/build_info.rs`.
//!
//! This is the only build script in the workspace that reads the build
//! environment. It declares exactly what it reads, so it reruns only when one
//! of those variables changes, never on a commit, checkout or rebase (#6181).

use std::time::{SystemTime, UNIX_EPOCH};

/// The Debian `Release` `Date:` floor a dev or test build (cargo's `debug`
/// profile family) bakes in when `SOURCE_DATE_EPOCH` is unset:
/// 2026-01-01T00:00:00Z. A constant keeps those builds a pure function of the
/// source, so the floor never differs between two builds of one commit. It
/// postdates the 2001 fixture of debian.rs's `release_date_floor` test.
const DEV_RELEASE_DATE_FLOOR_EPOCH: u64 = 1_767_225_600;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    // The commit the binary reports (`/health` `commit`, the startup log's
    // `git=`), taken ONLY from the `GIT_SHA` environment variable. Every
    // build that ships sets it: docker-publish.yml passes it as a build arg
    // to docker/Dockerfile.backend, release.yml's `build-binaries` and
    // release-cli-caches.yml set it from the checked-out commit, and ci.yml's
    // PR image passes it too. Without it the value is the literal `"unknown"`,
    // which build_info and health.rs treat as valid. Nothing here reads or
    // watches git (#6181); to embed the real commit in a local build, pass it:
    // `GIT_SHA=$(git rev-parse HEAD) cargo build ...`.
    let git_sha = std::env::var("GIT_SHA")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    // The compile-time floor for the Debian `Release` `Date:` field, in
    // seconds since the Unix epoch (see `release_date_floor` in the backend's
    // src/api/handlers/debian.rs for why it exists and why it must be a
    // build-time constant):
    //   1. `SOURCE_DATE_EPOCH`, when set: the reproducible-builds convention.
    //   2. A release-profile build (`--release`, `--profile ci`, every image
    //      and release binary): the build machine's clock, as before.
    //   3. A dev or test build: the fixed DEV_RELEASE_DATE_FLOOR_EPOCH.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let release_date_floor = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            if profile == "release" {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            } else {
                DEV_RELEASE_DATE_FLOOR_EPOCH
            }
        });

    let out =
        std::path::Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("build_info.rs");
    let generated = format!(
        "/// Full git commit SHA of the build, or `\"unknown\"` when the build did not set `GIT_SHA`.\n\
         pub const GIT_SHA: &str = {git_sha:?};\n\
         /// Floor for the Debian `Release` `Date:` field, seconds since the Unix epoch.\n\
         pub const RELEASE_DATE_FLOOR_EPOCH: i64 = {release_date_floor};\n"
    );
    // Write only on change, so an unchanged value leaves the file's mtime alone.
    if std::fs::read_to_string(&out).ok().as_deref() != Some(generated.as_str()) {
        std::fs::write(&out, generated).expect("write build_info.rs");
    }
}
