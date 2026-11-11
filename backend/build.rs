fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // Generate file descriptor set for gRPC reflection
    let descriptor_path = format!("{}/sbom_descriptor.bin", out_dir);

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(&descriptor_path)
        .out_dir(&out_dir)
        .compile_protos(&["proto/sbom.proto"], &["proto"])?;

    // Hex registry resources (`/names`, `/versions`, `/packages/{name}`) are
    // plain protobuf messages with no gRPC service, so they are generated with
    // prost only. The schemas mirror hex_core's `mix_hex_pb_*` definitions.
    prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(
            &[
                "proto/hex_signed.proto",
                "proto/hex_names.proto",
                "proto/hex_versions.proto",
                "proto/hex_package.proto",
            ],
            &["proto"],
        )?;

    let env_sha = std::env::var("GIT_SHA").ok().filter(|s| !s.is_empty());
    let git_sha = env_sha
        .clone()
        .or_else(|| git(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_SHA={git_sha}");
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    if env_sha.is_none() {
        emit_git_head_rerun();
    }

    // Compile-time floor for the Debian `Release` `Date:` field, in seconds
    // since the Unix epoch (see `release_date_floor` in
    // src/api/handlers/debian.rs for why it must exist and why it must be a
    // build-time constant rather than a process-start or per-request value).
    // `SOURCE_DATE_EPOCH` wins when set — the reproducible-builds convention —
    // otherwise the build machine's clock at compile time. Validated here so
    // the baked string is always a parseable integer.
    let release_date_floor = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=RELEASE_DATE_FLOOR_EPOCH={release_date_floor}");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    emit_test_shard_cfg();

    Ok(())
}

/// Run `git` in the package directory and return its trimmed stdout, or
/// `None` when git is missing, this is not a work tree (a source tarball, a
/// Docker build context without `.git`), or the command fails.
fn git(args: &[&str]) -> Option<String> {
    let dir = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(&dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// The path `git rev-parse --git-path <name>` reports, made absolute, when it
/// exists. In a linked worktree `.git` is a file, and HEAD lives under
/// `<common dir>/worktrees/<name>/` while branch refs live in the common dir;
/// `--git-path` resolves both.
fn git_path(name: &str) -> Option<std::path::PathBuf> {
    let reported = std::path::PathBuf::from(git(&["rev-parse", "--git-path", name])?);
    let path = if reported.is_absolute() {
        reported
    } else {
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?).join(reported)
    };
    path.exists().then_some(path)
}

/// Re-run this script (and so refresh `GIT_SHA`) when HEAD moves: a checkout
/// rewrites HEAD, a commit rewrites the branch ref it points at (a loose ref,
/// or `packed-refs` after `git pack-refs`). Only paths that exist are
/// watched: cargo re-runs a build script on every build when a watched path
/// is missing, which recompiled the whole crate each time in a worktree
/// while this watched `../.git/HEAD` (#5826). Without git nothing is
/// emitted.
fn emit_git_head_rerun() {
    let Some(head) = git_path("HEAD") else {
        return;
    };
    println!("cargo:rerun-if-changed={}", head.display());
    let Some(branch_ref) = git(&["symbolic-ref", "-q", "HEAD"]) else {
        // Detached HEAD: the commit id is in HEAD itself.
        return;
    };
    match git_path(&branch_ref) {
        Some(loose) => println!("cargo:rerun-if-changed={}", loose.display()),
        // A packed ref is rewritten loose on the next commit, inside its
        // existing parent directory, so watch that directory.
        None => {
            if let Some(parent) = std::path::Path::new(&branch_ref)
                .parent()
                .and_then(|p| p.to_str())
                .and_then(git_path)
            {
                println!("cargo:rerun-if-changed={}", parent.display());
            }
        }
    }
    if let Some(packed) = git_path("packed-refs") {
        println!("cargo:rerun-if-changed={}", packed.display());
    }
}

/// CI test shards, in the order scripts/ci/test-shards.py lists them. Keep
/// in step with the `test-shard-*` features in Cargo.toml; the script's
/// `check` fails when the three drift.
const TEST_SHARDS: &[&str] = &[
    "handlers-1",
    "handlers-2",
    "services-1",
    "services-2",
    "router",
];

/// Set `ak_test_shard = "<name>"` for the shards whose inline test modules
/// this build compiles. Every test module is gated by
/// `#[cfg(ak_test_shard = "<its shard>")]` on top of `#[cfg(test)]`.
///
/// No `test-shard-*` feature enabled -- every ordinary build, `cargo test`,
/// `cargo nextest run`, clippy -- sets ALL of them, so nothing is gated out.
/// `--features test-shard-<name>` sets only the ones selected, which is how
/// a CI matrix leg compiles one slice of the tests. `ak_test_shard_subset`
/// marks such a build: test helpers shared by several shards are then
/// legitimately unused in some of them, and lib.rs relaxes `dead_code`
/// for exactly that case (the full build keeps the lint).
fn emit_test_shard_cfg() {
    let values = TEST_SHARDS
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    println!("cargo::rustc-check-cfg=cfg(ak_test_shard, values({values}))");
    println!("cargo::rustc-check-cfg=cfg(ak_test_shard_subset)");

    let feature_on = |shard: &str| {
        let var = format!(
            "CARGO_FEATURE_TEST_SHARD_{}",
            shard.to_uppercase().replace('-', "_")
        );
        std::env::var_os(var).is_some()
    };
    let selected: Vec<&str> = TEST_SHARDS
        .iter()
        .copied()
        .filter(|s| feature_on(s))
        .collect();
    let active: &[&str] = if selected.is_empty() {
        TEST_SHARDS
    } else {
        &selected
    };
    if active.len() < TEST_SHARDS.len() {
        println!("cargo:rustc-cfg=ak_test_shard_subset");
    }
    for shard in active {
        println!("cargo:rustc-cfg=ak_test_shard=\"{shard}\"");
    }
}
