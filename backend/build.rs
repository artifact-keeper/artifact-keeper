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

    let git_sha = std::env::var("GIT_SHA")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        String::from_utf8(o.stdout)
                            .ok()
                            .map(|s| s.trim().to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "unknown".to_string())
        });
    println!("cargo:rustc-env=GIT_SHA={git_sha}");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-env-changed=GIT_SHA");

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
