fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // Declaring any rerun-if-changed at all turns off cargo's default of
    // rerunning on every change in the package. That default must stay off:
    // a rerun regenerates the protos and recompiles the whole crate (#6181).
    // So the schemas name themselves, or an edited .proto regenerates nothing
    // and the build fails against the previous generation -- or, worse, keeps
    // compiling against it.
    for entry in std::fs::read_dir("proto")? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "proto") {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

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

    // The hosted BSR endpoints answer the buf CLI, which speaks Connect with
    // the binary protobuf codec, so the messages it sends and expects need real
    // generated types rather than hand-written serde structs. Only the subset
    // the endpoints exchange is vendored; see proto/bsr_module_v1.proto.
    prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(
            &[
                "proto/bsr_owner_v1.proto",
                "proto/bsr_module_v1.proto",
                "proto/bsr_module_v1beta1.proto",
            ],
            &["proto"],
        )?;

    // The commit, version and Debian `Release` `Date:` floor are not baked
    // here: crates/ak-build-info's build script owns them, so this script
    // reads no build environment and reruns only for a .proto (#6181).

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
