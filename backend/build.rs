fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // Generate file descriptor set for gRPC reflection
    let descriptor_path = format!("{}/sbom_descriptor.bin", out_dir);

    tonic_build::configure()
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

    Ok(())
}
