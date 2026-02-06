fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = "src/grpc/generated";
    std::fs::create_dir_all(out_dir)?;

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(out_dir)
        .compile_protos(&["proto/sbom.proto"], &["proto"])?;
    Ok(())
}
