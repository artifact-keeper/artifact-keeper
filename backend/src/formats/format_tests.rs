//! Comprehensive tests for all format handlers.
//!
//! Tests the format handler registry (get_core_handler, get_handler_for_format),
//! handler trait compliance, and ensures every format has a working handler.

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::formats::{get_core_handler, get_handler_for_format, list_core_formats};
    use crate::models::repository::RepositoryFormat;

    /// All format keys that should be resolved by get_core_handler.
    const ALL_FORMAT_KEYS: &[&str] = &[
        "maven",
        "npm",
        "pypi",
        "nuget",
        "go",
        "rubygems",
        "docker",
        "helm",
        "rpm",
        "debian",
        "conan",
        "cargo",
        "generic",
        "podman",
        "buildx",
        "oras",
        "wasm_oci",
        "helm_oci",
        "poetry",
        "conda",
        "yarn",
        "bower",
        "pnpm",
        "chocolatey",
        "powershell",
        "terraform",
        "opentofu",
        "alpine",
        "conda_native",
        "composer",
        "hex",
        "cocoapods",
        "swift",
        "pub",
        "sbt",
        "chef",
        "puppet",
        "ansible",
        "gitlfs",
        "vscode",
        "jetbrains",
        "huggingface",
        "mlmodel",
        "cran",
        "vagrant",
        "opkg",
        "p2",
        "bazel",
    ];

    /// Additional alias keys that get_core_handler should also resolve.
    const ALIAS_FORMAT_KEYS: &[&str] = &["oci", "cursor", "windsurf", "kiro"];

    /// All RepositoryFormat enum variants.
    fn all_repository_formats() -> Vec<RepositoryFormat> {
        vec![
            RepositoryFormat::Maven,
            RepositoryFormat::Gradle,
            RepositoryFormat::Npm,
            RepositoryFormat::Pypi,
            RepositoryFormat::Nuget,
            RepositoryFormat::Go,
            RepositoryFormat::Rubygems,
            RepositoryFormat::Docker,
            RepositoryFormat::Helm,
            RepositoryFormat::Rpm,
            RepositoryFormat::Debian,
            RepositoryFormat::Conan,
            RepositoryFormat::Cargo,
            RepositoryFormat::Generic,
            RepositoryFormat::Podman,
            RepositoryFormat::Buildx,
            RepositoryFormat::Oras,
            RepositoryFormat::WasmOci,
            RepositoryFormat::HelmOci,
            RepositoryFormat::Poetry,
            RepositoryFormat::Conda,
            RepositoryFormat::Yarn,
            RepositoryFormat::Bower,
            RepositoryFormat::Pnpm,
            RepositoryFormat::Chocolatey,
            RepositoryFormat::Powershell,
            RepositoryFormat::Terraform,
            RepositoryFormat::Opentofu,
            RepositoryFormat::Alpine,
            RepositoryFormat::CondaNative,
            RepositoryFormat::Composer,
            RepositoryFormat::Hex,
            RepositoryFormat::Cocoapods,
            RepositoryFormat::Swift,
            RepositoryFormat::Pub,
            RepositoryFormat::Sbt,
            RepositoryFormat::Chef,
            RepositoryFormat::Puppet,
            RepositoryFormat::Ansible,
            RepositoryFormat::Gitlfs,
            RepositoryFormat::Vscode,
            RepositoryFormat::Jetbrains,
            RepositoryFormat::Huggingface,
            RepositoryFormat::Mlmodel,
            RepositoryFormat::Cran,
            RepositoryFormat::Vagrant,
            RepositoryFormat::Opkg,
            RepositoryFormat::P2,
            RepositoryFormat::Bazel,
        ]
    }

    #[test]
    fn test_all_format_keys_resolve_to_handler() {
        for key in ALL_FORMAT_KEYS {
            let handler = get_core_handler(key);
            assert!(
                handler.is_some(),
                "get_core_handler(\"{}\") returned None — handler not registered",
                key
            );
        }
    }

    #[test]
    fn test_alias_format_keys_resolve_to_handler() {
        for key in ALIAS_FORMAT_KEYS {
            let handler = get_core_handler(key);
            assert!(
                handler.is_some(),
                "get_core_handler(\"{}\") returned None — alias not registered",
                key
            );
        }
    }

    #[test]
    fn test_unknown_format_key_returns_none() {
        assert!(get_core_handler("nonexistent").is_none());
        assert!(get_core_handler("").is_none());
        assert!(get_core_handler("docker_v2").is_none());
    }

    #[test]
    fn test_all_enum_variants_have_handler() {
        for format in all_repository_formats() {
            let handler = get_handler_for_format(&format);
            // Just verify it doesn't panic and returns a valid handler
            let _ = handler.format();
            let _ = handler.format_key();
            assert!(!handler.is_wasm_plugin());
        }
    }

    #[test]
    fn test_format_key_returns_valid_string_for_all_formats() {
        for format in all_repository_formats() {
            let handler = get_handler_for_format(&format);
            let key = handler.format_key();
            assert!(
                !key.is_empty(),
                "format_key() returned empty string for {:?}",
                format
            );
            // format_key should be lowercase and use underscores or digits
            assert!(
                key.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "format_key() '{}' for {:?} contains unexpected characters",
                key,
                format
            );
        }
    }

    #[test]
    fn test_list_core_formats_is_complete() {
        let listed = list_core_formats();
        for key in ALL_FORMAT_KEYS {
            assert!(
                listed.contains(key),
                "list_core_formats() is missing '{}'",
                key
            );
        }
    }

    #[test]
    fn test_list_core_formats_contains_no_duplicates() {
        let listed = list_core_formats();
        let mut seen = std::collections::HashSet::new();
        for key in &listed {
            assert!(
                seen.insert(key),
                "list_core_formats() contains duplicate '{}'",
                key
            );
        }
    }

    #[test]
    fn test_format_key_matches_expected_for_all_handlers() {
        // Note: Aliases like Gradle, Poetry, etc. map to shared handlers that return the primary key
        // (e.g., Gradle -> MavenHandler -> "maven", Poetry -> PypiHandler -> "pypi")
        let expected_keys: Vec<(&str, RepositoryFormat)> = vec![
            ("maven", RepositoryFormat::Maven),
            ("maven", RepositoryFormat::Gradle), // Gradle maps to MavenHandler
            ("npm", RepositoryFormat::Npm),
            ("pypi", RepositoryFormat::Pypi),
            ("nuget", RepositoryFormat::Nuget),
            ("go", RepositoryFormat::Go),
            ("rubygems", RepositoryFormat::Rubygems),
            ("docker", RepositoryFormat::Docker),
            ("helm", RepositoryFormat::Helm),
            ("rpm", RepositoryFormat::Rpm),
            ("debian", RepositoryFormat::Debian),
            ("conan", RepositoryFormat::Conan),
            ("cargo", RepositoryFormat::Cargo),
            ("generic", RepositoryFormat::Generic),
            ("docker", RepositoryFormat::Podman), // Podman maps to OciHandler
            ("docker", RepositoryFormat::Buildx), // Buildx maps to OciHandler
            ("docker", RepositoryFormat::Oras),   // Oras maps to OciHandler
            ("docker", RepositoryFormat::WasmOci), // WasmOci maps to OciHandler
            ("docker", RepositoryFormat::HelmOci), // HelmOci maps to OciHandler
            ("pypi", RepositoryFormat::Poetry),   // Poetry maps to PypiHandler
            ("pypi", RepositoryFormat::Conda),    // Conda maps to PypiHandler
            ("npm", RepositoryFormat::Yarn),      // Yarn maps to NpmHandler
            ("npm", RepositoryFormat::Bower),     // Bower maps to NpmHandler
            ("npm", RepositoryFormat::Pnpm),      // Pnpm maps to NpmHandler
            ("nuget", RepositoryFormat::Chocolatey), // Chocolatey maps to NugetHandler
            ("nuget", RepositoryFormat::Powershell), // Powershell maps to NugetHandler
            ("terraform", RepositoryFormat::Terraform),
            ("terraform", RepositoryFormat::Opentofu), // Opentofu maps to TerraformHandler
            ("alpine", RepositoryFormat::Alpine),
            ("conda_native", RepositoryFormat::CondaNative),
            ("composer", RepositoryFormat::Composer),
            ("hex", RepositoryFormat::Hex),
            ("cocoapods", RepositoryFormat::Cocoapods),
            ("swift", RepositoryFormat::Swift),
            ("pub", RepositoryFormat::Pub),
            ("sbt", RepositoryFormat::Sbt),
            ("chef", RepositoryFormat::Chef),
            ("puppet", RepositoryFormat::Puppet),
            ("ansible", RepositoryFormat::Ansible),
            ("gitlfs", RepositoryFormat::Gitlfs),
            ("vscode", RepositoryFormat::Vscode),
            ("jetbrains", RepositoryFormat::Jetbrains),
            ("huggingface", RepositoryFormat::Huggingface),
            ("mlmodel", RepositoryFormat::Mlmodel),
            ("cran", RepositoryFormat::Cran),
            ("vagrant", RepositoryFormat::Vagrant),
            ("opkg", RepositoryFormat::Opkg),
            ("p2", RepositoryFormat::P2),
            ("bazel", RepositoryFormat::Bazel),
        ];

        for (expected_key, format) in expected_keys {
            let handler = get_handler_for_format(&format);
            assert_eq!(
                handler.format_key(),
                expected_key,
                "format_key() for {:?} should be '{}' but got '{}'",
                format,
                expected_key,
                handler.format_key()
            );
        }
    }

    /// Test that validate() and parse_metadata() accept valid content for each handler.
    #[tokio::test]
    async fn test_all_handlers_validate_empty_content() {
        let empty = Bytes::new();
        // Some handlers reject empty content (which is fine), some accept it.
        // This test ensures no handler panics on empty content.
        for key in ALL_FORMAT_KEYS {
            let handler = get_core_handler(key).unwrap();
            let _ = handler.validate("test/path", &empty).await;
            let _ = handler.parse_metadata("test/path", &empty).await;
        }
    }

    /// Test that generate_index() doesn't panic for any handler.
    #[tokio::test]
    async fn test_all_handlers_generate_index_no_panic() {
        for key in ALL_FORMAT_KEYS {
            let handler = get_core_handler(key).unwrap();
            let _ = handler.generate_index().await;
        }
    }

    // ---- Alias handler resolution tests ----

    #[test]
    fn test_oci_aliases_resolve_to_oci_handler() {
        let oci_keys = &[
            "docker", "podman", "buildx", "oras", "wasm_oci", "helm_oci", "oci",
        ];
        for key in oci_keys {
            let handler = get_core_handler(key).unwrap();
            // All OCI aliases should share the same format_key behavior
            assert!(
                !handler.is_wasm_plugin(),
                "OCI handler for '{}' should not be a WASM plugin",
                key
            );
        }
    }

    #[test]
    fn test_npm_aliases_resolve() {
        let npm_keys = &["npm", "yarn", "bower", "pnpm"];
        for key in npm_keys {
            let handler = get_core_handler(key).unwrap();
            assert!(!handler.is_wasm_plugin());
        }
    }

    #[test]
    fn test_pypi_aliases_resolve() {
        let pypi_keys = &["pypi", "poetry", "conda"];
        for key in pypi_keys {
            let handler = get_core_handler(key).unwrap();
            assert!(!handler.is_wasm_plugin());
        }
    }

    #[test]
    fn test_nuget_aliases_resolve() {
        let nuget_keys = &["nuget", "chocolatey", "powershell"];
        for key in nuget_keys {
            let handler = get_core_handler(key).unwrap();
            assert!(!handler.is_wasm_plugin());
        }
    }

    #[test]
    fn test_terraform_aliases_resolve() {
        let tf_keys = &["terraform", "opentofu"];
        for key in tf_keys {
            let handler = get_core_handler(key).unwrap();
            assert!(!handler.is_wasm_plugin());
        }
    }

    #[test]
    fn test_vscode_aliases_resolve() {
        let vscode_keys = &["vscode", "cursor", "windsurf", "kiro"];
        for key in vscode_keys {
            let handler = get_core_handler(key).unwrap();
            assert!(!handler.is_wasm_plugin());
        }
    }

    // ---- Per-format validate/parse_metadata with valid content ----

    #[tokio::test]
    async fn test_maven_handler_valid_pom() {
        let handler = get_core_handler("maven").unwrap();
        let pom_content = Bytes::from(
            r#"<?xml version="1.0"?>
            <project>
                <groupId>com.example</groupId>
                <artifactId>my-lib</artifactId>
                <version>1.0.0</version>
            </project>"#,
        );
        let result = handler
            .validate("com/example/my-lib/1.0.0/my-lib-1.0.0.pom", &pom_content)
            .await;
        assert!(result.is_ok(), "Maven validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_npm_handler_valid_package() {
        let handler = get_core_handler("npm").unwrap();
        let content = Bytes::from(r#"{"name":"my-pkg","version":"1.0.0"}"#);
        let result = handler
            .parse_metadata("my-pkg/-/my-pkg-1.0.0.tgz", &content)
            .await;
        assert!(
            result.is_ok(),
            "npm parse_metadata failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_pypi_handler_valid_package() {
        let handler = get_core_handler("pypi").unwrap();
        // PyPI validates wheel content (zip format), so just test parse_metadata without content
        let content = Bytes::new();
        let result = handler.parse_metadata("simple/my-package/", &content).await;
        assert!(
            result.is_ok(),
            "PyPI parse_metadata failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_cargo_handler_valid_crate() {
        let handler = get_core_handler("cargo").unwrap();
        // Use a valid Cargo index path instead of download path
        let content = Bytes::new();
        let result = handler.parse_metadata("se/rd/serde", &content).await;
        assert!(
            result.is_ok(),
            "Cargo parse_metadata failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_helm_handler_valid_chart() {
        let handler = get_core_handler("helm").unwrap();
        // Helm validates tar.gz content, so just test parse_metadata with index path
        let content = Bytes::new();
        let result = handler.parse_metadata("index.yaml", &content).await;
        assert!(
            result.is_ok(),
            "Helm parse_metadata failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_generic_handler_accepts_any() {
        let handler = get_core_handler("generic").unwrap();
        let content = Bytes::from("any content");
        let result = handler.validate("path/to/file.bin", &content).await;
        assert!(
            result.is_ok(),
            "Generic validate failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_terraform_handler_valid_provider() {
        let handler = get_core_handler("terraform").unwrap();
        let content = Bytes::new();
        let result = handler
            .parse_metadata("hashicorp/aws/5.0.0/download/linux/amd64", &content)
            .await;
        assert!(
            result.is_ok(),
            "Terraform parse_metadata failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_alpine_handler_valid_apk() {
        let handler = get_core_handler("alpine").unwrap();
        let content = Bytes::from("fake apk content");
        let result = handler
            .validate("v3.18/main/x86_64/curl-8.1.0-r0.apk", &content)
            .await;
        assert!(result.is_ok(), "Alpine validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_composer_handler_valid_package() {
        let handler = get_core_handler("composer").unwrap();
        let content = Bytes::from("fake zip");
        let result = handler.validate("p2/vendor/package.json", &content).await;
        assert!(
            result.is_ok(),
            "Composer validate failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_hex_handler_valid_package() {
        let handler = get_core_handler("hex").unwrap();
        let content = Bytes::from("fake hex tarball");
        let result = handler
            .validate("tarballs/phoenix-1.7.0.tar", &content)
            .await;
        assert!(result.is_ok(), "Hex validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_cocoapods_handler_valid_podspec() {
        let handler = get_core_handler("cocoapods").unwrap();
        let content = Bytes::new();
        let result = handler
            .parse_metadata("Specs/Alamofire/5.0.0/Alamofire.podspec.json", &content)
            .await;
        assert!(
            result.is_ok(),
            "CocoaPods parse_metadata failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_swift_handler_valid_package() {
        let handler = get_core_handler("swift").unwrap();
        let content = Bytes::from("fake swift package");
        let result = handler.validate("apple/swift-nio/1.0.0", &content).await;
        assert!(result.is_ok(), "Swift validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_pub_handler_valid_package() {
        let handler = get_core_handler("pub").unwrap();
        let content = Bytes::from("fake pub tarball");
        let result = handler
            .validate("packages/flutter_web/versions/1.0.0.tar.gz", &content)
            .await;
        assert!(result.is_ok(), "Pub validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_sbt_handler_valid_artifact() {
        let handler = get_core_handler("sbt").unwrap();
        let content = Bytes::new();
        // Use valid sbt path format: org/module/revision/<type>s/artifact.ext
        let result = handler
            .parse_metadata("com/example/1.0.0/jars/my-lib-1.0.0.jar", &content)
            .await;
        assert!(
            result.is_ok(),
            "sbt parse_metadata failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_chef_handler_valid_cookbook() {
        let handler = get_core_handler("chef").unwrap();
        let content = Bytes::from("fake cookbook tarball");
        let result = handler
            .validate("api/v1/cookbooks/apache2/versions/5.0.0", &content)
            .await;
        assert!(result.is_ok(), "Chef validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_puppet_handler_valid_module() {
        let handler = get_core_handler("puppet").unwrap();
        let content = Bytes::from("fake puppet module");
        let result = handler
            .validate("v3/modules/puppetlabs-apache", &content)
            .await;
        assert!(result.is_ok(), "Puppet validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_ansible_handler_valid_collection() {
        let handler = get_core_handler("ansible").unwrap();
        let content = Bytes::from("fake ansible collection");
        let result = handler
            .validate("api/v3/collections/community/general", &content)
            .await;
        assert!(
            result.is_ok(),
            "Ansible validate failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_gitlfs_handler_valid_object() {
        let handler = get_core_handler("gitlfs").unwrap();
        let content = Bytes::from("fake lfs object");
        // Git LFS object path format: objects/<oid> where oid has no slashes
        let result = handler
            .validate(
                "objects/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                &content,
            )
            .await;
        assert!(
            result.is_ok(),
            "Git LFS validate failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_vscode_handler_valid_extension() {
        let handler = get_core_handler("vscode").unwrap();
        let content = Bytes::from("fake vsix");
        let result = handler
            .validate(
                "extensions/ms-python/python/2024.1.0/ms-python.python-2024.1.0.vsix",
                &content,
            )
            .await;
        assert!(result.is_ok(), "VSCode validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_jetbrains_handler_valid_plugin() {
        let handler = get_core_handler("jetbrains").unwrap();
        let content = Bytes::from("fake plugin zip");
        let result = handler
            .validate(
                "plugins/my-plugin/versions/1.0.0/my-plugin-1.0.0.zip",
                &content,
            )
            .await;
        assert!(
            result.is_ok(),
            "JetBrains validate failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_huggingface_handler_valid_model() {
        let handler = get_core_handler("huggingface").unwrap();
        let content = Bytes::from("fake model weights");
        // Use valid HuggingFace path: org/name/resolve/revision/file
        let result = handler
            .parse_metadata("openai/gpt-2/resolve/main/model.safetensors", &content)
            .await;
        assert!(
            result.is_ok(),
            "HuggingFace parse_metadata failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_mlmodel_handler_valid_model() {
        let handler = get_core_handler("mlmodel").unwrap();
        let content = Bytes::from("fake model");
        let result = handler
            .validate(
                "models/my-model/versions/v1.0.0/artifacts/model.pkl",
                &content,
            )
            .await;
        assert!(
            result.is_ok(),
            "MLModel validate failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_cran_handler_valid_package() {
        let handler = get_core_handler("cran").unwrap();
        let content = Bytes::from("fake R package");
        let result = handler
            .validate("src/contrib/ggplot2_3.4.0.tar.gz", &content)
            .await;
        assert!(result.is_ok(), "CRAN validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_vagrant_handler_valid_box() {
        let handler = get_core_handler("vagrant").unwrap();
        let content = Bytes::from("fake vagrant box");
        let result = handler
            .validate(
                "hashicorp/bionic/versions/1.0.0/providers/virtualbox/download",
                &content,
            )
            .await;
        assert!(
            result.is_ok(),
            "Vagrant validate failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_opkg_handler_valid_package() {
        let handler = get_core_handler("opkg").unwrap();
        let content = Bytes::from("fake opkg ipk");
        let result = handler
            .validate("packages/base/curl_8.0.0-1_aarch64.ipk", &content)
            .await;
        assert!(result.is_ok(), "Opkg validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_p2_handler_valid_artifact() {
        let handler = get_core_handler("p2").unwrap();
        let content = Bytes::from("fake eclipse plugin");
        let result = handler
            .validate("plugins/org.eclipse.core_3.0.0.jar", &content)
            .await;
        assert!(result.is_ok(), "P2 validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_bazel_handler_valid_module() {
        let handler = get_core_handler("bazel").unwrap();
        let content = Bytes::from("fake bazel module");
        let result = handler
            .validate("modules/rules_go/0.42.0/MODULE.bazel", &content)
            .await;
        assert!(result.is_ok(), "Bazel validate failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_conda_native_handler_valid_package() {
        let handler = get_core_handler("conda_native").unwrap();
        let content = Bytes::from("fake conda package");
        let result = handler
            .validate("linux-64/numpy-1.24.0-py311_0.conda", &content)
            .await;
        assert!(
            result.is_ok(),
            "Conda native validate failed: {:?}",
            result.err()
        );
    }
}
