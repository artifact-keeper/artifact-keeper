//! Hex registry resource encoding (`/names`, `/versions`, `/packages/{name}`).
//!
//! A real `mix` client does not read JSON from a hex repository. It requires
//! every registry resource to be **gzipped, signed protobuf**:
//!
//! ```text
//! resource = gzip(Signed{ payload, signature })
//! payload  = <Names | Versions | Package> encoded as protobuf
//! signature = RSA PKCS#1 v1.5 over `payload`, digest SHA-512
//! ```
//!
//! and it verifies `signature` against the repository public key configured at
//! `mix hex.repo add <name> <url> --public-key=<pem>` before it will look at
//! the payload. Serving JSON makes the client fail inside `:zlib.gunzip/1`
//! (`:data_error`) because the very first thing it does is gunzip the body.
//!
//! The shapes here are not inferred from documentation: they mirror the real
//! client's own schemas (hex 2.5.1, `mix_hex_pb_{signed,names,versions,package}`)
//! and the encoders are pinned by golden-byte tests against registry files
//! produced by the real `mix hex.registry build`.
//!
//! Consumers pin the repository's key explicitly — `mix hex.repo add` performs
//! no key discovery:
//!
//! ```text
//! curl -o key.pem https://<host>/hex/<repo>/public_key
//! mix hex.repo add <repo> https://<host>/hex/<repo> --public-key=key.pem
//! ```
//!
//! The repo must be added under the same name AK serves it as: the client
//! pattern-matches the registry's `repository` field against its local repo
//! name and rejects a mismatch with `{error, bad_repo_name}`.

use std::io::Write;

use flate2::write::GzEncoder;
use flate2::Compression;
use prost::Message;
use serde::{Deserialize, Serialize};

/// Generated protobuf types mirroring hex_core's `mix_hex_pb_*` schemas.
pub mod pb {
    pub mod signed {
        include!(concat!(env!("OUT_DIR"), "/hexpb.signed.rs"));
    }
    pub mod names {
        include!(concat!(env!("OUT_DIR"), "/hexpb.names.rs"));
    }
    pub mod versions {
        include!(concat!(env!("OUT_DIR"), "/hexpb.versions.rs"));
    }
    pub mod pkg {
        include!(concat!(env!("OUT_DIR"), "/hexpb.pkg.rs"));
    }
}

/// Content type the hex client expects for registry resources.
pub const REGISTRY_CONTENT_TYPE: &str = "application/octet-stream";

/// A single dependency of a release, as carried in the registry.
///
/// Serializable so `publish` can record the parsed requirements alongside the
/// artifact and the registry path does not have to re-open the tarball.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HexDependency {
    pub package: String,
    pub requirement: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub app: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
}

/// A release row the registry advertises for a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexRelease {
    pub version: String,
    /// Raw 32 bytes of the tarball's `CHECKSUM` member.
    pub inner_checksum: Vec<u8>,
    /// Raw 32 bytes of the SHA-256 over the whole `.tar`.
    pub outer_checksum: Vec<u8>,
    pub dependencies: Vec<HexDependency>,
}

/// One package name plus the instant it last changed, for `/names`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexPackageName {
    pub name: String,
    /// Seconds since the unix epoch; `None` omits `updated_at`.
    pub updated_at_secs: Option<i64>,
}

// ---------------------------------------------------------------------------
// Payload builders (protobuf encoding, pre-signature)
// ---------------------------------------------------------------------------

/// Encode the `Names` payload advertised at `/names`.
pub fn encode_names_payload(repository: &str, packages: &[HexPackageName]) -> Vec<u8> {
    let msg = pb::names::Names {
        repository: repository.to_string(),
        packages: packages
            .iter()
            .map(|p| pb::names::Package {
                name: p.name.clone(),
                updated_at: p.updated_at_secs.map(|s| pb::names::Timestamp {
                    seconds: s,
                    nanos: 0,
                }),
            })
            .collect(),
    };
    msg.encode_to_vec()
}

/// Encode the `Versions` payload advertised at `/versions`.
pub fn encode_versions_payload(repository: &str, packages: &[(String, Vec<String>)]) -> Vec<u8> {
    let msg = pb::versions::Versions {
        repository: repository.to_string(),
        packages: packages
            .iter()
            .map(|(name, versions)| pb::versions::Package {
                name: name.clone(),
                versions: versions.clone(),
                retired: Vec::new(),
                with_advisories: Vec::new(),
            })
            .collect(),
    };
    msg.encode_to_vec()
}

/// Encode the `Package` payload advertised at `/packages/{name}`.
pub fn encode_package_payload(repository: &str, name: &str, releases: &[HexRelease]) -> Vec<u8> {
    let msg = pb::pkg::Package {
        name: name.to_string(),
        repository: repository.to_string(),
        advisories: Vec::new(),
        releases: releases
            .iter()
            .map(|r| pb::pkg::Release {
                version: r.version.clone(),
                inner_checksum: r.inner_checksum.clone(),
                outer_checksum: Some(r.outer_checksum.clone()),
                retired: None,
                advisory_indexes: Vec::new(),
                published_at: None,
                dependencies: r
                    .dependencies
                    .iter()
                    .map(|d| pb::pkg::Dependency {
                        package: d.package.clone(),
                        requirement: d.requirement.clone(),
                        optional: Some(d.optional),
                        app: d.app.clone(),
                        repository: d.repository.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    msg.encode_to_vec()
}

// ---------------------------------------------------------------------------
// Signing envelope
// ---------------------------------------------------------------------------

/// Wrap an encoded payload plus its signature into the gzipped `Signed`
/// envelope the client fetches.
///
/// `signature` must be an RSA PKCS#1 v1.5 signature over `payload` using a
/// SHA-512 digest — that is what `:mix_hex_registry.verify/3` checks.
pub fn signed_gzip(payload: Vec<u8>, signature: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let signed = pb::signed::Signed {
        payload,
        signature: Some(signature),
    };
    let encoded = signed.encode_to_vec();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&encoded)?;
    encoder.finish()
}

// ---------------------------------------------------------------------------
// Tarball-derived facts
// ---------------------------------------------------------------------------

/// Decode the ASCII-hex `CHECKSUM` member of a hex tarball into raw bytes.
///
/// Hex tarballs carry the inner checksum as an uppercase hex string; the
/// registry advertises it as raw bytes and the client copies it into
/// `mix.lock`, so a wrong value fails the install rather than degrading.
pub fn decode_inner_checksum(checksum_text: &str) -> Result<Vec<u8>, String> {
    let trimmed = checksum_text.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "CHECKSUM must be 64 hex characters, got {} characters",
            trimmed.len()
        ));
    }
    (0..32)
        .map(|i| {
            u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("Invalid CHECKSUM hex: {}", e))
        })
        .collect()
}

/// Decode a lowercase/uppercase hex digest string (the stored
/// `artifacts.checksum_sha256`) into the raw bytes the registry advertises as
/// `outer_checksum`.
pub fn decode_outer_checksum(digest_hex: &str) -> Result<Vec<u8>, String> {
    decode_inner_checksum(digest_hex)
}

// ---------------------------------------------------------------------------
// metadata.config requirements parsing
// ---------------------------------------------------------------------------

/// A value in the tiny subset of Erlang terms `metadata.config` uses.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ErlValue {
    Str(String),
    Bool(bool),
}

/// Parse the `requirements` term of a hex `metadata.config` into registry
/// dependencies.
///
/// The client resolves a package's dependencies from the **registry**, not from
/// the tarball, so dropping this would make `mix deps.get` silently install a
/// package without its dependencies. The term looks like:
///
/// ```erlang
/// {<<"requirements">>,
///  [[{<<"name">>,<<"jason">>},
///    {<<"app">>,<<"jason">>},
///    {<<"optional">>,false},
///    {<<"requirement">>,<<"~> 1.4">>},
///    {<<"repository">>,<<"hexpm">>}]]}.
/// ```
///
/// Returns an empty vector when the package declares no requirements.
pub fn parse_requirements(metadata_config: &str) -> Result<Vec<HexDependency>, String> {
    let term = match extract_term_value(metadata_config, "requirements") {
        Some(t) => t,
        None => return Ok(Vec::new()),
    };

    let mut deps = Vec::new();
    for group in split_top_level_groups(term) {
        let pairs = parse_kv_pairs(group);
        let package = match pairs.iter().find(|(k, _)| k == "name") {
            Some((_, ErlValue::Str(s))) => s.clone(),
            _ => continue,
        };
        let requirement = match pairs.iter().find(|(k, _)| k == "requirement") {
            Some((_, ErlValue::Str(s))) => s.clone(),
            // A requirement-less dependency means "any version".
            _ => String::new(),
        };
        let optional = matches!(
            pairs.iter().find(|(k, _)| k == "optional"),
            Some((_, ErlValue::Bool(true)))
        );
        let app = match pairs.iter().find(|(k, _)| k == "app") {
            Some((_, ErlValue::Str(s))) => Some(s.clone()),
            _ => None,
        };
        let repository = match pairs.iter().find(|(k, _)| k == "repository") {
            Some((_, ErlValue::Str(s))) => Some(s.clone()),
            _ => None,
        };
        deps.push(HexDependency {
            package,
            requirement,
            optional,
            app,
            repository,
        });
    }
    Ok(deps)
}

/// Return the raw text of the value side of a top-level `{<<"key">>, VALUE}`
/// term, with balanced brackets and quoted content respected.
fn extract_term_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{{<<\"{}\">>", key);
    let start = content.find(&needle)?;
    let after_key = start + needle.len();
    let rest = &content[after_key..];
    let comma = rest.find(',')?;
    let value_start = after_key + comma + 1;
    let value = content[value_start..].trim_start();
    let offset = value_start + (content[value_start..].len() - value.len());
    let end = balanced_end(&content[offset..])?;
    Some(content[offset..offset + end].trim())
}

/// Length of the balanced term starting at the beginning of `s`.
fn balanced_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            // Skip escapes inside a binary literal.
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
                if depth < 0 {
                    return None;
                }
            }
            // A bare value (e.g. `[]` handled above, or an atom) ends at the
            // terminating period of the top-level term.
            b'.' if depth == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split the outer `[ [...], [...] ]` requirements list into its groups.
fn split_top_level_groups(list_term: &str) -> Vec<&str> {
    let bytes = list_term.as_bytes();
    let mut groups = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut group_start: Option<usize> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'[' => {
                depth += 1;
                if depth == 2 {
                    group_start = Some(i);
                }
            }
            b']' => {
                if depth == 2 {
                    if let Some(s) = group_start.take() {
                        groups.push(&list_term[s..=i]);
                    }
                }
                depth -= 1;
            }
            _ => {}
        }
        i += 1;
    }
    groups
}

/// Parse `{<<"key">>,<<"value">>}` / `{<<"key">>,true}` pairs out of a group.
fn parse_kv_pairs(group: &str) -> Vec<(String, ErlValue)> {
    let mut pairs = Vec::new();
    let mut rest = group;
    while let Some(idx) = rest.find("{<<\"") {
        let after = &rest[idx + 4..];
        let key_end = match after.find("\">>") {
            Some(k) => k,
            None => break,
        };
        let key = after[..key_end].to_string();
        let after_key = &after[key_end + 3..];
        let comma = match after_key.find(',') {
            Some(c) => c,
            None => break,
        };
        let value_text = after_key[comma + 1..].trim_start();
        let value = if let Some(stripped) = value_text.strip_prefix("<<\"") {
            stripped
                .find("\">>")
                .map(|end| ErlValue::Str(stripped[..end].to_string()))
        } else if value_text.starts_with("true") {
            Some(ErlValue::Bool(true))
        } else if value_text.starts_with("false") {
            Some(ErlValue::Bool(false))
        } else {
            None
        };
        if let Some(v) = value {
            pairs.push((key, v));
        }
        rest = &rest[idx + 4 + key_end..];
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Golden bytes.
    //
    // These vectors were produced by the REAL client, not by this code: a
    // package was built with `mix hex.build` and a registry with
    // `mix hex.registry build --name=dtf` (elixir:1.17 / mix 1.17.3 /
    // hex 2.5.1), then the `Signed.payload` of each resource was dumped via
    // `mix_hex_registry:unpack_*` + `mix_hex_pb_*:encode_msg`. Any drift in
    // field numbers or proto2 required-field encoding breaks these.
    // -----------------------------------------------------------------------

    /// `Names{packages: [{name: "dtf_marker", updated_at: {1784245817, 0}}], repository: "dtf"}`
    const GOLDEN_NAMES_PAYLOAD: &str = "0A160A0A6474665F6D61726B65721A0808B9DCE5D20610001203647466";

    /// `Versions{packages: [{name: "dtf_marker", versions: ["1.0.0"]}], repository: "dtf"}`
    ///
    /// From `public/versions` of the same `mix hex.registry build` run as
    /// [`GOLDEN_NAMES_PAYLOAD`].
    const GOLDEN_VERSIONS_PAYLOAD: &str = "0A130A0A6474665F6D61726B65721205312E302E301203647466";

    /// `Package{releases: [{version: "1.0.0", inner_checksum: <32B>, outer_checksum: <32B>}],
    ///  name: "dtf_marker", repository: "dtf"}`
    ///
    /// From `public/packages/dtf_marker` of the same run. The two checksums are
    /// the ones the real client wrote into `mix.lock` for this package.
    const GOLDEN_PACKAGE_PAYLOAD: &str = "0A4B0A05312E302E3012204157D617FA279E00440545FBDB0BB74B8E0A96A776DAACCE33C690721F09A9C12A209C3091FB556D0B0AA0BD5DF5A40466B1C18BAC00538D0169A35E067598FF7456120A6474665F6D61726B65721A03647466";

    /// `inner_checksum` of `dtf_marker-1.0.0` — the `CHECKSUM` member of the
    /// real tarball, and the second checksum in the client's `mix.lock` entry.
    const GOLDEN_INNER_CHECKSUM_HEX: &str =
        "4157D617FA279E00440545FBDB0BB74B8E0A96A776DAACCE33C690721F09A9C1";

    /// `outer_checksum` of `dtf_marker-1.0.0` — SHA-256 over the whole `.tar`.
    const GOLDEN_OUTER_CHECKSUM_HEX: &str =
        "9C3091FB556D0B0AA0BD5DF5A40466B1C18BAC00538D0169A35E067598FF7456";

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02X}", b)).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_encode_names_payload_matches_real_hex_client_golden_bytes() {
        let payload = encode_names_payload(
            "dtf",
            &[HexPackageName {
                name: "dtf_marker".to_string(),
                updated_at_secs: Some(1784245817),
            }],
        );
        assert_eq!(to_hex(&payload), GOLDEN_NAMES_PAYLOAD);
    }

    #[test]
    fn test_encode_names_payload_encodes_required_zero_nanos() {
        // proto2 `required int32 nanos` must appear on the wire even when 0
        // (`1000` = field 2, varint, 0). gpb emits it; a proto3-style encoder
        // that skips defaults would produce a payload the client rejects.
        let payload = encode_names_payload(
            "dtf",
            &[HexPackageName {
                name: "dtf_marker".to_string(),
                updated_at_secs: Some(1784245817),
            }],
        );
        assert!(to_hex(&payload).contains("1000"));
    }

    #[test]
    fn test_encode_names_payload_omits_updated_at_when_absent() {
        let payload = encode_names_payload(
            "dtf",
            &[HexPackageName {
                name: "a".to_string(),
                updated_at_secs: None,
            }],
        );
        // packages{name:"a"} then repository:"dtf"
        assert_eq!(to_hex(&payload), "0A030A01611203647466");
    }

    #[test]
    fn test_encode_names_payload_empty_repo_still_names_repository() {
        let payload = encode_names_payload("dtf", &[]);
        assert_eq!(to_hex(&payload), "1203647466");
    }

    #[test]
    fn test_encode_versions_payload_matches_real_hex_client_golden_bytes() {
        let payload =
            encode_versions_payload("dtf", &[("dtf_marker".to_string(), vec!["1.0.0".into()])]);
        assert_eq!(to_hex(&payload), GOLDEN_VERSIONS_PAYLOAD);
    }

    #[test]
    fn test_encode_versions_payload_round_trips_through_prost() {
        let payload =
            encode_versions_payload("dtf", &[("dtf_marker".to_string(), vec!["1.0.0".into()])]);
        let decoded = pb::versions::Versions::decode(&payload[..]).unwrap();
        assert_eq!(decoded.repository, "dtf");
        assert_eq!(decoded.packages.len(), 1);
        assert_eq!(decoded.packages[0].name, "dtf_marker");
        assert_eq!(decoded.packages[0].versions, vec!["1.0.0".to_string()]);
    }

    #[test]
    fn test_encode_versions_payload_preserves_multiple_versions_in_order() {
        let payload = encode_versions_payload(
            "dtf",
            &[(
                "p".to_string(),
                vec!["1.0.0".into(), "1.1.0".into(), "2.0.0".into()],
            )],
        );
        let decoded = pb::versions::Versions::decode(&payload[..]).unwrap();
        assert_eq!(
            decoded.packages[0].versions,
            vec![
                "1.0.0".to_string(),
                "1.1.0".to_string(),
                "2.0.0".to_string()
            ]
        );
    }

    #[test]
    fn test_encode_package_payload_matches_real_hex_client_golden_bytes() {
        let payload = encode_package_payload(
            "dtf",
            "dtf_marker",
            &[HexRelease {
                version: "1.0.0".to_string(),
                inner_checksum: from_hex(GOLDEN_INNER_CHECKSUM_HEX),
                outer_checksum: from_hex(GOLDEN_OUTER_CHECKSUM_HEX),
                dependencies: vec![],
            }],
        );
        assert_eq!(to_hex(&payload), GOLDEN_PACKAGE_PAYLOAD);
    }

    #[test]
    fn test_encode_package_payload_carries_both_checksums() {
        let inner = vec![0x41u8; 32];
        let outer = vec![0x9Cu8; 32];
        let payload = encode_package_payload(
            "dtf",
            "dtf_marker",
            &[HexRelease {
                version: "1.0.0".to_string(),
                inner_checksum: inner.clone(),
                outer_checksum: outer.clone(),
                dependencies: vec![],
            }],
        );
        let decoded = pb::pkg::Package::decode(&payload[..]).unwrap();
        assert_eq!(decoded.name, "dtf_marker");
        assert_eq!(decoded.repository, "dtf");
        assert_eq!(decoded.releases[0].inner_checksum, inner);
        assert_eq!(decoded.releases[0].outer_checksum, Some(outer));
    }

    #[test]
    fn test_encode_package_payload_carries_dependencies() {
        let payload = encode_package_payload(
            "dtf",
            "dep_pkg",
            &[HexRelease {
                version: "2.1.0".to_string(),
                inner_checksum: vec![1u8; 32],
                outer_checksum: vec![2u8; 32],
                dependencies: vec![HexDependency {
                    package: "jason".to_string(),
                    requirement: "~> 1.4".to_string(),
                    optional: false,
                    app: Some("jason".to_string()),
                    repository: Some("hexpm".to_string()),
                }],
            }],
        );
        let decoded = pb::pkg::Package::decode(&payload[..]).unwrap();
        let dep = &decoded.releases[0].dependencies[0];
        assert_eq!(dep.package, "jason");
        assert_eq!(dep.requirement, "~> 1.4");
        assert_eq!(dep.optional, Some(false));
        assert_eq!(dep.app, Some("jason".to_string()));
        assert_eq!(dep.repository, Some("hexpm".to_string()));
    }

    // -----------------------------------------------------------------------
    // Signed envelope
    // -----------------------------------------------------------------------

    #[test]
    fn test_signed_gzip_is_gzip_wrapped_signed_message() {
        let payload = b"payload-bytes".to_vec();
        let signature = b"signature-bytes".to_vec();
        let out = signed_gzip(payload.clone(), signature.clone()).unwrap();

        // The client gunzips first; a non-gzip body is the original bug.
        assert_eq!(&out[..2], &[0x1f, 0x8b], "must carry the gzip magic");

        let mut decoder = flate2::read::GzDecoder::new(&out[..]);
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut raw).unwrap();
        let signed = pb::signed::Signed::decode(&raw[..]).unwrap();
        assert_eq!(signed.payload, payload);
        assert_eq!(signed.signature, Some(signature));
    }

    #[test]
    fn test_signed_gzip_round_trips_an_encoded_names_payload() {
        let payload = encode_names_payload(
            "dtf",
            &[HexPackageName {
                name: "dtf_marker".to_string(),
                updated_at_secs: Some(1784245817),
            }],
        );
        let out = signed_gzip(payload.clone(), vec![0u8; 256]).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&out[..]);
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut raw).unwrap();
        let signed = pb::signed::Signed::decode(&raw[..]).unwrap();
        let names = pb::names::Names::decode(&signed.payload[..]).unwrap();
        assert_eq!(names.packages[0].name, "dtf_marker");
    }

    // -----------------------------------------------------------------------
    // Checksums
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_inner_checksum_matches_real_tarball_checksum_member() {
        // The literal CHECKSUM member of the real `dtf_marker-1.0.0.tar`
        // built by `mix hex.build`, and the bytes the real registry advertised.
        let text = "4157D617FA279E00440545FBDB0BB74B8E0A96A776DAACCE33C690721F09A9C1";
        let bytes = decode_inner_checksum(text).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[..4], &[65, 87, 214, 23]);
        assert_eq!(to_hex(&bytes), text);
    }

    #[test]
    fn test_decode_outer_checksum_accepts_lowercase_stored_digest() {
        // `artifacts.checksum_sha256` is stored lowercase (`format!("{:x}")`).
        let text = "9c3091fb556d0b0aa0bd5df5a40466b1c18bac00538d0169a35e067598ff7456";
        let bytes = decode_outer_checksum(text).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(to_hex(&bytes).to_lowercase(), text);
    }

    #[test]
    fn test_decode_inner_checksum_rejects_wrong_length() {
        assert!(decode_inner_checksum("ABCD").is_err());
    }

    #[test]
    fn test_decode_inner_checksum_rejects_non_hex() {
        let bad = "Z157D617FA279E00440545FBDB0BB74B8E0A96A776DAACCE33C690721F09A9C1";
        assert!(decode_inner_checksum(bad).is_err());
    }

    #[test]
    fn test_decode_inner_checksum_trims_surrounding_whitespace() {
        let text = "  4157D617FA279E00440545FBDB0BB74B8E0A96A776DAACCE33C690721F09A9C1\n";
        assert!(decode_inner_checksum(text).is_ok());
    }

    // -----------------------------------------------------------------------
    // requirements parsing — inputs are literal `metadata.config` bodies
    // emitted by the real `mix hex.build`.
    // -----------------------------------------------------------------------

    const REAL_METADATA_NO_DEPS: &str = r#"{<<"links">>,[{<<"AK">>,<<"http://backend:8080">>}]}.
{<<"name">>,<<"dtf_marker">>}.
{<<"version">>,<<"1.0.0">>}.
{<<"description">>,<<"DTF marker package.">>}.
{<<"elixir">>,<<"~> 1.14">>}.
{<<"app">>,<<"dtf_marker">>}.
{<<"licenses">>,[<<"MIT">>]}.
{<<"files">>,[<<"lib">>,<<"lib/dtf_marker.ex">>,<<"mix.exs">>]}.
{<<"requirements">>,[]}.
{<<"build_tools">>,[<<"mix">>]}.
"#;

    const REAL_METADATA_WITH_DEPS: &str = r#"{<<"links">>,[{<<"AK">>,<<"http://x">>}]}.
{<<"name">>,<<"dep_pkg">>}.
{<<"version">>,<<"2.1.0">>}.
{<<"description">>,<<"pkg with deps">>}.
{<<"elixir">>,<<"~> 1.14">>}.
{<<"app">>,<<"dep_pkg">>}.
{<<"licenses">>,[<<"MIT">>]}.
{<<"files">>,[<<"lib">>,<<"lib/dep_pkg.ex">>,<<"mix.exs">>]}.
{<<"requirements">>,
 [[{<<"name">>,<<"jason">>},
   {<<"app">>,<<"jason">>},
   {<<"optional">>,false},
   {<<"requirement">>,<<"~> 1.4">>},
   {<<"repository">>,<<"hexpm">>}],
  [{<<"name">>,<<"decimal">>},
   {<<"app">>,<<"decimal">>},
   {<<"optional">>,true},
   {<<"requirement">>,<<"~> 2.0">>},
   {<<"repository">>,<<"hexpm">>}]]}.
{<<"build_tools">>,[<<"mix">>]}.
"#;

    #[test]
    fn test_parse_requirements_real_metadata_without_deps_is_empty() {
        assert_eq!(parse_requirements(REAL_METADATA_NO_DEPS).unwrap(), vec![]);
    }

    #[test]
    fn test_parse_requirements_real_metadata_with_deps() {
        let deps = parse_requirements(REAL_METADATA_WITH_DEPS).unwrap();
        assert_eq!(
            deps,
            vec![
                HexDependency {
                    package: "jason".to_string(),
                    requirement: "~> 1.4".to_string(),
                    optional: false,
                    app: Some("jason".to_string()),
                    repository: Some("hexpm".to_string()),
                },
                HexDependency {
                    package: "decimal".to_string(),
                    requirement: "~> 2.0".to_string(),
                    optional: true,
                    app: Some("decimal".to_string()),
                    repository: Some("hexpm".to_string()),
                },
            ]
        );
    }

    #[test]
    fn test_parse_requirements_missing_term_is_empty() {
        assert_eq!(
            parse_requirements("{<<\"name\">>,<<\"x\">>}.").unwrap(),
            vec![]
        );
    }

    #[test]
    fn test_parse_requirements_does_not_confuse_files_list_with_requirements() {
        // `files` also holds a list of binaries; the parser must key off the
        // requirements term specifically.
        let deps = parse_requirements(REAL_METADATA_NO_DEPS).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_requirements_single_line_form() {
        let md =
            r#"{<<"requirements">>,[[{<<"name">>,<<"plug">>},{<<"requirement">>,<<"~> 1.0">>}]]}."#;
        let deps = parse_requirements(md).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].package, "plug");
        assert_eq!(deps[0].requirement, "~> 1.0");
        assert!(!deps[0].optional);
        assert_eq!(deps[0].app, None);
    }

    #[test]
    fn test_parse_requirements_defaults_optional_to_false_when_absent() {
        let md =
            r#"{<<"requirements">>,[[{<<"name">>,<<"plug">>},{<<"requirement">>,<<"~> 1.0">>}]]}."#;
        assert!(!parse_requirements(md).unwrap()[0].optional);
    }

    #[test]
    fn test_parse_requirements_skips_group_without_a_name() {
        let md = r#"{<<"requirements">>,[[{<<"requirement">>,<<"~> 1.0">>}]]}."#;
        assert_eq!(parse_requirements(md).unwrap(), vec![]);
    }

    #[test]
    fn test_balanced_end_respects_brackets_inside_binaries() {
        // A requirement string containing a bracket must not end the term.
        let md = r#"{<<"requirements">>,[[{<<"name">>,<<"weird]">>},{<<"requirement">>,<<">= 1.0">>}]]}."#;
        let deps = parse_requirements(md).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].package, "weird]");
    }

    #[test]
    fn test_parse_requirements_empty_string_is_empty() {
        assert_eq!(parse_requirements("").unwrap(), vec![]);
    }
}
