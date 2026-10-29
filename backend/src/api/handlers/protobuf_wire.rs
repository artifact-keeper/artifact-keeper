//! The wire format the buf CLI actually speaks to a hosted protobuf
//! repository, and the identifiers and digests its messages must carry.
//!
//! The hosted endpoints in `protobuf.rs` grew as hand-written serde structs
//! served as `application/json`. The CLI never sends that: it speaks Connect
//! with the binary protobuf codec, so every one of its calls was answered
//! `415 Unsupported Media Type` by axum's `Json` extractor before a handler
//! ran (#5066). Its messages are also stricter than the JSON lookalike --
//! `Digest.type` is an enum whose only non-zero value is b5, `Digest.value` is
//! `bytes`, and every id is a tuuid -- so decoding the body is necessary but
//! not sufficient; a reply has to be conformant or the CLI rejects it.
//!
//! This module owns the three pieces that makes the difference:
//!
//!   * [`Codec`] -- which codec a request arrived in and how to answer in it.
//!   * [`b5_digest`] -- the digest the CLI verifies a commit against. Not the
//!     SHA-256 the repository stores objects under.
//!   * [`ids`] -- tuuids derived from the names the repository already keys on,
//!     so no new table or migration is needed to answer with ids at all.

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use prost::Message;
use serde::de::DeserializeOwned;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// The vendored subset of the BSR schemas, nested to match the proto package
/// paths so the generated cross-package references resolve.
pub mod proto {
    pub mod buf {
        pub mod registry {
            pub mod owner {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/buf.registry.owner.v1.rs"));
                }
            }
            pub mod module {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/buf.registry.module.v1.rs"));
                }
                pub mod v1beta1 {
                    include!(concat!(env!("OUT_DIR"), "/buf.registry.module.v1beta1.rs"));
                }
            }
        }
    }

    pub use buf::registry::module::{v1, v1beta1};
    pub use buf::registry::owner::v1 as owner_v1;
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// Which codec a Connect request arrived in.
///
/// Connect carries unary errors as JSON whatever the request codec, so only
/// the success body differs between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Json,
    Proto,
}

impl Codec {
    /// The codec the `Content-Type` selects. Anything that is not a protobuf
    /// media type is treated as JSON, which is what the pre-#5066 endpoints
    /// assumed of every request.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        if is_binary_protobuf(headers) {
            Codec::Proto
        } else {
            Codec::Json
        }
    }

    /// Decode a request body into the handler's own request type.
    ///
    /// `T` is the serde shape the JSON endpoints already use and `P` the
    /// generated message; `from_proto` lifts one into the other so a handler
    /// keeps a single body type.
    pub fn decode<T: DeserializeOwned, P: Message + Default>(
        self,
        body: &Bytes,
        from_proto: impl FnOnce(P) -> T,
    ) -> Result<T, Response> {
        match self {
            Codec::Json => serde_json::from_slice::<T>(body).map_err(|e| {
                connect_invalid_argument(&format!("malformed JSON request body: {e}"))
            }),
            Codec::Proto => P::decode(body.clone()).map(from_proto).map_err(|e| {
                connect_invalid_argument(&format!("malformed protobuf request body: {e}"))
            }),
        }
    }

    pub fn is_proto(self) -> bool {
        self == Codec::Proto
    }
}

/// A success reply in the JSON codec, the shape the pre-#5066 endpoints and
/// the curl-driven E2E suite exchange.
pub fn respond_json<J: serde::Serialize>(json: &J) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(json).unwrap_or_else(|_| b"{}".to_vec()),
        ))
        .unwrap()
}

/// A success reply in the binary protobuf codec, which is what the buf CLI
/// reads. Connect's unary errors stay JSON in both codecs, so the error
/// helpers are shared.
pub fn respond_proto<P: Message>(proto: &P) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/proto")
        .body(Body::from(proto.encode_to_vec()))
        .unwrap()
}

/// A protobuf-codec request. `application/grpc` is included because a gRPC
/// client reaching these routes is equally not sending JSON, and answering it
/// a Connect error beats axum's bare 415.
pub fn is_binary_protobuf(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("application/proto")
                || ct.starts_with("application/grpc")
                || ct.starts_with("application/connect+proto")
        })
        .unwrap_or(false)
}

fn connect_invalid_argument(message: &str) -> Response {
    let body = serde_json::json!({ "code": "invalid_argument", "message": message });
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

/// Decode a binary protobuf body, for a reply that exists only in the CLI's
/// codec.
pub fn decode_proto<P: Message + Default>(body: &Bytes) -> Result<P, Response> {
    P::decode(body.clone())
        .map_err(|e| connect_invalid_argument(&format!("malformed protobuf request body: {e}")))
}

/// Deserialise a JSON body, for the handlers whose request type has no
/// generated counterpart yet.
pub fn decode_json<T: DeserializeOwned>(body: &Bytes) -> Result<T, Response> {
    serde_json::from_slice::<T>(body)
        .map_err(|e| connect_invalid_argument(&format!("malformed JSON request body: {e}")))
}

// ---------------------------------------------------------------------------
// b5 digest
// ---------------------------------------------------------------------------

const SHAKE256_LEN: usize = 64;

fn shake256_hex(data: &[u8]) -> String {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut out = [0u8; SHAKE256_LEN];
    hasher.finalize_xof().read(&mut out);
    hex_lower(&out)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The digest of a module's own files: a `shake256:` manifest of one line per
/// file, sorted by path, hashed again.
pub fn files_digest(files: &[(String, Vec<u8>)]) -> String {
    let entries: Vec<(String, String)> = files
        .iter()
        .map(|(path, content)| (path.clone(), shake256_hex(content)))
        .collect();
    files_digest_of(&entries)
}

/// [`files_digest`] from each file's path and its own shake256, which is the
/// stage the manifest format lives in and the one a golden vector can pin
/// without carrying the module's whole content as a fixture.
///
/// The two spaces between digest and path, and the newline that ends every
/// line including the last, are part of the hash: the manifest is hashed as
/// the bytes buf writes it.
pub fn files_digest_of(entries: &[(String, String)]) -> String {
    // Sorted by path, which is not the same as sorting the rendered lines:
    // every line opens with the same `shake256:` and its hex, so sorting
    // those orders the manifest by digest instead and yields a digest that
    // looks plausible and matches nothing.
    let mut sorted: Vec<&(String, String)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let manifest: String = sorted
        .iter()
        .map(|(path, digest)| format!("shake256:{digest}  {path}\n"))
        .collect();
    format!("shake256:{}", shake256_hex(manifest.as_bytes()))
}

/// The b5 digest the CLI verifies a commit against: the module's own
/// [`files_digest`] and the b5 digests of its dependencies, sorted, joined by
/// newlines with no trailing newline, hashed.
///
/// `dep_digests` are the full `b5:...` strings of the direct dependencies.
pub fn b5_digest(files: &[(String, Vec<u8>)], dep_digests: &[String]) -> String {
    b5_of(&files_digest(files), dep_digests)
}

/// [`b5_digest`] from an already-computed `filesDigest`.
pub fn b5_of(files_digest: &str, dep_digests: &[String]) -> String {
    let mut parts = vec![files_digest.to_string()];
    let mut deps: Vec<String> = dep_digests.to_vec();
    deps.sort();
    parts.extend(deps);
    format!("b5:{}", shake256_hex(parts.join("\n").as_bytes()))
}

/// The 64 raw bytes of a `b5:<hex>` string, for `Digest.value`, which is
/// `bytes` and not the hex text the JSON endpoints put in it.
pub fn b5_bytes(digest: &str) -> Vec<u8> {
    let hex = digest.strip_prefix("b5:").unwrap_or(digest);
    hex.as_bytes()
        .chunks(2)
        .filter(|pair| pair.len() == 2)
        .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// The ids BSR messages carry are tuuids: a UUID's 32 hex digits with the
/// dashes removed. A hosted repository has no id columns for modules, commits
/// or labels -- it keys on names and on the SHA-256 an object is stored under
/// -- so the ids are derived from those names instead. Derivation is a pure
/// function, so the same module answers with the same id on every request and
/// across replicas, which is what the CLI compares between calls.
pub mod ids {
    use uuid::Uuid;

    /// Namespace for every derived id. A fixed random UUID, so a derived id
    /// cannot collide with one from another namespace.
    const NAMESPACE: Uuid = Uuid::from_u128(0x6e8b_2d2f_4c71_4a6e_9a3f_1c8d_5b7e_0f42);

    fn tuuid(kind: &str, key: &str) -> String {
        Uuid::new_v5(&NAMESPACE, format!("{kind}:{key}").as_bytes())
            .simple()
            .to_string()
    }

    /// `owner` is the first segment of a module name (`owner/module`).
    pub fn owner(owner: &str) -> String {
        tuuid("owner", owner)
    }

    /// `module_name` is the full `owner/module`.
    pub fn module(module_name: &str) -> String {
        tuuid("module", module_name)
    }

    /// Keyed on the SHA-256 the commit's bundle is stored under, so the id is
    /// stable for the content and distinct per commit of the same module.
    pub fn commit(module_name: &str, storage_digest: &str) -> String {
        tuuid("commit", &format!("{module_name}@{storage_digest}"))
    }

    pub fn label(module_name: &str, label_name: &str) -> String {
        tuuid("label", &format!("{module_name}#{label_name}"))
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    /// SHAKE-256's own published value for the empty input, so the primitive
    /// under every stage below is pinned against NIST and not against itself.
    #[test]
    fn shake256_matches_the_published_vector() {
        assert_eq!(
            shake256_hex(b""),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
    }

    /// The golden vector: buf.build/bufbuild/protovalidate at commit
    /// 511051f7f4374c3ca873b53ae68a9288. The inputs are that commit's files
    /// and their own shake256 digests, as buf's module cache records them; the
    /// expected b5 is the digest buf itself writes into a consumer's
    /// `buf.lock`. So this pins the manifest format and the composition
    /// against buf's implementation rather than against ours -- getting the
    /// two spaces, the trailing newline or the sort wrong fails here.
    #[test]
    fn b5_matches_buf_for_protovalidate() {
        let entries = [
            (
                "LICENSE".to_string(),
                "e702a95ca4516da9365b47a96282a3997660ecff5f614135d19a480ae7e9fb7f\
                 c0780efa034d133b95f5fe214a9fe4dd1cd65a9a9b6362db5f07792c0b699f38"
                    .to_string(),
            ),
            (
                "README.md".to_string(),
                "a2fa052e0d4f27b3d0168f60f86767e0693b25503b3548e0b20c74a046b430c9\
                 948fedb5b3db6f2541c4cc607a02da8044082ee6e36cd2b2eae0b01e11af88e1"
                    .to_string(),
            ),
            (
                "buf/validate/validate.proto".to_string(),
                "a6e1bbd04170ac1dc752c5ce686dab198542fa38941eefd3399b612f5439826a\
                 ad2a1856fbd48a31a51f2b4556a02aca35a33a6bb1beb4a769146af910326360"
                    .to_string(),
            ),
        ];

        let files_digest = files_digest_of(&entries);
        assert_eq!(
            files_digest,
            "shake256:75ba59fae4cdbce7701493469dc8cff65109ece50d417cb60c6f072c4375856d\
             44b9f4798a256f3d11cb60c36e739f0bc6300a6846d5e16eb2786b1f2eede237"
        );
        assert_eq!(
            b5_of(&files_digest, &[]),
            "b5:a4a2d4d808a25984cced60769c822c5d496ef0b740f56ac0c9e6b97aaa25b86a\
             9332a00ffd74e0cd202be29e91bd3edfb0bf2ba4dacfe48ff2d8217f9986e3c8"
        );
    }

    #[test]
    fn files_digest_is_input_order_independent() {
        let a = vec![
            ("b.proto".to_string(), b"second".to_vec()),
            ("a.proto".to_string(), b"first".to_vec()),
        ];
        let b = vec![
            ("a.proto".to_string(), b"first".to_vec()),
            ("b.proto".to_string(), b"second".to_vec()),
        ];
        assert_eq!(files_digest(&a), files_digest(&b));
    }

    /// The manifest is ordered by path. Sorting the rendered lines instead
    /// orders it by digest, which agrees with the path order often enough to
    /// pass a casual test -- so this fixture picks digests whose order is the
    /// reverse of their paths'.
    #[test]
    fn files_digest_orders_by_path_not_by_digest() {
        let entries = [
            ("a.proto".to_string(), "ff".to_string()),
            ("b.proto".to_string(), "00".to_string()),
        ];
        let by_digest = shake256_hex(b"shake256:00  b.proto\nshake256:ff  a.proto\n");
        let by_path = shake256_hex(b"shake256:ff  a.proto\nshake256:00  b.proto\n");

        assert_ne!(by_digest, by_path, "fixture must tell the two orders apart");
        assert_eq!(files_digest_of(&entries), format!("shake256:{by_path}"));
    }

    #[test]
    fn b5_is_dependency_order_independent() {
        let files = vec![("a.proto".to_string(), b"x".to_vec())];
        let one = b5_digest(&files, &["b5:02".to_string(), "b5:01".to_string()]);
        let two = b5_digest(&files, &["b5:01".to_string(), "b5:02".to_string()]);
        assert_eq!(one, two);
    }

    #[test]
    fn b5_covers_dependencies() {
        let files = vec![("a.proto".to_string(), b"x".to_vec())];
        assert_ne!(
            b5_digest(&files, &[]),
            b5_digest(&files, &["b5:01".to_string()])
        );
    }

    #[test]
    fn b5_bytes_are_the_64_raw_bytes() {
        let files = vec![("a.proto".to_string(), b"x".to_vec())];
        let digest = b5_digest(&files, &[]);
        assert!(digest.starts_with("b5:"));
        assert_eq!(digest.len(), "b5:".len() + SHAKE256_LEN * 2);
        assert_eq!(b5_bytes(&digest).len(), SHAKE256_LEN);
    }

    #[test]
    fn derived_ids_are_tuuids() {
        for id in [
            ids::owner("acme"),
            ids::module("acme/payments"),
            ids::commit("acme/payments", "abcd"),
            ids::label("acme/payments", "main"),
        ] {
            assert_eq!(id.len(), 32, "{id} is not a tuuid");
            assert!(id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        }
    }

    #[test]
    fn derived_ids_are_stable_and_distinct() {
        assert_eq!(ids::module("acme/payments"), ids::module("acme/payments"));
        assert_ne!(ids::module("acme/payments"), ids::module("acme/billing"));
        assert_ne!(ids::owner("acme"), ids::module("acme"));
        assert_ne!(
            ids::commit("acme/payments", "aa"),
            ids::commit("acme/payments", "bb")
        );
    }

    #[test]
    fn codec_follows_content_type() {
        let mut headers = HeaderMap::new();
        assert_eq!(Codec::from_headers(&headers), Codec::Json);
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        assert_eq!(Codec::from_headers(&headers), Codec::Json);
        headers.insert(CONTENT_TYPE, "application/proto".parse().unwrap());
        assert_eq!(Codec::from_headers(&headers), Codec::Proto);
        headers.insert(CONTENT_TYPE, "application/connect+proto".parse().unwrap());
        assert_eq!(Codec::from_headers(&headers), Codec::Proto);
    }
}
