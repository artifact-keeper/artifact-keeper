use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;
use crate::storage::StorageBackend;

/// Parsed information from an MLModel path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlModelPathInfo {
    /// Model name
    pub name: String,
    /// Optional version identifier
    pub version: Option<String>,
    /// Optional artifact file path
    pub artifact_path: Option<String>,
}

/// Handler for MLModel repositories
pub struct MlModelHandler;

impl MlModelHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse an MLModel repository path
    ///
    /// Supports patterns:
    /// - `models/<name>` - model info
    /// - `models/<name>/versions/<version>` - model version
    /// - `models/<name>/versions/<version>/artifacts/<path..>` - artifact file
    pub fn parse_path(path: &str) -> Result<MlModelPathInfo> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        // Must start with "models"
        if parts.is_empty() || parts[0] != "models" {
            return Err(AppError::Validation(format!(
                "Invalid MLModel path format: {}",
                path
            )));
        }

        if parts.len() < 2 {
            return Err(AppError::Validation(format!(
                "Invalid MLModel path format: {}",
                path
            )));
        }

        let name = parts[1].to_string();

        // Pattern: models/<name>
        if parts.len() == 2 {
            return Ok(MlModelPathInfo {
                name,
                version: None,
                artifact_path: None,
            });
        }

        // Pattern: models/<name>/versions/<version>
        // Pattern: models/<name>/versions/<version>/artifacts/<path..>
        if parts.len() >= 4 && parts[2] == "versions" {
            let version = Some(parts[3].to_string());

            // Check for artifacts: models/<name>/versions/<version>/artifacts/<path..>
            if parts.len() >= 6 && parts[4] == "artifacts" {
                let artifact_path = if parts.len() > 5 {
                    Some(parts[5..].join("/"))
                } else {
                    None
                };

                return Ok(MlModelPathInfo {
                    name,
                    version,
                    artifact_path,
                });
            }

            // Just version without artifacts
            return Ok(MlModelPathInfo {
                name,
                version,
                artifact_path: None,
            });
        }

        Err(AppError::Validation(format!(
            "Invalid MLModel path format: {}",
            path
        )))
    }
}

impl Default for MlModelHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for MlModelHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Mlmodel
    }

    fn format_key(&self) -> &str {
        "mlmodel"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;
        Ok(serde_json::to_value(info).unwrap_or(serde_json::json!({})))
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

// ---- safetensors header extraction (#2382, first slice) -------------------
//
// A `.safetensors` file is `[u64 LE header length N][N bytes of JSON][tensor
// data]`. The JSON header maps each tensor name to `{dtype, shape,
// data_offsets}` plus an optional free-form `__metadata__` string map, so the
// model's structure is recoverable from a bounded prefix without touching the
// (multi-GB) tensor data. The parse below is pure; the storage read lives in
// `read_safetensors_summary`, which issues two ranged reads and never buffers
// the whole object.

/// Upper bound on the JSON header we read and parse, matching the reference
/// `safetensors` implementation's `MAX_HEADER_SIZE` (100 MB). A file
/// declaring more is recorded as invalid instead of being read.
pub const SAFETENSORS_MAX_HEADER_BYTES: u64 = 100_000_000;

/// Upper bound on the per-tensor entries copied into `artifact_metadata`. The
/// counts and parameter totals still cover every tensor; only the listing is
/// cut (alphabetically by name) and flagged `tensors_truncated`.
pub const SAFETENSORS_MAX_RECORDED_TENSORS: usize = 10_000;

/// `artifact_metadata.metadata` key holding a parsed header summary.
pub const SAFETENSORS_METADATA_KEY: &str = "safetensors";

/// `artifact_metadata.metadata` key holding the reason a header was rejected.
pub const SAFETENSORS_ERROR_KEY: &str = "safetensors_error";

/// The reserved header entry carrying free-form string metadata.
const SAFETENSORS_FREEFORM_KEY: &str = "__metadata__";

/// Whether an upload at `path` into a repository of `format` gets its
/// safetensors header extracted: `.safetensors` files (case-insensitive) in
/// Mlmodel repositories only.
pub fn safetensors_metadata_eligible(format: &RepositoryFormat, path: &str) -> bool {
    matches!(format, RepositoryFormat::Mlmodel)
        && path
            .rsplit('/')
            .next()
            .is_some_and(|file| file.to_ascii_lowercase().ends_with(".safetensors"))
}

/// One tensor's dtype and shape as recorded in `artifact_metadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SafetensorsTensor {
    pub dtype: String,
    pub shape: Vec<u64>,
}

/// The structure recovered from a safetensors header.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SafetensorsSummary {
    /// Length of the JSON header in bytes (the file's leading u64).
    pub header_bytes: u64,
    /// Number of tensors in the file.
    pub tensor_count: usize,
    /// Sum over all tensors of the product of their shape.
    pub total_parameters: u64,
    /// Parameter count per dtype (e.g. `{"BF16": 6738415616}`).
    pub parameters_by_dtype: BTreeMap<String, u64>,
    /// Per-tensor dtype/shape, by name; at most
    /// [`SAFETENSORS_MAX_RECORDED_TENSORS`] entries.
    pub tensors: BTreeMap<String, SafetensorsTensor>,
    /// True when `tensors` was cut to the recording cap.
    pub tensors_truncated: bool,
    /// The header's `__metadata__` map, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Why a safetensors header could not be summarised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetensorsError {
    /// The object could not be read from storage. Transient: nothing is
    /// recorded, so a later re-upload or backfill can still succeed.
    Unreadable(String),
    /// The bytes are not a valid safetensors header. Recorded on the
    /// artifact so the operator can see why no model metadata exists.
    Invalid(String),
}

impl std::fmt::Display for SafetensorsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(m) | Self::Invalid(m) => f.write_str(m),
        }
    }
}

fn invalid(msg: impl Into<String>) -> SafetensorsError {
    SafetensorsError::Invalid(msg.into())
}

/// Validate the header length declared by the first 8 bytes of a file of
/// `file_size` bytes, returning it as a read length.
pub fn safetensors_header_len(
    prefix: &[u8],
    file_size: u64,
) -> std::result::Result<usize, SafetensorsError> {
    let raw: [u8; 8] = prefix
        .get(..8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid("file is shorter than the 8-byte header length prefix"))?;
    let len = u64::from_le_bytes(raw);
    if len == 0 {
        return Err(invalid("declared header length is zero"));
    }
    if len > SAFETENSORS_MAX_HEADER_BYTES {
        return Err(invalid(format!(
            "declared header length {len} exceeds the {SAFETENSORS_MAX_HEADER_BYTES}-byte limit"
        )));
    }
    if len > file_size.saturating_sub(8) {
        return Err(invalid(format!(
            "declared header length {len} exceeds the {file_size}-byte file"
        )));
    }
    usize::try_from(len).map_err(|_| invalid("declared header length does not fit in memory"))
}

#[derive(Deserialize)]
struct RawTensorInfo {
    dtype: String,
    shape: Vec<u64>,
    data_offsets: [u64; 2],
}

/// Parse a safetensors JSON header. `data_len` is the size of the tensor
/// data region (file size minus the prefix and header) and bounds every
/// tensor's `data_offsets`.
pub fn parse_safetensors_header(
    header: &[u8],
    data_len: u64,
) -> std::result::Result<SafetensorsSummary, SafetensorsError> {
    let entries: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(header)
        .map_err(|e| invalid(format!("header is not a JSON object: {e}")))?;

    let mut metadata = None;
    let mut tensors = BTreeMap::new();
    let mut parameters_by_dtype: BTreeMap<String, u64> = BTreeMap::new();
    let mut total_parameters: u64 = 0;

    for (name, value) in entries {
        if name == SAFETENSORS_FREEFORM_KEY {
            match value {
                serde_json::Value::Object(map) => metadata = Some(map),
                _ => return Err(invalid("`__metadata__` is not a JSON object")),
            }
            continue;
        }
        let info: RawTensorInfo = serde_json::from_value(value)
            .map_err(|e| invalid(format!("tensor `{name}` has an invalid entry: {e}")))?;
        let [begin, end] = info.data_offsets;
        if begin > end || end > data_len {
            return Err(invalid(format!(
                "tensor `{name}` data_offsets [{begin}, {end}] fall outside the {data_len}-byte data region"
            )));
        }
        // A rank-0 tensor (empty shape) is a scalar: one parameter.
        let params = info
            .shape
            .iter()
            .try_fold(1u64, |acc, dim| acc.checked_mul(*dim))
            .ok_or_else(|| invalid(format!("tensor `{name}` shape overflows u64")))?;
        total_parameters = total_parameters
            .checked_add(params)
            .ok_or_else(|| invalid("total parameter count overflows u64"))?;
        let by_dtype = parameters_by_dtype.entry(info.dtype.clone()).or_insert(0);
        *by_dtype = by_dtype.saturating_add(params);
        tensors.insert(
            name,
            SafetensorsTensor {
                dtype: info.dtype,
                shape: info.shape,
            },
        );
    }

    let tensor_count = tensors.len();
    let tensors_truncated = tensor_count > SAFETENSORS_MAX_RECORDED_TENSORS;
    if tensors_truncated {
        let cut = tensors
            .keys()
            .nth(SAFETENSORS_MAX_RECORDED_TENSORS)
            .cloned()
            .expect("more entries than the cap");
        tensors.split_off(&cut);
    }

    Ok(SafetensorsSummary {
        header_bytes: header.len() as u64,
        tensor_count,
        total_parameters,
        parameters_by_dtype,
        tensors,
        tensors_truncated,
        metadata,
    })
}

/// The `artifact_metadata.metadata` document for a summary attempt, or
/// `None` when nothing should be recorded (a transient storage failure).
pub fn safetensors_artifact_metadata(
    result: &std::result::Result<SafetensorsSummary, SafetensorsError>,
) -> Option<serde_json::Value> {
    match result {
        Ok(summary) => Some(serde_json::json!({ SAFETENSORS_METADATA_KEY: summary })),
        Err(SafetensorsError::Invalid(reason)) => {
            Some(serde_json::json!({ SAFETENSORS_ERROR_KEY: reason }))
        }
        Err(SafetensorsError::Unreadable(_)) => None,
    }
}

/// Summarise the safetensors header of the stored object `key` of
/// `file_size` bytes with two ranged reads: the 8-byte length prefix, then
/// exactly the (capped) header. The tensor data is never read. The JSON
/// parse runs on the blocking pool since it is proportional to an untrusted
/// header of up to [`SAFETENSORS_MAX_HEADER_BYTES`].
pub async fn read_safetensors_summary(
    storage: &dyn StorageBackend,
    key: &str,
    file_size: u64,
) -> std::result::Result<SafetensorsSummary, SafetensorsError> {
    let unreadable = |e: AppError| SafetensorsError::Unreadable(e.to_string());
    let prefix = storage.get_range(key, 0, 8).await.map_err(unreadable)?;
    let header_len = safetensors_header_len(&prefix, file_size)?;
    let header = storage
        .get_range(key, 8, header_len)
        .await
        .map_err(unreadable)?;
    if header.len() != header_len {
        return Err(SafetensorsError::Unreadable(format!(
            "short read: expected {header_len} header bytes, got {}",
            header.len()
        )));
    }
    let data_len = file_size - 8 - header_len as u64;
    tokio::task::spawn_blocking(move || parse_safetensors_header(&header, data_len))
        .await
        .map_err(|e| SafetensorsError::Unreadable(format!("header parse task failed: {e}")))?
}

/// Build a `.safetensors` byte image: the LE length prefix, `header`
/// serialised as JSON, then `data_len` zero bytes of tensor data. Shared by
/// the parser tests here and the upload-path DB tests in `artifact_service`.
#[cfg(test)]
pub(crate) fn safetensors_fixture(header: &serde_json::Value, data_len: usize) -> Vec<u8> {
    let json = serde_json::to_vec(header).expect("fixture header serialises");
    let mut out = Vec::with_capacity(8 + json.len() + data_len);
    out.extend_from_slice(&(json.len() as u64).to_le_bytes());
    out.extend_from_slice(&json);
    out.resize(out.len() + data_len, 0);
    out
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_model_info() {
        let path = "models/my-model";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, None);
        assert_eq!(info.artifact_path, None);
    }

    #[test]
    fn test_parse_model_with_version() {
        let path = "models/my-model/versions/v1.0.0";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert_eq!(info.artifact_path, None);
    }

    #[test]
    fn test_parse_artifact_file() {
        let path = "models/my-model/versions/v1.0.0/artifacts/model.pkl";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert_eq!(info.artifact_path, Some("model.pkl".to_string()));
    }

    #[test]
    fn test_parse_artifact_nested() {
        let path = "models/my-model/versions/v1.0.0/artifacts/weights/model.pkl";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert_eq!(info.artifact_path, Some("weights/model.pkl".to_string()));
    }

    #[test]
    fn test_parse_artifact_deeply_nested() {
        let path = "models/my-model/versions/v1.0.0/artifacts/dir1/dir2/dir3/file.bin";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert_eq!(
            info.artifact_path,
            Some("dir1/dir2/dir3/file.bin".to_string())
        );
    }

    #[test]
    fn test_parse_invalid_no_models_prefix() {
        let path = "invalid/my-model";
        let result = MlModelHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_models_only() {
        // "models/" splits to ["models", ""] which has len 2,
        // so it parses as model with empty name
        let path = "models/";
        let result = MlModelHandler::parse_path(path);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "");
    }

    #[test]
    fn test_parse_invalid_empty() {
        let path = "";
        let result = MlModelHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_model_with_special_chars() {
        let path = "models/my-model-v2_3/versions/v1.0.0-alpha";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model-v2_3");
        assert_eq!(info.version, Some("v1.0.0-alpha".to_string()));
    }

    #[test]
    fn test_handler_format() {
        let handler = MlModelHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Mlmodel);
    }

    #[test]
    fn test_handler_format_key() {
        let handler = MlModelHandler::new();
        assert_eq!(handler.format_key(), "mlmodel");
    }

    // ---- #2382 safetensors header extraction ------------------------------

    use crate::storage::PutStreamResult;
    use futures::stream::BoxStream;
    use serde_json::json;
    use std::sync::Mutex;

    /// A small but realistic header: two tensors, a scalar, `__metadata__`.
    fn sample_header() -> serde_json::Value {
        json!({
            "__metadata__": {"format": "pt", "source_url": "javascript:alert(1)"},
            "model.embed.weight": {"dtype": "BF16", "shape": [32, 8], "data_offsets": [0, 512]},
            "model.norm.weight": {"dtype": "F32", "shape": [8], "data_offsets": [512, 544]},
            "model.scale": {"dtype": "F32", "shape": [], "data_offsets": [544, 548]}
        })
    }

    fn parse_err(header: &serde_json::Value, data_len: u64) -> String {
        let bytes = serde_json::to_vec(header).unwrap();
        match parse_safetensors_header(&bytes, data_len) {
            Err(SafetensorsError::Invalid(m)) => m,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_safetensors_eligibility_is_mlmodel_and_extension_only() {
        let ml = RepositoryFormat::Mlmodel;
        assert!(safetensors_metadata_eligible(
            &ml,
            "models/m/model.safetensors"
        ));
        assert!(safetensors_metadata_eligible(
            &ml,
            "Model-00001.SafeTensors"
        ));
        assert!(!safetensors_metadata_eligible(&ml, "models/m/model.bin"));
        assert!(!safetensors_metadata_eligible(
            &ml,
            "models/m/model.safetensors.index.json"
        ));
        assert!(!safetensors_metadata_eligible(
            &ml,
            "model.safetensors/readme"
        ));
        assert!(!safetensors_metadata_eligible(
            &RepositoryFormat::Generic,
            "model.safetensors"
        ));
    }

    #[test]
    fn test_safetensors_header_len_bounds() {
        let prefix = |n: u64| n.to_le_bytes().to_vec();
        assert_eq!(safetensors_header_len(&prefix(100), 108).unwrap(), 100);
        assert_eq!(safetensors_header_len(&prefix(100), 4096).unwrap(), 100);
        let short = safetensors_header_len(&[1, 2, 3], 3).unwrap_err();
        assert!(short.to_string().contains("shorter than"), "{short}");
        let zero = safetensors_header_len(&prefix(0), 100).unwrap_err();
        assert!(zero.to_string().contains("zero"), "{zero}");
        let over_cap = safetensors_header_len(&prefix(SAFETENSORS_MAX_HEADER_BYTES + 1), u64::MAX)
            .unwrap_err();
        assert!(over_cap.to_string().contains("limit"), "{over_cap}");
        let past_eof = safetensors_header_len(&prefix(101), 108).unwrap_err();
        assert!(past_eof.to_string().contains("108-byte file"), "{past_eof}");
        assert!(matches!(past_eof, SafetensorsError::Invalid(_)));
        // Exactly at the cap is allowed.
        assert!(safetensors_header_len(
            &prefix(SAFETENSORS_MAX_HEADER_BYTES),
            SAFETENSORS_MAX_HEADER_BYTES + 8
        )
        .is_ok());
    }

    #[test]
    fn test_parse_safetensors_header_summarises_tensors() {
        let bytes = serde_json::to_vec(&sample_header()).unwrap();
        let s = parse_safetensors_header(&bytes, 548).unwrap();
        assert_eq!(s.header_bytes, bytes.len() as u64);
        assert_eq!(s.tensor_count, 3);
        assert_eq!(s.total_parameters, 32 * 8 + 8 + 1);
        assert_eq!(s.parameters_by_dtype.get("BF16"), Some(&256));
        assert_eq!(s.parameters_by_dtype.get("F32"), Some(&9));
        assert_eq!(
            s.tensors.get("model.embed.weight"),
            Some(&SafetensorsTensor {
                dtype: "BF16".into(),
                shape: vec![32, 8]
            })
        );
        assert_eq!(s.tensors["model.scale"].shape, Vec::<u64>::new());
        assert!(!s.tensors_truncated);
        let meta = s.metadata.as_ref().expect("__metadata__ kept");
        assert_eq!(meta.get("format"), Some(&json!("pt")));
        assert!(!s.tensors.contains_key("__metadata__"));
    }

    #[test]
    fn test_parse_safetensors_header_without_metadata_or_tensors() {
        let s = parse_safetensors_header(b"{}  ", 0).unwrap();
        assert_eq!(s.tensor_count, 0);
        assert_eq!(s.total_parameters, 0);
        assert!(s.metadata.is_none());
        let doc = serde_json::to_value(&s).unwrap();
        assert!(
            doc.get("metadata").is_none(),
            "absent __metadata__ is omitted"
        );
    }

    #[test]
    fn test_parse_safetensors_header_rejects_malformed_headers() {
        let not_json = match parse_safetensors_header(b"\x00\xffnot json", 0) {
            Err(SafetensorsError::Invalid(m)) => m,
            other => panic!("expected Invalid, got {other:?}"),
        };
        assert!(not_json.contains("not a JSON object"), "{not_json}");
        assert!(parse_err(&json!([1, 2]), 0).contains("not a JSON object"));
        assert!(parse_err(&json!({"__metadata__": "x"}), 0).contains("__metadata__"));
        assert!(
            parse_err(&json!({"t": {"shape": [1], "data_offsets": [0, 1]}}), 1)
                .contains("tensor `t`")
        );
        assert!(parse_err(
            &json!({"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 9]}}),
            4
        )
        .contains("outside"));
        assert!(parse_err(
            &json!({"t": {"dtype": "F32", "shape": [1], "data_offsets": [4, 0]}}),
            4
        )
        .contains("outside"));
        let huge = u64::MAX / 2;
        assert!(parse_err(
            &json!({"t": {"dtype": "U8", "shape": [huge, 3], "data_offsets": [0, 0]}}),
            0
        )
        .contains("overflows"));
        assert!(parse_err(
            &json!({
                "a": {"dtype": "U8", "shape": [huge], "data_offsets": [0, 0]},
                "b": {"dtype": "U8", "shape": [huge], "data_offsets": [0, 0]},
                "c": {"dtype": "U8", "shape": [huge], "data_offsets": [0, 0]}
            }),
            0
        )
        .contains("total parameter count"));
    }

    #[test]
    fn test_parse_safetensors_header_truncates_tensor_listing() {
        let mut entries = serde_json::Map::new();
        for i in 0..=SAFETENSORS_MAX_RECORDED_TENSORS {
            entries.insert(
                format!("t{i:06}"),
                json!({"dtype": "F16", "shape": [2], "data_offsets": [0, 4]}),
            );
        }
        let bytes = serde_json::to_vec(&serde_json::Value::Object(entries)).unwrap();
        let s = parse_safetensors_header(&bytes, 4).unwrap();
        assert_eq!(s.tensor_count, SAFETENSORS_MAX_RECORDED_TENSORS + 1);
        assert_eq!(s.tensors.len(), SAFETENSORS_MAX_RECORDED_TENSORS);
        assert!(s.tensors_truncated);
        assert_eq!(
            s.total_parameters,
            2 * (SAFETENSORS_MAX_RECORDED_TENSORS as u64 + 1),
            "totals cover every tensor, not just the recorded ones"
        );
        assert!(!s
            .tensors
            .contains_key(&format!("t{:06}", SAFETENSORS_MAX_RECORDED_TENSORS)));
    }

    #[test]
    fn test_safetensors_artifact_metadata_document_shape() {
        let bytes = serde_json::to_vec(&sample_header()).unwrap();
        let ok = parse_safetensors_header(&bytes, 548);
        let doc = safetensors_artifact_metadata(&ok).unwrap();
        assert_eq!(
            doc[SAFETENSORS_METADATA_KEY]["total_parameters"],
            json!(265)
        );
        assert_eq!(
            doc[SAFETENSORS_METADATA_KEY]["tensors"]["model.norm.weight"],
            json!({"dtype": "F32", "shape": [8]})
        );
        let bad = Err(SafetensorsError::Invalid("broken".into()));
        assert_eq!(
            safetensors_artifact_metadata(&bad),
            Some(json!({SAFETENSORS_ERROR_KEY: "broken"}))
        );
        let gone = Err(SafetensorsError::Unreadable("io".into()));
        assert_eq!(safetensors_artifact_metadata(&gone), None);
    }

    /// Serves ranged reads from memory and records every request; a full
    /// `get` fails, so a passing read proves the whole object was never
    /// requested.
    struct RangeOnlyStorage {
        object: Vec<u8>,
        ranges: Mutex<Vec<(u64, usize)>>,
    }

    impl RangeOnlyStorage {
        fn new(object: Vec<u8>) -> Self {
            Self {
                object,
                ranges: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for RangeOnlyStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            unreachable!("read-only test backend")
        }
        async fn get(&self, _key: &str) -> Result<Bytes> {
            Err(AppError::Storage("full read not allowed".into()))
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            unreachable!("read-only test backend")
        }
        async fn put_stream(
            &self,
            _key: &str,
            _stream: BoxStream<'static, Result<Bytes>>,
        ) -> Result<PutStreamResult> {
            unreachable!("read-only test backend")
        }
        async fn get_range(&self, key: &str, offset: u64, length: usize) -> Result<Bytes> {
            if key != "present" {
                return Err(AppError::NotFound(key.to_string()));
            }
            self.ranges.lock().unwrap().push((offset, length));
            let start = (offset as usize).min(self.object.len());
            let end = start.saturating_add(length).min(self.object.len());
            Ok(Bytes::copy_from_slice(&self.object[start..end]))
        }
    }

    #[tokio::test]
    async fn test_read_safetensors_summary_reads_only_the_header() {
        let file = safetensors_fixture(&sample_header(), 548);
        let header_len = file.len() - 8 - 548;
        let storage = RangeOnlyStorage::new(file.clone());
        let s = read_safetensors_summary(&storage, "present", file.len() as u64)
            .await
            .unwrap();
        assert_eq!(s.total_parameters, 265);
        assert_eq!(
            *storage.ranges.lock().unwrap(),
            vec![(0, 8), (8, header_len)],
            "exactly the prefix and the header are requested"
        );
    }

    #[tokio::test]
    async fn test_read_safetensors_summary_classifies_failures() {
        let storage = RangeOnlyStorage::new(safetensors_fixture(&sample_header(), 548));
        let missing = read_safetensors_summary(&storage, "absent", 1_000)
            .await
            .unwrap_err();
        assert!(
            matches!(missing, SafetensorsError::Unreadable(_)),
            "{missing:?}"
        );

        // A declared header longer than the file never triggers a header read.
        let lying = RangeOnlyStorage::new(u64::MAX.to_le_bytes().to_vec());
        let err = read_safetensors_summary(&lying, "present", 8)
            .await
            .unwrap_err();
        assert!(matches!(err, SafetensorsError::Invalid(_)), "{err:?}");
        assert_eq!(*lying.ranges.lock().unwrap(), vec![(0, 8)]);

        // The object is shorter than its recorded size: a short read.
        let truncated =
            RangeOnlyStorage::new(safetensors_fixture(&sample_header(), 0)[..20].to_vec());
        let err = read_safetensors_summary(&truncated, "present", 10_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("short read"), "{err}");

        // Valid prefix, garbage header bytes: rejected as invalid.
        let mut garbage = 4u64.to_le_bytes().to_vec();
        garbage.extend_from_slice(b"nope");
        let err = read_safetensors_summary(&RangeOnlyStorage::new(garbage), "present", 12)
            .await
            .unwrap_err();
        assert!(matches!(err, SafetensorsError::Invalid(_)), "{err:?}");
    }
}
