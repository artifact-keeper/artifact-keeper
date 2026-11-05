//! Model-file scanner (#5285): judges the files a model loader will open.
//!
//! A model repository is the one place where the artifact itself can be code.
//! A PyTorch `.bin`/`.pt`/`.ckpt` is a pickle, and `torch.load` without
//! `weights_only=True` runs whatever the pickle imports and calls. The CVE
//! scanners do not look at that, so this scanner does, in-process and
//! offline, without ever executing or unpickling anything:
//!
//! * **Pickle** (`.bin`, `.pt`, `.pth`, `.ckpt`, `.pkl`, `.pickle`,
//!   `.joblib`, and the `data.pkl` of a zip-wrapped PyTorch archive): a
//!   bounded opcode walk over protocols 0-5 that collects every `GLOBAL`,
//!   `STACK_GLOBAL` and `INST` import and classifies it against an allowlist
//!   of the globals a weights-only load needs and a denylist of known code
//!   execution primitives.
//! * **safetensors**: the bounded header parse from
//!   [`crate::formats::mlmodel`], plus the layout check the reference loader
//!   applies (tensor ranges tile the data region exactly).
//! * **GGUF**: the header, metadata key/value table and tensor-info table,
//!   walked with strict bounds against the file size.
//!
//! Every judgement is a [`RawFinding`] with a stable rule id (see
//! [`Rule::id`]) in `affected_component`, a `malicious` class for a
//! denylisted import and `policy` for everything else. Applies only to
//! hosted uploads into `huggingface` and `mlmodel` repositories: the
//! orchestrator passes the repository format on [`ScanTarget`], and the
//! inline proxy path does not, so proxied files are not judged yet.
//!
//! Memory: the orchestrator stages the artifact (in heap below 8 MiB, as a
//! file-backed `mmap` above), and every parser here reads a bounded prefix of
//! it: at most [`PICKLE_MAX_BYTES`] of pickle stream, the safetensors header
//! (capped at [`crate::formats::mlmodel::SAFETENSORS_MAX_HEADER_BYTES`]), at
//! most [`GGUF_MAX_HEADER_BYTES`] of GGUF header, and for a zip archive its
//! central directory plus one capped member. Tensor data is never read.

use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::{AppError, Result};
use crate::formats::mlmodel::{self, SafetensorsError, SafetensorsLayoutIssue};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{FindingClass, RawFinding, Severity};
use crate::services::scanner_service::{ScanCompleteness, ScanOutput, ScanTarget, Scanner};

/// The `scan_results.scan_type` of this scanner (migration 331).
pub const MODEL_SCAN_TYPE: &str = "model";

/// `scan_findings.source` of every finding this scanner writes.
const FINDING_SOURCE: &str = "model-scanner";

/// Pickle bytes walked at most per file (or per archive member). A real
/// `data.pkl` is kilobytes to a few MiB; a legacy (non-zip) checkpoint's
/// pickles sit in front of the tensor data and are as small.
pub const PICKLE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Opcodes walked at most per file.
pub const PICKLE_MAX_OPCODES: u64 = 10_000_000;

/// Longest newline-terminated argument (protocol 0 `GLOBAL`, `INST`, `INT`,
/// ...) accepted before the stream is called malformed.
pub const PICKLE_MAX_LINE_BYTES: usize = 4096;

/// Values held on the simulated stack (all mark levels together).
pub const PICKLE_MAX_STACK: usize = 500_000;

/// Memo entries held.
pub const PICKLE_MAX_MEMO: usize = 262_144;

/// A string longer than this is not tracked as a possible `STACK_GLOBAL`
/// operand (no importable module or attribute path is this long).
pub const PICKLE_MAX_TRACKED_STRING_BYTES: usize = 512;

/// Total bytes of strings tracked for `STACK_GLOBAL` resolution. A string
/// past the budget is tracked as an opaque value, so a `STACK_GLOBAL` that
/// consumes it is reported as an unresolved import, never as a clean one.
pub const PICKLE_MAX_TRACKED_STRING_TOTAL: usize = 8 * 1024 * 1024;

/// Distinct imports recorded per file.
pub const PICKLE_MAX_DISTINCT_GLOBALS: usize = 4096;

/// Concatenated pickle streams walked per file. A legacy `torch.save` file
/// is five (magic number, protocol, sys info, the object, storage keys).
pub const PICKLE_MAX_STREAMS: usize = 5;

/// Non-allowlisted imports reported one finding each; the rest are counted
/// in one summary finding.
pub const PICKLE_MAX_REPORTED_UNKNOWN: usize = 64;

/// Zip entries accepted in a PyTorch archive.
pub const ARCHIVE_MAX_ENTRIES: u64 = 100_000;

/// GGUF header bytes walked at most (metadata plus tensor infos). A large
/// vocabulary's token and merge arrays are a few tens of MiB.
pub const GGUF_MAX_HEADER_BYTES: usize = 128 * 1024 * 1024;

/// Metadata key/value pairs and tensor infos accepted in a GGUF file.
pub const GGUF_MAX_COUNT: u64 = 1_000_000;

/// Array elements walked at most across a GGUF file's metadata.
pub const GGUF_MAX_ARRAY_ELEMENTS: u64 = 64 * 1024 * 1024;

/// A `tokenizer.chat_template*` value longer than this is reported. The
/// template is Jinja that llama.cpp-based runtimes execute; real ones are a
/// few KiB.
pub const GGUF_MAX_CHAT_TEMPLATE_BYTES: u64 = 64 * 1024;

/// Longest GGUF metadata key (the spec's limit).
const GGUF_MAX_KEY_BYTES: u64 = 65_535;

/// Longest GGUF tensor name (`GGML_MAX_NAME` minus the terminator).
const GGUF_MAX_TENSOR_NAME_BYTES: u64 = 63;

/// Highest tensor rank (`GGML_MAX_DIMS`).
const GGUF_MAX_DIMS: u32 = 4;

/// Nesting depth of GGUF arrays accepted.
const GGUF_MAX_ARRAY_DEPTH: u32 = 3;

// ---------------------------------------------------------------------------
// Rules and findings
// ---------------------------------------------------------------------------

/// One kind of judgement, with a stable id, class and severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    PickleDangerousGlobal,
    PickleUnresolvedGlobal,
    PickleUnknownGlobal,
    PickleMalformed,
    PickleScanLimit,
    ArchiveMalformed,
    ArchiveNoPickle,
    SafetensorsHeaderLength,
    SafetensorsInvalidHeader,
    SafetensorsUnknownDtype,
    SafetensorsOffsetsOutOfRange,
    SafetensorsOverlappingOffsets,
    SafetensorsUnaccountedBytes,
    GgufMalformed,
    GgufImplausibleCounts,
    GgufScanLimit,
    GgufLargeChatTemplate,
}

impl Rule {
    /// The stable rule id, stored in `scan_findings.affected_component`.
    pub fn id(self) -> &'static str {
        match self {
            Rule::PickleDangerousGlobal => "model.pickle.dangerous-global",
            Rule::PickleUnresolvedGlobal => "model.pickle.unresolved-global",
            Rule::PickleUnknownGlobal => "model.pickle.unknown-global",
            Rule::PickleMalformed => "model.pickle.malformed",
            Rule::PickleScanLimit => "model.pickle.scan-limit",
            Rule::ArchiveMalformed => "model.archive.malformed",
            Rule::ArchiveNoPickle => "model.archive.no-pickle",
            Rule::SafetensorsHeaderLength => "model.safetensors.header-length",
            Rule::SafetensorsInvalidHeader => "model.safetensors.invalid-header",
            Rule::SafetensorsUnknownDtype => "model.safetensors.unknown-dtype",
            Rule::SafetensorsOffsetsOutOfRange => "model.safetensors.offsets-out-of-range",
            Rule::SafetensorsOverlappingOffsets => "model.safetensors.overlapping-offsets",
            Rule::SafetensorsUnaccountedBytes => "model.safetensors.unaccounted-bytes",
            Rule::GgufMalformed => "model.gguf.malformed",
            Rule::GgufImplausibleCounts => "model.gguf.implausible-counts",
            Rule::GgufScanLimit => "model.gguf.scan-limit",
            Rule::GgufLargeChatTemplate => "model.gguf.large-chat-template",
        }
    }

    /// `malicious` for a known code-execution import, `policy` otherwise.
    pub fn class(self) -> FindingClass {
        match self {
            Rule::PickleDangerousGlobal => FindingClass::Malicious,
            _ => FindingClass::Policy,
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            Rule::PickleDangerousGlobal => Severity::Critical,
            Rule::PickleUnresolvedGlobal => Severity::High,
            Rule::ArchiveNoPickle
            | Rule::SafetensorsUnaccountedBytes
            | Rule::GgufLargeChatTemplate => Severity::Low,
            _ => Severity::Medium,
        }
    }

    /// The finding title's stem; the subject is appended.
    fn title(self) -> &'static str {
        match self {
            Rule::PickleDangerousGlobal => "Pickle imports a code-execution primitive",
            Rule::PickleUnresolvedGlobal => "Pickle imports a global the scanner cannot name",
            Rule::PickleUnknownGlobal => "Pickle imports a non-allowlisted global",
            Rule::PickleMalformed => "Pickle stream is malformed",
            Rule::PickleScanLimit => "Pickle stream exceeds the scan limits",
            Rule::ArchiveMalformed => "PyTorch archive is unreadable",
            Rule::ArchiveNoPickle => "Zip archive has no data.pkl",
            Rule::SafetensorsHeaderLength => "safetensors header length is invalid",
            Rule::SafetensorsInvalidHeader => "safetensors header is malformed",
            Rule::SafetensorsUnknownDtype => "safetensors tensor has a non-standard dtype",
            Rule::SafetensorsOffsetsOutOfRange => "safetensors tensor offsets are out of range",
            Rule::SafetensorsOverlappingOffsets => "safetensors tensors overlap",
            Rule::SafetensorsUnaccountedBytes => "safetensors data region has unaccounted bytes",
            Rule::GgufMalformed => "GGUF header is malformed",
            Rule::GgufImplausibleCounts => "GGUF header counts are implausible",
            Rule::GgufScanLimit => "GGUF header exceeds the scan limits",
            Rule::GgufLargeChatTemplate => "GGUF chat template is unusually large",
        }
    }

    /// Whether this finding means part of the file went unexamined.
    fn is_limit(self) -> bool {
        matches!(self, Rule::PickleScanLimit | Rule::GgufScanLimit)
    }
}

/// One judgement about a model file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelFinding {
    pub rule: Rule,
    /// What it is about: an import (`os.system`), an archive member, a file.
    pub subject: String,
    /// Human-readable detail (offsets, counts, the parser's reason).
    pub detail: String,
}

impl ModelFinding {
    fn new(rule: Rule, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            rule,
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    /// The row the orchestrator persists. The title carries the rule and
    /// subject only, so the finding identity is stable across rescans.
    fn into_raw(self) -> RawFinding {
        RawFinding {
            severity: self.rule.severity(),
            title: format!("{}: {}", self.rule.title(), self.subject),
            description: Some(self.detail),
            cve_id: None,
            affected_component: Some(self.rule.id().to_string()),
            affected_version: None,
            fixed_version: None,
            source: Some(FINDING_SOURCE.to_string()),
            source_url: None,
            finding_class: self.rule.class(),
        }
    }
}

// ---------------------------------------------------------------------------
// Which files, which formats
// ---------------------------------------------------------------------------

/// How a file is examined, from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFileKind {
    /// Expected to be a pickle or a zip-wrapped PyTorch archive.
    Pickle,
    /// `.bin`: judged as a pickle or archive only when its bytes say it is
    /// one (`.bin` is also GGML, OpenVINO, raw tensors, ...).
    MaybePickle,
    Safetensors,
    Gguf,
}

/// The kind of model file at `path`, by extension (case-insensitive).
pub fn model_file_kind(path: &str) -> Option<ModelFileKind> {
    let file = path.rsplit('/').next()?.to_ascii_lowercase();
    let ext = file.rsplit_once('.')?.1;
    match ext {
        "pt" | "pth" | "ckpt" | "pkl" | "pickle" | "joblib" => Some(ModelFileKind::Pickle),
        "bin" => Some(ModelFileKind::MaybePickle),
        "safetensors" => Some(ModelFileKind::Safetensors),
        "gguf" => Some(ModelFileKind::Gguf),
        _ => None,
    }
}

/// Whether a repository of this format (`repositories.format`) is judged.
pub fn serves_model_files(repository_format: &str) -> bool {
    matches!(repository_format, "huggingface" | "mlmodel")
}

/// The judgements for one model file of `kind`. Pure and synchronous.
pub fn scan_model_bytes(kind: ModelFileKind, data: &[u8]) -> Vec<ModelFinding> {
    match kind {
        ModelFileKind::Safetensors => scan_safetensors(data),
        ModelFileKind::Gguf => scan_gguf(data),
        ModelFileKind::Pickle | ModelFileKind::MaybePickle if is_zip(data) => scan_archive(data),
        ModelFileKind::Pickle => scan_pickle_file(data, "file"),
        ModelFileKind::MaybePickle if looks_like_pickle(data) => scan_pickle_file(data, "file"),
        ModelFileKind::MaybePickle => Vec::new(),
    }
}

fn is_zip(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06")
}

/// A protocol 2-5 pickle opens with `PROTO <n>`.
fn looks_like_pickle(data: &[u8]) -> bool {
    matches!(data, [0x80, 2..=5, ..])
}

// ---------------------------------------------------------------------------
// The scanner
// ---------------------------------------------------------------------------

/// The in-process model-file scanner. Registered unconditionally by
/// `ScannerService::new`: it needs no engine, sidecar or network.
#[derive(Debug, Default)]
pub struct ModelFileScanner;

impl ModelFileScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for ModelFileScanner {
    fn name(&self) -> &str {
        "model-file"
    }

    fn scan_type(&self) -> &str {
        MODEL_SCAN_TYPE
    }

    /// Applicability depends on the repository format, which a bare
    /// artifact does not carry; only [`Self::is_applicable_for_target`]
    /// can say yes.
    fn is_applicable(&self, _artifact: &Artifact) -> bool {
        false
    }

    fn is_applicable_for_target(&self, target: &ScanTarget<'_>) -> bool {
        target.repository_format.is_some_and(serves_model_files)
            && model_file_kind(&target.artifact.path).is_some()
    }

    async fn version(&self) -> Option<String> {
        Some(format!("model-file-scanner-{}", env!("CARGO_PKG_VERSION")))
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        let kind = model_file_kind(&artifact.path).ok_or_else(|| {
            AppError::Internal(format!(
                "model-file scanner called on a non-model file {}",
                artifact.path
            ))
        })?;
        let content = content.clone();
        let findings = tokio::task::spawn_blocking(move || scan_model_bytes(kind, &content))
            .await
            .map_err(|e| AppError::Internal(format!("model-file scan task failed: {e}")))?;
        let partial = findings.iter().any(|f| f.rule.is_limit());
        let mut output =
            ScanOutput::findings_only(findings.into_iter().map(ModelFinding::into_raw).collect());
        if partial {
            output.scan_completeness = ScanCompleteness::Partial;
        }
        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// safetensors
// ---------------------------------------------------------------------------

fn scan_safetensors(data: &[u8]) -> Vec<ModelFinding> {
    let file_size = data.len() as u64;
    let header_len = match mlmodel::safetensors_header_len(data, file_size) {
        Ok(len) => len,
        Err(e) => {
            return vec![ModelFinding::new(
                Rule::SafetensorsHeaderLength,
                "file",
                e.to_string(),
            )]
        }
    };
    let header = &data[8..8 + header_len];
    let data_len = file_size - 8 - header_len as u64;
    match mlmodel::parse_safetensors_header(header, data_len) {
        Ok(summary) => match summary.layout_issue {
            None => Vec::new(),
            Some(issue @ SafetensorsLayoutIssue::Overlap { .. }) => vec![ModelFinding::new(
                Rule::SafetensorsOverlappingOffsets,
                "file",
                issue.to_string(),
            )],
            Some(issue) => vec![ModelFinding::new(
                Rule::SafetensorsUnaccountedBytes,
                "file",
                issue.to_string(),
            )],
        },
        Err(SafetensorsError::Invalid(reason) | SafetensorsError::Unreadable(reason)) => {
            vec![ModelFinding::new(
                safetensors_rule_for(&reason),
                "file",
                reason,
            )]
        }
    }
}

/// The rule a header rejection belongs to, from the parser's reason (the
/// reasons are this crate's own messages in `formats::mlmodel`).
fn safetensors_rule_for(reason: &str) -> Rule {
    if reason.contains("unknown dtype") {
        Rule::SafetensorsUnknownDtype
    } else if reason.contains("data_offsets") {
        Rule::SafetensorsOffsetsOutOfRange
    } else {
        Rule::SafetensorsInvalidHeader
    }
}

// ---------------------------------------------------------------------------
// Zip-wrapped PyTorch archives
// ---------------------------------------------------------------------------

/// The pickle member of a PyTorch zip archive: `data.pkl` at the root or one
/// directory down (`archive/data.pkl`, `<name>/data.pkl`).
fn is_archive_pickle(name: &str) -> bool {
    match name.split_once('/') {
        None => name == "data.pkl",
        Some((_, rest)) => rest == "data.pkl",
    }
}

fn scan_archive(data: &[u8]) -> Vec<ModelFinding> {
    let member = crate::util::bounded_archive::read_metadata_from_zip_limited(
        std::io::Cursor::new(data),
        is_archive_pickle,
        ARCHIVE_MAX_ENTRIES,
        PICKLE_MAX_BYTES as u64,
    );
    match member {
        Ok(Some(pickle)) => scan_pickle_file(&pickle, "data.pkl"),
        Ok(None) => vec![ModelFinding::new(
            Rule::ArchiveNoPickle,
            "file",
            "zip archive has no data.pkl member at the root or one directory down; \
             its contents were not analysed",
        )],
        Err(e) => vec![ModelFinding::new(
            Rule::ArchiveMalformed,
            "file",
            e.to_string(),
        )],
    }
}

// ---------------------------------------------------------------------------
// Pickle: classification
// ---------------------------------------------------------------------------

/// How an import is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalClass {
    Allowed,
    Dangerous,
    Unknown,
}

/// Modules (and everything under them) whose import from a model file is a
/// code-execution, file-system, network or interpreter-escape primitive.
const DENIED_MODULES: &[&str] = &[
    "os",
    "posix",
    "nt",
    "subprocess",
    "_posixsubprocess",
    "runpy",
    "webbrowser",
    "socket",
    "_socket",
    "shutil",
    "pty",
    "sys",
    "importlib",
    "ctypes",
    "_ctypes",
    "code",
    "codeop",
    "commands",
    "pdb",
    "bdb",
    "timeit",
    "pickle",
    "_pickle",
    "cPickle",
    "dill",
    "marshal",
    "shelve",
    "multiprocessing",
    "pydoc",
    "profile",
    "cProfile",
    "trace",
    "urllib",
    "urllib2",
    "http",
    "httplib",
    "requests",
    "ftplib",
    "telnetlib",
    "smtplib",
    "asyncio",
    "venv",
    "ensurepip",
    "pip",
    "setuptools",
    "distutils",
    "zipimport",
    "imp",
    "numpy.f2py",
];

/// Single globals that execute or reach arbitrary code.
const DENIED_GLOBALS: &[&str] = &[
    "builtins.eval",
    "builtins.exec",
    "builtins.execfile",
    "builtins.compile",
    "builtins.getattr",
    "builtins.setattr",
    "builtins.delattr",
    "builtins.__import__",
    "builtins.open",
    "builtins.input",
    "builtins.breakpoint",
    "builtins.globals",
    "builtins.locals",
    "builtins.vars",
    "builtins.apply",
    "builtins.file",
    "builtins.reload",
    "operator.attrgetter",
    "operator.methodcaller",
    "_operator.attrgetter",
    "_operator.methodcaller",
    "types.CodeType",
    "types.FunctionType",
    "types.LambdaType",
    "types.MethodType",
    "platform.popen",
    "numpy.testing._private.utils.runstring",
    "torch.storage._load_from_bytes",
];

/// Attribute names that, reached through a dotted protocol 4 name, escape to
/// the interpreter whatever module they start from.
const DENIED_ATTRIBUTES: &[&str] = &[
    "__builtins__",
    "__globals__",
    "__dict__",
    "__class__",
    "__subclasses__",
    "__getattribute__",
    "__code__",
    "__import__",
    "__loader__",
    "__spec__",
    "eval",
    "exec",
    "system",
    "popen",
];

/// The exact globals a weights-only state-dict load needs (the set
/// `torch.load(weights_only=True)` accepts, plus numpy's array rebuild).
const ALLOWED_GLOBALS: &[&str] = &[
    "collections.OrderedDict",
    "collections.Counter",
    "torch._utils._rebuild_tensor",
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_tensor_v3",
    "torch._utils._rebuild_parameter",
    "torch._utils._rebuild_parameter_with_state",
    "torch._utils._rebuild_sparse_tensor",
    "torch._utils._rebuild_nested_tensor",
    "torch._utils._rebuild_meta_tensor_no_storage",
    "torch._utils._rebuild_qtensor",
    "torch._utils._rebuild_wrapper_subclass",
    "torch._utils._rebuild_device_tensor_from_numpy",
    "torch._utils._rebuild_device_tensor_from_cpu_tensor",
    "torch._tensor._rebuild_from_type_v2",
    "torch.nn.parameter.Parameter",
    "torch.Tensor",
    "torch.Size",
    "torch.device",
    "torch.serialization._get_layout",
    "torch.storage.UntypedStorage",
    "torch.storage.TypedStorage",
    "torch.per_tensor_affine",
    "torch.per_tensor_symmetric",
    "torch.per_channel_affine",
    "torch.per_channel_symmetric",
    "numpy.core.multiarray._reconstruct",
    "numpy._core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    "numpy._core.multiarray.scalar",
    "numpy.ndarray",
    "numpy.dtype",
    "_codecs.encode",
    "builtins.set",
    "builtins.frozenset",
    "builtins.bytearray",
    "builtins.slice",
    "builtins.complex",
    "builtins.int",
    "builtins.float",
    "builtins.bool",
    "builtins.str",
    "builtins.bytes",
    "builtins.list",
    "builtins.dict",
    "builtins.tuple",
];

/// `torch.<X>Storage` / `torch.cuda.<X>Storage` legacy typed storages.
const TORCH_STORAGES: &[&str] = &[
    "FloatStorage",
    "DoubleStorage",
    "HalfStorage",
    "BFloat16Storage",
    "LongStorage",
    "IntStorage",
    "ShortStorage",
    "CharStorage",
    "ByteStorage",
    "BoolStorage",
    "ComplexFloatStorage",
    "ComplexDoubleStorage",
    "QUInt8Storage",
    "QInt8Storage",
    "QInt32Storage",
    "QUInt4x2Storage",
    "QUInt2x4Storage",
];

/// `torch.<dtype>` objects a tensor rebuild may name.
const TORCH_DTYPES: &[&str] = &[
    "float32",
    "float",
    "float64",
    "double",
    "float16",
    "half",
    "bfloat16",
    "float8_e4m3fn",
    "float8_e4m3fnuz",
    "float8_e5m2",
    "float8_e5m2fnuz",
    "complex64",
    "complex128",
    "int64",
    "long",
    "int32",
    "int",
    "int16",
    "short",
    "int8",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "bool",
];

/// Python 2 module names `find_class` maps onto their Python 3 home.
fn normalize_module(module: &str) -> &str {
    match module {
        "__builtin__" | "__builtins__" | "exceptions" => "builtins",
        "copy_reg" => "copyreg",
        other => other,
    }
}

fn under_denied_module(path: &str) -> bool {
    DENIED_MODULES.iter().any(|m| {
        path == *m
            || path
                .strip_prefix(m)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// Classify the import `module`.`name` (`name` may be a dotted attribute
/// path under protocol 4).
pub fn classify_global(module: &str, name: &str) -> GlobalClass {
    let module = normalize_module(module);
    let qualified = format!("{module}.{name}");
    let dotted_escape = name.contains('.')
        && name
            .split('.')
            .any(|seg| DENIED_ATTRIBUTES.contains(&seg) || under_denied_module(seg));
    if under_denied_module(module) || DENIED_GLOBALS.contains(&qualified.as_str()) || dotted_escape
    {
        return GlobalClass::Dangerous;
    }
    let allowed = ALLOWED_GLOBALS.contains(&qualified.as_str())
        || (matches!(module, "torch" | "torch.cuda") && TORCH_STORAGES.contains(&name))
        || (module == "torch" && TORCH_DTYPES.contains(&name))
        || (module == "numpy.dtypes" && name.ends_with("DType") && !name.contains('.'));
    if allowed {
        GlobalClass::Allowed
    } else {
        GlobalClass::Unknown
    }
}

// ---------------------------------------------------------------------------
// Pickle: the opcode walk
// ---------------------------------------------------------------------------

/// How often one import is referenced and invoked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalUse {
    /// `GLOBAL` / `STACK_GLOBAL` / `INST` occurrences.
    pub references: u64,
    /// Times it was called (`REDUCE`, `NEWOBJ`, `NEWOBJ_EX`, `OBJ`, `INST`).
    pub calls: u64,
}

/// What a pickle walk saw. Never contains the result of executing anything.
#[derive(Debug, Clone, Default)]
pub struct PickleReport {
    /// Every import by (module, name), capped at
    /// [`PICKLE_MAX_DISTINCT_GLOBALS`] (denylisted imports are always kept).
    pub globals: BTreeMap<(String, String), GlobalUse>,
    /// `STACK_GLOBAL`s whose operands were not trackable strings.
    pub unresolved_globals: u64,
    pub opcodes: u64,
    /// Pickle streams walked (a legacy checkpoint holds several).
    pub streams: usize,
    pub reduces: u64,
    pub builds: u64,
    pub newobjs: u64,
    pub persistent_ids: u64,
    pub extension_codes: u64,
    /// Why the stream is not a well-formed pickle, if it is not.
    pub malformed: Option<String>,
    /// Which cap stopped the walk, if one did.
    pub limit: Option<String>,
}

/// A simulated stack value: only strings (possible `STACK_GLOBAL` operands)
/// and imports (possible callables) are told apart.
#[derive(Debug, Clone)]
enum Val {
    Str(Rc<str>),
    Global(usize),
    Other,
}

enum Stop {
    Malformed(String),
    Limit(String),
}

struct Walker<'a> {
    data: &'a [u8],
    pos: usize,
    stack: Vec<Val>,
    metastack: Vec<Vec<Val>>,
    held: usize,
    memo: HashMap<u64, Val>,
    tracked_bytes: usize,
    names: Vec<(String, String)>,
    index: HashMap<(String, String), usize>,
    report: PickleReport,
}

impl<'a> Walker<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data: &data[..data.len().min(PICKLE_MAX_BYTES)],
            pos: 0,
            stack: Vec::new(),
            metastack: Vec::new(),
            held: 0,
            memo: HashMap::new(),
            tracked_bytes: 0,
            names: Vec::new(),
            index: HashMap::new(),
            report: PickleReport::default(),
        }
    }

    fn truncated(&self, what: &str) -> Stop {
        if self.data.len() == PICKLE_MAX_BYTES {
            Stop::Limit(format!(
                "pickle stream continues past the {PICKLE_MAX_BYTES}-byte scan limit"
            ))
        } else {
            Stop::Malformed(format!("truncated {what} at byte {}", self.pos))
        }
    }

    fn take(&mut self, n: usize, what: &str) -> std::result::Result<&'a [u8], Stop> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.data.len());
        let Some(end) = end else {
            return Err(self.truncated(what));
        };
        let data: &'a [u8] = self.data;
        let out = &data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn uint(&mut self, n: usize, what: &str) -> std::result::Result<u64, Stop> {
        let bytes = self.take(n, what)?;
        let mut buf = [0u8; 8];
        buf[..n].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(buf))
    }

    /// A length-prefixed argument whose prefix is `n` bytes wide.
    fn counted(&mut self, n: usize, what: &str) -> std::result::Result<&'a [u8], Stop> {
        let len = self.uint(n, what)?;
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        self.take(len, what)
    }

    fn line(&mut self, what: &str) -> std::result::Result<&'a [u8], Stop> {
        let data: &'a [u8] = self.data;
        let rest = &data[self.pos..];
        let window = &rest[..rest.len().min(PICKLE_MAX_LINE_BYTES + 1)];
        match window.iter().position(|b| *b == b'\n') {
            Some(i) => {
                let out = &rest[..i];
                self.pos += i + 1;
                Ok(out)
            }
            None if window.len() > PICKLE_MAX_LINE_BYTES => Err(Stop::Malformed(format!(
                "{what} at byte {} is longer than {PICKLE_MAX_LINE_BYTES} bytes",
                self.pos
            ))),
            None => Err(self.truncated(what)),
        }
    }

    fn push(&mut self, v: Val) -> std::result::Result<(), Stop> {
        if self.held >= PICKLE_MAX_STACK {
            return Err(Stop::Limit(format!(
                "more than {PICKLE_MAX_STACK} values on the pickle stack"
            )));
        }
        self.held += 1;
        self.stack.push(v);
        Ok(())
    }

    fn pop(&mut self) -> std::result::Result<Val, Stop> {
        let v = self
            .stack
            .pop()
            .ok_or_else(|| Stop::Malformed(format!("stack underflow at byte {}", self.pos)))?;
        self.held -= 1;
        Ok(v)
    }

    fn top(&self) -> std::result::Result<Val, Stop> {
        self.stack
            .last()
            .cloned()
            .ok_or_else(|| Stop::Malformed(format!("stack underflow at byte {}", self.pos)))
    }

    fn mark(&mut self) {
        let level = std::mem::take(&mut self.stack);
        self.metastack.push(level);
    }

    /// Pop everything above the last MARK, as Python 3's `pop_mark` does.
    fn pop_mark(&mut self) -> std::result::Result<Vec<Val>, Stop> {
        let below = self
            .metastack
            .pop()
            .ok_or_else(|| Stop::Malformed(format!("no MARK to pop at byte {}", self.pos)))?;
        let items = std::mem::replace(&mut self.stack, below);
        self.held -= items.len();
        Ok(items)
    }

    /// A pushed string, tracked when short enough and within budget.
    fn string(&mut self, bytes: &[u8]) -> Val {
        if bytes.len() > PICKLE_MAX_TRACKED_STRING_BYTES
            || self.tracked_bytes + bytes.len() > PICKLE_MAX_TRACKED_STRING_TOTAL
        {
            return Val::Other;
        }
        self.tracked_bytes += bytes.len();
        Val::Str(Rc::from(String::from_utf8_lossy(bytes).as_ref()))
    }

    fn memo_put(&mut self, key: u64, v: Val) -> std::result::Result<(), Stop> {
        if self.memo.len() >= PICKLE_MAX_MEMO && !self.memo.contains_key(&key) {
            return Err(Stop::Limit(format!(
                "more than {PICKLE_MAX_MEMO} pickle memo entries"
            )));
        }
        self.memo.insert(key, v);
        Ok(())
    }

    fn memo_get(&mut self, key: u64) -> std::result::Result<(), Stop> {
        let v = self.memo.get(&key).cloned().ok_or_else(|| {
            Stop::Malformed(format!("memo key {key} not found at byte {}", self.pos))
        })?;
        self.push(v)
    }

    fn decimal(&self, line: &[u8], what: &str) -> std::result::Result<u64, Stop> {
        std::str::from_utf8(line)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| Stop::Malformed(format!("bad {what} index at byte {}", self.pos)))
    }

    /// Record the import `module`.`name`; returns its stack value.
    fn global(&mut self, module: &[u8], name: &[u8]) -> Val {
        let key = (
            String::from_utf8_lossy(module).into_owned(),
            String::from_utf8_lossy(name).into_owned(),
        );
        if let Some(&i) = self.index.get(&key) {
            self.bump(i, false);
            return Val::Global(i);
        }
        let keep = self.names.len() < PICKLE_MAX_DISTINCT_GLOBALS
            || classify_global(&key.0, &key.1) == GlobalClass::Dangerous;
        if !keep {
            if self.report.limit.is_none() {
                self.report.limit = Some(format!(
                    "more than {PICKLE_MAX_DISTINCT_GLOBALS} distinct imports"
                ));
            }
            return Val::Other;
        }
        let i = self.names.len();
        self.names.push(key.clone());
        self.index.insert(key.clone(), i);
        self.report.globals.insert(key, GlobalUse::default());
        self.bump(i, false);
        Val::Global(i)
    }

    fn bump(&mut self, i: usize, call: bool) {
        if let Some(entry) = self.report.globals.get_mut(&self.names[i]) {
            if call {
                entry.calls += 1;
            } else {
                entry.references += 1;
            }
        }
    }

    fn called(&mut self, callable: &Val) {
        if let Val::Global(i) = callable {
            self.bump(*i, true);
        }
    }

    /// Walk one stream up to its STOP.
    fn stream(&mut self) -> std::result::Result<(), Stop> {
        loop {
            if self.report.opcodes >= PICKLE_MAX_OPCODES {
                return Err(Stop::Limit(format!(
                    "more than {PICKLE_MAX_OPCODES} pickle opcodes"
                )));
            }
            let at = self.pos;
            let op = self.take(1, "opcode")?[0];
            self.report.opcodes += 1;
            match op {
                b'.' => return Ok(()),
                0x80 => {
                    let proto = self.uint(1, "PROTO")?;
                    if proto > 5 {
                        return Err(Stop::Malformed(format!(
                            "unsupported pickle protocol {proto} at byte {at}"
                        )));
                    }
                }
                0x95 => {
                    self.take(8, "FRAME")?;
                }
                b'(' => self.mark(),
                b'0' => {
                    if self.stack.is_empty() {
                        self.pop_mark()?;
                    } else {
                        self.pop()?;
                    }
                }
                b'1' => {
                    self.pop_mark()?;
                }
                b'2' => {
                    let v = self.top()?;
                    self.push(v)?;
                }
                // Scalars and empty containers.
                b'F' | b'I' | b'L' => {
                    self.line("number")?;
                    self.push(Val::Other)?;
                }
                b'J' => {
                    self.take(4, "BININT")?;
                    self.push(Val::Other)?;
                }
                b'K' => {
                    self.take(1, "BININT1")?;
                    self.push(Val::Other)?;
                }
                b'M' => {
                    self.take(2, "BININT2")?;
                    self.push(Val::Other)?;
                }
                b'G' => {
                    self.take(8, "BINFLOAT")?;
                    self.push(Val::Other)?;
                }
                0x8a => {
                    self.counted(1, "LONG1")?;
                    self.push(Val::Other)?;
                }
                0x8b => {
                    self.counted(4, "LONG4")?;
                    self.push(Val::Other)?;
                }
                b'N' | 0x88 | 0x89 | b'}' | b']' | b')' | 0x8f => self.push(Val::Other)?,
                // Strings: possible STACK_GLOBAL operands.
                b'S' => {
                    let raw = self.line("STRING")?;
                    let unquoted = raw
                        .strip_prefix(b"'")
                        .and_then(|r| r.strip_suffix(b"'"))
                        .or_else(|| raw.strip_prefix(b"\"").and_then(|r| r.strip_suffix(b"\"")))
                        .unwrap_or(raw);
                    let v = self.string(unquoted);
                    self.push(v)?;
                }
                b'V' => {
                    let raw = self.line("UNICODE")?;
                    let v = self.string(raw);
                    self.push(v)?;
                }
                b'T' | b'X' => {
                    let raw = self.counted(4, "string")?;
                    let v = self.string(raw);
                    self.push(v)?;
                }
                b'U' | 0x8c => {
                    let raw = self.counted(1, "string")?;
                    let v = self.string(raw);
                    self.push(v)?;
                }
                0x8d => {
                    let raw = self.counted(8, "BINUNICODE8")?;
                    let v = self.string(raw);
                    self.push(v)?;
                }
                // Bytes are not accepted as STACK_GLOBAL operands.
                b'B' => {
                    self.counted(4, "BINBYTES")?;
                    self.push(Val::Other)?;
                }
                b'C' => {
                    self.counted(1, "SHORT_BINBYTES")?;
                    self.push(Val::Other)?;
                }
                0x8e | 0x96 => {
                    self.counted(8, "BINBYTES8")?;
                    self.push(Val::Other)?;
                }
                0x97 => self.push(Val::Other)?,
                0x98 => {
                    self.top()?;
                }
                // Imports.
                b'c' => {
                    let module = self.line("GLOBAL module")?;
                    let name = self.line("GLOBAL name")?;
                    let v = self.global(module, name);
                    self.push(v)?;
                }
                0x93 => {
                    let name = self.pop()?;
                    let module = self.pop()?;
                    let v = match (module, name) {
                        (Val::Str(m), Val::Str(n)) => self.global(m.as_bytes(), n.as_bytes()),
                        _ => {
                            self.report.unresolved_globals += 1;
                            Val::Other
                        }
                    };
                    self.push(v)?;
                }
                b'i' => {
                    let module = self.line("INST module")?;
                    let name = self.line("INST name")?;
                    let v = self.global(module, name);
                    self.called(&v);
                    self.report.newobjs += 1;
                    self.pop_mark()?;
                    self.push(Val::Other)?;
                }
                0x82 => {
                    self.take(1, "EXT1")?;
                    self.report.extension_codes += 1;
                    self.push(Val::Other)?;
                }
                0x83 => {
                    self.take(2, "EXT2")?;
                    self.report.extension_codes += 1;
                    self.push(Val::Other)?;
                }
                0x84 => {
                    self.take(4, "EXT4")?;
                    self.report.extension_codes += 1;
                    self.push(Val::Other)?;
                }
                // Calls and object construction.
                b'R' => {
                    self.pop()?;
                    let callable = self.pop()?;
                    self.called(&callable);
                    self.report.reduces += 1;
                    self.push(Val::Other)?;
                }
                0x81 => {
                    self.pop()?;
                    let cls = self.pop()?;
                    self.called(&cls);
                    self.report.newobjs += 1;
                    self.push(Val::Other)?;
                }
                0x92 => {
                    self.pop()?;
                    self.pop()?;
                    let cls = self.pop()?;
                    self.called(&cls);
                    self.report.newobjs += 1;
                    self.push(Val::Other)?;
                }
                b'o' => {
                    let items = self.pop_mark()?;
                    if let Some(cls) = items.first() {
                        self.called(cls);
                    }
                    self.report.newobjs += 1;
                    self.push(Val::Other)?;
                }
                b'b' => {
                    self.pop()?;
                    self.top()?;
                    self.report.builds += 1;
                }
                b'P' => {
                    self.line("PERSID")?;
                    self.report.persistent_ids += 1;
                    self.push(Val::Other)?;
                }
                b'Q' => {
                    self.pop()?;
                    self.report.persistent_ids += 1;
                    self.push(Val::Other)?;
                }
                // Containers.
                b'a' => {
                    self.pop()?;
                    self.top()?;
                }
                b's' => {
                    self.pop()?;
                    self.pop()?;
                    self.top()?;
                }
                b'e' | b'u' | 0x90 => {
                    self.pop_mark()?;
                    self.top()?;
                }
                b't' | b'l' | b'd' | 0x91 => {
                    self.pop_mark()?;
                    self.push(Val::Other)?;
                }
                0x85 => {
                    self.pop()?;
                    self.push(Val::Other)?;
                }
                0x86 => {
                    self.pop()?;
                    self.pop()?;
                    self.push(Val::Other)?;
                }
                0x87 => {
                    self.pop()?;
                    self.pop()?;
                    self.pop()?;
                    self.push(Val::Other)?;
                }
                // Memo.
                b'p' => {
                    let line = self.line("PUT")?;
                    let key = self.decimal(line, "PUT")?;
                    let v = self.top()?;
                    self.memo_put(key, v)?;
                }
                b'q' => {
                    let key = self.uint(1, "BINPUT")?;
                    let v = self.top()?;
                    self.memo_put(key, v)?;
                }
                b'r' => {
                    let key = self.uint(4, "LONG_BINPUT")?;
                    let v = self.top()?;
                    self.memo_put(key, v)?;
                }
                0x94 => {
                    let key = self.memo.len() as u64;
                    let v = self.top()?;
                    self.memo_put(key, v)?;
                }
                b'g' => {
                    let line = self.line("GET")?;
                    let key = self.decimal(line, "GET")?;
                    self.memo_get(key)?;
                }
                b'h' => {
                    let key = self.uint(1, "BINGET")?;
                    self.memo_get(key)?;
                }
                b'j' => {
                    let key = self.uint(4, "LONG_BINGET")?;
                    self.memo_get(key)?;
                }
                other => {
                    return Err(Stop::Malformed(format!(
                        "unknown pickle opcode 0x{other:02x} at byte {at}"
                    )))
                }
            }
        }
    }

    /// Reset per-stream state (a new `Unpickler.load` starts empty).
    fn reset(&mut self) {
        self.stack.clear();
        self.metastack.clear();
        self.held = 0;
        self.memo.clear();
    }
}

/// Walk the pickle stream(s) in `data` without executing anything. Further
/// streams after the first STOP are walked while the next bytes open a
/// protocol 2-5 pickle (a legacy `torch.save` file), up to
/// [`PICKLE_MAX_STREAMS`]. A later stream that does not parse is taken to be
/// tensor data and ends the walk quietly; the imports it showed before that
/// are still recorded.
pub fn walk_pickle(data: &[u8]) -> PickleReport {
    let mut w = Walker::new(data);
    loop {
        let first = w.report.streams == 0;
        w.report.streams += 1;
        match w.stream() {
            Ok(()) => {}
            Err(Stop::Limit(why)) => {
                w.report.limit = Some(why);
                break;
            }
            Err(Stop::Malformed(why)) => {
                if first {
                    w.report.malformed = Some(why);
                }
                break;
            }
        }
        if w.report.streams >= PICKLE_MAX_STREAMS || !looks_like_pickle(&w.data[w.pos..]) {
            break;
        }
        w.reset();
    }
    w.report
}

/// The findings for one pickle (a file or an archive's `data.pkl`).
fn scan_pickle_file(data: &[u8], member: &str) -> Vec<ModelFinding> {
    let report = walk_pickle(data);
    pickle_findings(&report, member)
}

fn pickle_findings(report: &PickleReport, member: &str) -> Vec<ModelFinding> {
    let counts = format!(
        "{} opcode(s) over {} stream(s): {} REDUCE, {} BUILD, {} NEWOBJ/OBJ/INST, \
         {} persistent id(s), {} extension code(s)",
        report.opcodes,
        report.streams,
        report.reduces,
        report.builds,
        report.newobjs,
        report.persistent_ids,
        report.extension_codes
    );
    let mut findings = Vec::new();
    let mut unknown = Vec::new();
    for ((module, name), uses) in &report.globals {
        let qualified = format!("{module}.{name}");
        let detail = format!(
            "{member}: `{qualified}` referenced {} time(s), called {} time(s); {counts}",
            uses.references, uses.calls
        );
        match classify_global(module, name) {
            GlobalClass::Allowed => {}
            GlobalClass::Dangerous => findings.push(ModelFinding::new(
                Rule::PickleDangerousGlobal,
                qualified,
                detail,
            )),
            GlobalClass::Unknown => unknown.push(ModelFinding::new(
                Rule::PickleUnknownGlobal,
                qualified,
                detail,
            )),
        }
    }
    if unknown.len() > PICKLE_MAX_REPORTED_UNKNOWN {
        let rest = unknown.split_off(PICKLE_MAX_REPORTED_UNKNOWN);
        let names: Vec<&str> = rest.iter().map(|f| f.subject.as_str()).take(16).collect();
        unknown.push(ModelFinding::new(
            Rule::PickleUnknownGlobal,
            "further imports",
            format!(
                "{member}: {} more non-allowlisted import(s), e.g. {}",
                rest.len(),
                names.join(", ")
            ),
        ));
    }
    findings.extend(unknown);
    if report.unresolved_globals > 0 {
        findings.push(ModelFinding::new(
            Rule::PickleUnresolvedGlobal,
            "STACK_GLOBAL",
            format!(
                "{member}: {} STACK_GLOBAL import(s) whose module or name is not a \
                 trackable string; {counts}",
                report.unresolved_globals
            ),
        ));
    }
    if let Some(why) = &report.malformed {
        findings.push(ModelFinding::new(
            Rule::PickleMalformed,
            member,
            format!("{member}: {why}; {counts}"),
        ));
    }
    if let Some(why) = &report.limit {
        findings.push(ModelFinding::new(
            Rule::PickleScanLimit,
            member,
            format!("{member}: {why}; the rest was not examined; {counts}"),
        ));
    }
    findings
}

// ---------------------------------------------------------------------------
// GGUF
// ---------------------------------------------------------------------------

/// What a GGUF header walk recovered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GgufReport {
    pub version: u32,
    pub tensor_count: u64,
    pub kv_count: u64,
    pub architecture: Option<String>,
    /// `(key, byte length)` of every `tokenizer.chat_template*` string.
    pub chat_templates: Vec<(String, u64)>,
}

const GGUF_TYPE_STRING: u32 = 8;
const GGUF_TYPE_ARRAY: u32 = 9;

/// Byte width of a fixed-size GGUF value type.
fn gguf_scalar_width(ty: u32) -> Option<u64> {
    match ty {
        0 | 1 | 7 => Some(1),
        2 | 3 => Some(2),
        4..=6 => Some(4),
        10..=12 => Some(8),
        _ => None,
    }
}

struct GgufReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Version 1 encodes lengths and counts as u32; later versions as u64.
    wide: bool,
    array_elements: u64,
}

impl<'a> GgufReader<'a> {
    fn eof(&self, what: &str) -> Stop {
        Stop::Malformed(format!(
            "{what} at byte {} runs past the end of the file",
            self.pos
        ))
    }

    fn take(&mut self, n: u64, what: &str) -> std::result::Result<&'a [u8], Stop> {
        let end = usize::try_from(n)
            .ok()
            .and_then(|n| self.pos.checked_add(n))
            .filter(|end| *end <= self.data.len());
        let Some(end) = end else {
            return Err(self.eof(what));
        };
        if end > GGUF_MAX_HEADER_BYTES {
            return Err(Stop::Limit(format!(
                "header continues past the {GGUF_MAX_HEADER_BYTES}-byte scan limit"
            )));
        }
        let data: &'a [u8] = self.data;
        let out = &data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32(&mut self, what: &str) -> std::result::Result<u32, Stop> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, what: &str) -> std::result::Result<u64, Stop> {
        let b = self.take(8, what)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(b);
        Ok(u64::from_le_bytes(buf))
    }

    /// A length or count: u32 in version 1, u64 after.
    fn size(&mut self, what: &str) -> std::result::Result<u64, Stop> {
        if self.wide {
            self.u64(what)
        } else {
            self.u32(what).map(u64::from)
        }
    }

    fn string(&mut self, what: &str) -> std::result::Result<&'a [u8], Stop> {
        let len = self.size(what)?;
        self.take(len, what)
    }

    fn remaining(&self) -> u64 {
        (self.data.len() - self.pos) as u64
    }

    /// Skip one value of type `ty`, returning its bytes when it is a string.
    fn value(&mut self, ty: u32, depth: u32) -> std::result::Result<Option<&'a [u8]>, Stop> {
        if let Some(width) = gguf_scalar_width(ty) {
            self.take(width, "value")?;
            return Ok(None);
        }
        match ty {
            GGUF_TYPE_STRING => self.string("string value").map(Some),
            GGUF_TYPE_ARRAY => {
                if depth >= GGUF_MAX_ARRAY_DEPTH {
                    return Err(Stop::Malformed(format!(
                        "arrays nested deeper than {GGUF_MAX_ARRAY_DEPTH} at byte {}",
                        self.pos
                    )));
                }
                let elem = self.u32("array type")?;
                let count = self.size("array length")?;
                if let Some(width) = gguf_scalar_width(elem) {
                    let bytes = count.checked_mul(width).ok_or_else(|| self.eof("array"))?;
                    self.take(bytes, "array")?;
                    return Ok(None);
                }
                // Every string or array element takes at least one length.
                let min_element = if self.wide { 8 } else { 4 };
                if count > self.remaining() / min_element {
                    return Err(Stop::Malformed(format!(
                        "array of {count} elements at byte {} cannot fit in the file",
                        self.pos
                    )));
                }
                for _ in 0..count {
                    self.array_elements += 1;
                    if self.array_elements > GGUF_MAX_ARRAY_ELEMENTS {
                        return Err(Stop::Limit(format!(
                            "more than {GGUF_MAX_ARRAY_ELEMENTS} metadata array elements"
                        )));
                    }
                    self.value(elem, depth + 1)?;
                }
                Ok(None)
            }
            other => Err(Stop::Malformed(format!(
                "unknown value type {other} at byte {}",
                self.pos
            ))),
        }
    }
}

/// Walk a GGUF header: magic, version, counts, every metadata key/value and
/// every tensor info, each bounded by the file.
pub fn walk_gguf(data: &[u8]) -> (GgufReport, Vec<ModelFinding>) {
    let mut report = GgufReport::default();
    let mut findings = Vec::new();
    if let Err(stop) = walk_gguf_into(data, &mut report, &mut findings) {
        let (rule, why) = match stop {
            Stop::Malformed(why) => (Rule::GgufMalformed, why),
            Stop::Limit(why) => (Rule::GgufScanLimit, why),
        };
        findings.push(ModelFinding::new(rule, "file", why));
    }
    (report, findings)
}

fn walk_gguf_into(
    data: &[u8],
    report: &mut GgufReport,
    findings: &mut Vec<ModelFinding>,
) -> std::result::Result<(), Stop> {
    if !data.starts_with(b"GGUF") {
        return Err(Stop::Malformed("missing GGUF magic".to_string()));
    }
    let mut r = GgufReader {
        data,
        pos: 4,
        wide: true,
        array_elements: 0,
    };
    report.version = r.u32("version")?;
    if !(1..=3).contains(&report.version) {
        return Err(Stop::Malformed(format!(
            "unsupported GGUF version {}",
            report.version
        )));
    }
    r.wide = report.version >= 2;
    report.tensor_count = r.size("tensor count")?;
    report.kv_count = r.size("metadata count")?;

    // A key/value pair takes at least a key length, a type and one byte; a
    // tensor info at least a name length, a rank, a type and an offset.
    let len_width = if r.wide { 8 } else { 4 };
    let min_kv = len_width + 4 + 1;
    let min_tensor = len_width + 4 + 4 + 8;
    let room = r.remaining();
    let fits = report
        .kv_count
        .checked_mul(min_kv)
        .zip(report.tensor_count.checked_mul(min_tensor))
        .and_then(|(a, b)| a.checked_add(b))
        .is_some_and(|need| need <= room);
    if !fits || report.kv_count > GGUF_MAX_COUNT || report.tensor_count > GGUF_MAX_COUNT {
        findings.push(ModelFinding::new(
            Rule::GgufImplausibleCounts,
            "file",
            format!(
                "header declares {} metadata entries and {} tensors, which cannot fit in \
                 the {room} bytes after the header (or exceed {GGUF_MAX_COUNT})",
                report.kv_count, report.tensor_count
            ),
        ));
        return Ok(());
    }

    let mut alignment: u64 = 32;
    for _ in 0..report.kv_count {
        let key_len = r.size("metadata key")?;
        if key_len > GGUF_MAX_KEY_BYTES {
            return Err(Stop::Malformed(format!(
                "metadata key of {key_len} bytes at byte {}",
                r.pos
            )));
        }
        let key = String::from_utf8_lossy(r.take(key_len, "metadata key")?).into_owned();
        let ty = r.u32("value type")?;
        let value_at = r.pos;
        let value = r.value(ty, 0)?;
        if key == "general.alignment" && ty == 4 {
            let b = &data[value_at..value_at + 4];
            alignment = u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        }
        if let Some(s) = value {
            if key == "general.architecture" {
                report.architecture = Some(String::from_utf8_lossy(s).chars().take(64).collect());
            }
            if key.starts_with("tokenizer.chat_template") {
                report.chat_templates.push((key, s.len() as u64));
            }
        }
    }
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(Stop::Malformed(format!(
            "general.alignment {alignment} is not a power of two"
        )));
    }

    let mut offsets = Vec::new();
    for _ in 0..report.tensor_count {
        let name_len = r.size("tensor name")?;
        if name_len > GGUF_MAX_TENSOR_NAME_BYTES {
            return Err(Stop::Malformed(format!(
                "tensor name of {name_len} bytes at byte {}",
                r.pos
            )));
        }
        r.take(name_len, "tensor name")?;
        let dims = r.u32("tensor rank")?;
        if dims > GGUF_MAX_DIMS {
            return Err(Stop::Malformed(format!(
                "tensor of rank {dims} at byte {}",
                r.pos
            )));
        }
        for _ in 0..dims {
            r.size("tensor dimension")?;
        }
        r.u32("tensor type")?;
        offsets.push(r.u64("tensor offset")?);
    }
    let data_start = (r.pos as u64).div_ceil(alignment) * alignment;
    if report.tensor_count > 0 && data_start > data.len() as u64 {
        return Err(Stop::Malformed(format!(
            "tensor data section at byte {data_start} starts past the end of the file"
        )));
    }
    let data_len = (data.len() as u64).saturating_sub(data_start);
    if let Some(bad) = offsets.iter().find(|o| **o > data_len) {
        return Err(Stop::Malformed(format!(
            "tensor offset {bad} lies past the {data_len}-byte data section"
        )));
    }

    for (key, len) in &report.chat_templates {
        if *len > GGUF_MAX_CHAT_TEMPLATE_BYTES {
            findings.push(ModelFinding::new(
                Rule::GgufLargeChatTemplate,
                key.clone(),
                format!(
                    "`{key}` is {len} bytes (limit {GGUF_MAX_CHAT_TEMPLATE_BYTES}); the \
                     template is Jinja that llama.cpp-based runtimes execute"
                ),
            ));
        }
    }
    Ok(())
}

fn scan_gguf(data: &[u8]) -> Vec<ModelFinding> {
    walk_gguf(data).1
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    // ---- pickle fixtures (hand-built; verified with `pickletools.dis`) ----

    /// A torch-like state dict, protocol 2: an OrderedDict holding one
    /// tensor rebuilt from a FloatStorage persistent id. Allowlisted only.
    const BENIGN_TORCH: &[u8] = b"\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01\
X\x06\x00\x00\x00weightq\x02ctorch._utils\n_rebuild_tensor_v2\nq\x03\
((X\x07\x00\x00\x00storageq\x04ctorch\nFloatStorage\nq\x05X\x01\x00\x00\x000q\x06\
X\x03\x00\x00\x00cpuq\x07K\x04tq\x08QK\x00K\x04\x85K\x01\x85\x89h\x00)Rq\x09tq\x0aRq\x0bs.";

    /// `os.system("id")` the classic way: protocol 0 GLOBAL + REDUCE.
    const OS_SYSTEM_GLOBAL: &[u8] = b"cos\nsystem\n(S'id'\ntR.";

    /// What `pickle.dumps(obj, protocol=4)` emits for an object whose
    /// `__reduce__` returns `(os.system, ("id",))` on Linux.
    const POSIX_SYSTEM_STACK_GLOBAL: &[u8] = b"\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\
\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.";

    /// STACK_GLOBAL whose operands come back out of the memo.
    const OS_SYSTEM_VIA_MEMO: &[u8] =
        b"\x80\x04\x8c\x02os\x940\x8c\x06system\x940h\x00h\x01\x93\x94\x8c\x02id\x94\x85R.";

    fn rules(findings: &[ModelFinding]) -> Vec<Rule> {
        findings.iter().map(|f| f.rule).collect()
    }

    fn subjects(findings: &[ModelFinding], rule: Rule) -> Vec<&str> {
        findings
            .iter()
            .filter(|f| f.rule == rule)
            .map(|f| f.subject.as_str())
            .collect()
    }

    #[test]
    fn test_benign_torch_pickle_is_clean() {
        let report = walk_pickle(BENIGN_TORCH);
        assert!(report.malformed.is_none(), "{:?}", report.malformed);
        assert!(report.limit.is_none());
        assert_eq!(report.globals.len(), 3);
        let od = &report.globals[&("collections".to_string(), "OrderedDict".to_string())];
        assert_eq!(od.references, 1);
        assert_eq!(od.calls, 2, "called directly and again through BINGET");
        assert_eq!(report.reduces, 3);
        assert_eq!(report.persistent_ids, 1);
        assert!(scan_model_bytes(ModelFileKind::Pickle, BENIGN_TORCH).is_empty());
    }

    #[test]
    fn test_os_system_via_global_is_malicious() {
        let findings = scan_model_bytes(ModelFileKind::Pickle, OS_SYSTEM_GLOBAL);
        assert_eq!(rules(&findings), vec![Rule::PickleDangerousGlobal]);
        assert_eq!(findings[0].subject, "os.system");
        assert!(findings[0].detail.contains("called 1 time(s)"));
        let raw = findings[0].clone().into_raw();
        assert_eq!(raw.finding_class, FindingClass::Malicious);
        assert_eq!(raw.severity, Severity::Critical);
        assert_eq!(
            raw.affected_component.as_deref(),
            Some("model.pickle.dangerous-global")
        );
        assert_eq!(raw.source.as_deref(), Some(FINDING_SOURCE));
    }

    #[test]
    fn test_posix_system_via_stack_global_is_malicious() {
        for fixture in [POSIX_SYSTEM_STACK_GLOBAL, OS_SYSTEM_VIA_MEMO] {
            let findings = scan_model_bytes(ModelFileKind::MaybePickle, fixture);
            assert_eq!(rules(&findings), vec![Rule::PickleDangerousGlobal]);
        }
        let findings = scan_model_bytes(ModelFileKind::Pickle, POSIX_SYSTEM_STACK_GLOBAL);
        assert_eq!(findings[0].subject, "posix.system");
        let findings = scan_model_bytes(ModelFileKind::Pickle, OS_SYSTEM_VIA_MEMO);
        assert_eq!(findings[0].subject, "os.system");
    }

    #[test]
    fn test_unknown_global_is_policy() {
        let pickle = b"\x80\x02cfoo.bar\nBaz\nq\x00)\x81q\x01.";
        let findings = scan_model_bytes(ModelFileKind::Pickle, pickle);
        assert_eq!(rules(&findings), vec![Rule::PickleUnknownGlobal]);
        assert_eq!(findings[0].subject, "foo.bar.Baz");
        let raw = findings[0].clone().into_raw();
        assert_eq!(raw.finding_class, FindingClass::Policy);
        assert_eq!(raw.severity, Severity::Medium);
    }

    #[test]
    fn test_unresolved_stack_global_is_reported() {
        // STACK_GLOBAL over two integers: nothing nameable.
        let pickle = b"\x80\x04K\x01K\x02\x93).";
        let findings = scan_model_bytes(ModelFileKind::Pickle, pickle);
        assert_eq!(rules(&findings), vec![Rule::PickleUnresolvedGlobal]);
        assert_eq!(findings[0].clone().into_raw().severity, Severity::High);
    }

    #[test]
    fn test_classify_global_lists() {
        use GlobalClass::*;
        for (m, n) in [
            ("posix", "system"),
            ("nt", "system"),
            ("subprocess", "Popen"),
            ("builtins", "eval"),
            ("__builtin__", "exec"),
            ("builtins", "getattr"),
            ("runpy", "_run_code"),
            ("webbrowser", "open"),
            ("socket", "create_connection"),
            ("shutil", "rmtree"),
            ("pty", "spawn"),
            ("os.path", "join"),
            ("posixpath", "os.system"),
            ("torch", "load.__globals__"),
        ] {
            assert_eq!(classify_global(m, n), Dangerous, "{m}.{n}");
        }
        for (m, n) in [
            ("torch._utils", "_rebuild_tensor_v2"),
            ("torch", "BFloat16Storage"),
            ("torch.cuda", "HalfStorage"),
            ("torch", "bfloat16"),
            ("numpy.core.multiarray", "_reconstruct"),
            ("numpy.dtypes", "Float32DType"),
            ("__builtin__", "set"),
        ] {
            assert_eq!(classify_global(m, n), Allowed, "{m}.{n}");
        }
        for (m, n) in [
            ("transformers.training_args", "TrainingArguments"),
            ("builtins", "print"),
            ("ossify", "x"),
            ("torch", "nn.Module"),
        ] {
            assert_eq!(classify_global(m, n), Unknown, "{m}.{n}");
        }
    }

    #[test]
    fn test_truncated_and_garbage_pickles_are_findings_not_panics() {
        for cut in 1..BENIGN_TORCH.len() {
            let findings = scan_model_bytes(ModelFileKind::Pickle, &BENIGN_TORCH[..cut]);
            assert!(
                findings.iter().any(|f| f.rule == Rule::PickleMalformed),
                "cut at {cut}: {findings:?}"
            );
        }
        let garbage_inputs: [&[u8]; 8] = [
            b"",
            b"\xff\xfe\xfd",
            b"\x80\x09.",
            b"a.",
            b"1.",
            b"h\x05.",
            b"c\xff\xff",
            b"\x80\x04\x8d\xff\xff\xff\xff\xff\xff\xff\xff",
        ];
        for garbage in garbage_inputs {
            let findings = scan_model_bytes(ModelFileKind::Pickle, garbage);
            assert_eq!(rules(&findings), vec![Rule::PickleMalformed], "{garbage:?}");
        }
        // Imports seen before the stream broke are still judged.
        let findings = scan_model_bytes(ModelFileKind::Pickle, b"cos\nsystem\n(S'id");
        assert_eq!(
            rules(&findings),
            vec![Rule::PickleDangerousGlobal, Rule::PickleMalformed]
        );
        // An overlong protocol 0 line.
        let mut long = b"c".to_vec();
        long.extend(std::iter::repeat_n(b'a', PICKLE_MAX_LINE_BYTES + 10));
        let findings = scan_model_bytes(ModelFileKind::Pickle, &long);
        assert!(findings[0].detail.contains("longer than"));
    }

    #[test]
    fn test_stack_cap_is_a_scan_limit() {
        let mut deep = b"\x80\x02".to_vec();
        deep.extend(std::iter::repeat_n(b'N', PICKLE_MAX_STACK + 1));
        deep.push(b'.');
        let findings = scan_model_bytes(ModelFileKind::Pickle, &deep);
        assert_eq!(rules(&findings), vec![Rule::PickleScanLimit]);
        assert!(Rule::PickleScanLimit.is_limit());
    }

    #[test]
    fn test_legacy_checkpoint_streams_are_all_walked() {
        // magic number, then the object: the import sits in stream two.
        let mut legacy = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19.".to_vec();
        legacy.extend_from_slice(POSIX_SYSTEM_STACK_GLOBAL);
        legacy.extend_from_slice(b"\x80\x02 raw tensor bytes that are not a pickle");
        let report = walk_pickle(&legacy);
        assert_eq!(report.streams, 3);
        assert!(report.malformed.is_none(), "trailing data is not malformed");
        let findings = scan_model_bytes(ModelFileKind::MaybePickle, &legacy);
        assert_eq!(rules(&findings), vec![Rule::PickleDangerousGlobal]);
    }

    #[test]
    fn test_non_pickle_bin_is_not_judged() {
        assert!(scan_model_bytes(ModelFileKind::MaybePickle, b"ggml\x00\x01weights").is_empty());
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Pickle, b"ggml\x00\x01")),
            vec![Rule::PickleMalformed]
        );
    }

    #[test]
    fn test_zip_wrapped_data_pkl_is_found_and_scanned() {
        let zip = crate::formats::agent_plugins::test_zip(&[
            ("archive/version", b"3\n"),
            ("archive/data.pkl", OS_SYSTEM_GLOBAL),
            ("archive/data/0", b"\x00\x00\x80\x3f"),
        ]);
        let findings = scan_model_bytes(ModelFileKind::MaybePickle, &zip);
        assert_eq!(rules(&findings), vec![Rule::PickleDangerousGlobal]);
        assert!(findings[0].detail.starts_with("data.pkl:"));

        let clean = crate::formats::agent_plugins::test_zip(&[("model/data.pkl", BENIGN_TORCH)]);
        assert!(scan_model_bytes(ModelFileKind::Pickle, &clean).is_empty());

        let deep = crate::formats::agent_plugins::test_zip(&[("a/b/data.pkl", OS_SYSTEM_GLOBAL)]);
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Pickle, &deep)),
            vec![Rule::ArchiveNoPickle]
        );
        let broken = b"PK\x03\x04 not really a zip";
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Pickle, broken)),
            vec![Rule::ArchiveMalformed]
        );
    }

    // ---- safetensors ------------------------------------------------------

    fn safetensors(header: serde_json::Value, data_len: usize) -> Vec<u8> {
        mlmodel::safetensors_fixture(&header, data_len)
    }

    #[test]
    fn test_safetensors_good_and_bad() {
        use serde_json::json;
        let good = safetensors(
            json!({
                "__metadata__": {"format": "pt"},
                "a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
                "b": {"dtype": "BF16", "shape": [4], "data_offsets": [8, 16]}
            }),
            16,
        );
        assert!(scan_model_bytes(ModelFileKind::Safetensors, &good).is_empty());

        let overlap = safetensors(
            json!({
                "a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
                "b": {"dtype": "F32", "shape": [2], "data_offsets": [4, 12]}
            }),
            12,
        );
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Safetensors, &overlap)),
            vec![Rule::SafetensorsOverlappingOffsets]
        );

        let oob = safetensors(
            json!({"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 64]}}),
            8,
        );
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Safetensors, &oob)),
            vec![Rule::SafetensorsOffsetsOutOfRange]
        );

        let dtype = safetensors(
            json!({"a": {"dtype": "OBJECT", "shape": [1], "data_offsets": [0, 8]}}),
            8,
        );
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Safetensors, &dtype)),
            vec![Rule::SafetensorsUnknownDtype]
        );

        let trailing = safetensors(
            json!({"a": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}),
            100,
        );
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Safetensors, &trailing)),
            vec![Rule::SafetensorsUnaccountedBytes]
        );

        let mut past_eof = 4096u64.to_le_bytes().to_vec();
        past_eof.extend_from_slice(b"{}");
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Safetensors, &past_eof)),
            vec![Rule::SafetensorsHeaderLength]
        );
        let mut garbage = 4u64.to_le_bytes().to_vec();
        garbage.extend_from_slice(b"nope");
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Safetensors, &garbage)),
            vec![Rule::SafetensorsInvalidHeader]
        );
    }

    // ---- GGUF -------------------------------------------------------------

    fn gguf_str(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s);
    }

    /// A v3 GGUF with string metadata `kvs` (plus a u32 alignment and a
    /// string array) and one 2x2 tensor.
    fn gguf_fixture(kvs: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"GGUF".to_vec();
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&(kvs.len() as u64 + 2).to_le_bytes());
        for (key, value) in kvs {
            gguf_str(&mut out, key.as_bytes());
            out.extend_from_slice(&GGUF_TYPE_STRING.to_le_bytes());
            gguf_str(&mut out, value);
        }
        gguf_str(&mut out, b"general.alignment");
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&32u32.to_le_bytes());
        gguf_str(&mut out, b"tokenizer.ggml.tokens");
        out.extend_from_slice(&GGUF_TYPE_ARRAY.to_le_bytes());
        out.extend_from_slice(&GGUF_TYPE_STRING.to_le_bytes());
        out.extend_from_slice(&2u64.to_le_bytes());
        gguf_str(&mut out, b"<s>");
        gguf_str(&mut out, b"</s>");
        // Tensor info: name, rank 2, dims, type F32, offset 0.
        gguf_str(&mut out, b"token_embd.weight");
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&2u64.to_le_bytes());
        out.extend_from_slice(&2u64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        while !out.len().is_multiple_of(32) {
            out.push(0);
        }
        out.extend_from_slice(&[0u8; 16]);
        out
    }

    #[test]
    fn test_gguf_good_file_is_clean_and_summarised() {
        let file = gguf_fixture(&[
            ("general.architecture", b"qwen2"),
            (
                "tokenizer.chat_template",
                b"{% for m in messages %}{{ m.content }}{% endfor %}",
            ),
        ]);
        let (report, findings) = walk_gguf(&file);
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(report.version, 3);
        assert_eq!(report.tensor_count, 1);
        assert_eq!(report.kv_count, 4);
        assert_eq!(report.architecture.as_deref(), Some("qwen2"));
        assert_eq!(report.chat_templates.len(), 1);
    }

    #[test]
    fn test_gguf_truncated_is_malformed() {
        let file = gguf_fixture(&[("general.architecture", b"llama")]);
        for cut in 0..file.len() - 16 {
            let findings = scan_model_bytes(ModelFileKind::Gguf, &file[..cut]);
            assert!(
                !findings.is_empty(),
                "a GGUF cut at {cut} of {} must be reported",
                file.len()
            );
            assert!(findings
                .iter()
                .all(|f| matches!(f.rule, Rule::GgufMalformed | Rule::GgufImplausibleCounts)));
        }
    }

    #[test]
    fn test_gguf_oversized_counts_and_large_template() {
        let mut file = b"GGUF".to_vec();
        file.extend_from_slice(&3u32.to_le_bytes());
        file.extend_from_slice(&u64::MAX.to_le_bytes());
        file.extend_from_slice(&1u64.to_le_bytes());
        file.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Gguf, &file)),
            vec![Rule::GgufImplausibleCounts]
        );

        let big = vec![b'x'; GGUF_MAX_CHAT_TEMPLATE_BYTES as usize + 1];
        let file = gguf_fixture(&[("tokenizer.chat_template", &big)]);
        let findings = scan_model_bytes(ModelFileKind::Gguf, &file);
        assert_eq!(rules(&findings), vec![Rule::GgufLargeChatTemplate]);
        assert_eq!(
            subjects(&findings, Rule::GgufLargeChatTemplate),
            vec!["tokenizer.chat_template"]
        );
        assert!(findings[0].detail.contains(&big.len().to_string()));

        let mut bad_magic = gguf_fixture(&[]);
        bad_magic[0] = b'X';
        assert_eq!(
            rules(&scan_model_bytes(ModelFileKind::Gguf, &bad_magic)),
            vec![Rule::GgufMalformed]
        );
    }

    // ---- applicability and the Scanner entry --------------------------------

    #[test]
    fn test_model_file_kind_and_formats() {
        assert_eq!(
            model_file_kind("gpt2/main/pytorch_model.bin"),
            Some(ModelFileKind::MaybePickle)
        );
        assert_eq!(model_file_kind("m/x.PT"), Some(ModelFileKind::Pickle));
        assert_eq!(model_file_kind("m/x.joblib"), Some(ModelFileKind::Pickle));
        assert_eq!(
            model_file_kind("m/model.safetensors"),
            Some(ModelFileKind::Safetensors)
        );
        assert_eq!(model_file_kind("m/q4.gguf"), Some(ModelFileKind::Gguf));
        assert_eq!(model_file_kind("m/config.json"), None);
        assert_eq!(model_file_kind("m/model.safetensors.index.json"), None);
        assert_eq!(model_file_kind("m/README"), None);
        assert!(serves_model_files("huggingface"));
        assert!(serves_model_files("mlmodel"));
        assert!(!serves_model_files("generic"));
        for rule in [Rule::PickleDangerousGlobal, Rule::GgufLargeChatTemplate] {
            assert!(rule.id().starts_with("model."));
        }
    }

    fn target<'a>(artifact: &'a Artifact, format: Option<&'a str>) -> ScanTarget<'a> {
        ScanTarget {
            artifact,
            repository_key: "models",
            repository_type: "local",
            db: None,
            storage: None,
            manifest_body: None,
            expected_component: None,
            require_nonempty_catalog: false,
            repository_format: format,
        }
    }

    #[tokio::test]
    async fn test_scanner_entry_judges_hosted_model_files_only() {
        use crate::services::scanner_service::test_helpers::make_test_artifact;
        let scanner = ModelFileScanner::new();
        let bin = make_test_artifact(
            "gpt2",
            "application/octet-stream",
            "gpt2/main/pytorch_model.bin",
        );
        assert!(scanner.is_applicable_for_target(&target(&bin, Some("huggingface"))));
        assert!(scanner.is_applicable_for_target(&target(&bin, Some("mlmodel"))));
        assert!(!scanner.is_applicable_for_target(&target(&bin, Some("generic"))));
        assert!(!scanner.is_applicable_for_target(&target(&bin, None)));
        assert!(!scanner.is_applicable(&bin));
        let json = make_test_artifact("gpt2", "application/json", "gpt2/main/config.json");
        assert!(!scanner.is_applicable_for_target(&target(&json, Some("huggingface"))));

        let out = scanner
            .scan(&bin, None, &Bytes::from_static(POSIX_SYSTEM_STACK_GLOBAL))
            .await
            .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].finding_class, FindingClass::Malicious);
        assert_eq!(out.scan_completeness, ScanCompleteness::Complete);
        assert!(out.packages.is_empty());

        let clean = scanner
            .scan(&bin, None, &Bytes::from_static(BENIGN_TORCH))
            .await
            .unwrap();
        assert!(clean.findings.is_empty());
        assert!(scanner
            .version()
            .await
            .unwrap()
            .starts_with("model-file-scanner-"));
        assert_eq!(scanner.scan_type(), MODEL_SCAN_TYPE);

        assert!(scanner.scan(&json, None, &Bytes::new()).await.is_err());
    }

    /// The normal scan path end to end: a malicious `pytorch_model.bin` in a
    /// hosted huggingface repository, scanned by the orchestrator, lands a
    /// critical `malicious` row in `scan_findings` under scan_type `model`.
    /// Skips without `DATABASE_URL`.
    #[tokio::test]
    async fn test_malicious_pytorch_bin_in_huggingface_repo_is_flagged() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::scanner_service::ScannerService;
        use std::sync::Arc;
        let Some(fx) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let artifact_id = uuid::Uuid::new_v4();
        let storage_key = format!("huggingface/evil/main/{artifact_id}/pytorch_model.bin");
        fx.state
            .storage
            .put(&storage_key, Bytes::from_static(POSIX_SYSTEM_STACK_GLOBAL))
            .await
            .expect("store artifact bytes");
        let checksum = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        sqlx::query(
            "INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, \
             checksum_sha256, content_type, storage_key, is_deleted) \
             VALUES ($1, $2, 'evil', 'main', 'evil/main/pytorch_model.bin', $3, $4, \
             'application/octet-stream', $5, false)",
        )
        .bind(artifact_id)
        .bind(fx.repo_id)
        .bind(POSIX_SYSTEM_STACK_GLOBAL.len() as i64)
        .bind(&checksum)
        .bind(&storage_key)
        .execute(&fx.pool)
        .await
        .expect("insert artifact");

        let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(ModelFileScanner::new())];
        let service = ScannerService::new_for_test_with_scanners(
            fx.pool.clone(),
            scanners,
            fx.state.storage.clone(),
            fx.state.storage_registry.clone(),
            fx.storage_dir.to_string_lossy().into_owned(),
            fx.storage_dir
                .join("scan-workspace")
                .to_string_lossy()
                .into_owned(),
        );
        service
            .scan_artifact_with_options(artifact_id, true, true)
            .await
            .expect("scan orchestration returns Ok");

        let rows: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT sf.finding_class, sf.severity, sf.affected_component, sr.status \
             FROM scan_findings sf JOIN scan_results sr ON sr.id = sf.scan_result_id \
             WHERE sf.artifact_id = $1 AND sr.scan_type = 'model'",
        )
        .bind(artifact_id)
        .fetch_all(&fx.pool)
        .await
        .expect("read findings");
        let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        assert_eq!(rows.len(), 1, "{rows:?}");
        let (class, severity, rule, status) = &rows[0];
        assert_eq!(class, "malicious");
        assert_eq!(severity, "critical");
        assert_eq!(rule.as_deref(), Some("model.pickle.dangerous-global"));
        assert_eq!(status, "completed");
    }
}
