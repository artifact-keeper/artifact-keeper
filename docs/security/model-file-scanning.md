# Model-file scanning

Since #5285 Artifact Keeper judges the model files uploaded to a hosted
`huggingface` or `mlmodel` repository before anything loads them. A PyTorch
checkpoint is a pickle, and `torch.load` without `weights_only=True` (or an
older `transformers`) runs whatever the pickle imports and calls. None of the
CVE scanners look at that, so a backdoored `pytorch_model.bin` used to scan
clean.

The scanner is in-process Rust (`backend/src/services/model_file_scanner.rs`).
It needs no sidecar, engine, signature feed or network access, so it works the
same inside a disconnected enclave. It never executes, unpickles or imports
anything from the file.

## When it runs

It is registered with every scanner service and runs through the normal scan
path: scan on upload (`scan_on_upload`), a manual or repository-wide scan, and
the `block_unscanned` and quarantine gates that read the scan results. Its
rows have `scan_type = model`.

It applies when the artifact's repository has format `huggingface` or
`mlmodel` and its file name ends in one of:

| Extension | Examined as |
|---|---|
| `.pt`, `.pth`, `.ckpt`, `.pkl`, `.pickle`, `.joblib` | pickle, or a zip-wrapped PyTorch archive |
| `.bin` | pickle or PyTorch archive when its bytes say so (a protocol 2-5 pickle or a zip); any other `.bin` (GGML, OpenVINO, raw tensors) completes with no findings |
| `.safetensors` | safetensors header |
| `.gguf` | GGUF header |

For any other file, and for every file in a repository of another format, the
scan is recorded as `not_applicable`.

## What it checks

### Pickles

The scanner walks the pickle opcode stream (protocols 0 to 5) and simulates
just enough of the unpickler's stack and memo to name every import:
`GLOBAL`, `INST`, and `STACK_GLOBAL` (including operands fetched back out of
the memo). A legacy `torch.save` file holds several pickles back to back; all
of them are walked. For a zip-wrapped archive (the format `torch.save` has
used since PyTorch 1.6) the scanner reads the zip central directory and
examines the `data.pkl` at the root or one directory down
(`archive/data.pkl`).

Each import is classified:

- **Denylisted**: a code-execution, file-system, network or interpreter-escape
  primitive, such as `os.*`, `posix.*`, `nt.*`, `subprocess.*`, `runpy.*`,
  `webbrowser.*`, `socket.*`, `shutil.*`, `pty.*`, `sys.*`, `importlib.*`,
  `ctypes.*`, `pickle.*`, `marshal.*`, `builtins.eval` / `exec` / `compile` /
  `getattr` / `__import__` / `open`, `operator.attrgetter` /
  `methodcaller`, `types.CodeType` / `FunctionType`, and dotted protocol 4
  names that traverse into one of them (`posixpath` + `os.system`,
  `x.__globals__`).
- **Allowlisted**: what a weights-only state dict needs: the
  `torch._utils._rebuild_*` functions, `torch.*Storage`, `torch` dtypes,
  `torch.Size`, `torch.device`, `torch.nn.parameter.Parameter`,
  `collections.OrderedDict`, numpy's array and dtype reconstruction, and
  plain builtin types (`set`, `frozenset`, `bytearray`, `slice`, ...).
- **Anything else** is unknown: a full `nn.Module` pickle, a
  `TrainingArguments` object, a scikit-learn estimator.

Each finding names the import and how often it was referenced and called
(`REDUCE`, `NEWOBJ`, `OBJ`, `INST`), with counts of `REDUCE`, `BUILD`,
persistent ids and extension codes in the description.

### safetensors

The header is parsed with the same bounded reader that records the
safetensors summary in `artifact_metadata`. A finding is raised for a header
length that is zero, above the 8 MiB cap or past the end of the file, a
header that is not valid, a dtype the format does not define, `data_offsets`
outside the data region, two tensors whose bytes overlap, and bytes of the
data region that belong to no tensor (the reference loader refuses such a
file).

### GGUF

The scanner checks the magic and version (1 to 3), that the declared metadata
and tensor counts can fit in the file, and then walks every metadata key/value
(nested arrays included) and every tensor info against the file size: key
and tensor-name lengths, tensor rank, `general.alignment`, and tensor offsets
inside the data section. A `tokenizer.chat_template*` value larger than 64 KiB
is reported with its length; the template is Jinja that llama.cpp-based
runtimes execute.

## Findings

Every finding has `source = model-scanner` and its rule id in
`affected_component`.

| Rule id | Class | Severity | Meaning |
|---|---|---|---|
| `model.pickle.dangerous-global` | `malicious` | critical | A denylisted import. |
| `model.pickle.unresolved-global` | `policy` | high | A `STACK_GLOBAL` whose module or name the walk could not track as a string. |
| `model.pickle.unknown-global` | `policy` | medium | An import that is neither allowlisted nor denylisted (one finding per import, up to 64, then one summary). |
| `model.pickle.malformed` | `policy` | medium | Truncated stream, unknown opcode, stack underflow, missing memo entry, unsupported protocol, or a `.pt`-style file that is not a pickle at all. |
| `model.pickle.scan-limit` | `policy` | medium | A cap below was reached; the rest of the stream was not examined. The scan is marked `partial`. |
| `model.archive.malformed` | `policy` | medium | The zip could not be read, or its `data.pkl` is over the size cap. |
| `model.archive.no-pickle` | `policy` | low | A zip without a `data.pkl` where one is expected. |
| `model.safetensors.header-length` | `policy` | medium | Header length zero, over the cap, or past the end of the file. |
| `model.safetensors.invalid-header` | `policy` | medium | The JSON header is malformed. |
| `model.safetensors.unknown-dtype` | `policy` | medium | A dtype the format does not define. |
| `model.safetensors.offsets-out-of-range` | `policy` | medium | `data_offsets` outside the data region. |
| `model.safetensors.overlapping-offsets` | `policy` | medium | Two tensors share bytes. |
| `model.safetensors.unaccounted-bytes` | `policy` | low | A gap between tensors, or bytes after the last one. |
| `model.gguf.malformed` | `policy` | medium | Bad magic or version, a value or string past the end of the file, an unknown value type, an oversize key or tensor name, a rank above 4, a bad alignment, or a tensor offset past the data section. |
| `model.gguf.implausible-counts` | `policy` | medium | The declared counts cannot fit in the file (or exceed one million). |
| `model.gguf.scan-limit` | `policy` | medium | The header is larger than the cap. The scan is marked `partial`. |
| `model.gguf.large-chat-template` | `policy` | low | A chat template over 64 KiB. |

A `malicious` finding is graded critical, so every severity-based gate
(quarantine, `max_cve_severity` promotion rules) treats it as such.

## Limits

| Limit | Value |
|---|---|
| Pickle bytes walked per file or archive member | 64 MiB |
| Pickle opcodes walked | 10,000,000 |
| Pickle streams per file | 5 |
| Simulated stack values / memo entries | 500,000 / 262,144 |
| Tracked strings (for `STACK_GLOBAL` names) | 512 bytes each, 8 MiB total |
| Distinct imports recorded | 4,096 (denylisted imports are always kept) |
| Zip entries | 100,000 |
| safetensors header | 8 MiB |
| GGUF header walked | 128 MiB |
| GGUF metadata entries / tensor infos | 1,000,000 each |
| GGUF array elements | 64 Mi |

Tensor data is never read. Large artifacts are staged as a file-backed
memory map, and each parser touches only its bounded prefix.

## What it does not catch

- **Malicious weights.** Backdoored or poisoned weights, and prompt-level or
  trigger-phrase backdoors, are numbers in a valid file. No file-format check
  can see them.
- **Chat template content.** Only the size of a GGUF chat template is judged
  in this release, not its Jinja.
- **Proxied files.** Files served from a Remote `huggingface` repository are
  not judged on proxy fetch yet (scan-on-proxy for Hugging Face is #4097).
- **Other formats.** ONNX, Keras (`.h5`, `.keras`), TensorFlow SavedModel,
  NumPy `.npy`/`.npz` with object arrays, and compressed `joblib` files
  (which report `model.pickle.malformed`) are not inspected.
- **Nested archives.** Only a `data.pkl` at the root of the zip or one
  directory down is examined; other pickles in the archive (TorchScript
  `constants.pkl`, nested zips) are not.
- **joblib with inline arrays.** joblib writes raw numpy array bytes into the
  stream after the pickle opcodes that describe them, so such files can
  report `model.pickle.malformed` once the walk reaches the raw bytes. The
  imports before that point are still judged.
- **Allowlist misuse.** An allowlisted callable is not judged by its
  arguments; the allowlist mirrors what a `weights_only` load accepts.
