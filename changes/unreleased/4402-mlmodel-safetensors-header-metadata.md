---
section: Added
issues: [#4402, #2382]
---
- **`.safetensors` files uploaded to Mlmodel repositories now expose their tensor structure as artifact metadata** (#4402, #2382). After the upload commits, the server reads only the 8-byte header length and the JSON header (capped at 100 MB, as in the reference implementation) through ranged storage reads, never the tensor data, and records each tensor's dtype and shape, the total and per-dtype parameter counts, and the header's `__metadata__` map under `safetensors` in `artifact_metadata` (format `mlmodel`). It is returned in the `metadata` field of `GET /api/v1/repositories/{key}/artifacts/{path}` and `GET /api/v1/artifacts/{id}`, and by `GET /api/v1/artifacts/{id}/metadata`. A malformed header never fails the upload; the rejection reason is recorded as `safetensors_error` instead. Applies to generic `PUT`, multipart and chunked uploads; GGUF and ONNX are not parsed yet.
