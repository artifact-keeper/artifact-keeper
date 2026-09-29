---
section: Security
issues: [#4332]
---
- **WASM plugin runtime updated to wasmtime 36.0.16** (#4332; RUSTSEC-2026-0314, RUSTSEC-2026-0316). A WASM plugin guest could allocate past its host-call fuel limit through dynamic record lifting, or panic the host through a filesystem datetime overflow in WASI. Both are fixed upstream in 36.0.16; no configuration change is needed.
