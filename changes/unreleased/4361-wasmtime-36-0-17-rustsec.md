---
section: Security
issues: [#4361]
---
- **WASM plugin runtime updated to wasmtime 36.0.17** (#4361; RUSTSEC-2026-0321, RUSTSEC-2026-0322, RUSTSEC-2026-0323). A WASM plugin guest could get around its fuel limit through WASI preview 0 `poll_oneoff`, make the host allocate excessive memory when it had no stdio, or read uninitialized host memory through `fd_readdir`. All three are fixed upstream in 36.0.17; no configuration change is needed.
