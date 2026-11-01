---
section: Fixed
issues: [#5143]
---
- **A scanned `.crate` is no longer graded on the packages in its own bundled `Cargo.lock`** (#5143). Many published crates ship the author's `Cargo.lock`, and both engines cataloged it, so a crate such as `async-ctrlc@1.2.0` was blocked (403 on a `scan_on_proxy` Cargo remote) for advisories against `crossbeam-deque@0.7.3` and others that no consumer installs: Cargo never resolves a dependent against a dependency's lockfile. When a crate is scanned with its pinned coordinate, any `Cargo.lock` it ships is now removed from the scan workspace, so the crate is graded on its own name and version only. `cargo install --locked` still fetches each locked crate through the registry, where each is graded on its own coordinate. A vulnerable verdict already stored for a crate's digest is still reused until it expires (30 days) or the CVE scanner version changes.
