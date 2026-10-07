---
section: Fixed
issues: [#4555]
---
- **A conda upload whose subdir disagrees with the package's own `info/index.json` is refused, and a POST without `X-Conda-Subdir` files the package under its own subdir** (#4555). The upload took the subdir from the PUT path or the `X-Conda-Subdir` header (defaulting to `noarch`) and never compared it with the package, so a `linux-64` build POSTed without the header was published as `noarch`, offered to every platform, and broke on the ones it was not built for. The package's `index.json` subdir is now authoritative: a PUT path or header that names a different subdir gets `400` naming both values, and a POST without the header uses the package's subdir. A package whose `index.json` declares no subdir keeps the previous behaviour.
