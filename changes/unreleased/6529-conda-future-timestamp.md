---
section: Added
issues: [#6529]
---
- **Conda uploads whose builder `timestamp` is in the future are flagged, or refused when configured** (#6529). CEP 47 asks channel servers to flag or reject such packages, because clients without `indexed_timestamp` fall back to that builder-controlled value for their cooldown. A hosted upload whose `info/index.json` `timestamp` is later than now plus `CONDA_FUTURE_TIMESTAMP_SKEW_SECS` (default 600) is accepted by default, with an `X-Conda-Timestamp-Warning` header on the 201, a `package.future_timestamp` block in the upload's `ARTIFACT_UPLOADED` audit row, a warning in the log and the `ak_conda_future_timestamp_total{repository, action="flagged"}` metric. With `CONDA_FUTURE_TIMESTAMP=reject` the upload is refused with 400 and counted as `action="rejected"`; `off` disables the check. Timestamps in seconds (older packages) are compared as seconds. The default does not change what an existing publisher sees, apart from the header.
