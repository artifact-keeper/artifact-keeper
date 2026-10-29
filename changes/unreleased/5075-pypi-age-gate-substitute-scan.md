---
section: Fixed
issues: [#5075]
---
- **PyPI: the age gate's last-known-good substitute is served through the scan gate on a Remote that scans on proxy** (#5075). When the download age gate withholds a young version, a PyPI Remote answers with the newest older version it holds. That substitute was served through the plain proxy path (presigned redirect, cache stream or upstream fetch) while every other distribution download of the repository went through the scan-on-proxy gate. It now goes through the same gate as a requested distribution, on the direct route and for a Remote member of a Virtual repository (under the stricter-of-two policy): a stored blocking verdict refuses it with `403`, `fail_closed` withholds it with `423` until it is scanned, and `fail_open` serves it `pending`. Repositories that do not scan on proxy are unchanged.
