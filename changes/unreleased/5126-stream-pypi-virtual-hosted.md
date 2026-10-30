---
section: Fixed
issues: [#5126]
---
- **Hosted members of a PyPI virtual are streamed instead of read into memory when no presigned redirect is available** (#5126). On filesystem storage, or S3 without presigned downloads, serving a wheel or sdist through a virtual repository buffered the whole stored object per concurrent request. The shared local serve now opens the object as a stream, keeping memory bounded, with the existing stored-object integrity verification applied before the headers for small objects and while streaming for large ones.
