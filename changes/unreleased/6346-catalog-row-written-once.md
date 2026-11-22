---
section: Changed
issues: [#6346]
---
- **A PyPI, NuGet, Debian or nested-layout RPM upload, and a generic PUT of a package into a repository of those formats, writes its package catalog row once instead of twice** (#6346). The shared upload service registered the package in the catalog, then the format handler registered it again with the description and metadata it had parsed. The handler now tells the service it registers the row itself, so each upload makes two fewer database round trips and pool checkouts. The catalog contents are unchanged.
