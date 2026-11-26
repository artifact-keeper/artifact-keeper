---
section: Fixed
issues: [#6402]
---
- **The root simple index of a Remote PyPI repository no longer lists the proxy cache in object storage on every request** (#6402). Each `GET /pypi/{repo}/simple/` listed the whole `simple/` cache prefix to find the projects the proxy had served, a paginated LIST per 1000 keys on S3, GCS and Azure, paid on every request and per Remote member of a virtual. The names now come from the proxy cache catalog in one query. A repository whose cache predates the catalog still lists storage until it caches a project index again
