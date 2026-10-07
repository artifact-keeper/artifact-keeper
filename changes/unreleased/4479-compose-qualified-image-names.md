---
section: Fixed
issues: [#4479]
---
- **Every image in the stock `docker-compose.yml` now names its registry** (#4479). `postgres:18-alpine`, `alpine:3.24`, `caddy:2-alpine`, `opensearchproject/opensearch` and the two Dependency-Track images were short names, which the container engine resolves per host: under podman's default `short-name-mode = "enforcing"` the `db` service ran a locally cached `ghcr.io/artifact-keeper/ci-mirror/postgres:18-alpine` instead of Docker Hub's image, and hosts with several unqualified search registries need an alias or a TTY prompt that compose does not have. They are now `docker.io/library/...` and `docker.io/<namespace>/...` with unchanged tags, so every host pulls the same image.
