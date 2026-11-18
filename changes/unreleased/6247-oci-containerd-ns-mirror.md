---
section: Added
issues: [#6247]
---
- **OCI pulls through a containerd registry mirror (`/v2/<image>/...?ns=<registry>`) are served by the Remote for that registry** (#6247). containerd's `hosts.toml` mirrors (and so Talos, k3s, RKE2 and kind nodes) send a mirror pull without a repository key and name the upstream registry in the `ns` query parameter. A read whose path names no repository is now routed by `ns` to the one OCI Remote whose upstream URL is that registry, or, for docker.io with no such Remote, to `AK_DEFAULT_DOCKER_MIRROR_REPO`. A registry no Remote proxies, or several do, is answered as an unknown repository and never falls through to the Docker Hub mirror. Requests without `ns`, paths that name a repository, and writes are unchanged.
