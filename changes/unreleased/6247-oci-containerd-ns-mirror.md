---
section: Added
issues: [#6247]
---
- **OCI pulls through a containerd registry mirror (`/v2/<image>/...?ns=<registry>`) are served by the Remote for that registry** (#6247). containerd's `hosts.toml` mirrors (and so Talos, k3s, RKE2 and kind nodes) send a mirror pull without a repository key and name the upstream registry in the `ns` query parameter. A read whose path names no repository is now routed by `ns` to the one OCI Remote whose upstream URL is that registry. With `AK_DEFAULT_DOCKER_MIRROR_REPO` set, docker.io reads keep going to that repository as before. Otherwise a registry that no Remote proxies, or several do, is answered as an unknown repository; a registry other than docker.io never falls through to the Docker Hub mirror. Requests without `ns`, paths that name a repository, and writes are unchanged.
