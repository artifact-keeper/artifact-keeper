---
section: Changed
issues: [#6181]
---
- **A commit no longer recompiles the whole backend crate in a dev checkout; a build from source now reports its commit only when `GIT_SHA` is set** (#6181). `backend/build.rs` ran `git rev-parse HEAD` and watched HEAD, the branch ref and `packed-refs`, so every commit, checkout or rebase reran it with a new `GIT_SHA` (and a new build-clock reading), and Cargo recompiled the lib, every test harness and both binaries for a change that touched no source. The commit now comes only from the `GIT_SHA` build environment variable, and nothing watches git.

  Shipped artifacts report exactly what they did before: the Docker images already pass `GIT_SHA` as a build argument, and the release binaries now set it from the commit they build. A local or source build that does not set it reports `commit` as absent in `/health` and `git=unknown` in the startup log, the same as an image built without the argument; to keep the old behaviour, build with `GIT_SHA=$(git rev-parse HEAD) cargo build ...`. The Debian `Release` `Date:` floor is still the build time.
