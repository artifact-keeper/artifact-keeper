---
section: Fixed
issues: [#5826]
---
- **The backend no longer recompiles on every build in a git worktree** ([#5826]). The build script watched `../.git/HEAD` to refresh the embedded `GIT_SHA`. In a linked worktree `.git` is a file, so that path never exists, and cargo re-ran the build script and recompiled the backend crate on every invocation. The script now asks git where HEAD, the current branch's ref and `packed-refs` live (`git rev-parse --git-path`), and watches only the ones that exist. A commit now also refreshes `GIT_SHA`; before, only a checkout did. Nothing git-related is emitted when git or the work tree is unavailable (a source tarball or a Docker build context) or when `GIT_SHA` is set.
