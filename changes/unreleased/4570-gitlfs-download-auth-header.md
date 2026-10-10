---
section: Fixed
issues: [#4570]
---
- **`git lfs pull` from a private Git LFS repository no longer hangs on 401** (#4570). The batch response marked download actions `authenticated: true` but sent an empty `header` map, so git-lfs fetched each object without credentials and retried the 401 forever. Download actions now carry the caller's `Authorization` header, the same way upload and verify actions already did.
