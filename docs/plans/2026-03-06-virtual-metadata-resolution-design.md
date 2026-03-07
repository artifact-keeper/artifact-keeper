# Virtual Metadata Resolution Design

**Date:** 2026-03-06
**Issue:** #345 (expanded scope)
**Status:** Approved

## Problem

31 format handlers use the shared `resolve_virtual_download` helper for artifact downloads through virtual repositories. But metadata endpoints (package indexes, repo manifests, package info) each implement their own virtual member iteration logic. This creates duplicated code across 6 handlers. Additionally, 2 handlers (helm, rubygems) support virtual downloads but are missing virtual metadata resolution entirely.

## Design

### Two New Helpers in `proxy_helpers.rs`

**`resolve_virtual_metadata`** (first-match mode):

```rust
pub async fn resolve_virtual_metadata<F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    transform: F,
) -> Result<Response, Response>
where
    F: Fn(Bytes, &str) -> Fut,
    Fut: Future<Output = Result<Response, Response>>,
```

Iterates members by priority. Returns the first successful transformed response. Failed members are skipped with a warning log. Returns NOT_FOUND when all members fail. Used by: npm, pypi, hex, rubygems `gem_info`.

**`collect_virtual_metadata`** (merge-all mode):

```rust
pub async fn collect_virtual_metadata<T, F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    extract: F,
) -> Result<Vec<(String, T)>, Response>
where
    F: Fn(Bytes, &str) -> Fut,
    Fut: Future<Output = Result<T, Response>>,
```

Collects parsed data from ALL members (best-effort, warns on failures). Returns vec of `(member_repo_key, T)` pairs for the caller to merge. Returns empty vec only when all members fail. Used by: conda (repodata, channeldata), cran, helm, rubygems `specs_index`.

Both functions reuse `fetch_virtual_members` and existing proxy fetch internals.

### Handler Migrations

#### First-match handlers (use `resolve_virtual_metadata`)

- **npm.rs** `get_package_metadata`: Replace ~55 lines. Transform callback calls `rewrite_npm_tarball_urls`.
- **pypi.rs** `simple_project`: Replace ~33 lines. Transform is pass-through with correct content-type.
- **hex.rs** `package_info`: Replace manual iteration. Transform is pass-through (protobuf blob).

#### Merge-all handlers (use `collect_virtual_metadata`)

- **conda.rs** `build_virtual_repodata`: Replace ~70 lines. Extract parses repodata JSON. Caller merges with existing `merge_package_maps`.
- **conda.rs** `build_virtual_channeldata`: Replace ~53 lines. Same pattern, different JSON structure.
- **cran.rs** `package_index`: Replace manual iteration. Extract parses PACKAGES text. Caller concatenates.

#### New virtual metadata support

- **helm.rs** `index_yaml`: Add `collect_virtual_metadata`. Extract parses index.yaml. Caller merges chart entries.
- **rubygems.rs** `gem_info`: Add `resolve_virtual_metadata` (first-match, pass-through).
- **rubygems.rs** `specs_index` / `latest_specs_index`: Add `collect_virtual_metadata`. Extract parses Marshal'd specs. Caller merges gem lists.

#### Untouched (caching wrapper)

- **cargo.rs** `try_virtual_index`: Keeps its caching wrapper. Refactored internally to call `resolve_virtual_metadata` for member iteration.

### Estimated Impact

- ~200 lines of duplicated iteration logic removed
- ~80 lines added for two new helpers
- ~60 lines added for helm/rubygems virtual support
- Net reduction of ~60 lines

## Testing

### Unit Tests (proxy_helpers.rs)

- `resolve_virtual_metadata` returns first match by priority
- `resolve_virtual_metadata` skips failed members, tries next
- `resolve_virtual_metadata` returns NOT_FOUND when all fail
- `collect_virtual_metadata` collects from all successful members
- `collect_virtual_metadata` skips failed members (best-effort)
- `collect_virtual_metadata` returns empty vec when all fail

### Existing Tests

All existing handler tests pass unchanged (behavior preserved, only internals refactored).

### New Handler Tests

- Helm `index_yaml` merges entries from two virtual members
- RubyGems `gem_info` resolves through virtual members
- RubyGems `specs_index` merges gem lists from virtual members

### E2E Tests (new: `scripts/native-tests/test-virtual-metadata.sh`)

For each format: create two hosted repos, publish packages to each, create a virtual repo pointing at both, hit the metadata endpoint, verify merged/resolved results.

Formats covered:
- **npm**: `GET /npm/virtual-repo/pkg-name` returns metadata with tarballs from both members
- **pypi**: `GET /pypi/virtual-repo/simple/pkg/` lists files from both members
- **helm**: `GET /helm/virtual-repo/index.yaml` contains charts from both members
- **conda**: `GET /conda/virtual-repo/linux-64/repodata.json` merges packages from both members

RubyGems, hex, cran, cargo E2E deferred (harder to set up with native clients).

## Decisions

- **Two functions, not one**: First-match and merge-all are different enough that a single function with a mode flag would be awkward. Two clear functions with distinct return types.
- **No caching in helpers**: Cargo is the only handler that needs caching. It wraps the helper rather than baking caching into the shared code.
- **Best-effort on failures**: Failed members are skipped with a warning log, matching `resolve_virtual_download` behavior.
