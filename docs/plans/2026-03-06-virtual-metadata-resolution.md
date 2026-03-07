# Virtual Metadata Resolution Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract shared virtual metadata resolution helpers and fill gaps in helm/rubygems/cran handlers.

**Architecture:** Two new generic async functions in proxy_helpers.rs (`resolve_virtual_metadata` for first-match, `collect_virtual_metadata` for merge-all) that encapsulate the fetch-members + iterate + proxy pattern. Each format handler provides a transform/extract callback. Handlers that currently duplicate this logic get migrated; handlers missing it get virtual support added.

**Tech Stack:** Rust, axum, sqlx, tokio, bytes, serde_json, serde_yaml

---

### Task 1: Add `resolve_virtual_metadata` helper with tests

**Files:**
- Modify: `backend/src/api/handlers/proxy_helpers.rs:116` (after `resolve_virtual_download`)
- Test: same file, `mod tests` section

**Step 1: Write the failing test**

Add to the test module in `proxy_helpers.rs`:

```rust
// ── resolve_virtual_metadata tests ──────────────────────────────

#[test]
fn test_resolve_virtual_metadata_signature_compiles() {
    // Compile-time check that the function signature exists and is correct.
    // Actual async integration tests require a DB; this validates the API shape.
    fn _assert_send<T: Send>(_t: T) {}
    // We can't call the async fn without a DB, but we can reference it
    let _fn_ptr: fn(
        &PgPool,
        Option<&ProxyService>,
        Uuid,
        &str,
        fn(Bytes, String) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Response>> + Send>>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Response>> + Send>> ;
    // This test passes if it compiles
}
```

Wait - that's overly complex for a compile check. Instead, write the function first (TDD at the integration level since these are async DB functions).

**Step 1: Write `resolve_virtual_metadata` function**

Add after `resolve_virtual_download` (after line 116) in `proxy_helpers.rs`:

```rust
/// Resolve virtual repository members for a metadata endpoint (first-match).
///
/// Iterates members by priority. For each member, tries to proxy-fetch the
/// metadata at `path`, then passes the bytes through `transform` to build
/// the response. Returns the first successful transformed response.
///
/// For hosted/local members, the caller should handle local data before
/// calling this function (or include local lookup in the transform).
pub async fn resolve_virtual_metadata<F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    transform: F,
) -> Result<Response, Response>
where
    F: Fn(Bytes, String) -> Fut,
    Fut: std::future::Future<Output = Result<Response, Response>>,
{
    let members = fetch_virtual_members(db, virtual_repo_id).await?;

    if members.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Virtual repository has no members").into_response());
    }

    for member in &members {
        if member.repo_type == RepositoryType::Remote {
            if let (Some(proxy), Some(upstream_url)) =
                (proxy_service, member.upstream_url.as_deref())
            {
                match proxy_fetch(proxy, member.id, &member.key, upstream_url, path).await {
                    Ok((bytes, _content_type)) => {
                        match transform(bytes, member.key.clone()).await {
                            Ok(response) => return Ok(response),
                            Err(_) => {
                                tracing::warn!(
                                    member = %member.key,
                                    path,
                                    "Virtual metadata transform failed, trying next member"
                                );
                            }
                        }
                    }
                    Err(_) => {
                        tracing::debug!(
                            member = %member.key,
                            path,
                            "Virtual metadata proxy fetch failed, trying next member"
                        );
                    }
                }
            }
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        "Metadata not found in any member repository",
    )
        .into_response())
}
```

**Step 2: Run `cargo test --workspace --lib proxy_helpers` to verify existing tests still pass**

Run: `cargo test --workspace --lib proxy_helpers`
Expected: All existing proxy_helpers tests PASS

**Step 3: Commit**

```bash
git add backend/src/api/handlers/proxy_helpers.rs
git commit -m "feat: add resolve_virtual_metadata helper to proxy_helpers"
```

---

### Task 2: Add `collect_virtual_metadata` helper

**Files:**
- Modify: `backend/src/api/handlers/proxy_helpers.rs` (after `resolve_virtual_metadata`)

**Step 1: Write `collect_virtual_metadata` function**

Add after `resolve_virtual_metadata`:

```rust
/// Collect metadata from all virtual repository members (merge-all).
///
/// Iterates all members, proxy-fetching metadata at `path` for remote members.
/// Each successful fetch is passed through `extract` to parse into type `T`.
/// Returns a vec of `(member_key, parsed_data)` pairs.
///
/// Failed members are skipped with a warning (best-effort). Returns an error
/// only if fetching the member list itself fails.
pub async fn collect_virtual_metadata<T, F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    extract: F,
) -> Result<Vec<(String, T)>, Response>
where
    F: Fn(Bytes, String) -> Fut,
    Fut: std::future::Future<Output = Result<T, Response>>,
{
    let members = fetch_virtual_members(db, virtual_repo_id).await?;
    let mut results = Vec::new();

    for member in &members {
        if member.repo_type == RepositoryType::Remote {
            if let (Some(proxy), Some(upstream_url)) =
                (proxy_service, member.upstream_url.as_deref())
            {
                match proxy_fetch(proxy, member.id, &member.key, upstream_url, path).await {
                    Ok((bytes, _content_type)) => {
                        match extract(bytes, member.key.clone()).await {
                            Ok(data) => results.push((member.key.clone(), data)),
                            Err(_) => {
                                tracing::warn!(
                                    member = %member.key,
                                    path,
                                    "Virtual metadata extract failed, skipping member"
                                );
                            }
                        }
                    }
                    Err(_) => {
                        tracing::warn!(
                            member = %member.key,
                            path,
                            "Virtual metadata proxy fetch failed, skipping member"
                        );
                    }
                }
            }
        }
    }

    Ok(results)
}
```

**Step 2: Run tests**

Run: `cargo test --workspace --lib proxy_helpers`
Expected: PASS

**Step 3: Commit**

```bash
git add backend/src/api/handlers/proxy_helpers.rs
git commit -m "feat: add collect_virtual_metadata helper to proxy_helpers"
```

---

### Task 3: Migrate npm.rs virtual metadata

**Files:**
- Modify: `backend/src/api/handlers/npm.rs:209-265`

**Step 1: Read current `get_package_metadata` virtual section (lines 209-265)**

Understand the existing pattern: fetches members, checks local artifact count, proxies remote members, rewrites tarball URLs.

**Step 2: Replace the virtual member iteration with `resolve_virtual_metadata`**

Replace the manual `fetch_virtual_members` + for loop (lines ~209-265) with:

```rust
if repo.repo_type == RepositoryType::Virtual {
    let base_url = /* extract from request */;
    let repo_key = repo.key.clone();
    return proxy_helpers::resolve_virtual_metadata(
        &state.db,
        state.proxy_service.as_ref(),
        repo.id,
        package_name,
        |bytes, _member_key| {
            let base_url = base_url.clone();
            let repo_key = repo_key.clone();
            async move {
                let mut json: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|_| (StatusCode::BAD_GATEWAY, "Invalid JSON from upstream").into_response())?;
                rewrite_npm_tarball_urls(&mut json, &base_url, &repo_key);
                Ok(axum::Json(json).into_response())
            }
        },
    ).await;
}
```

Adapt variable names to match the actual code context.

**Step 3: Run npm-related tests**

Run: `cargo test --workspace --lib npm`
Expected: PASS

**Step 4: Commit**

```bash
git add backend/src/api/handlers/npm.rs
git commit -m "refactor: migrate npm metadata to resolve_virtual_metadata helper"
```

---

### Task 4: Migrate pypi.rs virtual metadata

**Files:**
- Modify: `backend/src/api/handlers/pypi.rs:246-279`

**Step 1: Read current `simple_project` virtual section (lines 246-279)**

**Step 2: Replace with `resolve_virtual_metadata`**

```rust
if repo.repo_type == RepositoryType::Virtual {
    let normalized = /* normalize project name */;
    let upstream_path = format!("simple/{}/", normalized);
    return proxy_helpers::resolve_virtual_metadata(
        &state.db,
        state.proxy_service.as_ref(),
        repo.id,
        &upstream_path,
        |bytes, _member_key| async move {
            Ok((
                StatusCode::OK,
                [("content-type", "text/html; charset=utf-8")],
                bytes,
            ).into_response())
        },
    ).await;
}
```

**Step 3: Run pypi tests**

Run: `cargo test --workspace --lib pypi`
Expected: PASS

**Step 4: Commit**

```bash
git add backend/src/api/handlers/pypi.rs
git commit -m "refactor: migrate pypi metadata to resolve_virtual_metadata helper"
```

---

### Task 5: Migrate hex.rs virtual metadata

**Files:**
- Modify: `backend/src/api/handlers/hex.rs:159-190`

**Step 1: Read current `package_info` virtual section (lines 159-190)**

**Step 2: Replace with `resolve_virtual_metadata`**

The hex handler proxies `packages/{name}` and returns the protobuf blob as-is.

```rust
if repo.repo_type == RepositoryType::Virtual {
    let upstream_path = format!("packages/{}", name);
    return proxy_helpers::resolve_virtual_metadata(
        &state.db,
        state.proxy_service.as_ref(),
        repo.id,
        &upstream_path,
        |bytes, _member_key| async move {
            Ok((StatusCode::OK, bytes).into_response())
        },
    ).await;
}
```

**Step 3: Run hex tests**

Run: `cargo test --workspace --lib hex`
Expected: PASS

**Step 4: Commit**

```bash
git add backend/src/api/handlers/hex.rs
git commit -m "refactor: migrate hex metadata to resolve_virtual_metadata helper"
```

---

### Task 6: Migrate conda.rs virtual repodata

**Files:**
- Modify: `backend/src/api/handlers/conda.rs` - `build_virtual_repodata` (lines 2212-2283)

**Step 1: Read current `build_virtual_repodata` function**

**Step 2: Replace remote member iteration with `collect_virtual_metadata`**

Keep the local member artifact queries. Replace the remote proxy loop with:

```rust
let upstream_path = format!("{}/repodata.json", subdir);
let remote_data = proxy_helpers::collect_virtual_metadata(
    db,
    proxy_service,
    virtual_repo_id,
    &upstream_path,
    |bytes, _member_key| async move {
        parse_upstream_repodata(&bytes)
            .map_err(|_| (StatusCode::BAD_GATEWAY, "Failed to parse upstream repodata").into_response())
    },
).await?;

for (_member_key, (pkgs, conda_pkgs)) in &remote_data {
    merge_package_maps(&mut merged_packages, pkgs);
    merge_package_maps(&mut merged_conda_packages, conda_pkgs);
}
```

Adjust to also handle local members as before (query DB for hosted member artifacts).

**Step 3: Run conda tests**

Run: `cargo test --workspace --lib conda`
Expected: PASS

**Step 4: Commit**

```bash
git add backend/src/api/handlers/conda.rs
git commit -m "refactor: migrate conda repodata to collect_virtual_metadata helper"
```

---

### Task 7: Migrate conda.rs virtual channeldata

**Files:**
- Modify: `backend/src/api/handlers/conda.rs` - `build_virtual_channeldata` (lines 2286-2339)

**Step 1: Read current `build_virtual_channeldata` function**

**Step 2: Replace remote member iteration with `collect_virtual_metadata`**

Same pattern as repodata but for channeldata.json:

```rust
let remote_data = proxy_helpers::collect_virtual_metadata(
    db,
    proxy_service,
    virtual_repo_id,
    "channeldata.json",
    |bytes, _member_key| async move {
        parse_upstream_channeldata(&bytes)
            .map_err(|_| (StatusCode::BAD_GATEWAY, "Failed to parse upstream channeldata").into_response())
    },
).await?;

for (_member_key, packages) in &remote_data {
    // merge into channeldata_packages map
}
```

**Step 3: Run conda tests**

Run: `cargo test --workspace --lib conda`
Expected: PASS

**Step 4: Commit**

```bash
git add backend/src/api/handlers/conda.rs
git commit -m "refactor: migrate conda channeldata to collect_virtual_metadata helper"
```

---

### Task 8: Refactor cargo.rs `try_virtual_index` internals

**Files:**
- Modify: `backend/src/api/handlers/cargo.rs` - `try_virtual_index` (lines 963-1080)

**Step 1: Read current `try_virtual_index` function**

Note: This function has its own caching layer. Keep the cache wrapper, refactor only the inner member iteration to use `resolve_virtual_metadata`.

**Step 2: Extract the proxy-fetch portion into a `resolve_virtual_metadata` call**

The cargo handler is special: it checks local artifacts first (builds index entries from DB), then falls back to proxy. Keep the local artifact lookup. Replace the proxy fallback loop with `resolve_virtual_metadata`. The cache check/store wraps the whole thing.

**Step 3: Run cargo tests**

Run: `cargo test --workspace --lib cargo`
Expected: PASS

**Step 4: Commit**

```bash
git add backend/src/api/handlers/cargo.rs
git commit -m "refactor: use resolve_virtual_metadata in cargo index resolution"
```

---

### Task 9: Add virtual metadata support to helm.rs

**Files:**
- Modify: `backend/src/api/handlers/helm.rs` - `index_yaml` (lines 100-199)

**Step 1: Read current `index_yaml` function**

Currently queries only `repo.id` for artifacts. No virtual member iteration.

**Step 2: Add virtual repo branch**

After the repo lookup, before the artifact query, add:

```rust
if repo.repo_type == RepositoryType::Virtual {
    // Collect index.yaml from all members and merge chart entries
    let remote_indexes = proxy_helpers::collect_virtual_metadata(
        &state.db,
        state.proxy_service.as_ref(),
        repo.id,
        "index.yaml",
        |bytes, _member_key| async move {
            // Parse upstream index.yaml into chart entries
            let yaml_str = String::from_utf8(bytes.to_vec())
                .map_err(|_| (StatusCode::BAD_GATEWAY, "Invalid UTF-8 from upstream").into_response())?;
            let index: serde_yaml::Value = serde_yaml::from_str(&yaml_str)
                .map_err(|_| (StatusCode::BAD_GATEWAY, "Invalid YAML from upstream").into_response())?;
            Ok(index)
        },
    ).await?;

    // Also collect local artifacts from hosted members
    let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
    let mut all_charts: BTreeMap<String, Vec<ChartEntry>> = BTreeMap::new();

    // Merge remote member charts
    for (_member_key, index_yaml) in &remote_indexes {
        if let Some(entries) = index_yaml.get("entries").and_then(|e| e.as_mapping()) {
            for (name, versions) in entries {
                if let (Some(name_str), Some(versions_seq)) = (name.as_str(), versions.as_sequence()) {
                    // Parse each version entry and add to all_charts
                    // ... format-specific merge logic
                }
            }
        }
    }

    // Query local member artifacts
    for member in &members {
        if member.repo_type != RepositoryType::Remote {
            // Query artifacts for this member and build chart entries
            // Same SQL as the non-virtual path but with member.id
        }
    }

    let yaml_output = generate_index_yaml(all_charts);
    return Ok((
        StatusCode::OK,
        [("content-type", "application/x-yaml")],
        yaml_output,
    ).into_response());
}
```

Adapt to use the existing `generate_index_yaml` function and `ChartEntry` struct.

**Step 3: Write a unit test for helm virtual index merging**

Add a test that verifies chart entries from two sources are merged correctly.

**Step 4: Run helm tests**

Run: `cargo test --workspace --lib helm`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/src/api/handlers/helm.rs
git commit -m "feat: add virtual metadata support to helm index.yaml"
```

---

### Task 10: Add virtual metadata support to rubygems.rs

**Files:**
- Modify: `backend/src/api/handlers/rubygems.rs` - `gem_info` (lines 109-183), `specs_index` (lines 549-602), `latest_specs_index` (lines 608-662)

**Step 1: Add virtual support to `gem_info` (first-match)**

After the local artifact query returns None, before returning 404:

```rust
if repo.repo_type == RepositoryType::Virtual && artifact.is_none() {
    return proxy_helpers::resolve_virtual_metadata(
        &state.db,
        state.proxy_service.as_ref(),
        repo.id,
        &format!("api/v1/gems/{}.json", gem_name),
        |bytes, _member_key| async move {
            Ok((
                StatusCode::OK,
                [("content-type", "application/json")],
                bytes,
            ).into_response())
        },
    ).await;
}
```

**Step 2: Add virtual support to `specs_index` (merge-all)**

After the local artifact query, if virtual repo, collect from members:

```rust
if repo.repo_type == RepositoryType::Virtual {
    let remote_specs = proxy_helpers::collect_virtual_metadata(
        &state.db,
        state.proxy_service.as_ref(),
        repo.id,
        "specs.4.8.gz",
        |bytes, _member_key| async move {
            // Decompress gzip, parse JSON array of [name, version, platform] tuples
            // Return as Vec<(String, String)>
            // ...
            Ok(parsed_specs)
        },
    ).await?;

    // Merge remote specs with local artifacts
    // Deduplicate by (name, version)
    // Compress and return
}
```

**Step 3: Add virtual support to `latest_specs_index`**

Same pattern as `specs_index` but with `latest_specs.4.8.gz` and deduplication keeps only latest version per gem.

**Step 4: Run rubygems tests**

Run: `cargo test --workspace --lib rubygems`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/src/api/handlers/rubygems.rs
git commit -m "feat: add virtual metadata support to rubygems endpoints"
```

---

### Task 11: Add virtual metadata support to cran.rs

**Files:**
- Modify: `backend/src/api/handlers/cran.rs` - `package_index` (lines 114-127)

**Step 1: Read current `package_index` and `build_source_index` functions**

Currently no virtual support at all.

**Step 2: Add virtual repo branch to `package_index`**

```rust
if repo.repo_type == RepositoryType::Virtual {
    let remote_indexes = proxy_helpers::collect_virtual_metadata(
        &state.db,
        state.proxy_service.as_ref(),
        repo.id,
        "src/contrib/PACKAGES",
        |bytes, _member_key| async move {
            String::from_utf8(bytes.to_vec())
                .map_err(|_| (StatusCode::BAD_GATEWAY, "Invalid UTF-8").into_response())
        },
    ).await?;

    // Also build local index from hosted members
    let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
    let mut combined = String::new();

    for member in &members {
        if member.repo_type != RepositoryType::Remote {
            let local_index = build_source_index(&state.db, member.id).await?;
            combined.push_str(&local_index);
        }
    }

    for (_key, remote_index) in remote_indexes {
        combined.push_str(&remote_index);
    }

    return Ok((StatusCode::OK, [("content-type", "text/plain")], combined).into_response());
}
```

**Step 3: Run cran tests**

Run: `cargo test --workspace --lib cran`
Expected: PASS

**Step 4: Commit**

```bash
git add backend/src/api/handlers/cran.rs
git commit -m "feat: add virtual metadata support to CRAN package index"
```

---

### Task 12: E2E test script

**Files:**
- Create: `scripts/native-tests/test-virtual-metadata.sh`

**Step 1: Write the E2E test script**

```bash
#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

# Helper: create a repository via API
create_repo() { ... }

# Helper: create a virtual repo with two members
create_virtual_repo() { ... }

# Test 1: npm virtual metadata
echo "=== npm virtual metadata ==="
# Create npm-hosted-1, npm-hosted-2, npm-virtual
# Publish a package to each hosted repo
# GET /npm/npm-virtual/pkg-name -> verify response has versions from both
npm_test() { ... }

# Test 2: pypi virtual metadata
echo "=== pypi virtual metadata ==="
# Create pypi repos, publish wheels, check simple index
pypi_test() { ... }

# Test 3: helm virtual metadata
echo "=== helm virtual metadata ==="
# Create helm repos, push charts, check index.yaml merges
helm_test() { ... }

# Test 4: conda virtual metadata
echo "=== conda virtual metadata ==="
# Create conda repos, push packages, check repodata.json merges
conda_test() { ... }

npm_test
pypi_test
helm_test
conda_test

echo "All virtual metadata tests passed"
```

**Step 2: Make executable and verify it runs (against running backend)**

Run: `chmod +x scripts/native-tests/test-virtual-metadata.sh`

**Step 3: Commit**

```bash
git add scripts/native-tests/test-virtual-metadata.sh
git commit -m "test: add E2E virtual metadata resolution tests"
```

---

### Task 13: Final verification and PR

**Step 1: Run full lint and test suite**

```bash
cargo fmt --check
cargo clippy --workspace
cargo test --workspace --lib
```

Expected: All pass, no warnings

**Step 2: Create PR**

```bash
git push -u origin feat/virtual-metadata-helpers
gh pr create --title "feat: shared virtual metadata resolution helpers" --body "$(cat <<'EOF'
## Summary
- Add `resolve_virtual_metadata` (first-match) and `collect_virtual_metadata` (merge-all) helpers to proxy_helpers.rs
- Migrate npm, pypi, hex, conda (repodata + channeldata), cargo to use shared helpers
- Add virtual metadata support to helm (index.yaml), rubygems (gem_info, specs_index, latest_specs_index), and CRAN (PACKAGES)
- Add E2E test script for virtual metadata across npm, pypi, helm, conda

## Context
Closes #345. Expanded scope to cover all handlers with virtual metadata patterns and fill gaps where virtual metadata was missing.

## Test plan
- [ ] `cargo test --workspace --lib` passes
- [ ] `cargo clippy --workspace` clean
- [ ] E2E: `scripts/native-tests/test-virtual-metadata.sh` passes against local stack
- [ ] Manual: create virtual repo in UI, verify metadata endpoints merge results
EOF
)"
```
