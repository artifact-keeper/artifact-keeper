# Maven Spec Compliance Audit - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring our Maven repository implementation to 100% compliance with the Maven Repository Layout spec, Maven Resolver behavior, and Maven Central conventions.

**Architecture:** Four independent work streams that can execute in parallel. Team 1 (wire format) and Team 2 (metadata engine) share `maven.rs` but touch different sections. Team 3 (SNAPSHOT/storage) touches GAV grouping and virtual repos. Team 4 (tests) validates everything. Teams 1-3 produce code; Team 4 produces tests that cover it all.

**Tech Stack:** Rust (axum, sqlx, sha2, sha1, md5), PostgreSQL, existing proxy_helpers infrastructure.

**Spec:** `docs/superpowers/specs/2026-03-24-maven-compliance-audit.md`

**SQLx Note:** This project uses `SQLX_OFFLINE=true` with cached query metadata in `.sqlx/`. Any task that modifies a `sqlx::query!()` or `sqlx::query_scalar!()` macro call (changing SELECT columns, INSERT parameters, removing ORDER BY, etc.) **must** regenerate the offline cache before committing:

```bash
# Requires local PostgreSQL running at localhost:30432
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo sqlx prepare --workspace
git add .sqlx/
```

Tasks 1.3, 1.4, and 2.2 modify `sqlx::query!()` calls and must include this step.

**Deferred to follow-up:** The following spec items are intentionally deferred from this plan. They are lower-priority or require infrastructure that doesn't exist yet. Track them as separate issues after this plan completes:
- M2: SNAPSHOT version-level metadata generation (P2)
- L5: Non-unique SNAPSHOT support (P3)
- SNAPSHOT cleanup/retention policies (P3)
- Expect-Continue verification (P3)
- Multi-client E2E matrix with Maven 3.8/3.9/4.0 and Gradle 8.x (P1, requires Docker test infra)

---

## Team 1: Protocol and Wire Format

### Task 1.1: Fix Content-Type for POM, metadata, and .asc files (C5, M5)

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:200-208` (content_type_for_path)
- Modify: `backend/src/api/handlers/maven.rs:1202-1245` (content_type tests)

- [ ] **Step 1: Update existing content_type tests to expect spec-correct values**

The tests currently assert `application/xml`. Update them to match Maven Central:

```rust
// In mod tests:

#[test]
fn test_content_type_pom() {
    assert_eq!(content_type_for_path("artifact.pom"), "text/xml");
}

#[test]
fn test_content_type_xml() {
    assert_eq!(content_type_for_path("maven-metadata.xml"), "text/xml");
}

// Add new tests:

#[test]
fn test_content_type_asc() {
    assert_eq!(content_type_for_path("artifact.jar.asc"), "text/plain");
}

#[test]
fn test_content_type_ear() {
    assert_eq!(content_type_for_path("app-1.0.ear"), "application/java-archive");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --workspace --lib test_content_type -v`
Expected: FAIL for `test_content_type_pom`, `test_content_type_xml`, `test_content_type_asc`, `test_content_type_ear`

- [ ] **Step 3: Update content_type_for_path**

Replace the function at `maven.rs:200-208`:

```rust
fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".pom") || path.ends_with(".xml") {
        "text/xml"
    } else if path.ends_with(".jar") || path.ends_with(".war") || path.ends_with(".ear") {
        "application/java-archive"
    } else if path.ends_with(".asc") {
        "text/plain"
    } else {
        "application/octet-stream"
    }
}
```

- [ ] **Step 4: Also update the two hardcoded `application/xml` in download() section 2**

At `maven.rs:269` and `maven.rs:281`, the metadata responses hardcode `"application/xml"`. Change both to `"text/xml"`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --workspace --lib test_content_type -v`
Expected: All PASS

- [ ] **Step 6: Run full Maven test suite to check for regressions**

Run: `cargo test --workspace --lib maven -v`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add backend/src/api/handlers/maven.rs
git commit -m "fix: use text/xml for POM and metadata, text/plain for .asc per Maven spec"
```

---

### Task 1.2: Add SHA-512 checksum support (C4)

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:180-198` (ChecksumType, parse_checksum_path, checksum_suffix)
- Modify: `backend/src/api/handlers/maven.rs:595-614` (compute_checksum)
- Modify: `backend/src/formats/maven.rs:74-98` (parse_filename metadata fallback)

Note: The `sha2` crate (already in Cargo.toml at v0.10) includes `sha2::Sha512`. No new dependency needed.

- [ ] **Step 1: Write failing tests for SHA-512**

Add to `maven.rs` tests section:

```rust
#[test]
fn test_parse_checksum_path_sha512() {
    let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.jar.sha512");
    assert!(result.is_some());
    let (base, ct) = result.unwrap();
    assert_eq!(base, "com/example/my-lib/1.0/my-lib-1.0.jar");
    assert!(matches!(ct, ChecksumType::Sha512));
}

#[test]
fn test_compute_checksum_sha512() {
    let data = b"hello maven";
    let result = compute_checksum(data, ChecksumType::Sha512);
    assert_eq!(result.len(), 128); // SHA-512 = 128 hex chars
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_checksum_suffix_sha512() {
    assert_eq!(checksum_suffix(ChecksumType::Sha512), "sha512");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --workspace --lib test_parse_checksum_path_sha512 test_compute_checksum_sha512 test_checksum_suffix_sha512 -v`
Expected: FAIL (compile error, Sha512 variant doesn't exist)

- [ ] **Step 3: Add Sha512 to ChecksumType enum**

At `maven.rs:193-198`:

```rust
#[derive(Debug, Clone, Copy)]
enum ChecksumType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}
```

- [ ] **Step 4: Update parse_checksum_path to handle .sha512**

At `maven.rs:181-190`, add the `.sha512` case **before** the `.sha1` check (since `.sha1` is a suffix of `.sha512` if checked first with strip_suffix, though actually strip_suffix(".sha1") won't match ".sha512" so order doesn't matter, but put `.sha512` first for clarity):

```rust
fn parse_checksum_path(path: &str) -> Option<(&str, ChecksumType)> {
    if let Some(base) = path.strip_suffix(".sha512") {
        Some((base, ChecksumType::Sha512))
    } else if let Some(base) = path.strip_suffix(".sha256") {
        Some((base, ChecksumType::Sha256))
    } else if let Some(base) = path.strip_suffix(".sha1") {
        Some((base, ChecksumType::Sha1))
    } else if let Some(base) = path.strip_suffix(".md5") {
        Some((base, ChecksumType::Md5))
    } else {
        None
    }
}
```

- [ ] **Step 5: Update checksum_suffix**

```rust
fn checksum_suffix(ct: ChecksumType) -> &'static str {
    match ct {
        ChecksumType::Md5 => "md5",
        ChecksumType::Sha1 => "sha1",
        ChecksumType::Sha256 => "sha256",
        ChecksumType::Sha512 => "sha512",
    }
}
```

- [ ] **Step 6: Update compute_checksum**

Add the SHA-512 arm at `maven.rs:595-614`:

```rust
fn compute_checksum(data: &[u8], checksum_type: ChecksumType) -> String {
    match checksum_type {
        ChecksumType::Md5 => {
            use md5::Md5;
            let mut hasher = Md5::new();
            md5::Digest::update(&mut hasher, data);
            format!("{:x}", md5::Digest::finalize(hasher))
        }
        ChecksumType::Sha1 => {
            use sha1::Sha1;
            let mut hasher = Sha1::new();
            sha1::Digest::update(&mut hasher, data);
            format!("{:x}", sha1::Digest::finalize(hasher))
        }
        ChecksumType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        ChecksumType::Sha512 => {
            use sha2::Sha512;
            let mut hasher = Sha512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
    }
}
```

- [ ] **Step 7: Update serve_computed_checksum for SHA-512**

At `maven.rs:575-586`, the match only returns the stored value for SHA-256. SHA-512 must fall through to compute:

No change needed; the `_` arm already handles Sha512 by computing from content.

- [ ] **Step 8: Update parse_filename in formats/maven.rs to accept .sha512**

At `formats/maven.rs:74-98`, the metadata file check uses hardcoded extensions. Add `.sha512`:

```rust
if filename == "maven-metadata.xml"
    || filename.ends_with(".md5")
    || filename.ends_with(".sha1")
    || filename.ends_with(".sha256")
    || filename.ends_with(".sha512")
{
    return Ok((None, filename.to_string()));
}
```

There are TWO copies of this block in `parse_filename` (lines 74-79 and 88-93). Update both.

- [ ] **Step 9: Run tests**

Run: `cargo test --workspace --lib maven -v`
Expected: All pass including the 3 new SHA-512 tests

- [ ] **Step 10: Commit**

```bash
git add backend/src/api/handlers/maven.rs backend/src/formats/maven.rs
git commit -m "feat: add SHA-512 checksum support for Maven artifacts"
```

---

### Task 1.3: Add checksum response headers on artifact downloads (M1)

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:525-531` (serve_artifact normal response)
- Modify: `backend/src/api/handlers/maven.rs:409-415` (SNAPSHOT resolution response)
- Modify: `backend/src/api/handlers/maven.rs:437-442` (proxy response)

- [ ] **Step 1: Add x-checksum-sha1 and x-checksum-md5 headers to the main artifact download response**

At `maven.rs:525-531`, the response already includes `X-Checksum-SHA256`. We need to also include MD5 and SHA-1 when stored in the DB.

First, query the additional checksum columns. Modify the SQL at `maven.rs:379-387`:

```rust
let artifact = sqlx::query!(
    r#"
    SELECT id, path, size_bytes, checksum_sha256, checksum_md5, checksum_sha1,
           content_type, storage_key
    FROM artifacts
    WHERE repository_id = $1
      AND is_deleted = false
      AND path = $2
    LIMIT 1
    "#,
    repo.id,
    path,
)
```

Then update the response builder at `maven.rs:525-531`:

```rust
let mut builder = Response::builder()
    .status(StatusCode::OK)
    .header(CONTENT_TYPE, ct)
    .header(CONTENT_LENGTH, content.len().to_string())
    .header("X-Checksum-SHA256", &artifact.checksum_sha256);

if let Some(ref md5) = artifact.checksum_md5 {
    builder = builder.header("X-Checksum-MD5", md5);
}
if let Some(ref sha1) = artifact.checksum_sha1 {
    builder = builder.header("X-Checksum-SHA1", sha1);
}

Ok(builder.body(Body::from(content)).unwrap())
```

- [ ] **Step 2: Run full test suite to verify no regressions**

Run: `cargo test --workspace --lib maven -v`
Expected: All pass

- [ ] **Step 3: Regenerate SQLx offline cache** (this task modifies a `sqlx::query!()`)

```bash
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo sqlx prepare --workspace
```

- [ ] **Step 4: Commit**

```bash
git add backend/src/api/handlers/maven.rs .sqlx/
git commit -m "feat: include x-checksum-md5 and x-checksum-sha1 headers on Maven downloads"
```

---

### Task 1.4: Compute and store MD5/SHA-1 during upload (M4)

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:750-753` (upload SHA-256 computation)
- Modify: `backend/src/api/handlers/maven.rs:1005-1050` (INSERT INTO artifacts)
- Modify: `backend/src/api/handlers/maven.rs:681-698` (update_artifact_record)

- [ ] **Step 1: Compute MD5 and SHA-1 alongside SHA-256 during upload**

At `maven.rs:750-753`, after computing SHA-256, also compute the other two:

```rust
// Compute checksums
let mut sha256_hasher = Sha256::new();
sha256_hasher.update(&body);
let checksum_sha256 = format!("{:x}", sha256_hasher.finalize());

let checksum_md5 = {
    use md5::Md5;
    let mut hasher = Md5::new();
    md5::Digest::update(&mut hasher, &body);
    format!("{:x}", md5::Digest::finalize(hasher))
};

let checksum_sha1 = {
    use sha1::Sha1;
    let mut hasher = Sha1::new();
    sha1::Digest::update(&mut hasher, &body);
    format!("{:x}", sha1::Digest::finalize(hasher))
};
```

- [ ] **Step 2: Update the INSERT query to include checksum_md5 and checksum_sha1**

Find the INSERT INTO artifacts query (around `maven.rs:1005-1050`) and add the two new columns:

```sql
INSERT INTO artifacts (
    repository_id, path, name, version, size_bytes,
    checksum_sha256, checksum_md5, checksum_sha1,
    content_type, storage_key, uploaded_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id
```

Bind `checksum_md5` and `checksum_sha1` in the appropriate positions.

- [ ] **Step 3: Update update_artifact_record to also store MD5/SHA-1**

At `maven.rs:670-698`, add parameters for md5 and sha1. Update the SQL:

```rust
async fn update_artifact_record(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
    artifact_id: uuid::Uuid,
    path: &str,
    size_bytes: i64,
    checksum_sha256: &str,
    checksum_md5: &str,
    checksum_sha1: &str,
    content_type: &str,
    storage_key: &str,
) -> Result<(), Response> {
    super::cleanup_soft_deleted_artifact(db, repo_id, path).await;
    sqlx::query(
        r#"
        UPDATE artifacts
        SET path = $1, size_bytes = $2, checksum_sha256 = $3,
            checksum_md5 = $4, checksum_sha1 = $5,
            content_type = $6, storage_key = $7, updated_at = NOW()
        WHERE id = $8
        "#,
    )
    .bind(path)
    .bind(size_bytes)
    .bind(checksum_sha256)
    .bind(checksum_md5)
    .bind(checksum_sha1)
    .bind(content_type)
    .bind(storage_key)
    .bind(artifact_id)
    .execute(db)
    .await
    .map_err(map_db_err)?;
    Ok(())
}
```

Update all callers of `update_artifact_record` to pass the new parameters.

- [ ] **Step 4: Update serve_computed_checksum to use stored MD5/SHA-1**

At `maven.rs:541-586`, update the query to also select `checksum_md5` and `checksum_sha1`, then return them when available:

```rust
let checksum = match checksum_type {
    ChecksumType::Sha256 => resolved_sha256,
    ChecksumType::Md5 if resolved_md5.is_some() => resolved_md5.unwrap(),
    ChecksumType::Sha1 if resolved_sha1.is_some() => resolved_sha1.unwrap(),
    _ => {
        // Fall back to computing from content
        let storage = state.storage_for_repo_or_500(location)?;
        let content = storage.get(&resolved_storage_key).await.map_err(map_storage_err)?;
        compute_checksum(&content, checksum_type)
    }
};
```

- [ ] **Step 5: Run full test suite**

Run: `cargo test --workspace --lib maven -v`
Expected: All pass

- [ ] **Step 6: Regenerate SQLx offline cache** (this task modifies `sqlx::query!()` calls)

```bash
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo sqlx prepare --workspace
```

- [ ] **Step 7: Commit**

```bash
git add backend/src/api/handlers/maven.rs .sqlx/
git commit -m "feat: compute and store MD5/SHA-1 during Maven upload for efficient checksum serving"
```

---

## Team 2: Metadata Engine

### Task 2.1: Implement Maven ComparableVersion ordering (C1)

**Files:**
- Create: `backend/src/formats/maven_version.rs`
- Modify: `backend/src/formats/mod.rs` (add module)

This is the most important fix. Maven's `ComparableVersion` algorithm is complex but well-specified. We port it to Rust as a standalone module.

- [ ] **Step 1: Write comprehensive test vectors first**

Create `backend/src/formats/maven_version.rs` with tests derived from Maven's own `ComparableVersionTest.java`:

```rust
//! Maven version comparison implementing the ComparableVersion algorithm.
//!
//! Port of org.apache.maven.artifact.versioning.ComparableVersion from Maven.
//! See: https://maven.apache.org/ref/3.9.6/maven-artifact/

use std::cmp::Ordering;

/// A parsed Maven version that can be compared using Maven's ordering rules.
///
/// Parsing rules:
/// - `.` and `-` are segment separators
/// - Transitions between digits and letters are implicit separators
/// - Known qualifiers have a defined order: alpha < beta < milestone < rc < snapshot < "" (release) < sp
/// - Unknown qualifiers sort after all known qualifiers, ordered lexically
/// - Numeric segments compare as integers (no leading-zero issues)
/// - Trailing zero segments and empty qualifiers are trimmed for equivalence
#[derive(Debug, Clone)]
pub struct MavenVersion {
    canonical: String,
    items: ListItem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Int(u64),
    String(StringItem),
    List(ListItem),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StringItem(String);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListItem(Vec<Item>);

impl StringItem {
    /// Known qualifier ordering. Returns a comparable rank.
    fn qualifier_rank(s: &str) -> Option<i32> {
        match s {
            "alpha" | "a" => Some(0),
            "beta" | "b" => Some(1),
            "milestone" | "m" => Some(2),
            "rc" | "cr" => Some(3),
            "snapshot" => Some(4),
            "" | "ga" | "final" | "release" => Some(5),
            "sp" => Some(6),
            _ => None,
        }
    }
}

impl MavenVersion {
    pub fn parse(version: &str) -> Self {
        let lower = version.to_lowercase();
        let items = Self::parse_items(&lower);
        let canonical = format!("{}", items);
        MavenVersion { canonical, items }
    }

    fn parse_items(version: &str) -> ListItem {
        let mut stack: Vec<ListItem> = vec![ListItem(Vec::new())];
        let mut current = String::new();
        let mut is_digit = false;

        for ch in version.chars() {
            if ch == '.' {
                // Dot separator
                if !current.is_empty() {
                    let item = Self::make_item(is_digit, &current);
                    stack.last_mut().unwrap().0.push(item);
                    current.clear();
                } else {
                    // Empty segment between dots: equivalent to "0"
                    stack.last_mut().unwrap().0.push(Item::Int(0));
                }
            } else if ch == '-' {
                // Hyphen: start a new sub-list (lower precedence than dot)
                if !current.is_empty() {
                    let item = Self::make_item(is_digit, &current);
                    stack.last_mut().unwrap().0.push(item);
                    current.clear();
                }
                let new_list = ListItem(Vec::new());
                stack.push(new_list);
            } else {
                let ch_is_digit = ch.is_ascii_digit();
                if !current.is_empty() && ch_is_digit != is_digit {
                    // Transition between digits and letters: implicit separator
                    let item = Self::make_item(is_digit, &current);
                    stack.last_mut().unwrap().0.push(item);
                    current.clear();
                    // digit->letter transition starts a sub-list (like hyphen)
                    if !ch_is_digit {
                        let new_list = ListItem(Vec::new());
                        stack.push(new_list);
                    }
                }
                is_digit = ch_is_digit;
                current.push(ch);
            }
        }

        if !current.is_empty() {
            let item = Self::make_item(is_digit, &current);
            stack.last_mut().unwrap().0.push(item);
        }

        // Collapse stack: each sub-list becomes an item in its parent
        while stack.len() > 1 {
            let mut child = stack.pop().unwrap();
            Self::trim_trailing_nulls(&mut child);
            stack.last_mut().unwrap().0.push(Item::List(child));
        }

        let mut root = stack.pop().unwrap();
        Self::trim_trailing_nulls(&mut root);
        root
    }

    fn make_item(is_digit: bool, token: &str) -> Item {
        if is_digit {
            Item::Int(token.parse::<u64>().unwrap_or(0))
        } else {
            // Normalize known qualifier aliases
            let normalized = match token {
                "a" => "alpha",
                "b" => "beta",
                "m" => "milestone",
                "cr" => "rc",
                "ga" | "final" | "release" => "",
                other => other,
            };
            Item::String(StringItem(normalized.to_string()))
        }
    }

    /// Remove trailing "null" items (0 for ints, "" for strings, empty lists).
    fn trim_trailing_nulls(list: &mut ListItem) {
        while let Some(last) = list.0.last() {
            match last {
                Item::Int(0) => { list.0.pop(); }
                Item::String(s) if s.0.is_empty() => { list.0.pop(); }
                Item::List(l) if l.0.is_empty() => { list.0.pop(); }
                _ => break,
            }
        }
    }
}

impl PartialEq for MavenVersion {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for MavenVersion {}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_list(&self.items, &other.items)
    }
}

fn cmp_list(a: &ListItem, b: &ListItem) -> Ordering {
    let max_len = a.0.len().max(b.0.len());
    for i in 0..max_len {
        let ai = a.0.get(i);
        let bi = b.0.get(i);
        let ord = match (ai, bi) {
            (Some(a_item), Some(b_item)) => cmp_item(a_item, b_item),
            (Some(a_item), None) => cmp_item_with_null(a_item),
            (None, Some(b_item)) => cmp_item_with_null(b_item).reverse(),
            (None, None) => Ordering::Equal,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

fn cmp_item(a: &Item, b: &Item) -> Ordering {
    match (a, b) {
        (Item::Int(a), Item::Int(b)) => a.cmp(b),
        (Item::String(a), Item::String(b)) => cmp_string(a, b),
        (Item::List(a), Item::List(b)) => cmp_list(a, b),
        // Int vs String: all ints > all string qualifiers
        (Item::Int(_), Item::String(_)) => Ordering::Greater,
        (Item::String(_), Item::Int(_)) => Ordering::Less,
        // Int vs List: compare int to first element of list
        (Item::Int(_), Item::List(b)) => {
            let b_first = b.0.first();
            match b_first {
                Some(bf) => cmp_item(a, bf),
                None => cmp_item_with_null(a),
            }
        }
        (Item::List(a), Item::Int(_)) => {
            let a_first = a.0.first();
            match a_first {
                Some(af) => cmp_item(af, b),
                None => cmp_item_with_null(b).reverse(),
            }
        }
        // String vs List: compare string to first element of list
        (Item::String(_), Item::List(b)) => {
            let b_first = b.0.first();
            match b_first {
                Some(bf) => cmp_item(a, bf),
                None => cmp_item_with_null(a),
            }
        }
        (Item::List(a), Item::String(_)) => {
            let a_first = a.0.first();
            match a_first {
                Some(af) => cmp_item(af, b),
                None => cmp_item_with_null(b).reverse(),
            }
        }
    }
}

fn cmp_string(a: &StringItem, b: &StringItem) -> Ordering {
    let a_rank = StringItem::qualifier_rank(&a.0);
    let b_rank = StringItem::qualifier_rank(&b.0);
    match (a_rank, b_rank) {
        (Some(ar), Some(br)) => ar.cmp(&br),
        (Some(_), None) => Ordering::Less, // known < unknown
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.0.cmp(&b.0), // both unknown: lexical
    }
}

/// Compare an item against an absent/null position.
/// In Maven: null is equivalent to 0 for ints, "" for strings.
fn cmp_item_with_null(item: &Item) -> Ordering {
    match item {
        Item::Int(n) => n.cmp(&0),
        Item::String(s) => {
            let rank = StringItem::qualifier_rank(&s.0);
            match rank {
                Some(r) => r.cmp(&5), // compare against "" (release) rank
                None => Ordering::Greater, // unknown qualifier > release
            }
        }
        Item::List(l) => {
            if l.0.is_empty() {
                Ordering::Equal
            } else {
                cmp_item_with_null(l.0.first().unwrap())
            }
        }
    }
}

impl std::fmt::Display for ListItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, item) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            match item {
                Item::Int(n) => write!(f, "{}", n)?,
                Item::String(s) => write!(f, "{}", s.0)?,
                Item::List(l) => write!(f, "({})", l)?,
            }
        }
        Ok(())
    }
}

/// Sort a slice of version strings using Maven ordering. Returns a new sorted Vec.
pub fn sort_maven_versions(versions: &[String]) -> Vec<String> {
    let mut versioned: Vec<_> = versions
        .iter()
        .map(|v| (MavenVersion::parse(v), v.clone()))
        .collect();
    versioned.sort_by(|a, b| a.0.cmp(&b.0));
    versioned.into_iter().map(|(_, v)| v).collect()
}

/// Find the latest version (highest by Maven ordering).
pub fn latest_version(versions: &[String]) -> Option<&String> {
    versions
        .iter()
        .max_by(|a, b| MavenVersion::parse(a).cmp(&MavenVersion::parse(b)))
}

/// Find the latest release (non-SNAPSHOT) version.
pub fn latest_release(versions: &[String]) -> Option<&String> {
    versions
        .iter()
        .filter(|v| !v.contains("SNAPSHOT"))
        .max_by(|a, b| MavenVersion::parse(a).cmp(&MavenVersion::parse(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: assert a < b in Maven ordering
    fn assert_order(lesser: &str, greater: &str) {
        let a = MavenVersion::parse(lesser);
        let b = MavenVersion::parse(greater);
        assert!(
            a < b,
            "Expected '{}' < '{}', but got {:?}",
            lesser, greater, a.cmp(&b)
        );
    }

    /// Helper: assert a == b in Maven ordering
    fn assert_equiv(a_str: &str, b_str: &str) {
        let a = MavenVersion::parse(a_str);
        let b = MavenVersion::parse(b_str);
        assert!(
            a == b,
            "Expected '{}' == '{}', but got {:?}",
            a_str, b_str, a.cmp(&b)
        );
    }

    // -- Equivalences (from Maven's own ComparableVersionTest.java) --

    #[test]
    fn test_equiv_trailing_zeros() {
        assert_equiv("1", "1.0");
        assert_equiv("1", "1.0.0");
        assert_equiv("1.0", "1.0.0");
    }

    #[test]
    fn test_equiv_release_qualifiers() {
        assert_equiv("1.0", "1.0-ga");
        assert_equiv("1.0", "1.0-final");
        assert_equiv("1.0", "1.0-release");
        assert_equiv("1.0.0", "1.0-ga");
    }

    #[test]
    fn test_equiv_qualifier_aliases() {
        assert_equiv("1.0-alpha1", "1.0-a1");
        assert_equiv("1.0-beta1", "1.0-b1");
        assert_equiv("1.0-rc1", "1.0-cr1");
    }

    // -- Ordering --

    #[test]
    fn test_qualifier_ordering() {
        assert_order("1.0-alpha", "1.0-beta");
        assert_order("1.0-beta", "1.0-milestone");
        assert_order("1.0-milestone", "1.0-rc");
        assert_order("1.0-rc", "1.0-snapshot");
        assert_order("1.0-snapshot", "1.0");
        assert_order("1.0", "1.0-sp");
    }

    #[test]
    fn test_numeric_ordering() {
        assert_order("1.0-alpha1", "1.0-alpha2");
        assert_order("1.0-alpha1", "1.0-alpha10");
        assert_order("1.0-beta1", "1.0-beta2");
        assert_order("1.0-rc1", "1.0-rc2");
    }

    #[test]
    fn test_version_ordering() {
        assert_order("1.0", "1.1");
        assert_order("1.0", "2.0");
        assert_order("1.0.0", "1.0.1");
        assert_order("1.0.1", "1.1.0");
    }

    #[test]
    fn test_numeric_vs_lexicographic() {
        // This is the critical fix: SQL ORDER BY gets this wrong
        assert_order("1.0.2", "1.0.10");
        assert_order("1.2", "1.10");
        assert_order("2.0", "10.0");
    }

    #[test]
    fn test_snapshot_ordering() {
        assert_order("1.0-SNAPSHOT", "1.0");
        assert_order("1.0-alpha-SNAPSHOT", "1.0-alpha");
        assert_order("1.0-rc1-SNAPSHOT", "1.0-rc1");
    }

    #[test]
    fn test_hyphen_vs_dot() {
        // Hyphen creates a sub-list (lower precedence)
        assert_order("1-1", "1.1");
    }

    #[test]
    fn test_digit_letter_transition() {
        // Implicit separator at digit-letter boundary
        assert_order("1.0alpha1", "1.0beta1");
        assert_order("1.0alpha1", "1.0.1");
    }

    // -- sort_maven_versions --

    #[test]
    fn test_sort_maven_versions() {
        let versions = vec![
            "1.0.10".to_string(),
            "1.0.2".to_string(),
            "1.0.1".to_string(),
            "2.0.0".to_string(),
            "1.0.0".to_string(),
        ];
        let sorted = sort_maven_versions(&versions);
        assert_eq!(sorted, vec!["1.0.0", "1.0.1", "1.0.2", "1.0.10", "2.0.0"]);
    }

    // -- latest_version / latest_release --

    #[test]
    fn test_latest_version() {
        let versions = vec![
            "1.0.0".to_string(),
            "2.0.0-SNAPSHOT".to_string(),
            "1.5.0".to_string(),
        ];
        assert_eq!(latest_version(&versions).unwrap(), "2.0.0-SNAPSHOT");
    }

    #[test]
    fn test_latest_release() {
        let versions = vec![
            "1.0.0".to_string(),
            "2.0.0-SNAPSHOT".to_string(),
            "1.5.0".to_string(),
        ];
        assert_eq!(latest_release(&versions).unwrap(), "1.5.0");
    }

    #[test]
    fn test_latest_release_all_snapshots() {
        let versions = vec![
            "1.0.0-SNAPSHOT".to_string(),
            "2.0.0-SNAPSHOT".to_string(),
        ];
        assert!(latest_release(&versions).is_none());
    }
}
```

- [ ] **Step 2: Register the module**

Add to `backend/src/formats/mod.rs`:

```rust
pub mod maven_version;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test --workspace --lib maven_version -v`
Expected: All pass (the implementation is included in the file above)

- [ ] **Step 4: Commit**

```bash
git add backend/src/formats/maven_version.rs backend/src/formats/mod.rs
git commit -m "feat: implement Maven ComparableVersion ordering algorithm"
```

---

### Task 2.2: Fix metadata generation to use Maven ordering and separate latest/release (C1, C2)

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:334-371` (generate_metadata_for_artifact)
- Modify: `backend/src/formats/maven.rs:339-376` (generate_metadata_xml)

- [ ] **Step 1: Write a test for correct metadata with mixed versions**

Add to `formats/maven.rs` tests:

```rust
#[test]
fn test_generate_metadata_version_ordering() {
    let xml = generate_metadata_xml(
        "com.example",
        "my-lib",
        &["1.0.0".into(), "1.0.2".into(), "1.0.10".into(), "2.0.0-SNAPSHOT".into()],
        "2.0.0-SNAPSHOT",
        Some("1.0.10"),
    );
    assert!(xml.contains("<latest>2.0.0-SNAPSHOT</latest>"));
    assert!(xml.contains("<release>1.0.10</release>"));
}

#[test]
fn test_generate_metadata_no_release() {
    let xml = generate_metadata_xml(
        "com.example",
        "my-lib",
        &["1.0.0-SNAPSHOT".into(), "2.0.0-SNAPSHOT".into()],
        "2.0.0-SNAPSHOT",
        None,
    );
    assert!(xml.contains("<latest>2.0.0-SNAPSHOT</latest>"));
    assert!(!xml.contains("<release>"));
}
```

- [ ] **Step 2: Run tests to verify they pass** (these test the XML generator, which already takes latest/release as params)

Run: `cargo test --workspace --lib test_generate_metadata -v`
Expected: PASS

- [ ] **Step 3: Update generate_metadata_for_artifact to use Maven ordering**

Replace `maven.rs:334-371`:

```rust
async fn generate_metadata_for_artifact(
    db: &PgPool,
    repo_id: uuid::Uuid,
    group_id: &str,
    artifact_id: &str,
) -> Result<String, Response> {
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT a.version as "version?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'maven'
          AND am.metadata->>'groupId' = $2
          AND am.metadata->>'artifactId' = $3
          AND a.version IS NOT NULL
        "#,
        repo_id,
        group_id,
        artifact_id,
    )
    .fetch_all(db)
    .await
    .map_err(map_db_err)?;

    let versions: Vec<String> = rows.into_iter().filter_map(|r| r.version).collect();

    if versions.is_empty() {
        return Err(AppError::NotFound("No versions found".to_string()).into_response());
    }

    use crate::formats::maven_version;

    let sorted = maven_version::sort_maven_versions(&versions);
    // sorted is already in Maven order, so last element is latest
    let latest = sorted.last().unwrap().clone();
    let release = maven_version::latest_release(&sorted).cloned();

    let xml = generate_metadata_xml(
        group_id,
        artifact_id,
        &sorted,
        &latest,
        release.as_deref(),
    );

    Ok(xml)
}
```

Key changes:
1. Removed `ORDER BY a.version` from SQL (we sort in Rust now)
2. Use `maven_version::sort_maven_versions` for correct ordering
3. Use `maven_version::latest_version` for `latest` (may be SNAPSHOT)
4. Use `maven_version::latest_release` for `release` (non-SNAPSHOT only, `None` if all are SNAPSHOTs)

- [ ] **Step 4: Run all tests**

Run: `cargo test --workspace --lib maven -v`
Expected: All pass

- [ ] **Step 5: Regenerate SQLx offline cache** (this task removed `ORDER BY` from a `sqlx::query!()`)

```bash
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo sqlx prepare --workspace
```

- [ ] **Step 6: Commit**

```bash
git add backend/src/api/handlers/maven.rs .sqlx/
git commit -m "fix: use Maven ComparableVersion ordering for metadata generation

Sort versions semantically instead of lexicographically, and separate
latest (any version) from release (non-SNAPSHOT only) per spec."
```

---

### Task 2.3: Proxy metadata from upstream for remote repos (C6)

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:262-289` (download section 2)

- [ ] **Step 1: Add remote proxy fallback to metadata section**

At `maven.rs:262-289`, after the existing "Metadata not found anywhere" error, add proxy fallback before returning 404. Replace:

```rust
// 2. Check if this is a maven-metadata.xml request
if MavenHandler::is_metadata(&path) {
    // Try stored metadata file first (handles version-level metadata)
    let meta_storage_key = format!("maven/{}", path);
    if let Ok(content) = storage.get(&meta_storage_key).await {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/xml")
            .header(CONTENT_LENGTH, content.len().to_string())
            .body(Body::from(content))
            .unwrap());
    }

    // Fall back to dynamic generation for artifact-level metadata
    if let Some((group_id, artifact_id)) = parse_metadata_path(&path) {
        let xml =
            generate_metadata_for_artifact(&state.db, repo.id, &group_id, &artifact_id).await;
        if let Ok(xml) = xml {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/xml")
                .header(CONTENT_LENGTH, xml.len().to_string())
                .body(Body::from(xml))
                .unwrap());
        }
    }

    // Fallback: proxy metadata from upstream for remote repos
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let (content, _content_type) =
                proxy_helpers::proxy_fetch(proxy, repo.id, &repo_key, upstream_url, &path)
                    .await?;
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/xml")
                .header(CONTENT_LENGTH, content.len().to_string())
                .body(Body::from(content))
                .unwrap());
        }
    }

    // Metadata not found anywhere
    return Err(AppError::NotFound("Metadata not found".to_string()).into_response());
}
```

Note: Dynamic generation is tried but allowed to fail (changed from `?` to `if let Ok`). This way, if the DB has no artifacts (common for remote repos), it falls through to the proxy.

- [ ] **Step 2: Run tests**

Run: `cargo test --workspace --lib maven -v`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add backend/src/api/handlers/maven.rs
git commit -m "fix: proxy maven-metadata.xml from upstream for remote repos

When metadata can't be served from storage or generated from the DB,
fall back to fetching from the upstream repository."
```

---

### Task 2.4: Merge metadata across virtual repo members (C3)

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:262-289` (download section 2, virtual repo case)
- Modify: `backend/src/formats/maven.rs` (add `merge_metadata_xml` and `parse_metadata_xml` functions)

- [ ] **Step 1: Add metadata XML parsing function to formats/maven.rs**

We need to parse metadata XML from members so we can merge version lists. Add after `generate_metadata_xml`:

```rust
/// Parse a maven-metadata.xml to extract the version list.
/// Returns (groupId, artifactId, versions).
pub fn parse_metadata_versions(xml: &str) -> Option<(String, String, Vec<String>)> {
    // Simple XML parsing - extract groupId, artifactId, and version elements
    let group_id = xml
        .split("<groupId>")
        .nth(1)?
        .split("</groupId>")
        .next()?
        .to_string();
    let artifact_id = xml
        .split("<artifactId>")
        .nth(1)?
        .split("</artifactId>")
        .next()?
        .to_string();

    let mut versions = Vec::new();
    // Find the <versions> block and extract each <version>
    if let Some(versions_block) = xml.split("<versions>").nth(1) {
        if let Some(versions_block) = versions_block.split("</versions>").next() {
            for segment in versions_block.split("<version>").skip(1) {
                if let Some(ver) = segment.split("</version>").next() {
                    let ver = ver.trim();
                    if !ver.is_empty() {
                        versions.push(ver.to_string());
                    }
                }
            }
        }
    }

    Some((group_id, artifact_id, versions))
}
```

- [ ] **Step 2: Write a test for parse_metadata_versions**

```rust
#[test]
fn test_parse_metadata_versions() {
    let xml = generate_metadata_xml(
        "com.example",
        "my-lib",
        &["1.0.0".into(), "1.1.0".into()],
        "1.1.0",
        Some("1.1.0"),
    );
    let (g, a, versions) = parse_metadata_versions(&xml).unwrap();
    assert_eq!(g, "com.example");
    assert_eq!(a, "my-lib");
    assert_eq!(versions, vec!["1.0.0", "1.1.0"]);
}
```

- [ ] **Step 3: Add virtual metadata merging to download section 2**

In the metadata section of `download()`, after the remote proxy fallback, add virtual repo handling:

```rust
// Virtual repo: merge metadata from all members
if repo.repo_type == RepositoryType::Virtual {
    if let Some((group_id, artifact_id)) = parse_metadata_path(&path) {
        let mut all_versions: Vec<String> = Vec::new();

        // Collect versions from local members
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        for member in &members {
            // Try generating metadata from this member's artifacts
            if let Ok(xml) = generate_metadata_for_artifact(
                &state.db,
                member.id,
                &group_id,
                &artifact_id,
            )
            .await
            {
                if let Some((_, _, versions)) =
                    crate::formats::maven::parse_metadata_versions(&xml)
                {
                    all_versions.extend(versions);
                }
            }

            // For remote members, also try proxying metadata from upstream
            if member.repo_type == RepositoryType::Remote {
                if let (Some(upstream_url), Some(ref proxy)) =
                    (member.upstream_url.as_deref(), &state.proxy_service)
                {
                    if let Ok((content, _)) = proxy_helpers::proxy_fetch(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &path,
                    )
                    .await
                    {
                        if let Ok(xml_str) = std::str::from_utf8(&content) {
                            if let Some((_, _, versions)) =
                                crate::formats::maven::parse_metadata_versions(xml_str)
                            {
                                all_versions.extend(versions);
                            }
                        }
                    }
                }
            }
        }

        if !all_versions.is_empty() {
            // Deduplicate and sort using Maven ordering
            all_versions.sort();
            all_versions.dedup();

            use crate::formats::maven_version;
            let sorted = maven_version::sort_maven_versions(&all_versions);
            let latest = maven_version::latest_version(&sorted).unwrap().clone();
            let release = maven_version::latest_release(&sorted).cloned();

            let xml = generate_metadata_xml(
                &group_id,
                &artifact_id,
                &sorted,
                &latest,
                release.as_deref(),
            );

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/xml")
                .header(CONTENT_LENGTH, xml.len().to_string())
                .body(Body::from(xml))
                .unwrap());
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test --workspace --lib maven -v`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add backend/src/api/handlers/maven.rs backend/src/formats/maven.rs
git commit -m "feat: merge maven-metadata.xml across virtual repo members

Collect versions from all members (local DB + remote upstream proxy),
deduplicate, sort using Maven version ordering, and generate a merged
metadata response with correct latest/release values."
```

---

## Team 3: SNAPSHOT and Storage Correctness

### Task 3.1: Debug and fix virtual repo artifact resolution (C7 / Issue #461)

**Files:**
- Investigate: `backend/src/api/handlers/proxy_helpers.rs:208-250` (resolve_virtual_download)
- Investigate: `backend/src/api/handlers/proxy_helpers.rs:377-412` (fetch_virtual_members)
- Investigate: Web frontend virtual repo member management

This is an investigation task. The virtual repo resolution code looks correct on paper (`resolve_virtual_download` iterates members, tries local fetch then proxy). The bug may be in:
1. Member association not being saved correctly (web UI issue)
2. `virtual_repo_members` table not populated
3. Format mismatch filtering

- [ ] **Step 1: Write a diagnostic query to check virtual member state**

```bash
# Connect to local dev DB and check virtual member associations
psql "postgresql://registry:registry@localhost:30432/artifact_registry" -c "
SELECT v.key as virtual_key, m.key as member_key, vrm.priority
FROM virtual_repo_members vrm
JOIN repositories v ON v.id = vrm.virtual_repo_id
JOIN repositories m ON m.id = vrm.member_repo_id
ORDER BY v.key, vrm.priority;
"
```

- [ ] **Step 2: Create a virtual Maven repo via API and verify members are stored**

```bash
# Create local and remote repos, then virtual
curl -s -u admin:password -X POST http://localhost:8080/api/v1/repositories \
  -H "Content-Type: application/json" \
  -d '{"key":"maven-local-test","name":"Local Maven","format":"maven","repoType":"local"}'

curl -s -u admin:password -X POST http://localhost:8080/api/v1/repositories \
  -H "Content-Type: application/json" \
  -d '{"key":"maven-remote-central","name":"Maven Central","format":"maven","repoType":"remote","upstreamUrl":"https://repo.maven.apache.org/maven2"}'

curl -s -u admin:password -X POST http://localhost:8080/api/v1/repositories \
  -H "Content-Type: application/json" \
  -d '{"key":"maven-virtual-all","name":"Virtual Maven","format":"maven","repoType":"virtual","members":["maven-local-test","maven-remote-central"]}'

# Verify members
curl -s -u admin:password http://localhost:8080/api/v1/repositories/maven-virtual-all | jq '.members'
```

- [ ] **Step 3: Test artifact resolution through virtual repo**

```bash
# Try to fetch a well-known artifact through the virtual repo
curl -v http://localhost:8080/maven/maven-virtual-all/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
```

- [ ] **Step 4: Fix the identified issue**

Based on investigation, apply the fix. Common causes:
- If members aren't stored: fix the repository creation API to handle `members` field
- If members are stored but not found: check the `fetch_virtual_members` SQL join
- If format doesn't match: check format validation in virtual resolution

- [ ] **Step 5: Commit the fix**

```bash
git add <affected files>
git commit -m "fix: resolve virtual Maven repo member lookup (closes #461)"
```

---

### Task 3.2: Audit and test GAV grouping edge cases

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:848-998` (GAV grouping in upload)
- Test: unit tests in `maven.rs` tests section

- [ ] **Step 1: Write tests for GAV grouping edge cases**

Add to the tests in `maven.rs`:

```rust
#[test]
fn test_is_primary_maven_artifact_aar() {
    let coords = MavenCoordinates {
        group_id: "com.example".into(),
        artifact_id: "lib".into(),
        version: "1.0".into(),
        classifier: None,
        extension: "aar".into(),
    };
    assert!(is_primary_maven_artifact(&coords));
}

#[test]
fn test_is_primary_maven_artifact_pom_only() {
    let coords = MavenCoordinates {
        group_id: "com.example".into(),
        artifact_id: "parent".into(),
        version: "1.0".into(),
        classifier: None,
        extension: "pom".into(),
    };
    assert!(!is_primary_maven_artifact(&coords));
}

#[test]
fn test_is_primary_maven_artifact_sources() {
    let coords = MavenCoordinates {
        group_id: "com.example".into(),
        artifact_id: "lib".into(),
        version: "1.0".into(),
        classifier: Some("sources".into()),
        extension: "jar".into(),
    };
    assert!(!is_primary_maven_artifact(&coords));
}

#[test]
fn test_is_primary_maven_artifact_javadoc() {
    let coords = MavenCoordinates {
        group_id: "com.example".into(),
        artifact_id: "lib".into(),
        version: "1.0".into(),
        classifier: Some("javadoc".into()),
        extension: "jar".into(),
    };
    assert!(!is_primary_maven_artifact(&coords));
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --workspace --lib test_is_primary -v`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add backend/src/api/handlers/maven.rs
git commit -m "test: add GAV grouping edge case tests for .aar, POM-only, sources, javadoc"
```

---

## Team 4: Test Matrix and Validation

### Task 4.1: Maven version ordering conformance tests

This is covered by Task 2.1's tests. Team 4 should verify those tests pass after Team 2 completes Task 2.1.

- [ ] **Step 1: Run version ordering tests**

Run: `cargo test --workspace --lib maven_version -v`
Expected: All pass

- [ ] **Step 2: Add additional edge case tests if any gaps found**

Consider adding: versions with build metadata (+build), very long version strings, single-digit versions, etc.

---

### Task 4.2: Metadata generation integration tests

**Files:**
- Modify: `backend/src/formats/maven.rs` tests section

- [ ] **Step 1: Write tests that verify the full metadata generation pipeline**

```rust
#[test]
fn test_generate_metadata_mixed_versions_ordering() {
    // Simulate what generate_metadata_for_artifact would produce
    let versions = vec![
        "1.0.0".to_string(),
        "1.0.10".to_string(),
        "1.0.2".to_string(),
        "2.0.0-SNAPSHOT".to_string(),
        "1.0.1-beta".to_string(),
    ];

    use crate::formats::maven_version;
    let sorted = maven_version::sort_maven_versions(&versions);
    let latest = maven_version::latest_version(&sorted).unwrap().clone();
    let release = maven_version::latest_release(&sorted).cloned();

    let xml = generate_metadata_xml(
        "com.example",
        "my-lib",
        &sorted,
        &latest,
        release.as_deref(),
    );

    // Verify version order in XML
    let version_positions: Vec<usize> = sorted
        .iter()
        .map(|v| xml.find(&format!("<version>{}</version>", v)).unwrap())
        .collect();
    // Each version should appear after the previous one
    for window in version_positions.windows(2) {
        assert!(window[0] < window[1], "Versions not in correct order in XML");
    }

    assert!(xml.contains("<latest>2.0.0-SNAPSHOT</latest>"));
    assert!(xml.contains("<release>1.0.10</release>"));
}

#[test]
fn test_generate_metadata_lastUpdated_format() {
    let xml = generate_metadata_xml(
        "com.example",
        "my-lib",
        &["1.0.0".into()],
        "1.0.0",
        Some("1.0.0"),
    );
    // lastUpdated should be 14 digits: yyyyMMddHHmmss
    let start = xml.find("<lastUpdated>").unwrap() + "<lastUpdated>".len();
    let end = xml.find("</lastUpdated>").unwrap();
    let timestamp = &xml[start..end];
    assert_eq!(timestamp.len(), 14, "lastUpdated should be 14 digits");
    assert!(
        timestamp.chars().all(|c| c.is_ascii_digit()),
        "lastUpdated should be all digits"
    );
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --workspace --lib test_generate_metadata -v`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add backend/src/formats/maven.rs
git commit -m "test: add metadata generation integration tests for ordering and format"
```

---

### Task 4.3: Checksum completeness E2E test

**Files:**
- Create: `scripts/native-tests/test-maven-checksums.sh`

- [ ] **Step 1: Write checksum E2E test script**

```bash
#!/usr/bin/env bash
set -euo pipefail

# Test that all checksum variants work for Maven artifacts
BACKEND="${BACKEND_URL:-http://localhost:8080}"
REPO="maven-checksum-test-$$"
USER="${ADMIN_USER:-admin}"
PASS="${ADMIN_PASS:-password}"

echo "=== Maven Checksum Completeness Test ==="

# Create test repo
curl -sf -u "$USER:$PASS" -X POST "$BACKEND/api/v1/repositories" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"$REPO\",\"name\":\"Checksum Test\",\"format\":\"maven\",\"repoType\":\"local\"}" >/dev/null

# Upload a test artifact
echo "test-content" > /tmp/test-artifact.jar
curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/example/test/1.0/test-1.0.jar" \
  --data-binary @/tmp/test-artifact.jar >/dev/null

PASS_COUNT=0
FAIL_COUNT=0

for ext in sha1 md5 sha256 sha512; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BACKEND/maven/$REPO/com/example/test/1.0/test-1.0.jar.$ext")
  if [ "$STATUS" = "200" ]; then
    echo "PASS: .${ext} checksum returned 200"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: .${ext} checksum returned $STATUS (expected 200)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done

# Cleanup
curl -sf -u "$USER:$PASS" -X DELETE "$BACKEND/api/v1/repositories/$REPO" >/dev/null 2>&1 || true

echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
[ "$FAIL_COUNT" -eq 0 ] || exit 1
```

- [ ] **Step 2: Make it executable**

```bash
chmod +x scripts/native-tests/test-maven-checksums.sh
```

- [ ] **Step 3: Commit**

```bash
git add scripts/native-tests/test-maven-checksums.sh
git commit -m "test: add Maven checksum completeness E2E test covering all 4 algorithms"
```

---

### Task 4.4: Regression tests for historical Maven issues

**Files:**
- Create: `scripts/native-tests/test-maven-regressions.sh`

- [ ] **Step 1: Write regression test covering critical historical issues**

```bash
#!/usr/bin/env bash
set -euo pipefail

BACKEND="${BACKEND_URL:-http://localhost:8080}"
REPO="maven-regression-$$"
USER="${ADMIN_USER:-admin}"
PASS="${ADMIN_PASS:-password}"

echo "=== Maven Regression Tests ==="

curl -sf -u "$USER:$PASS" -X POST "$BACKEND/api/v1/repositories" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"$REPO\",\"name\":\"Regression\",\"format\":\"maven\",\"repoType\":\"local\"}" >/dev/null

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# --- #297/#321: SNAPSHOT re-upload should succeed ---
echo "test-v1" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar" \
  --data-binary @- >/dev/null
echo "test-v2" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar" \
  --data-binary @- >/dev/null && pass "#297 SNAPSHOT re-upload" || fail "#297 SNAPSHOT re-upload"

# --- Release re-upload should fail (409) ---
echo "test" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/rel/1.0/rel-1.0.jar" \
  --data-binary @- >/dev/null
STATUS=$(echo "test2" | curl -s -o /dev/null -w "%{http_code}" -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/rel/1.0/rel-1.0.jar" --data-binary @-)
[ "$STATUS" = "409" ] && pass "Release re-upload rejected (409)" || fail "Release re-upload: got $STATUS"

# --- #414: Checksum for SNAPSHOT should return hash, not XML ---
CHECKSUM=$(curl -sf "$BACKEND/maven/$REPO/com/test/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar.sha1" || echo "FETCH_FAILED")
if echo "$CHECKSUM" | grep -qv "<?xml"; then
  pass "#414 SNAPSHOT checksum is hash not XML"
else
  fail "#414 SNAPSHOT checksum returned XML"
fi

# --- #415: POM + JAR should group under same artifact ---
echo "<project></project>" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.pom" --data-binary @- >/dev/null
echo "jar-content" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.jar" --data-binary @- >/dev/null
# Both should be downloadable
JAR_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.jar")
POM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.pom")
[ "$JAR_STATUS" = "200" ] && [ "$POM_STATUS" = "200" ] && pass "#415 POM+JAR both accessible" || fail "#415 POM=$POM_STATUS JAR=$JAR_STATUS"

# --- Content-Type check (C5) ---
CT=$(curl -sf -o /dev/null -w "%{content_type}" "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.pom")
echo "$CT" | grep -q "text/xml" && pass "C5 POM content-type is text/xml" || fail "C5 POM content-type: $CT"

# Cleanup
curl -sf -u "$USER:$PASS" -X DELETE "$BACKEND/api/v1/repositories/$REPO" >/dev/null 2>&1 || true

echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
[ "$FAIL_COUNT" -eq 0 ] || exit 1
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x scripts/native-tests/test-maven-regressions.sh
git add scripts/native-tests/test-maven-regressions.sh
git commit -m "test: add Maven regression tests for issues #297, #414, #415, C5"
```
