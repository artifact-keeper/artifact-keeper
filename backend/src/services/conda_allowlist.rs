//! Package allowlist on a virtual conda channel (#4576).
//!
//! A virtual conda repository can restrict what its **remote** members
//! contribute to an approved set of packages. The list is enforced at the two
//! seams a conda client touches, and the two always agree:
//!
//! - the merged index (`repodata.json` in every encoding, and
//!   `channeldata.json`): a remote record the list does not admit is dropped,
//!   so the solver never sees it and reports the package as not found;
//! - the package download through the virtual: a filename the list does not
//!   admit is never fetched from (or served out of the cache of) a remote
//!   member, and answers the same 404 the index implies.
//!
//! Hosted (local and staging) members are not filtered: what they hold is
//! already curated by upload policy and promotion gates. The per-remote
//! upstream filter ([`crate::services::upstream_filter`]) stays an independent
//! backstop on the remote itself.
//!
//! # Entries and matching
//!
//! An entry is `{ "name": ..., "version": ..., "subdirs": [...] }`:
//!
//! - `name`: an exact conda package name, or a glob where `*` matches any run
//!   of characters and `?` one character. Matching is case-insensitive.
//! - `version` (optional): a conda version spec, evaluated with conda's own
//!   ordering through `rattler_conda_types` (the same implementation curation
//!   uses for conda repositories, #4040): `2.2.3` (exact; `2.2.3.0` is equal),
//!   `2.2.*`, `>=2,<3`, `1.0|1.1`, `!=1.5`, `~=1.2`, `*`. A record whose version
//!   does not parse is not admitted by a version-constrained entry (fail
//!   closed). Omitted or `*`: every version.
//! - `subdirs` (optional): the platforms the entry applies to (`noarch`,
//!   `linux-64`, ...). Omitted or empty: every subdir.
//!
//! A record is admitted when ANY entry admits it. A record is identified by
//! its filename (`<name>-<version>-<build>.conda|.tar.bz2`); in the index the
//! record's own `name` and `version` fields must be admitted too, so an
//! upstream record that claims a different identity than its filename is
//! dropped. A filename that does not have the conda shape is never admitted.
//!
//! `channeldata.json` is a per-name summary, so it is filtered by name only: a
//! remote entry is kept when some list entry's `name` admits it.
//!
//! # State
//!
//! `enabled` is explicit. An enabled list admits only what its entries admit,
//! so an enabled EMPTY list admits nothing from remote members. A disabled
//! list (or none at all) leaves the merge unfiltered. The list is stored as
//! JSON in `repository_config` under [`CONDA_ALLOWLIST_CONFIG_KEY`]; a stored
//! value that no longer parses or validates (only reachable by editing the
//! table directly) is enforced as admit-nothing, never as "no list".
//!
//! # Validation
//!
//! Bounded and validated on write, like the upstream filter: at most
//! [`MAX_ENTRIES`] entries, names up to [`MAX_NAME_LEN`] bytes of
//! `[a-z0-9_.-]` plus the glob characters, version specs up to
//! [`MAX_VERSION_LEN`] bytes that must parse, at most
//! [`MAX_SUBDIRS_PER_ENTRY`] subdirs per entry. The compiled form (exact names
//! in a hash map, globs and version specs pre-parsed) is built once per stored
//! value and reused until the value changes.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache as MokaCache;
use once_cell::sync::Lazy;
use rattler_conda_types::{ParseStrictness, Version, VersionSpec};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// `repository_config` key the allowlist is stored under (JSON value).
pub const CONDA_ALLOWLIST_CONFIG_KEY: &str = "conda_allowlist";

/// Maximum number of entries in one allowlist. A solved environment for a
/// few platforms is a few hundred to a few thousand (name, version) pairs.
pub const MAX_ENTRIES: usize = 10_000;

/// Maximum length, in bytes, of an entry's `name`.
pub const MAX_NAME_LEN: usize = 128;

/// Maximum length, in bytes, of an entry's `version` spec.
pub const MAX_VERSION_LEN: usize = 256;

/// Maximum number of `subdirs` on one entry.
pub const MAX_SUBDIRS_PER_ENTRY: usize = 32;

/// Maximum length, in bytes, of one subdir.
const MAX_SUBDIR_LEN: usize = 32;

/// One allowlist entry, as stored and as exchanged over the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    /// Exact conda package name, or a glob (`*`, `?`). Case-insensitive.
    pub name: String,
    /// Optional conda version spec (`2.2.3`, `2.2.*`, `>=2,<3`, `1.0|1.1`).
    /// Omitted: every version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional subdirs the entry applies to (`noarch`, `linux-64`, ...).
    /// Omitted or empty: every subdir.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subdirs: Vec<String>,
}

/// The allowlist of a virtual conda repository, as stored and as accepted by
/// `PUT /api/v1/repositories/{key}/allowlist`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CondaAllowlist {
    /// Whether the list is enforced. Required: an enabled empty list admits
    /// nothing from remote members.
    pub enabled: bool,
    /// The admitted packages.
    #[serde(default)]
    pub entries: Vec<AllowlistEntry>,
}

impl CondaAllowlist {
    /// Validate and compile. The error names the offending entry by index.
    pub fn compile(&self) -> std::result::Result<CompiledAllowlist, String> {
        if self.entries.len() > MAX_ENTRIES {
            return Err(format!(
                "entries: at most {MAX_ENTRIES} entries are allowed, got {}",
                self.entries.len()
            ));
        }
        let mut compiled = CompiledAllowlist {
            exact: HashMap::new(),
            globs: Vec::new(),
            rules: Vec::with_capacity(self.entries.len()),
            deny_all: false,
        };
        for (i, entry) in self.entries.iter().enumerate() {
            let rule = compile_entry(entry).map_err(|e| format!("entries[{i}]: {e}"))?;
            let idx = compiled.rules.len();
            if rule.name.contains(['*', '?']) {
                compiled.globs.push(idx);
            } else {
                compiled
                    .exact
                    .entry(rule.name.clone())
                    .or_default()
                    .push(idx);
            }
            compiled.rules.push(rule);
        }
        Ok(compiled)
    }
}

fn compile_entry(entry: &AllowlistEntry) -> std::result::Result<CompiledEntry, String> {
    let name = entry.name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if name.len() > MAX_NAME_LEN {
        return Err(format!("name exceeds {MAX_NAME_LEN} bytes"));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-*?".contains(*c)))
    {
        return Err(format!(
            "name {:?} contains {bad:?}; conda names are [a-z0-9_.-], plus * and ? as globs",
            entry.name
        ));
    }
    let version = match entry.version.as_deref().map(str::trim) {
        None | Some("") | Some("*") => None,
        Some(v) if v.len() > MAX_VERSION_LEN => {
            return Err(format!("version exceeds {MAX_VERSION_LEN} bytes"));
        }
        Some(v) => Some(
            VersionSpec::from_str(v, ParseStrictness::Lenient)
                .map_err(|e| format!("version {v:?} is not a conda version spec: {e}"))?,
        ),
    };
    if entry.subdirs.len() > MAX_SUBDIRS_PER_ENTRY {
        return Err(format!(
            "at most {MAX_SUBDIRS_PER_ENTRY} subdirs are allowed, got {}",
            entry.subdirs.len()
        ));
    }
    let mut subdirs = Vec::with_capacity(entry.subdirs.len());
    for s in &entry.subdirs {
        let s = s.trim();
        let valid = !s.is_empty()
            && s.len() <= MAX_SUBDIR_LEN
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if !valid {
            return Err(format!(
                "subdir {s:?} is not a conda subdir (e.g. noarch, linux-64)"
            ));
        }
        subdirs.push(s.to_string());
    }
    Ok(CompiledEntry {
        name,
        version,
        subdirs,
    })
}

#[derive(Debug, Clone)]
struct CompiledEntry {
    /// Lower-cased name or glob.
    name: String,
    /// `None`: every version.
    version: Option<VersionSpec>,
    /// Empty: every subdir.
    subdirs: Vec<String>,
}

impl CompiledEntry {
    fn admits_version(&self, version: &str, parsed: &mut Option<Option<Version>>) -> bool {
        let Some(spec) = &self.version else {
            return true;
        };
        // Parse at most once per record, and only when a constrained entry
        // needs it. Unparseable: not admitted (fail closed).
        let parsed = parsed.get_or_insert_with(|| Version::from_str(version.trim()).ok());
        parsed.as_ref().is_some_and(|v| spec.matches(v))
    }

    fn admits_subdir(&self, subdir: &str) -> bool {
        self.subdirs.is_empty() || self.subdirs.iter().any(|s| s == subdir)
    }
}

/// A validated, compiled [`CondaAllowlist`] (enabled lists only: a disabled
/// list is never compiled for enforcement).
#[derive(Debug, Clone)]
pub struct CompiledAllowlist {
    /// Exact name -> indices into `rules`.
    exact: HashMap<String, Vec<usize>>,
    /// Indices of glob-named rules.
    globs: Vec<usize>,
    rules: Vec<CompiledEntry>,
    /// Fail-closed stand-in for a stored value that no longer parses.
    deny_all: bool,
}

impl CompiledAllowlist {
    fn deny_all() -> Self {
        Self {
            exact: HashMap::new(),
            globs: Vec::new(),
            rules: Vec::new(),
            deny_all: true,
        }
    }

    /// The rules whose name admits `name` (already lower-cased).
    fn rules_for<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a CompiledEntry> + 'a {
        let exact = self
            .exact
            .get(name)
            .map(|v| v.as_slice())
            .unwrap_or_default();
        let globs = self
            .globs
            .iter()
            .filter(move |&&i| glob_match(&self.rules[i].name, name));
        exact.iter().chain(globs).map(|&i| &self.rules[i])
    }

    /// Whether the package `name` at `version` in `subdir` is admitted.
    pub fn admits(&self, name: &str, version: &str, subdir: &str) -> bool {
        if self.deny_all {
            return false;
        }
        let name = fold(name);
        let mut parsed = None;
        let admitted = self
            .rules_for(&name)
            .any(|r| r.admits_subdir(subdir) && r.admits_version(version, &mut parsed));
        admitted
    }

    /// Whether some entry admits the package name at all, whatever its
    /// version or subdir (the `channeldata.json` test).
    pub fn admits_name(&self, name: &str) -> bool {
        if self.deny_all {
            return false;
        }
        let name = fold(name);
        let admitted = self.rules_for(&name).next().is_some();
        admitted
    }

    /// Whether some entry admits EVERY version of `name` in `subdir`: an
    /// entry without a version constraint whose name matches and whose
    /// subdirs include `subdir`.
    ///
    /// A CEP-16 shard carries every version of its package and is addressed
    /// by the hash of its bytes, so the sharded view of a virtual channel
    /// (#4577) can admit a remote package only whole. A name admitted under a
    /// version constraint is left out of the shard index and stays available
    /// through `repodata.json`, where records are filtered one by one.
    pub fn admits_all_versions(&self, name: &str, subdir: &str) -> bool {
        if self.deny_all {
            return false;
        }
        let name = fold(name);
        let admitted = self.rules_for(&name).any(|r| {
            r.admits_subdir(subdir)
                && match &r.version {
                    None => true,
                    Some(spec) => matches!(spec, VersionSpec::Any),
                }
        });
        admitted
    }

    /// Whether the package file `filename` in `subdir` is admitted, by the
    /// name and version its filename carries. A filename without the conda
    /// `<name>-<version>-<build>.conda|.tar.bz2` shape is not.
    pub fn admits_filename(&self, subdir: &str, filename: &str) -> bool {
        match split_conda_filename(filename) {
            Some((name, version)) => self.admits(name, version, subdir),
            None => false,
        }
    }
}

fn fold(name: &str) -> std::borrow::Cow<'_, str> {
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(name.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(name)
    }
}

/// `(name, version)` of a conda package filename
/// (`<name>-<version>-<build>.conda` or `.tar.bz2`). Version and build never
/// contain `-` (CEP-26), so the split is on the last two hyphens.
pub fn split_conda_filename(filename: &str) -> Option<(&str, &str)> {
    let stem = filename
        .strip_suffix(".conda")
        .or_else(|| filename.strip_suffix(".tar.bz2"))?;
    let mut parts = stem.rsplitn(3, '-');
    let _build = parts.next().filter(|s| !s.is_empty())?;
    let version = parts.next().filter(|s| !s.is_empty())?;
    let name = parts.next().filter(|s| !s.is_empty())?;
    Some((name, version))
}

/// Glob match on ASCII names: `*` any run, `?` one character. Linear-time
/// two-pointer form with one backtrack point, so a pattern of many `*` cannot
/// blow up on a long name.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// What is stored for a repository, as the read API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredAllowlist {
    /// No allowlist configured: remote members are not filtered.
    None,
    /// A valid list, enforced as stored when `enabled`.
    Valid(CondaAllowlist),
    /// A stored value that no longer parses or validates. Enforced as
    /// admit-nothing.
    Unusable(String),
}

fn parse_stored(raw: &str) -> std::result::Result<(CondaAllowlist, CompiledAllowlist), String> {
    let list = serde_json::from_str::<CondaAllowlist>(raw)
        .map_err(|e| format!("stored value is not a valid allowlist: {e}"))?;
    let compiled = list.compile()?;
    Ok((list, compiled))
}

async fn load_raw(db: &PgPool, repo_id: Uuid) -> Result<Option<String>> {
    sqlx::query_scalar("SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2")
        .bind(repo_id)
        .bind(CONDA_ALLOWLIST_CONFIG_KEY)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

/// Load the stored list for display.
pub async fn load_allowlist(db: &PgPool, repo_id: Uuid) -> Result<StoredAllowlist> {
    Ok(match load_raw(db, repo_id).await? {
        None => StoredAllowlist::None,
        Some(raw) => match parse_stored(&raw) {
            Ok((list, _)) => StoredAllowlist::Valid(list),
            Err(e) => StoredAllowlist::Unusable(e),
        },
    })
}

/// Validate and persist `list` (enabled or not).
pub async fn save_allowlist(db: &PgPool, repo_id: Uuid, list: &CondaAllowlist) -> Result<()> {
    list.compile().map_err(AppError::Validation)?;
    let value = serde_json::to_string(list)
        .map_err(|e| AppError::Internal(format!("Failed to serialize allowlist: {e}")))?;
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $3, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(CONDA_ALLOWLIST_CONFIG_KEY)
    .bind(&value)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Remove the list (idempotent). Returns whether a row was removed.
pub async fn delete_allowlist(db: &PgPool, repo_id: Uuid) -> Result<bool> {
    let done = sqlx::query("DELETE FROM repository_config WHERE repository_id = $1 AND key = $2")
        .bind(repo_id)
        .bind(CONDA_ALLOWLIST_CONFIG_KEY)
        .execute(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(done.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// Compiled lists keyed by repository, each with the raw value it was compiled
/// from. The raw value is re-read on every use (one small row), so a change is
/// seen at once on every replica; only the compile is reused.
type CacheEntry = Arc<(String, Option<Arc<CompiledAllowlist>>)>;

static COMPILED: Lazy<MokaCache<Uuid, CacheEntry>> = Lazy::new(|| {
    MokaCache::builder()
        .max_capacity(1_000)
        .time_to_idle(Duration::from_secs(600))
        .build()
});

/// Compile a raw stored value for enforcement: `None` for a disabled list,
/// admit-nothing for one that no longer parses.
fn compile_for_enforcement(repo_id: Uuid, raw: &str) -> Option<Arc<CompiledAllowlist>> {
    match parse_stored(raw) {
        Ok((list, compiled)) => list.enabled.then(|| Arc::new(compiled)),
        Err(err) => {
            tracing::error!(
                repository_id = %repo_id,
                error = %err,
                "stored conda allowlist is unusable; admitting nothing from remote members until it is replaced"
            );
            Some(Arc::new(CompiledAllowlist::deny_all()))
        }
    }
}

/// The enforced allowlist of the virtual repository `repo_id`: `Ok(None)`
/// when none is configured or it is disabled. A database error is returned,
/// never treated as "no list" (callers fail closed).
pub async fn enforced_allowlist(
    db: &PgPool,
    repo_id: Uuid,
) -> Result<Option<Arc<CompiledAllowlist>>> {
    let Some(raw) = load_raw(db, repo_id).await? else {
        return Ok(None);
    };
    if let Some(hit) = COMPILED.get(&repo_id).await {
        if hit.0 == raw {
            return Ok(hit.1.clone());
        }
    }
    let compiled = compile_for_enforcement(repo_id, &raw);
    COMPILED
        .insert(repo_id, Arc::new((raw, compiled.clone())))
        .await;
    Ok(compiled)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, version: Option<&str>, subdirs: &[&str]) -> AllowlistEntry {
        AllowlistEntry {
            name: name.to_string(),
            version: version.map(str::to_string),
            subdirs: subdirs.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn compiled(entries: Vec<AllowlistEntry>) -> CompiledAllowlist {
        CondaAllowlist {
            enabled: true,
            entries,
        }
        .compile()
        .expect("valid allowlist")
    }

    #[test]
    fn empty_list_admits_nothing() {
        let list = compiled(vec![]);
        assert!(!list.admits("numpy", "2.2.3", "linux-64"));
        assert!(!list.admits_name("numpy"));
    }

    #[test]
    fn exact_name_admits_every_version_and_subdir() {
        let list = compiled(vec![entry("numpy", None, &[])]);
        assert!(list.admits("numpy", "2.2.3", "linux-64"));
        assert!(list.admits("numpy", "1.0", "osx-arm64"));
        assert!(list.admits("NumPy", "1.0", "noarch"), "case-insensitive");
        assert!(!list.admits("numpy-base", "2.2.3", "linux-64"));
        assert!(!list.admits("colorama", "0.4.6", "noarch"));
        // No version constraint: even an unparseable version is admitted.
        assert!(list.admits("numpy", "not a version!", "linux-64"));
    }

    #[test]
    fn version_spec_uses_conda_semantics_and_fails_closed() {
        let list = compiled(vec![entry("numpy", Some(">=2,<3"), &[])]);
        assert!(list.admits("numpy", "2.2.3", "linux-64"));
        assert!(!list.admits("numpy", "1.26.4", "linux-64"));
        assert!(!list.admits("numpy", "3.0", "linux-64"));
        // Conda ordering: 3.0a1 is a pre-release of 3.0, so it is < 3.
        assert!(list.admits("numpy", "3.0a1", "linux-64"));
        assert!(
            !list.admits("numpy", "&&", "linux-64"),
            "unparseable fails closed"
        );

        let exact = compiled(vec![entry("tzdata", Some("2025b"), &[])]);
        assert!(exact.admits("tzdata", "2025b", "noarch"));
        assert!(!exact.admits("tzdata", "2025a", "noarch"));
        let pinned = compiled(vec![entry("numpy", Some("2.2.3"), &[])]);
        assert!(
            pinned.admits("numpy", "2.2.3.0", "linux-64"),
            "trailing zeros are equal"
        );
        assert!(!pinned.admits("numpy", "2.2.30", "linux-64"));
        let prefix = compiled(vec![entry("numpy", Some("2.2.*"), &[])]);
        assert!(prefix.admits("numpy", "2.2.3", "linux-64"));
        assert!(!prefix.admits("numpy", "2.3.0", "linux-64"));
        let either = compiled(vec![entry("numpy", Some("1.26.4|2.2.3"), &[])]);
        assert!(either.admits("numpy", "1.26.4", "linux-64"));
        assert!(either.admits("numpy", "2.2.3", "linux-64"));
        assert!(!either.admits("numpy", "2.0", "linux-64"));
        let any = compiled(vec![entry("numpy", Some("*"), &[])]);
        assert!(any.admits("numpy", "whatever", "linux-64"));
    }

    #[test]
    fn subdirs_restrict_the_entry() {
        let list = compiled(vec![entry(
            "python",
            Some("3.13.*"),
            &["linux-64", "osx-arm64"],
        )]);
        assert!(list.admits("python", "3.13.2", "linux-64"));
        assert!(list.admits("python", "3.13.2", "osx-arm64"));
        assert!(!list.admits("python", "3.13.2", "win-64"));
        assert!(!list.admits("python", "3.13.2", "noarch"));
        assert!(list.admits_name("python"));
    }

    #[test]
    fn any_entry_admits() {
        let list = compiled(vec![
            entry("numpy", Some("1.26.4"), &["linux-64"]),
            entry("numpy", Some("2.2.3"), &["osx-arm64"]),
        ]);
        assert!(list.admits("numpy", "1.26.4", "linux-64"));
        assert!(list.admits("numpy", "2.2.3", "osx-arm64"));
        assert!(!list.admits("numpy", "2.2.3", "linux-64"));
    }

    #[test]
    fn glob_names() {
        let list = compiled(vec![entry("lib*", None, &[]), entry("py?", None, &[])]);
        assert!(list.admits("libzlib", "1.3.1", "linux-64"));
        assert!(list.admits("lib", "1", "linux-64"));
        assert!(list.admits("pyc", "1", "noarch"));
        assert!(!list.admits("pyca", "1", "noarch"));
        assert!(!list.admits("zlib", "1.3.1", "linux-64"));
        assert!(list.admits_name("libgcc-ng"));
        let everything = compiled(vec![entry("*", None, &[])]);
        assert!(everything.admits("anything", "1", "noarch"));
    }

    #[test]
    fn glob_match_is_linear_and_correct() {
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
        assert!(glob_match("*-ng", "libgcc-ng"));
        assert!(glob_match("**", ""));
        assert!(!glob_match("?", ""));
        let pattern = "*a".repeat(60);
        let text = "a".repeat(127) + "b";
        let start = std::time::Instant::now();
        assert!(!glob_match(&pattern, &text));
        assert!(start.elapsed() < std::time::Duration::from_millis(50));
    }

    #[test]
    fn filenames_are_split_on_the_last_two_hyphens() {
        assert_eq!(
            split_conda_filename("numpy-base-2.2.3-py313h17eae1a_0.conda"),
            Some(("numpy-base", "2.2.3"))
        );
        assert_eq!(
            split_conda_filename("tzdata-2025b-h78e105d_0.tar.bz2"),
            Some(("tzdata", "2025b"))
        );
        assert_eq!(split_conda_filename("numpy-2.2.3.conda"), None);
        assert_eq!(split_conda_filename("numpy-2.2.3-0.whl"), None);
        let list = compiled(vec![entry("numpy", Some(">=2"), &["linux-64"])]);
        assert!(list.admits_filename("linux-64", "numpy-2.2.3-py313h17eae1a_0.conda"));
        assert!(!list.admits_filename("linux-64", "numpy-1.26.4-py312h_0.conda"));
        assert!(!list.admits_filename("noarch", "numpy-2.2.3-py313h17eae1a_0.conda"));
        assert!(!list.admits_filename("linux-64", "repodata.json"));
    }

    #[test]
    fn deny_all_admits_nothing() {
        let list = CompiledAllowlist::deny_all();
        assert!(!list.admits("numpy", "1", "noarch"));
        assert!(!list.admits_name("numpy"));
    }

    #[test]
    fn invalid_entries_are_rejected_naming_the_index() {
        let bad = |e: AllowlistEntry| {
            CondaAllowlist {
                enabled: true,
                entries: vec![entry("ok", None, &[]), e],
            }
            .compile()
            .unwrap_err()
        };
        assert!(bad(entry("", None, &[])).starts_with("entries[1]: "));
        assert!(bad(entry("num py", None, &[])).contains("conda names"));
        assert!(bad(entry("numpy/../x", None, &[])).contains("conda names"));
        assert!(bad(entry(&"a".repeat(MAX_NAME_LEN + 1), None, &[])).contains("exceeds"));
        assert!(bad(entry("numpy", Some(">=>2"), &[])).contains("not a conda version spec"));
        assert!(bad(entry("numpy", Some("1.0 2.0"), &[])).contains("not a conda version spec"));
        assert!(
            bad(entry("numpy", Some(&"1".repeat(MAX_VERSION_LEN + 1)), &[])).contains("exceeds")
        );
        assert!(bad(entry("numpy", None, &["Linux-64"])).contains("subdir"));
        assert!(bad(entry("numpy", None, &[""])).contains("subdir"));
        let many_subdirs: Vec<&str> = vec!["noarch"; MAX_SUBDIRS_PER_ENTRY + 1];
        assert!(bad(entry("numpy", None, &many_subdirs)).contains("subdirs"));
        let too_many = CondaAllowlist {
            enabled: true,
            entries: vec![entry("numpy", None, &[]); MAX_ENTRIES + 1],
        };
        assert!(too_many.compile().unwrap_err().contains("at most"));
    }

    #[test]
    fn wire_format_is_strict_and_round_trips() {
        let list: CondaAllowlist = serde_json::from_str(
            r#"{"enabled":true,"entries":[{"name":"numpy","version":">=2,<3","subdirs":["linux-64"]},{"name":"tzdata"}]}"#,
        )
        .unwrap();
        assert_eq!(list.entries.len(), 2);
        assert_eq!(
            serde_json::to_value(&list).unwrap(),
            serde_json::json!({"enabled":true,"entries":[
                {"name":"numpy","version":">=2,<3","subdirs":["linux-64"]},
                {"name":"tzdata"}
            ]})
        );
        // `enabled` is explicit and unknown fields are refused.
        assert!(serde_json::from_str::<CondaAllowlist>(r#"{"entries":[]}"#).is_err());
        assert!(serde_json::from_str::<CondaAllowlist>(
            r#"{"enabled":true,"entries":[{"name":"numpy","build":"x"}]}"#
        )
        .is_err());
    }

    /// #4577: a shard is admitted whole or not at all, so only an entry
    /// without a version constraint admits a name into the sharded view.
    #[test]
    fn admits_all_versions_requires_an_unconstrained_entry() {
        let list = compiled(vec![
            entry("tzdata", None, &[]),
            entry("numpy", Some(">=2,<3"), &["linux-64"]),
            entry("ri*", Some("*"), &[]),
            entry("scipy", None, &["osx-arm64"]),
        ]);
        assert!(list.admits_all_versions("tzdata", "noarch"));
        assert!(list.admits_all_versions("TZDATA", "linux-64"));
        // `*` is no constraint.
        assert!(list.admits_all_versions("rich", "noarch"));
        // A version constraint admits records one by one, never the shard.
        assert!(!list.admits_all_versions("numpy", "linux-64"));
        assert!(list.admits("numpy", "2.2.3", "linux-64"));
        // Subdirs still apply.
        assert!(list.admits_all_versions("scipy", "osx-arm64"));
        assert!(!list.admits_all_versions("scipy", "linux-64"));
        assert!(!list.admits_all_versions("absent", "noarch"));
        assert!(!CompiledAllowlist::deny_all().admits_all_versions("tzdata", "noarch"));
    }

    #[test]
    fn unusable_stored_value_is_enforced_as_admit_nothing() {
        let id = Uuid::new_v4();
        let enforced = compile_for_enforcement(id, "{not json").expect("enforced");
        assert!(!enforced.admits("numpy", "1", "noarch"));
        assert!(compile_for_enforcement(id, r#"{"enabled":false,"entries":[]}"#).is_none());
        let on = compile_for_enforcement(id, r#"{"enabled":true,"entries":[{"name":"numpy"}]}"#)
            .expect("enabled");
        assert!(on.admits("numpy", "1", "noarch"));
    }
}
