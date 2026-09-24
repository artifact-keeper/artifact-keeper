//! Environment SBOM: the lockfile graph as CycloneDX / SPDX documents (#4053).
//!
//! [`crate::services::environment_lock`] parses a lockfile into a solved
//! environment — packages and `dependant -> dependency` edges, scoped per
//! (environment, platform). This module renders that graph as SBOM documents.
//!
//! # N graphs, N documents
//!
//! A conda environment is N graphs, one per subdir: `depends`/`constrains`
//! resolve differently per platform, so one document covering `linux-64` and
//! `osx-arm64` at once is wrong for both. This module therefore emits **one
//! document per [`Scope`]**, and every node and edge in a document comes from
//! that scope alone — there is no cross-platform edge leakage by construction,
//! because no scope's generator ever sees another scope's rows. Formats with a
//! single global scope (`Cargo.lock`, `uv.lock`, …) yield exactly one
//! document.
//!
//! # Identity: the qualified purl is the bom-ref
//!
//! Conda components are identified by the qualified purl of #4041
//! ([`CondaPurl`]: name, version, build, channel, subdir), so two builds of
//! one name/version on two subdirs are two components with two bom-refs, and a
//! bom-ref is stable for a given (package, subdir). Other ecosystems use their
//! conventional purl type (`pkg:pypi/…`, `pkg:npm/…`, `pkg:cargo/…`). A
//! package whose coordinates cannot form a purl (no recorded version, an npm
//! workspace link) falls back to a ref derived from its lockfile key, and any
//! residual collision is disambiguated with a numeric suffix — uniqueness
//! within a document is enforced, never assumed.
//!
//! # Edges
//!
//! CycloneDX expresses the graph as `dependencies[].dependsOn` over bom-refs;
//! SPDX as `relationships[]` of type `DEPENDS_ON`. Edges come from the
//! lockfile parser's resolved [`LockEdge`]s — never from re-resolving repodata
//! — so a document says exactly what the lockfile says. A conda `constrains`
//! entry is *not* an install requirement and must not masquerade as one: it is
//! carried as an `artifact-keeper:constrains` property on the constraining
//! component instead of a graph edge. Conda virtual packages (`__glibc`,
//! `__cuda`, `__osx`) describe the host, not an installed package; the parser
//! already records them as explained absences, so they appear in no document
//! as nodes and a fortiori leak no edges anywhere.
//!
//! # The root layer
//!
//! "You asked for pillow" is the layer that makes a finding actionable. Where
//! the format records the project itself (npm v2/v3, `uv.lock`) that root node
//! is in the graph already; where it does not, the lockfile records only the
//! solved set and the best available root layer is the packages nothing else
//! depends on — the same convention [`LockedEnvironment::explain`] uses.
//! Either way the document's own root — CycloneDX `metadata.component`, an
//! SPDX `SPDXRef-Environment` package `DESCRIBE`d by the document — depends on
//! exactly the in-degree-zero nodes of the emitted graph.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{json, Value};

use crate::models::sbom::SbomFormat;
use crate::services::conda_identity::CondaPurl;
use crate::services::environment_lock::{
    Ecosystem, EdgeKind, LockFormat, LockedEnvironment, LockedPackage, PackageHash, Scope,
};

/// Property namespaced so it cannot collide with a scanner-produced property.
pub const PROP_LOCKFILE_FORMAT: &str = "artifact-keeper:lockfile-format";
/// Scope axis recorded on the document's root component, when the format has one.
pub const PROP_ENVIRONMENT: &str = "artifact-keeper:environment";
/// Scope axis recorded on the document's root component, when the format has one.
pub const PROP_PLATFORM: &str = "artifact-keeper:platform";
/// The ecosystem a component was locked from (conda, pypi, npm, cargo).
pub const PROP_ECOSYSTEM: &str = "artifact-keeper:ecosystem";
/// A conda `constrains` requirement: not an install edge, recorded as data.
pub const PROP_CONSTRAINS: &str = "artifact-keeper:constrains";

/// One scope's SBOM document.
#[derive(Debug, Clone)]
pub struct ScopedSbom {
    /// The graph this document renders. Every node and edge in `document`
    /// belongs to this scope.
    pub scope: Scope,
    pub document: Value,
}

/// An environment rendered as SBOM documents: one per scope, sorted.
#[derive(Debug, Clone)]
pub struct EnvironmentSbom {
    pub format: SbomFormat,
    pub documents: Vec<ScopedSbom>,
}

impl EnvironmentSbom {
    /// The document for one scope, if that graph exists.
    pub fn document_for(&self, scope: &Scope) -> Option<&Value> {
        self.documents
            .iter()
            .find(|d| &d.scope == scope)
            .map(|d| &d.document)
    }
}

/// Render every graph of `env` as one SBOM document per scope.
///
/// `name` is the human-facing environment name (typically the lockfile's file
/// name); it becomes each document's root component name.
pub fn generate_environment_sbom(
    env: &LockedEnvironment,
    name: &str,
    format: SbomFormat,
) -> EnvironmentSbom {
    let documents = env
        .scopes()
        .into_iter()
        .map(|scope| {
            let graph = ScopeGraph::build(env, &scope);
            let document = match format {
                SbomFormat::CycloneDX => cyclonedx_document(env, name, &graph),
                SbomFormat::SPDX => spdx_document(env, name, &graph),
            };
            ScopedSbom { scope, document }
        })
        .collect();
    EnvironmentSbom { format, documents }
}

// ---------------------------------------------------------------------------
// One scope's graph, ready to render
// ---------------------------------------------------------------------------

/// The graph of a single [`Scope`], with every document-level decision
/// (node ids, root layer, which edges are edges at all) already taken.
struct ScopeGraph<'a> {
    scope: Scope,
    lock_format: LockFormat,
    packages: Vec<&'a LockedPackage>,
    /// Document node id per package, unique within this graph.
    refs: Vec<String>,
    /// The purl per package, when its coordinates form one.
    purls: Vec<Option<String>>,
    /// Emitted dependency edges, `from -> {to}` by package index.
    edges: BTreeMap<usize, BTreeSet<usize>>,
    /// `constrains` requirement text per package index, for the property.
    constrains: BTreeMap<usize, Vec<String>>,
    /// Package indexes nothing (emitted) points at: the root layer.
    roots: BTreeSet<usize>,
}

impl<'a> ScopeGraph<'a> {
    fn build(env: &'a LockedEnvironment, scope: &Scope) -> Self {
        let packages: Vec<&LockedPackage> = env.packages_in(scope).collect();
        let key_to_index: HashMap<&str, usize> = packages
            .iter()
            .enumerate()
            .map(|(idx, pkg)| (pkg.key.as_str(), idx))
            .collect();

        let mut edges: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        let mut constrains: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        for edge in env.edges_in(scope) {
            // Both ends are keys of packages in this same scope by parser
            // construction; a miss would be a parser bug, so skip defensively
            // rather than panic on a document we are only rendering.
            let (Some(from), Some(to)) = (
                key_to_index.get(edge.from.as_str()),
                key_to_index.get(edge.to.as_str()),
            ) else {
                continue;
            };
            match edge.kind {
                // A constrains entry is not an install requirement; it must
                // not become a dependsOn/DEPENDS_ON fact. It is kept as data.
                EdgeKind::Constrains => {
                    constrains
                        .entry(*from)
                        .or_default()
                        .push(edge.requirement.clone());
                }
                _ => {
                    edges.entry(*from).or_default().insert(*to);
                }
            }
        }

        let mut refs = Vec::with_capacity(packages.len());
        let mut purls = Vec::with_capacity(packages.len());
        let mut seen: HashMap<String, usize> = HashMap::new();
        for pkg in &packages {
            let (base, purl) = node_ref(pkg, scope);
            let count = seen.entry(base.clone()).or_insert(0);
            *count += 1;
            // Uniqueness is enforced, never assumed: two packages that render
            // to the same ref (same name/version on one platform with no
            // build recorded) get a stable ordinal suffix.
            let rendered = if *count == 1 {
                base.clone()
            } else {
                format!("{}#{}", base, count)
            };
            refs.push(rendered);
            purls.push(purl);
        }

        let depended_on: BTreeSet<usize> = edges.values().flatten().copied().collect();
        let roots: BTreeSet<usize> = (0..packages.len())
            .filter(|idx| !depended_on.contains(idx))
            .collect();

        ScopeGraph {
            scope: scope.clone(),
            lock_format: env.format,
            packages,
            refs,
            purls,
            edges,
            constrains,
            roots,
        }
    }
}

/// The document node id and purl for one package. The id IS the purl whenever
/// one can be formed — the #4041 qualified identity for conda, the
/// conventional purl type elsewhere — so a bom-ref is stable per
/// (package, subdir). Packages whose coordinates cannot form a purl fall back
/// to a ref derived from their lockfile key, which the parser guarantees
/// unique within the scope.
fn node_ref(pkg: &LockedPackage, scope: &Scope) -> (String, Option<String>) {
    match package_purl(pkg, scope) {
        Some(purl) => (purl.clone(), Some(purl)),
        None => (
            format!("ak:lock:{}:{}", pkg.ecosystem.as_str(), pkg.key),
            None,
        ),
    }
}

/// The purl one locked package forms from its coordinates, if any: the
/// #4041 qualified identity for conda, the conventional purl type elsewhere.
///
/// `pub(crate)` so the stored-environment reverse index (#4054,
/// [`crate::services::environment_service`]) keys memberships on exactly the
/// identity these documents render — two derivations of "the purl of this
/// package" would drift.
pub(crate) fn package_purl(pkg: &LockedPackage, scope: &Scope) -> Option<String> {
    match pkg.ecosystem {
        Ecosystem::Conda => {
            let version = pkg.version.as_deref()?;
            let build = pkg.build.as_deref().unwrap_or("");
            // The package's *own* subdir is the identity-bearing one (#4151):
            // a `noarch` build resolved into a `linux-64` scope keeps
            // `subdir=noarch`, which is what
            // [`crate::services::conda_identity::artifact_purl_from_metadata`]
            // derives from the same build's `info/index.json`. Keying on the
            // scope platform instead would give one noarch build N identities
            // across N platforms, none of them the artifact's.
            //
            // The scope platform is the fallback for a lockfile that records
            // no subdir -- and, because the attempt is a whole `from_index`,
            // for one that records a subdir `CondaPurl` rejects, so a
            // malformed field costs a component no identity it had before.
            let mut identity = pkg
                .subdir
                .as_deref()
                .and_then(|subdir| CondaPurl::from_index(&pkg.name, version, build, subdir).ok())
                .or_else(|| {
                    let platform = scope.platform.as_deref()?;
                    CondaPurl::from_index(&pkg.name, version, build, platform).ok()
                })?;
            let channel = pkg
                .source
                .as_deref()
                .or_else(|| pkg.url.as_deref().and_then(channel_from_url));
            if let Some(channel) = channel {
                identity = identity.with_channel(channel);
            }
            Some(identity.to_purl())
        }
        // PEP 503 normalisation keeps `Zope.Interface` and `zope-interface`
        // from becoming two components.
        Ecosystem::PyPi => Some(with_version(
            format!("pkg:pypi/{}", Ecosystem::PyPi.normalize(&pkg.name)),
            pkg.version.as_deref(),
        )),
        Ecosystem::Npm => Some(with_version(
            format!("pkg:npm/{}", npm_purl_name(&pkg.name)),
            pkg.version.as_deref(),
        )),
        Ecosystem::Cargo => Some(with_version(
            format!("pkg:cargo/{}", pkg.name.trim()),
            pkg.version.as_deref(),
        )),
    }
}

fn with_version(base: String, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("{}@{}", base, version),
        _ => base,
    }
}

/// An npm scoped name (`@scope/pkg`) as a purl path (`%40scope/pkg`).
fn npm_purl_name(name: &str) -> String {
    match name.strip_prefix('@') {
        Some(rest) => format!("%40{}", rest),
        None => name.to_string(),
    }
}

/// The channel a package URL encodes: the directory above the artifact file,
/// with the trailing subdir segment left for [`CondaPurl::with_channel`] to
/// drop (`…/conda-forge/linux-64/pkg.conda` -> `…/conda-forge/linux-64` ->
/// `conda-forge`).
fn channel_from_url(url: &str) -> Option<&str> {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    let (directory, file) = without_query.rsplit_once('/')?;
    if file.is_empty() || directory.is_empty() {
        return None;
    }
    Some(directory)
}

/// The document root's node id: stable per (format, scope).
fn root_ref(lock_format: LockFormat, scope: &Scope) -> String {
    match (&scope.environment, &scope.platform) {
        (Some(environment), Some(platform)) => format!(
            "ak:environment:{}:{}/{}",
            lock_format.as_str(),
            environment,
            platform
        ),
        (Some(environment), None) => {
            format!("ak:environment:{}:{}", lock_format.as_str(), environment)
        }
        (None, Some(platform)) => {
            format!("ak:environment:{}:{}", lock_format.as_str(), platform)
        }
        (None, None) => format!("ak:environment:{}", lock_format.as_str()),
    }
}

/// The root component's display name.
fn root_name(name: &str, scope: &Scope) -> String {
    if scope.environment.is_none() && scope.platform.is_none() {
        name.to_string()
    } else {
        format!("{} ({})", name, scope)
    }
}

fn root_properties(lock_format: LockFormat, scope: &Scope) -> Vec<Value> {
    let mut props = vec![json!({
        "name": PROP_LOCKFILE_FORMAT,
        "value": lock_format.as_str(),
    })];
    if let Some(environment) = &scope.environment {
        props.push(json!({"name": PROP_ENVIRONMENT, "value": environment}));
    }
    if let Some(platform) = &scope.platform {
        props.push(json!({"name": PROP_PLATFORM, "value": platform}));
    }
    props
}

/// CycloneDX hash algorithm names; an algorithm CycloneDX does not enumerate
/// is dropped rather than emitted as a value the schema forbids.
fn cyclonedx_hash(hash: &PackageHash) -> Option<Value> {
    let alg = match hash.algorithm.as_str() {
        "sha256" => "SHA-256",
        "sha512" => "SHA-512",
        "sha384" => "SHA-384",
        "sha1" => "SHA-1",
        "md5" => "MD5",
        _ => return None,
    };
    Some(json!({"alg": alg, "content": hash.value}))
}

/// SPDX checksum algorithm names, same drop-unknown rule.
fn spdx_checksum(hash: &PackageHash) -> Option<Value> {
    let algorithm = match hash.algorithm.as_str() {
        "sha256" => "SHA256",
        "sha512" => "SHA512",
        "sha384" => "SHA384",
        "sha1" => "SHA1",
        "md5" => "MD5",
        _ => return None,
    };
    Some(json!({"algorithm": algorithm, "checksumValue": hash.value}))
}

// ---------------------------------------------------------------------------
// CycloneDX 1.5
// ---------------------------------------------------------------------------

fn cyclonedx_document(env: &LockedEnvironment, name: &str, graph: &ScopeGraph) -> Value {
    let root_ref = root_ref(graph.lock_format, &graph.scope);

    let components: Vec<Value> = graph
        .packages
        .iter()
        .enumerate()
        .map(|(idx, pkg)| {
            let mut component = json!({
                "bom-ref": graph.refs[idx],
                "type": "library",
                "name": pkg.name,
            });
            if let Some(version) = &pkg.version {
                component["version"] = json!(version);
            }
            if let Some(purl) = &graph.purls[idx] {
                component["purl"] = json!(purl);
            }
            let hashes: Vec<Value> = pkg.hashes.iter().filter_map(cyclonedx_hash).collect();
            if !hashes.is_empty() {
                component["hashes"] = json!(hashes);
            }
            let mut properties = vec![json!({
                "name": PROP_ECOSYSTEM,
                "value": pkg.ecosystem.as_str(),
            })];
            if let Some(requirements) = graph.constrains.get(&idx) {
                for requirement in requirements {
                    properties.push(json!({"name": PROP_CONSTRAINS, "value": requirement}));
                }
            }
            component["properties"] = json!(properties);
            component
        })
        .collect();

    // The dependencies section declares every node, leaves included, so the
    // section and the component list can never disagree about membership.
    let mut dependencies: Vec<Value> = Vec::with_capacity(graph.packages.len() + 1);
    let root_targets: Vec<&str> = graph
        .roots
        .iter()
        .map(|idx| graph.refs[*idx].as_str())
        .collect();
    dependencies.push(json!({"ref": root_ref, "dependsOn": root_targets}));
    for (idx, _) in graph.packages.iter().enumerate() {
        let targets: Vec<&str> = graph
            .edges
            .get(&idx)
            .map(|set| set.iter().map(|to| graph.refs[*to].as_str()).collect())
            .unwrap_or_default();
        dependencies.push(json!({"ref": graph.refs[idx], "dependsOn": targets}));
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "tools": [{
                "vendor": "Artifact Keeper",
                "name": "artifact-keeper",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "component": {
                "bom-ref": root_ref,
                "type": "platform",
                "name": root_name(name, &graph.scope),
                "properties": root_properties(graph.lock_format, &graph.scope),
            },
        },
        "components": components,
        "dependencies": dependencies,
        // `env` is the parse result; its unresolved rows say how much of the
        // lockfile the graph covers, which is metadata about the document,
        // not a component of it.
        "properties": coverage_properties(env, &graph.scope),
    })
}

/// `artifact-keeper:unresolved` markers so "we understood 380 of 400" stays
/// visible to a document consumer. Counts are per-scope.
fn coverage_properties(env: &LockedEnvironment, scope: &Scope) -> Vec<Value> {
    let mut unparsed = 0usize;
    let mut missing = 0usize;
    for entry in &env.unresolved {
        if &entry.scope == scope || entry.scope == Scope::global() {
            match entry.kind {
                crate::services::environment_lock::UnresolvedKind::Unparsed => unparsed += 1,
                crate::services::environment_lock::UnresolvedKind::MissingDependency => {
                    missing += 1
                }
                _ => {}
            }
        }
    }
    let mut props = Vec::new();
    if unparsed > 0 {
        props.push(
            json!({"name": "artifact-keeper:unparsed-entries", "value": unparsed.to_string()}),
        );
    }
    if missing > 0 {
        props.push(
            json!({"name": "artifact-keeper:missing-dependencies", "value": missing.to_string()}),
        );
    }
    props
}

// ---------------------------------------------------------------------------
// SPDX 2.3
// ---------------------------------------------------------------------------

const SPDX_ENVIRONMENT_ID: &str = "SPDXRef-Environment";

/// An SPDXID for one package: stable per package, restricted to the charset
/// the specification allows (`[A-Za-z0-9.-]` after the `SPDXRef-` prefix).
fn spdx_ids(graph: &ScopeGraph) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    graph
        .packages
        .iter()
        .enumerate()
        .map(|(idx, pkg)| {
            fn sanitize(raw: &str) -> String {
                raw.chars()
                    .map(|ch| {
                        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
                            ch
                        } else {
                            '-'
                        }
                    })
                    .collect()
            }
            let mut slug = sanitize(&pkg.name);
            if let Some(version) = &pkg.version {
                slug.push('-');
                slug.push_str(&sanitize(version));
            }
            if let Some(build) = &pkg.build {
                slug.push('-');
                slug.push_str(&sanitize(build));
            }
            if slug.is_empty() {
                slug = format!("pkg{}", idx);
            }
            let count = seen.entry(slug.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                format!("SPDXRef-Package-{}", slug)
            } else {
                format!("SPDXRef-Package-{}-{}", slug, count)
            }
        })
        .collect()
}

fn spdx_document(env: &LockedEnvironment, name: &str, graph: &ScopeGraph) -> Value {
    let ids = spdx_ids(graph);

    let mut packages: Vec<Value> = Vec::with_capacity(graph.packages.len() + 1);
    packages.push(json!({
        "SPDXID": SPDX_ENVIRONMENT_ID,
        "name": root_name(name, &graph.scope),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "comment": format!(
            "{} environment ({}), locked by {}",
            root_name(name, &graph.scope),
            graph.scope,
            graph.lock_format.as_str()
        ),
    }));
    for (idx, pkg) in graph.packages.iter().enumerate() {
        let mut package = json!({
            "SPDXID": ids[idx],
            "name": pkg.name,
            "downloadLocation": pkg.url.as_deref().unwrap_or("NOASSERTION"),
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        });
        if let Some(version) = &pkg.version {
            package["versionInfo"] = json!(version);
        }
        let checksums: Vec<Value> = pkg.hashes.iter().filter_map(spdx_checksum).collect();
        if !checksums.is_empty() {
            package["checksums"] = json!(checksums);
        }
        if let Some(purl) = &graph.purls[idx] {
            package["externalRefs"] = json!([{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }]);
        }
        packages.push(package);
    }

    let mut relationships: Vec<Value> = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": SPDX_ENVIRONMENT_ID,
    })];
    for idx in &graph.roots {
        relationships.push(json!({
            "spdxElementId": SPDX_ENVIRONMENT_ID,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": ids[*idx],
        }));
    }
    for (from, targets) in &graph.edges {
        for to in targets {
            relationships.push(json!({
                "spdxElementId": ids[*from],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": ids[*to],
            }));
        }
    }

    let unparsed = coverage_properties(env, &graph.scope);
    let comment = if unparsed.is_empty() {
        String::new()
    } else {
        let parts: Vec<String> = unparsed
            .iter()
            .filter_map(|p| Some(format!("{}={}", p["name"].as_str()?, p["value"].as_str()?)))
            .collect();
        format!(" artifact-keeper coverage: {}.", parts.join(", "))
    };

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root_name(name, &graph.scope),
        "documentNamespace": format!(
            "https://artifact-keeper.com/environment-sbom/{}",
            uuid::Uuid::new_v4()
        ),
        "creationInfo": {
            "created": chrono::Utc::now().to_rfc3339(),
            "creators": [format!("Tool: artifact-keeper-{}", env!("CARGO_PKG_VERSION"))],
            "comment": format!("Generated from a {} lockfile.{}", graph.lock_format.as_str(), comment),
        },
        "documentDescribes": [SPDX_ENVIRONMENT_ID],
        "packages": packages,
        "relationships": relationships,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::conda_identity::{
        artifact_purl_from_metadata, AliasMap, CondaIdentity, CondaIdentityInput, NoarchKind,
        IDENTITY_METADATA_KEY,
    };
    use crate::services::environment_lock::{parse_lockfile, LockFormat};

    const CF: &str = "https://conda.anaconda.org/conda-forge";
    const PYPI_FILES: &str = "https://files.pythonhosted.org/packages/ab";

    /// The sentinel name used for the document's own root node when graphs are
    /// compared by package name.
    const ROOT: &str = "<environment>";

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A pixi.lock whose two platforms resolve *conflicting* builds of the
    /// same libwebp version, and where `python` exists only on linux-64.
    fn pixi_two_platforms() -> String {
        format!(
            r#"version: 6
environments:
  default:
    packages:
      linux-64:
      - conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
      - conda: {cf}/linux-64/python-3.11.6-h5678_0_cpython.conda
      - conda: {cf}/linux-64/pypy-7.3.13-h0000_0.conda
      - conda: {cf}/linux-64/pillow-10.0.1-py311h1111_0.conda
      osx-arm64:
      - conda: {cf}/osx-arm64/libwebp-1.3.2-h9999_0.conda
      - conda: {cf}/osx-arm64/pillow-10.0.1-py311h2222_0.conda
packages:
- conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
  name: libwebp
  version: 1.3.2
  build: h1234_0
  sha256: aaaa1111
  depends:
  - __glibc >=2.17
- conda: {cf}/osx-arm64/libwebp-1.3.2-h9999_0.conda
  name: libwebp
  version: 1.3.2
  build: h9999_0
  sha256: aaaa2222
  depends: []
- conda: {cf}/linux-64/python-3.11.6-h5678_0_cpython.conda
  name: python
  version: 3.11.6
  build: h5678_0_cpython
  sha256: cccc1111
  depends: []
  constrains:
  - pypy <0a0
- conda: {cf}/linux-64/pypy-7.3.13-h0000_0.conda
  name: pypy
  version: 7.3.13
  build: h0000_0
  sha256: cccc2222
  depends: []
- conda: {cf}/linux-64/pillow-10.0.1-py311h1111_0.conda
  name: pillow
  version: 10.0.1
  build: py311h1111_0
  sha256: dddd1111
  depends:
  - libwebp >=1.3.2,<2.0a0
  - python >=3.11,<3.12.0a0
- conda: {cf}/osx-arm64/pillow-10.0.1-py311h2222_0.conda
  name: pillow
  version: 10.0.1
  build: py311h2222_0
  sha256: dddd2222
  depends:
  - libwebp >=1.3.2,<2.0a0
"#,
            cf = CF
        )
    }

    /// A pixi.lock in which one `noarch` build (`tzdata`) is a member of two
    /// platform scopes, next to a platform build of the same channel. The
    /// `noarch` entry deliberately carries its subdir only in its URL, which
    /// is where pixi's v6 schema puts it.
    fn pixi_with_noarch() -> String {
        format!(
            r#"version: 6
environments:
  default:
    packages:
      linux-64:
      - conda: {cf}/noarch/tzdata-2024a-h0c530f3_0.conda
      - conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
      osx-arm64:
      - conda: {cf}/noarch/tzdata-2024a-h0c530f3_0.conda
packages:
- conda: {cf}/noarch/tzdata-2024a-h0c530f3_0.conda
  name: tzdata
  version: 2024a
  build: h0c530f3_0
  noarch: generic
  sha256: eeee1111
  depends: []
- conda: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
  name: libwebp
  version: 1.3.2
  build: h1234_0
  sha256: aaaa1111
  depends: []
"#,
            cf = CF
        )
    }

    /// A conda-lock.yml carrying the same `noarch` build twice, once per
    /// solved platform. `platform:` names the graph; only the URL says
    /// `noarch`.
    fn conda_lock_with_noarch() -> String {
        format!(
            r#"version: 1
metadata:
  platforms:
  - linux-64
  - osx-64
package:
- name: tzdata
  version: 2024a
  build: h0c530f3_0
  manager: conda
  platform: linux-64
  dependencies: {{}}
  url: {cf}/noarch/tzdata-2024a-h0c530f3_0.conda
  hash:
    sha256: eeee1111
- name: tzdata
  version: 2024a
  build: h0c530f3_0
  manager: conda
  platform: osx-64
  dependencies: {{}}
  url: {cf}/noarch/tzdata-2024a-h0c530f3_0.conda
  hash:
    sha256: eeee1111
- name: libwebp
  version: 1.3.2
  build: h1234_0
  manager: conda
  platform: linux-64
  dependencies: {{}}
  url: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
  hash:
    sha256: aaaa1111
"#,
            cf = CF
        )
    }

    /// A conda-lock with a virtual-package dependency (`__glibc`) and pip
    /// packages present on linux-64 only.
    fn conda_lock_two_platforms() -> String {
        format!(
            r#"version: 1
metadata:
  content_hash:
    linux-64: hash-linux
    osx-64: hash-osx
  channels:
  - url: conda-forge
    used_env_vars: []
  platforms:
  - linux-64
  - osx-64
package:
- name: libwebp
  version: 1.3.2
  manager: conda
  platform: linux-64
  dependencies: {{}}
  url: {cf}/linux-64/libwebp-1.3.2-h1234_0.conda
  hash:
    sha256: aaaa1111
- name: pillow
  version: 10.0.1
  manager: conda
  platform: linux-64
  dependencies:
    libwebp: '>=1.3.2,<2.0a0'
    __glibc: '>=2.17'
  url: {cf}/linux-64/pillow-10.0.1-py311h1111_0.conda
  hash:
    sha256: dddd1111
- name: requests
  version: 2.31.0
  manager: pip
  platform: linux-64
  dependencies:
    urllib3: '>=1.21.1,<3'
  url: {pypi}/requests-2.31.0-py3-none-any.whl
  hash:
    sha256: eeee1111
- name: urllib3
  version: 2.0.7
  manager: pip
  platform: linux-64
  dependencies: {{}}
  url: {pypi}/urllib3-2.0.7-py3-none-any.whl
  hash:
    sha256: ffff1111
- name: libwebp
  version: 1.3.2
  manager: conda
  platform: osx-64
  dependencies: {{}}
  url: {cf}/osx-64/libwebp-1.3.2-h8888_0.conda
  hash:
    sha256: aaaa3333
- name: pillow
  version: 10.0.1
  manager: conda
  platform: osx-64
  dependencies:
    libwebp: '>=1.3.2,<2.0a0'
  url: {cf}/osx-64/pillow-10.0.1-py311h3333_0.conda
  hash:
    sha256: dddd3333
"#,
            cf = CF,
            pypi = PYPI_FILES
        )
    }

    /// A uv.lock, which records the project itself as an editable root.
    fn uv_lock_with_root() -> &'static str {
        r#"version = 1

[[package]]
name = "demo"
source = { editable = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
"#
    }

    // -----------------------------------------------------------------------
    // Graph extraction (the round-trip read side)
    // -----------------------------------------------------------------------

    /// Nodes and edges of a document, keyed by the document's own node ids.
    struct Graph {
        nodes: BTreeSet<String>,
        /// (from, to) pairs; the document root's outgoing edges are the root
        /// layer.
        edges: BTreeSet<(String, String)>,
    }

    fn cdx_graph(doc: &Value) -> Graph {
        let mut nodes = BTreeSet::new();
        if let Some(root) = doc["metadata"]["component"]["bom-ref"].as_str() {
            nodes.insert(root.to_string());
        }
        for component in doc["components"].as_array().expect("components array") {
            nodes.insert(
                component["bom-ref"]
                    .as_str()
                    .expect("component bom-ref")
                    .to_string(),
            );
        }
        let mut edges = BTreeSet::new();
        for entry in doc["dependencies"].as_array().expect("dependencies array") {
            let from = entry["ref"].as_str().expect("dependency ref");
            if let Some(targets) = entry["dependsOn"].as_array() {
                for target in targets {
                    edges.insert((
                        from.to_string(),
                        target.as_str().expect("dependsOn target").to_string(),
                    ));
                }
            }
        }
        Graph { nodes, edges }
    }

    fn spdx_graph(doc: &Value) -> Graph {
        let mut nodes = BTreeSet::new();
        for package in doc["packages"].as_array().expect("packages array") {
            nodes.insert(package["SPDXID"].as_str().expect("SPDXID").to_string());
        }
        let mut edges = BTreeSet::new();
        for rel in doc["relationships"]
            .as_array()
            .expect("relationships array")
        {
            if rel["relationshipType"].as_str() == Some("DEPENDS_ON") {
                edges.insert((
                    rel["spdxElementId"]
                        .as_str()
                        .expect("spdxElementId")
                        .to_string(),
                    rel["relatedSpdxElement"]
                        .as_str()
                        .expect("relatedSpdxElement")
                        .to_string(),
                ));
            }
        }
        Graph { nodes, edges }
    }

    fn graph_of(doc: &Value, format: SbomFormat) -> Graph {
        match format {
            SbomFormat::CycloneDX => cdx_graph(doc),
            SbomFormat::SPDX => spdx_graph(doc),
        }
    }

    /// Translate a document graph into package *names*, with the document's
    /// own root renamed to [`ROOT`], so graphs can be compared against
    /// expectations written in lockfile vocabulary.
    fn named_graph(
        doc: &Value,
        format: SbomFormat,
    ) -> (BTreeSet<String>, BTreeSet<(String, String)>) {
        let mut name_of: HashMap<String, String> = HashMap::new();
        match format {
            SbomFormat::CycloneDX => {
                let root = doc["metadata"]["component"]["bom-ref"]
                    .as_str()
                    .expect("root bom-ref");
                name_of.insert(root.to_string(), ROOT.to_string());
                for component in doc["components"].as_array().expect("components array") {
                    name_of.insert(
                        component["bom-ref"].as_str().unwrap().to_string(),
                        component["name"].as_str().unwrap().to_string(),
                    );
                }
            }
            SbomFormat::SPDX => {
                for package in doc["packages"].as_array().expect("packages array") {
                    let id = package["SPDXID"].as_str().unwrap().to_string();
                    let name = if id == "SPDXRef-Environment" {
                        ROOT.to_string()
                    } else {
                        package["name"].as_str().unwrap().to_string()
                    };
                    name_of.insert(id, name);
                }
            }
        }
        let graph = graph_of(doc, format);
        let names: BTreeSet<String> = graph
            .nodes
            .iter()
            .map(|n| name_of.get(n).cloned().unwrap_or_else(|| n.clone()))
            .collect();
        let edges: BTreeSet<(String, String)> = graph
            .edges
            .iter()
            .map(|(from, to)| {
                (
                    name_of.get(from).cloned().unwrap_or_else(|| from.clone()),
                    name_of.get(to).cloned().unwrap_or_else(|| to.clone()),
                )
            })
            .collect();
        (names, edges)
    }

    /// The graph the *parser* says a scope has, in names, with [`ROOT`] for
    /// the document root: every non-constrains edge, plus a root edge to every
    /// package nothing (emitted) points at. Built purely from
    /// [`LockedEnvironment`]'s public API — this is the independent side of
    /// the round-trip.
    fn expected_named_graph(
        env: &LockedEnvironment,
        scope: &Scope,
    ) -> (BTreeSet<String>, BTreeSet<(String, String)>) {
        let mut names: BTreeSet<String> = BTreeSet::from([ROOT.to_string()]);
        let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
        let mut depended_on: BTreeSet<&str> = BTreeSet::new();
        for pkg in env.packages_in(scope) {
            names.insert(pkg.name.clone());
        }
        for edge in env.edges_in(scope) {
            if edge.kind == EdgeKind::Constrains {
                continue;
            }
            let from = env.package(scope, &edge.from).expect("edge from resolves");
            let to = env.package(scope, &edge.to).expect("edge to resolves");
            depended_on.insert(to.key.as_str());
            edges.insert((from.name.clone(), to.name.clone()));
        }
        for pkg in env.packages_in(scope) {
            if !depended_on.contains(pkg.key.as_str()) {
                edges.insert((ROOT.to_string(), pkg.name.clone()));
            }
        }
        (names, edges)
    }

    /// Generate -> serialize -> parse back -> extract, for one scope.
    fn round_trip(env: &LockedEnvironment, scope: &Scope, format: SbomFormat) -> (Value, Graph) {
        let sbom = generate_environment_sbom(env, "test.lock", format);
        let doc = sbom
            .document_for(scope)
            .unwrap_or_else(|| panic!("no document for {}", scope));
        let serialized = serde_json::to_string(doc).expect("document serializes");
        let parsed: Value = serde_json::from_str(&serialized).expect("document parses back");
        let graph = graph_of(&parsed, format);
        (parsed, graph)
    }

    // -----------------------------------------------------------------------
    // Document-per-scope structure
    // -----------------------------------------------------------------------

    #[test]
    fn one_document_per_platform_scope() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_two_platforms().as_bytes())
            .expect("fixture parses");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "pixi.lock", format);
            assert_eq!(sbom.documents.len(), 2, "{format}: one document per scope");
            let linux = Scope::env_platform("default", "linux-64");
            let osx = Scope::env_platform("default", "osx-arm64");
            assert!(
                sbom.document_for(&linux).is_some(),
                "{format}: linux-64 doc"
            );
            assert!(sbom.document_for(&osx).is_some(), "{format}: osx-arm64 doc");
        }
    }

    #[test]
    fn global_scope_produces_a_single_document() {
        let env = parse_lockfile(LockFormat::UvLock, uv_lock_with_root().as_bytes())
            .expect("fixture parses");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "uv.lock", format);
            assert_eq!(sbom.documents.len(), 1, "{format}: one global document");
            assert!(sbom.document_for(&Scope::global()).is_some());
        }
    }

    // -----------------------------------------------------------------------
    // The core invariant: separate graphs, no cross-platform leakage
    // -----------------------------------------------------------------------

    #[test]
    fn conflicting_resolution_produces_separate_graphs() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_two_platforms().as_bytes())
            .expect("fixture parses");
        let linux = Scope::env_platform("default", "linux-64");
        let osx = Scope::env_platform("default", "osx-arm64");

        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "pixi.lock", format);
            let (linux_names, linux_edges) =
                named_graph(sbom.document_for(&linux).unwrap(), format);
            let (osx_names, osx_edges) = named_graph(sbom.document_for(&osx).unwrap(), format);

            // linux-64 resolved python in; osx-arm64 did not.
            assert!(
                linux_names.contains("python"),
                "{format}: linux graph has python"
            );
            assert!(
                !osx_names.contains("python"),
                "{format}: osx graph must not"
            );
            // Both graphs have their own pillow -> libwebp edge.
            let pillow_webp = ("pillow".to_string(), "libwebp".to_string());
            assert!(linux_edges.contains(&pillow_webp), "{format}: linux edge");
            assert!(osx_edges.contains(&pillow_webp), "{format}: osx edge");
            // Only linux has pillow -> python.
            let pillow_python = ("pillow".to_string(), "python".to_string());
            assert!(
                linux_edges.contains(&pillow_python),
                "{format}: linux python edge"
            );
            assert!(
                !osx_edges.contains(&pillow_python),
                "{format}: no osx python edge"
            );
        }
    }

    #[test]
    fn conflicting_builds_have_distinct_bom_refs() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_two_platforms().as_bytes())
            .expect("fixture parses");
        let linux = Scope::env_platform("default", "linux-64");
        let osx = Scope::env_platform("default", "osx-arm64");
        let sbom = generate_environment_sbom(&env, "pixi.lock", SbomFormat::CycloneDX);

        let libwebp_ref = |doc: &Value| -> String {
            doc["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"].as_str() == Some("libwebp"))
                .map(|c| c["bom-ref"].as_str().unwrap().to_string())
                .expect("libwebp component")
        };
        let linux_ref = libwebp_ref(sbom.document_for(&linux).unwrap());
        let osx_ref = libwebp_ref(sbom.document_for(&osx).unwrap());
        assert_ne!(
            linux_ref, osx_ref,
            "same name+version, different build/subdir: bom-refs must differ"
        );
        assert!(
            linux_ref.contains("subdir=linux-64") && linux_ref.contains("build=h1234_0"),
            "linux ref is the qualified purl: {linux_ref}"
        );
        assert!(
            osx_ref.contains("subdir=osx-arm64") && osx_ref.contains("build=h9999_0"),
            "osx ref is the qualified purl: {osx_ref}"
        );
    }

    #[test]
    fn no_cross_platform_ref_leakage() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_two_platforms().as_bytes())
            .expect("fixture parses");
        let linux = Scope::env_platform("default", "linux-64");
        let osx = Scope::env_platform("default", "osx-arm64");

        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "pixi.lock", format);
            let linux_doc = sbom.document_for(&linux).unwrap();
            let osx_doc = sbom.document_for(&osx).unwrap();

            // Platform-qualified purls are the identity: the other platform's
            // subdir must appear nowhere in this document — not as a
            // component, not as an edge endpoint.
            let linux_text = serde_json::to_string(linux_doc).unwrap();
            let osx_text = serde_json::to_string(osx_doc).unwrap();
            assert!(
                !linux_text.contains("subdir=osx-arm64"),
                "{format}: osx-arm64 identity leaked into the linux-64 document"
            );
            assert!(
                !osx_text.contains("subdir=linux-64"),
                "{format}: linux-64 identity leaked into the osx-arm64 document"
            );

            // Node membership is exactly the scope's packages — a document
            // that absorbed another platform's nodes (even relabelled onto
            // its own subdir) has too many, and one that dropped some has
            // too few.
            for (doc, scope, label) in
                [(linux_doc, &linux, "linux doc"), (osx_doc, &osx, "osx doc")]
            {
                let (names, _edges) = named_graph(doc, format);
                let mut expected: BTreeSet<String> =
                    env.packages_in(scope).map(|p| p.name.clone()).collect();
                expected.insert(ROOT.to_string());
                assert_eq!(names, expected, "{format}: {label} node membership");
            }

            // Node ids unique to one document must appear nowhere in the
            // other's edges — as source or as target.
            let linux_graph = graph_of(linux_doc, format);
            let osx_graph = graph_of(osx_doc, format);
            for (a, b, label) in [
                (&linux_graph, &osx_graph, "osx ids in linux doc"),
                (&osx_graph, &linux_graph, "linux ids in osx doc"),
            ] {
                let foreign: BTreeSet<&String> = b.nodes.difference(&a.nodes).collect();
                for (from, to) in &a.edges {
                    assert!(
                        !foreign.contains(from) && !foreign.contains(to),
                        "{format}: {label} leak: {from} -> {to}"
                    );
                }
            }
        }
    }

    #[test]
    fn package_present_only_on_linux_has_no_osx_presence() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_two_platforms().as_bytes())
            .expect("fixture parses");
        let osx = Scope::env_platform("default", "osx-arm64");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "pixi.lock", format);
            let osx_doc = sbom.document_for(&osx).unwrap();
            let serialized = serde_json::to_string(osx_doc).unwrap();
            assert!(
                !serialized.contains("python"),
                "{format}: osx document must not mention python at all: {serialized}"
            );
        }
    }

    #[test]
    fn virtual_packages_are_not_nodes_and_carry_no_edges() {
        let env = parse_lockfile(LockFormat::CondaLock, conda_lock_two_platforms().as_bytes())
            .expect("fixture parses");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "conda-lock.yml", format);
            for scoped in &sbom.documents {
                let serialized = serde_json::to_string(&scoped.document).unwrap();
                assert!(
                    !serialized.contains("__glibc"),
                    "{format} {}: virtual package leaked into document",
                    scoped.scope
                );
                let (names, edges) = named_graph(&scoped.document, format);
                assert!(
                    names.iter().all(|n| !n.starts_with("__")),
                    "{format} {}: virtual package is a node: {:?}",
                    scoped.scope,
                    names
                );
                assert!(
                    edges
                        .iter()
                        .all(|(f, t)| !f.starts_with("__") && !t.starts_with("__")),
                    "{format} {}: virtual package carries an edge",
                    scoped.scope
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Referential integrity
    // -----------------------------------------------------------------------

    #[test]
    fn no_dangling_refs_in_either_format() {
        for (format_name, bytes) in [
            (LockFormat::PixiLock, pixi_two_platforms()),
            (LockFormat::CondaLock, conda_lock_two_platforms()),
            (LockFormat::UvLock, uv_lock_with_root().to_string()),
        ] {
            let env = parse_lockfile(format_name, bytes.as_bytes()).expect("fixture parses");
            for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
                let sbom = generate_environment_sbom(&env, "test.lock", format);
                for scoped in &sbom.documents {
                    let graph = graph_of(&scoped.document, format);
                    for (from, to) in &graph.edges {
                        assert!(
                            graph.nodes.contains(from) && graph.nodes.contains(to),
                            "{format} {} {}: dangling edge {from} -> {to}",
                            format_name,
                            scoped.scope
                        );
                    }
                    // Every declared node except the root must be reachable as
                    // an edge source or target in the dependencies section…
                    // (leaf components appear with an empty dependsOn), which
                    // is what keeps the section and the component list in
                    // agreement.
                }
            }
        }
    }

    #[test]
    fn bom_refs_are_unique_within_a_document() {
        let env = parse_lockfile(LockFormat::CondaLock, conda_lock_two_platforms().as_bytes())
            .expect("fixture parses");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "conda-lock.yml", format);
            for scoped in &sbom.documents {
                let graph = graph_of(&scoped.document, format);
                let package_count = env.packages_in(&scoped.scope).count();
                // nodes == packages + document root; if two packages had
                // collapsed onto one id the set would be smaller.
                assert_eq!(
                    graph.nodes.len(),
                    package_count + 1,
                    "{format} {}: node ids must be unique per package",
                    scoped.scope
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // The root layer
    // -----------------------------------------------------------------------

    #[test]
    fn root_edges_name_the_requested_layer() {
        let env = parse_lockfile(LockFormat::CondaLock, conda_lock_two_platforms().as_bytes())
            .expect("fixture parses");
        let linux = Scope::platform("linux-64");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "conda-lock.yml", format);
            let (_names, edges) = named_graph(sbom.document_for(&linux).unwrap(), format);
            // pillow and requests are what the environment "asked for";
            // libwebp and urllib3 are pulled in, so they are NOT root edges.
            let root_edges: BTreeSet<&String> = edges
                .iter()
                .filter(|(from, _)| from == ROOT)
                .map(|(_, to)| to)
                .collect();
            assert_eq!(
                root_edges,
                BTreeSet::from([&"pillow".to_string(), &"requests".to_string()])
                    .into_iter()
                    .collect(),
                "{format}: root layer must be exactly the in-degree-zero packages"
            );
        }
    }

    #[test]
    fn uv_project_root_is_the_single_environment_root_edge() {
        let env = parse_lockfile(LockFormat::UvLock, uv_lock_with_root().as_bytes())
            .expect("fixture parses");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "uv.lock", format);
            let (_names, edges) = named_graph(sbom.document_for(&Scope::global()).unwrap(), format);
            let root_edges: BTreeSet<&String> = edges
                .iter()
                .filter(|(from, _)| from == ROOT)
                .map(|(_, to)| to)
                .collect();
            assert_eq!(
                root_edges,
                BTreeSet::from([&"demo".to_string()]).into_iter().collect(),
                "{format}: the recorded project root is the only root edge"
            );
            // …and the chain below it is intact.
            assert!(edges.contains(&("demo".to_string(), "requests".to_string())));
            assert!(edges.contains(&("requests".to_string(), "urllib3".to_string())));
        }
    }

    // -----------------------------------------------------------------------
    // constrains is data, not an edge
    // -----------------------------------------------------------------------

    #[test]
    fn constrains_is_not_a_dependency_edge() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_two_platforms().as_bytes())
            .expect("fixture parses");
        let linux = Scope::env_platform("default", "linux-64");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "pixi.lock", format);
            let doc = sbom.document_for(&linux).unwrap();
            let (_names, edges) = named_graph(doc, format);
            // pypy IS installed, so it is a node — but python's constrains on
            // it is not an install requirement and must not be an edge.
            assert!(
                !edges.contains(&("python".to_string(), "pypy".to_string())),
                "{format}: a constrains entry must never become a dependency edge"
            );
        }
        // The constraint itself survives as a property on the constraining
        // component.
        let sbom = generate_environment_sbom(&env, "pixi.lock", SbomFormat::CycloneDX);
        let doc = sbom.document_for(&linux).unwrap();
        let python = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"].as_str() == Some("python"))
            .expect("python component");
        let props = python["properties"].as_array().expect("python properties");
        assert!(
            props.iter().any(|p| {
                p["name"].as_str() == Some(PROP_CONSTRAINS)
                    && p["value"].as_str().is_some_and(|v| v.contains("pypy"))
            }),
            "constrains text must be recorded as a component property: {props:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    #[test]
    fn conda_components_use_the_qualified_purl() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_two_platforms().as_bytes())
            .expect("fixture parses");
        let linux = Scope::env_platform("default", "linux-64");
        let sbom = generate_environment_sbom(&env, "pixi.lock", SbomFormat::CycloneDX);
        let doc = sbom.document_for(&linux).unwrap();
        let pillow = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"].as_str() == Some("pillow"))
            .expect("pillow component");
        let purl = pillow["purl"].as_str().expect("pillow purl");
        assert_eq!(
            purl,
            "pkg:conda/pillow@10.0.1?build=py311h1111_0&channel=conda-forge&subdir=linux-64"
        );
        // The bom-ref IS the qualified purl (#4041 identity).
        assert_eq!(pillow["bom-ref"].as_str(), Some(purl));
    }

    /// The purl the ingest path derives for one conda artifact, from the
    /// identity block `build_conda_metadata` stores on it. Both derivations
    /// must produce the same string or an environment membership and its
    /// artifact never join (#4151).
    fn artifact_purl(
        name: &str,
        version: &str,
        build: &str,
        subdir: &str,
        noarch: Option<NoarchKind>,
    ) -> String {
        let identity = CondaIdentity::resolve(
            CondaIdentityInput {
                name,
                version,
                build,
                subdir,
                noarch,
                channel: Some("conda-forge"),
                archive_type: None,
            },
            &AliasMap::builtin_only(),
        );
        let metadata = json!({ IDENTITY_METADATA_KEY: identity.to_document() });
        artifact_purl_from_metadata(&metadata).expect("artifact purl")
    }

    /// The purl of one component of one scope's document, by package name.
    fn component_purl(sbom: &EnvironmentSbom, scope: &Scope, name: &str) -> String {
        let doc = sbom.document_for(scope).expect("scope document");
        let component = doc["components"]
            .as_array()
            .expect("components")
            .iter()
            .find(|c| c["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("no `{name}` component in {scope}"));
        component["purl"]
            .as_str()
            .unwrap_or_else(|| panic!("`{name}` has no purl"))
            .to_string()
    }

    #[test]
    fn noarch_member_keeps_its_own_subdir_in_a_platform_scope() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_with_noarch().as_bytes())
            .expect("fixture parses");
        let sbom = generate_environment_sbom(&env, "pixi.lock", SbomFormat::CycloneDX);
        let linux = Scope::env_platform("default", "linux-64");

        // The scope is linux-64; the package is not.
        let tzdata = component_purl(&sbom, &linux, "tzdata");
        assert_eq!(
            tzdata,
            "pkg:conda/tzdata@2024a?build=h0c530f3_0&channel=conda-forge&subdir=noarch"
        );
        // ... and it is exactly what the same build's artifact is ingested as.
        assert_eq!(
            tzdata,
            artifact_purl(
                "tzdata",
                "2024a",
                "h0c530f3_0",
                "noarch",
                Some(NoarchKind::Generic)
            ),
            "environment membership and artifact identity must be one string"
        );

        // One noarch build is one identity, not one per platform it lands on.
        let osx = Scope::env_platform("default", "osx-arm64");
        assert_eq!(component_purl(&sbom, &osx, "tzdata"), tzdata);
    }

    #[test]
    fn platform_member_keeps_its_own_subdir() {
        let env = parse_lockfile(LockFormat::PixiLock, pixi_with_noarch().as_bytes())
            .expect("fixture parses");
        let sbom = generate_environment_sbom(&env, "pixi.lock", SbomFormat::CycloneDX);
        let linux = Scope::env_platform("default", "linux-64");

        let libwebp = component_purl(&sbom, &linux, "libwebp");
        assert_eq!(
            libwebp,
            "pkg:conda/libwebp@1.3.2?build=h1234_0&channel=conda-forge&subdir=linux-64"
        );
        assert_eq!(
            libwebp,
            artifact_purl("libwebp", "1.3.2", "h1234_0", "linux-64", None)
        );
    }

    #[test]
    fn conda_lock_noarch_member_keeps_its_own_subdir() {
        let env = parse_lockfile(LockFormat::CondaLock, conda_lock_with_noarch().as_bytes())
            .expect("fixture parses");
        let sbom = generate_environment_sbom(&env, "conda-lock.yml", SbomFormat::CycloneDX);

        let tzdata = component_purl(&sbom, &Scope::platform("linux-64"), "tzdata");
        assert_eq!(
            tzdata,
            "pkg:conda/tzdata@2024a?build=h0c530f3_0&channel=conda-forge&subdir=noarch"
        );
        // conda-lock lists the entry once per solved platform; both must
        // reduce to the one identity, and neither may borrow `platform:`.
        assert_eq!(
            component_purl(&sbom, &Scope::platform("osx-64"), "tzdata"),
            tzdata
        );
        assert_eq!(
            component_purl(&sbom, &Scope::platform("linux-64"), "libwebp"),
            "pkg:conda/libwebp@1.3.2?build=h1234_0&channel=conda-forge&subdir=linux-64"
        );
    }

    #[test]
    fn a_package_with_no_recorded_subdir_falls_back_to_the_scope_platform() {
        let scope = Scope::env_platform("default", "linux-64");
        let pkg = LockedPackage {
            scope: scope.clone(),
            ecosystem: Ecosystem::Conda,
            name: "libwebp".to_string(),
            version: Some("1.3.2".to_string()),
            build: Some("h1234_0".to_string()),
            subdir: None,
            url: None,
            source: Some("conda-forge".to_string()),
            hashes: Vec::new(),
            key: "libwebp 1.3.2".to_string(),
            is_root: false,
        };
        assert_eq!(
            package_purl(&pkg, &scope).as_deref(),
            Some("pkg:conda/libwebp@1.3.2?build=h1234_0&channel=conda-forge&subdir=linux-64")
        );

        // A subdir `CondaPurl` will not accept is no better than none: the
        // component keeps the identity it had before rather than losing one.
        let unusable = LockedPackage {
            subdir: Some("Linux 64!".to_string()),
            ..pkg
        };
        assert_eq!(
            package_purl(&unusable, &scope).as_deref(),
            Some("pkg:conda/libwebp@1.3.2?build=h1234_0&channel=conda-forge&subdir=linux-64")
        );
    }

    #[test]
    fn pypi_components_use_pypi_purls() {
        let env = parse_lockfile(LockFormat::CondaLock, conda_lock_two_platforms().as_bytes())
            .expect("fixture parses");
        let linux = Scope::platform("linux-64");
        let sbom = generate_environment_sbom(&env, "conda-lock.yml", SbomFormat::CycloneDX);
        let doc = sbom.document_for(&linux).unwrap();
        let requests = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"].as_str() == Some("requests"))
            .expect("requests component");
        assert_eq!(requests["purl"].as_str(), Some("pkg:pypi/requests@2.31.0"));
    }

    // -----------------------------------------------------------------------
    // Round-trip: generate -> serialize -> parse back -> same graph
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_reproduces_the_lockfile_graph() {
        for (lock_format, bytes) in [
            (LockFormat::PixiLock, pixi_two_platforms()),
            (LockFormat::CondaLock, conda_lock_two_platforms()),
            (LockFormat::UvLock, uv_lock_with_root().to_string()),
        ] {
            let env = parse_lockfile(lock_format, bytes.as_bytes()).expect("fixture parses");
            for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
                for scope in env.scopes() {
                    let (doc, _graph) = round_trip(&env, &scope, format);
                    let actual = named_graph(&doc, format);
                    let expected = expected_named_graph(&env, &scope);
                    assert_eq!(
                        actual, expected,
                        "{format} {lock_format} {scope}: round-tripped graph differs"
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Schema-shaped structure (the repo carries no schema fixtures, so the
    // required fields of each specification are asserted directly)
    // -----------------------------------------------------------------------

    #[test]
    fn cyclonedx_document_has_required_fields() {
        let env = parse_lockfile(LockFormat::CondaLock, conda_lock_two_platforms().as_bytes())
            .expect("fixture parses");
        let sbom = generate_environment_sbom(&env, "conda-lock.yml", SbomFormat::CycloneDX);
        for scoped in &sbom.documents {
            let doc = &scoped.document;
            assert_eq!(doc["bomFormat"].as_str(), Some("CycloneDX"));
            assert_eq!(doc["specVersion"].as_str(), Some("1.5"));
            assert_eq!(doc["version"].as_u64(), Some(1));
            assert!(doc["metadata"]["timestamp"].is_string());
            assert!(doc["metadata"]["tools"].is_array());
            // The root component: type "platform", with the scope recorded.
            let root = &doc["metadata"]["component"];
            assert_eq!(root["type"].as_str(), Some("platform"));
            assert!(root["bom-ref"].is_string());
            let props = root["properties"].as_array().expect("root properties");
            assert!(props
                .iter()
                .any(|p| p["name"].as_str() == Some(PROP_LOCKFILE_FORMAT)
                    && p["value"].as_str() == Some("conda-lock")));
            assert!(props
                .iter()
                .any(|p| p["name"].as_str() == Some(PROP_PLATFORM)
                    && p["value"].as_str()
                        == Some(scoped.scope.platform.as_deref().unwrap_or(""))));
            // Every component: required type + name + bom-ref.
            for component in doc["components"].as_array().expect("components") {
                assert!(component["bom-ref"].is_string(), "component bom-ref");
                assert_eq!(component["type"].as_str(), Some("library"));
                assert!(component["name"].is_string(), "component name");
            }
            // Every dependency entry names a declared ref.
            let graph = cdx_graph(doc);
            for entry in doc["dependencies"].as_array().expect("dependencies") {
                let r = entry["ref"].as_str().unwrap();
                assert!(graph.nodes.contains(r), "dependency ref undeclared: {r}");
            }
        }
    }

    #[test]
    fn spdx_document_has_required_fields() {
        let env = parse_lockfile(LockFormat::CondaLock, conda_lock_two_platforms().as_bytes())
            .expect("fixture parses");
        let sbom = generate_environment_sbom(&env, "conda-lock.yml", SbomFormat::SPDX);
        for scoped in &sbom.documents {
            let doc = &scoped.document;
            assert_eq!(doc["spdxVersion"].as_str(), Some("SPDX-2.3"));
            assert_eq!(doc["dataLicense"].as_str(), Some("CC0-1.0"));
            assert_eq!(doc["SPDXID"].as_str(), Some("SPDXRef-DOCUMENT"));
            assert!(doc["name"].is_string());
            assert!(doc["documentNamespace"].is_string());
            assert!(doc["creationInfo"]["created"].is_string());
            assert!(doc["creationInfo"]["creators"].is_array());
            // The document describes its environment package…
            let describes = doc["documentDescribes"]
                .as_array()
                .expect("documentDescribes");
            assert!(describes
                .iter()
                .any(|d| d.as_str() == Some("SPDXRef-Environment")));
            // …and every package carries the fields SPDX 2.3 requires.
            for package in doc["packages"].as_array().expect("packages") {
                let id = package["SPDXID"].as_str().expect("SPDXID");
                assert!(
                    id.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
                    "SPDXID charset: {id}"
                );
                assert!(package["name"].is_string(), "package name");
                assert!(package["downloadLocation"].is_string(), "downloadLocation");
                assert_eq!(package["filesAnalyzed"].as_bool(), Some(false));
                assert!(package["licenseConcluded"].is_string());
                assert!(package["licenseDeclared"].is_string());
                assert!(package["copyrightText"].is_string());
            }
            // DEPENDS_ON relationships reference declared SPDXIDs only.
            let graph = spdx_graph(doc);
            for (from, to) in &graph.edges {
                assert!(graph.nodes.contains(from), "dangling source {from}");
                assert!(graph.nodes.contains(to), "dangling target {to}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // purl fallback: a package with no version still gets a unique, stable ref
    // -----------------------------------------------------------------------

    #[test]
    fn versionless_packages_get_unique_refs() {
        // Two conda entries with no version: neither can form a versioned
        // purl, but both must appear as distinct components with distinct
        // refs.
        let lock = format!(
            r#"version: 1
metadata:
  content_hash:
    linux-64: hash-linux
  channels:
  - url: conda-forge
    used_env_vars: []
  platforms:
  - linux-64
package:
- name: tool
  version: 1.0
  manager: conda
  platform: linux-64
  dependencies:
    helper: ''
    helper2: ''
  url: {cf}/linux-64/tool-1.0-h0000_0.conda
  hash:
    sha256: 1111aaaa
- name: helper
  manager: conda
  platform: linux-64
  dependencies: {{}}
  url: {cf}/linux-64/helper.tar.bz2
  hash:
    sha256: 2222aaaa
- name: helper2
  manager: conda
  platform: linux-64
  dependencies: {{}}
  url: {cf}/linux-64/helper2.tar.bz2
  hash:
    sha256: 3333aaaa
"#,
            cf = CF
        );
        let env = parse_lockfile(LockFormat::CondaLock, lock.as_bytes()).expect("fixture parses");
        for format in [SbomFormat::CycloneDX, SbomFormat::SPDX] {
            let sbom = generate_environment_sbom(&env, "conda-lock.yml", format);
            let doc = sbom.document_for(&Scope::platform("linux-64")).unwrap();
            let graph = graph_of(doc, format);
            // 3 packages + root, all distinct.
            assert_eq!(graph.nodes.len(), 4, "{format}: distinct refs");
            // tool still depends on both versionless helpers.
            let (_names, edges) = named_graph(doc, format);
            assert!(edges.contains(&("tool".to_string(), "helper".to_string())));
            assert!(edges.contains(&("tool".to_string(), "helper2".to_string())));
        }
    }
}
