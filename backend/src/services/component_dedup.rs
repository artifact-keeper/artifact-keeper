//! Component-identity dedup for artifacts discovered through more than one
//! path (#4044).
//!
//! # The defect
//!
//! A conda artifact now carries two identities (#4041/#4042): the qualified
//! conda purl, and the PyPI alias its advisory coverage rides on. Once the
//! payload is also cataloged, the SAME underlying component is discovered
//! more than once:
//!
//! * the conda component itself (`py-opencv 4.9.0`, cataloged by syft with no
//!   purl — #4039 — and restated with the qualified conda purl by
//!   `attach_conda_artifact_purl`),
//! * the `.dist-info` inside the payload (`opencv-python 4.9.0`, cataloged as
//!   a PyPI distribution),
//! * the advisory finding reached through the alias (`DependencyScanner`
//!   queries OSV/GHSA as `opencv-python` and names the finding `py-opencv`).
//!
//! Every one of those is true. None of them is a second component. Reporting
//! the same CVE two or three times destroys confidence in the count faster
//! than missing one does.
//!
//! # The layer
//!
//! Dedup happens at the COMPONENT-IDENTITY layer, at the scan persistence
//! boundary (`scan_artifact_inner`), scoped to ONE artifact: identity is
//! `(normalized name, version)` across ecosystems linked by the alias map —
//! same name+version via alias = same component. The dedup key rides
//! [`crate::services::conda_identity::AliasMap`], the same graph the advisory
//! path queries with, so the two never disagree about what is the same
//! package.
//!
//! Two mechanisms:
//!
//! 1. **Inventory merge** ([`merge_artifact_packages`]): rows that name the
//!    component the artifact IS collapse to one row. The survivor keeps the
//!    richest identity (the qualified conda purl when present) and records
//!    EVERY discovery path in a merged `source_target` seen-via list — the
//!    paths are diagnostic information and are never silently dropped.
//! 2. **Finding merge + coverage-aware suppression**
//!    ([`merge_artifact_self_findings`], [`partition_covered_findings`]):
//!    within one scan, artifact-self findings sharing a vulnerability
//!    identity merge (max severity retained, every discovery path recorded on
//!    the survivor). Across scans, a cataloging scanner's artifact-self
//!    finding is suppressed ONLY when the advisory (`dependency`) scan of the
//!    same artifact already recorded a finding with the same `(vulnerability,
//!    component, version)` identity — which is what keeps finding counts
//!    stable when a rescan catalogs MORE than the last one did. A finding the
//!    advisory path did NOT record is always kept: suppression can never hide
//!    unique coverage.
//!
//! # False merge is worse than false dup
//!
//! The merge refuses every doubtful case, deliberately:
//!
//! * a versionless row can name anything, so it never merges;
//! * a name that does not normalize (hostile or misidentified input) never
//!   merges;
//! * a vendored native library inside a DIFFERENT artifact is never touched —
//!   the scope is the artifact's own identity, and `libwebp` is not in
//!   `numpy`'s accepted-name set;
//! * cross-scan suppression only fires when the alias graph positively owns
//!   the component (`Mapped` or `NotPythonPackage`). An `Unmapped` package is
//!   an unasked question (#4042); the payload catalog is its only coverage
//!   and every finding against it is kept.
//!
//! Keeping a false duplicate costs a number that reads slightly high.
//! Merging two genuinely different components loses a real finding. The
//! asymmetry is intentional, and this module always errs toward keeping both
//! rows.
//!
//! # Out of scope (follow-ups, not defects)
//!
//! * Vendored native components discovered by BOTH package analysis and the
//!   payload catalog (e.g. `libwebp` inside a wheel) still produce one
//!   finding per scanner: they are not alias-linked identities, and merging
//!   them is a different decision.
//! * Artifacts scanned BEFORE this change keep both rows in `scan_packages`;
//!   the SBOM read path is unchanged and reflects the merged inventory from
//!   the next scan onward.

use std::collections::{HashMap, HashSet};

use crate::models::security::{RawFinding, RawPackage};
use crate::services::conda_identity::{self, AliasMap};

/// The scan_type whose findings are the canonical owner of artifact-self
/// findings for a conda artifact. `DependencyScanner::scan_type()` returns
/// this literal; persisted `scan_results.scan_type` rows key on it.
pub const ADVISORY_SCAN_TYPE: &str = "dependency";

/// The component identity ONE conda artifact ships, plus every spelling a
/// discovery path may use for it.
///
/// Constructed per artifact per scan by [`Self::for_artifact`]; `None` for
/// non-conda artifacts and for conda artifacts without a usable name or
/// version (a versionless identity can confirm nothing — the same honesty
/// rule as `conda_identity::row_names_artifact`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactComponentScope {
    /// The conda-normalized name the merged component/finding is named by:
    /// the identity the reader actually holds.
    canonical_name: String,
    /// The artifact's version, trimmed. Both halves of the identity must
    /// hold for a merge; name alone is never enough.
    version: String,
    /// Every normalized spelling that names this component: the conda name,
    /// its PEP 503 form, and every PyPI alias the graph knows.
    accepted_names: HashSet<String>,
    /// True when the advisory path answers for this component (`Mapped` or
    /// `NotPythonPackage`), so a catalog-path finding identical to one the
    /// advisory path recorded is a proven duplicate.
    advisory_path_owns_findings: bool,
}

impl ArtifactComponentScope {
    /// Resolve the dedup scope for one artifact.
    ///
    /// The accepted-name set is the conda name, its PEP 503 folding (the
    /// `.dist-info` of the same distribution folds separators the conda
    /// channel index does not), and the alias graph's PyPI names. A name the
    /// graph does not know is NOT guessed into an alias — the same refusal
    /// as `pypi_aliases` — but separator folding inside the artifact's own
    /// payload is accepted, because two rows of one artifact carrying the
    /// same folded name AND the same version are the same distribution.
    pub fn for_artifact(
        repository_format: &str,
        artifact_name: &str,
        artifact_version: Option<&str>,
        map: &AliasMap,
    ) -> Option<Self> {
        if !repository_format.eq_ignore_ascii_case("conda") {
            return None;
        }
        let canonical_name = conda_identity::normalize_conda_name(artifact_name)?;
        let version = artifact_version?.trim();
        if version.is_empty() {
            return None;
        }

        let resolution = conda_identity::pypi_aliases(&canonical_name, map);
        let mut accepted_names = HashSet::new();
        accepted_names.insert(canonical_name.clone());
        if let Some(folded) = conda_identity::normalize_pypi_name(&canonical_name) {
            accepted_names.insert(folded);
        }
        let advisory_path_owns_findings = match &resolution.coverage {
            conda_identity::AliasCoverage::Mapped => {
                for alias in &resolution.aliases {
                    accepted_names.insert(alias.pypi_name.clone());
                }
                true
            }
            conda_identity::AliasCoverage::NotPythonPackage { .. } => true,
            conda_identity::AliasCoverage::Unmapped { .. } => false,
        };

        Some(ArtifactComponentScope {
            canonical_name,
            version: version.to_string(),
            accepted_names,
            advisory_path_owns_findings,
        })
    }

    /// The name the merged component and its findings are reported under.
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// True when the advisory scan is the canonical owner of this
    /// component's findings, making a catalog-scan duplicate suppressible.
    pub fn advisory_path_owns_findings(&self) -> bool {
        self.advisory_path_owns_findings
    }

    /// True when `(name, version)` names the component this artifact IS.
    ///
    /// BOTH halves must hold: the name must normalize to an accepted
    /// spelling AND the version must equal the artifact's exactly. A
    /// versionless row — or a row at any other version, like a genuinely
    /// different vendored copy — never merges.
    pub fn matches(&self, name: &str, version: Option<&str>) -> bool {
        let Some(version) = version.map(str::trim) else {
            return false;
        };
        if version != self.version {
            return false;
        }
        // Both normalizations are tried: they disagree on separator folding
        // (`OpenCV_Python` is `opencv_python` as a conda name and
        // `opencv-python` as a PEP 503 name), and either spelling may be the
        // one a discovery path reported.
        let conda = conda_identity::normalize_conda_name(name);
        let pypi = conda_identity::normalize_pypi_name(name);
        conda
            .as_ref()
            .is_some_and(|n| self.accepted_names.contains(n))
            || pypi
                .as_ref()
                .is_some_and(|n| self.accepted_names.contains(n))
    }
}

/// Merge inventory rows that name the component the artifact IS into a
/// single row (#4044).
///
/// Survivor selection is deterministic and order-independent: the row with
/// the richest identity wins (qualified conda purl, then any purl, then a
/// bare row; ties broken by name and purl lexicographically), and the merged
/// row is RENAMED to the artifact's conda identity — the package the reader
/// holds, not the alias a cataloger happened to report.
///
/// Preservation: the survivor's `source_target` becomes the union of every
/// merged row's `source_target`, sorted and deduplicated. That list is the
/// seen-via record — every discovery path that observed this component —
/// and it is never collapsed away. License and purl fill from the richest
/// available source rather than first-come.
///
/// Rows that do not name the artifact's own component pass through in their
/// original relative order, untouched.
pub fn merge_artifact_packages(
    packages: Vec<RawPackage>,
    scope: &ArtifactComponentScope,
) -> Vec<RawPackage> {
    let mut member_positions: Vec<usize> = Vec::new();
    for (i, pkg) in packages.iter().enumerate() {
        if scope.matches(&pkg.name, pkg.version.as_deref()) {
            member_positions.push(i);
        }
    }
    if member_positions.len() < 2 {
        return packages;
    }

    // Deterministic survivor rank: fewer is better.
    let rank = |pkg: &RawPackage| {
        let purl_rank = match pkg.purl.as_deref() {
            Some(p) if p.starts_with("pkg:conda/") => 0,
            Some(_) => 1,
            None => 2,
        };
        let name_rank = usize::from(pkg.name != scope.canonical_name);
        (
            purl_rank,
            name_rank,
            pkg.name.clone(),
            pkg.purl.clone().unwrap_or_default(),
            pkg.source_target.clone().unwrap_or_default(),
        )
    };

    let members: Vec<&RawPackage> = member_positions.iter().map(|&i| &packages[i]).collect();
    let mut ranked: Vec<&RawPackage> = members.clone();
    ranked.sort_by_key(|pkg| rank(pkg));
    let base = ranked[0];

    // Fill gaps in ranked (richest-first) order, never first-come.
    let purl = ranked.iter().find_map(|pkg| pkg.purl.clone());
    let license = ranked.iter().find_map(|pkg| pkg.license.clone());

    // The seen-via list: EVERY discovery path, sorted and deduplicated.
    let mut seen_via: Vec<String> = members
        .iter()
        .filter_map(|pkg| pkg.source_target.clone())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    seen_via.sort();
    seen_via.dedup();

    let merged = RawPackage {
        name: scope.canonical_name.clone(),
        version: Some(scope.version.clone()),
        purl: purl.or_else(|| base.purl.clone()),
        license,
        source_target: (!seen_via.is_empty()).then(|| seen_via.join("+")),
    };

    let first = member_positions[0];
    let member_set: HashSet<usize> = member_positions.into_iter().collect();
    let mut out = Vec::with_capacity(packages.len() - member_set.len() + 1);
    for (i, pkg) in packages.into_iter().enumerate() {
        if i == first {
            out.push(merged.clone());
        } else if !member_set.contains(&i) {
            out.push(pkg);
        }
    }
    out
}

/// The vulnerability-identity half of a finding key, mirroring
/// `dedupe_findings`: the CVE id when there is one, else the advisory's
/// native identity `(source, title)` so two different CVE-less advisories
/// never collapse into each other.
fn vuln_identity(cve_id: Option<&str>, source: Option<&str>, title: &str) -> String {
    match cve_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => format!("cve:{id}"),
        None => format!("native:{}|{}", source.unwrap_or(""), title),
    }
}

/// Stable identity of an artifact-self finding: the vulnerability plus the
/// artifact's component identity. Two findings with the same key — whatever
/// spelling or scanner produced them — are the same finding about the same
/// component.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactSelfFindingKey {
    pub vuln: String,
    pub version: String,
}

/// The key of a finding IF it names the artifact's own component. `None`
/// for findings about anything else — they are never merged or suppressed.
pub fn artifact_self_finding_key(
    finding: &RawFinding,
    scope: &ArtifactComponentScope,
) -> Option<ArtifactSelfFindingKey> {
    let component = finding.affected_component.as_deref()?;
    scope
        .matches(component, finding.affected_version.as_deref())
        .then(|| ArtifactSelfFindingKey {
            vuln: vuln_identity(
                finding.cve_id.as_deref(),
                finding.source.as_deref(),
                &finding.title,
            ),
            version: scope.version.clone(),
        })
}

/// The key of a PERSISTED finding row (the cross-scan coverage lookup), IF
/// it names the artifact's own component.
pub fn covered_row_key(
    cve_id: Option<&str>,
    title: &str,
    source: Option<&str>,
    component: Option<&str>,
    version: Option<&str>,
    scope: &ArtifactComponentScope,
) -> Option<ArtifactSelfFindingKey> {
    let component = component?;
    scope
        .matches(component, version)
        .then(|| ArtifactSelfFindingKey {
            vuln: vuln_identity(cve_id, source, title),
            version: scope.version.clone(),
        })
}

/// Merge artifact-self findings that share a vulnerability identity within
/// ONE scan's output (#4044).
///
/// The merge group keeps its MAXIMUM-severity member (severity is ordered
/// Critical=0 .. Info=4), renamed to the artifact's conda identity, with
/// every discovery path preserved two ways: the survivor's `source` becomes
/// the sorted union of the group's sources, and its description gains an
/// "Also discovered via" sentence naming the paths it did not itself come
/// from. Tie-breaks are fully deterministic (severity, then source, then
/// title, then the originally reported component), so the result does not
/// depend on which discovery path produced a row first.
///
/// Findings about anything but the artifact's own component pass through in
/// their original relative order, untouched.
pub fn merge_artifact_self_findings(
    findings: Vec<RawFinding>,
    scope: &ArtifactComponentScope,
) -> Vec<RawFinding> {
    let mut groups: HashMap<ArtifactSelfFindingKey, Vec<usize>> = HashMap::new();
    for (i, finding) in findings.iter().enumerate() {
        if let Some(key) = artifact_self_finding_key(finding, scope) {
            groups.entry(key).or_default().push(i);
        }
    }

    let mut merged_at: HashMap<usize, RawFinding> = HashMap::new();
    let mut absorbed: HashSet<usize> = HashSet::new();

    for members in groups.values() {
        if members.len() < 2 {
            continue;
        }
        let mut ranked: Vec<usize> = members.clone();
        ranked.sort_by_key(|&i| {
            let f = &findings[i];
            (
                f.severity,
                f.source.clone().unwrap_or_default(),
                f.title.clone(),
                f.affected_component.clone().unwrap_or_default(),
            )
        });
        let base = &findings[ranked[0]];

        let mut sources: Vec<String> = members
            .iter()
            .filter_map(|&i| findings[i].source.clone())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        sources.sort();
        sources.dedup();

        // fixed_version / source_url fill from the ranked (most severe,
        // then most deterministic) order rather than first-come.
        let fixed_version = ranked
            .iter()
            .filter_map(|&i| findings[i].fixed_version.clone())
            .next();
        let source_url = ranked
            .iter()
            .filter_map(|&i| findings[i].source_url.clone())
            .next();

        let base_source = base.source.as_deref().unwrap_or("").trim().to_string();
        let other_paths: Vec<&String> = sources.iter().filter(|s| **s != base_source).collect();
        let description = if other_paths.is_empty() {
            base.description.clone()
        } else {
            let via = other_paths
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Some(match &base.description {
                Some(d) => format!("{d}\n\nAlso discovered via: {via}."),
                None => format!("Also discovered via: {via}."),
            })
        };

        let merged = RawFinding {
            severity: base.severity,
            title: base.title.clone(),
            description,
            cve_id: base.cve_id.clone(),
            affected_component: Some(scope.canonical_name.clone()),
            affected_version: Some(scope.version.clone()),
            fixed_version,
            source: (!sources.is_empty()).then(|| sources.join(" + ")),
            source_url,
        };

        merged_at.insert(members[0], merged);
        for &i in &members[1..] {
            absorbed.insert(i);
        }
    }

    let mut out = Vec::with_capacity(findings.len());
    for (i, finding) in findings.into_iter().enumerate() {
        if let Some(merged) = merged_at.remove(&i) {
            out.push(merged);
        } else if !absorbed.contains(&i) {
            out.push(finding);
        }
    }
    out
}

/// Split a scan's findings into those to KEEP and those to SUPPRESS because
/// the advisory scan already recorded the same `(vulnerability, component,
/// version)` identity for this artifact (#4044).
///
/// This is the cross-scan half of the dedup, and it is deliberately the
/// conservative direction: a finding is suppressed ONLY when `covered`
/// positively contains its identity — i.e. the advisory path already
/// reported the same CVE against the same component at the same version.
/// Anything else is kept. Suppression can therefore never hide unique
/// coverage; the worst it can do is leave a false duplicate, which is the
/// acceptable failure direction.
///
/// The suppressed list is returned (not dropped silently) so the caller can
/// log every one with its identity.
pub fn partition_covered_findings(
    findings: Vec<RawFinding>,
    scope: &ArtifactComponentScope,
    covered: &HashSet<ArtifactSelfFindingKey>,
) -> (Vec<RawFinding>, Vec<RawFinding>) {
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for finding in findings {
        let duplicate =
            artifact_self_finding_key(&finding, scope).is_some_and(|key| covered.contains(&key));
        if duplicate {
            suppressed.push(finding);
        } else {
            kept.push(finding);
        }
    }
    (kept, suppressed)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::Severity;
    use crate::services::conda_identity::AliasMap;

    // -- helpers ------------------------------------------------------------

    fn pkg(
        name: &str,
        version: &str,
        purl: Option<&str>,
        source_target: Option<&str>,
    ) -> RawPackage {
        RawPackage {
            name: name.to_string(),
            version: Some(version.to_string()),
            purl: purl.map(str::to_string),
            license: None,
            source_target: source_target.map(str::to_string),
        }
    }

    fn finding(
        severity: Severity,
        cve: &str,
        component: &str,
        version: &str,
        source: &str,
    ) -> RawFinding {
        RawFinding {
            severity,
            title: format!("{cve} in {component}"),
            description: Some(format!("advisory details for {cve}")),
            cve_id: Some(cve.to_string()),
            affected_component: Some(component.to_string()),
            affected_version: Some(version.to_string()),
            fixed_version: Some("9.9.9".to_string()),
            source: Some(source.to_string()),
            source_url: None,
        }
    }

    fn numpy_scope() -> ArtifactComponentScope {
        ArtifactComponentScope::for_artifact(
            "conda",
            "numpy",
            Some("1.26.4"),
            &AliasMap::builtin_only(),
        )
        .expect("numpy scope")
    }

    fn opencv_scope() -> ArtifactComponentScope {
        ArtifactComponentScope::for_artifact(
            "conda",
            "py-opencv",
            Some("4.9.0"),
            &AliasMap::builtin_only(),
        )
        .expect("py-opencv scope")
    }

    // =======================================================================
    // Scope construction and matching
    // =======================================================================

    #[test]
    fn scope_exists_only_for_conda_artifacts_with_a_version() {
        assert!(ArtifactComponentScope::for_artifact(
            "pypi",
            "numpy",
            Some("1.26.4"),
            &AliasMap::builtin_only()
        )
        .is_none());
        assert!(ArtifactComponentScope::for_artifact(
            "conda",
            "numpy",
            None,
            &AliasMap::builtin_only()
        )
        .is_none());
        assert!(ArtifactComponentScope::for_artifact(
            "conda",
            "numpy",
            Some("  "),
            &AliasMap::builtin_only()
        )
        .is_none());
    }

    #[test]
    fn scope_matches_name_spellings_but_always_requires_the_version() {
        let scope = opencv_scope();
        // The conda name, the PEP 503 alias, and case/spelling variants.
        assert!(scope.matches("py-opencv", Some("4.9.0")));
        assert!(scope.matches("opencv-python", Some("4.9.0")));
        assert!(scope.matches("OpenCV_Python", Some("4.9.0")));
        // Version must hold: same name at any other version is a DIFFERENT
        // component, and a versionless row can confirm nothing.
        assert!(!scope.matches("opencv-python", Some("4.8.1")));
        assert!(!scope.matches("opencv-python", None));
        assert!(!scope.matches("opencv-python", Some("")));
        // A different package is a different package.
        assert!(!scope.matches("numpy", Some("4.9.0")));
    }

    #[test]
    fn unmapped_coverage_does_not_claim_finding_ownership() {
        let scope = ArtifactComponentScope::for_artifact(
            "conda",
            "some-vendor-internal-thing",
            Some("1.0"),
            &AliasMap::builtin_only(),
        )
        .expect("scope still exists for inventory merge");
        assert!(!scope.advisory_path_owns_findings());
        // The inventory merge still works on the name itself.
        assert!(scope.matches("some-vendor-internal-thing", Some("1.0")));

        let mapped = opencv_scope();
        assert!(mapped.advisory_path_owns_findings());

        let not_python = ArtifactComponentScope::for_artifact(
            "conda",
            "libwebp",
            Some("1.3.2"),
            &AliasMap::builtin_only(),
        )
        .expect("libwebp scope");
        assert!(not_python.advisory_path_owns_findings());
    }

    // =======================================================================
    // Inventory merge
    // =======================================================================

    /// Acceptance #1: a conda package containing a Python distribution of
    /// the same name and version reports ONE component, with both discovery
    /// paths recorded.
    #[test]
    fn conda_row_and_dist_info_of_same_name_and_version_merge_to_one_component() {
        let scope = numpy_scope();
        let packages = vec![
            pkg(
                "numpy",
                "1.26.4",
                Some("pkg:conda/numpy@1.26.4?subdir=linux-64"),
                Some("conda"),
            ),
            pkg("libzlib", "1.3", None, Some("binary")),
            pkg(
                "numpy",
                "1.26.4",
                Some("pkg:pypi/numpy@1.26.4"),
                Some("python"),
            ),
        ];
        let merged = merge_artifact_packages(packages, &scope);
        assert_eq!(merged.len(), 2, "one component, not two");
        let numpy = merged
            .iter()
            .find(|p| p.name == "numpy")
            .expect("surviving row");
        // Mutation-check the preservation invariant: BOTH discovery paths
        // must be present on the survivor, not just whichever came first.
        let seen_via = numpy.source_target.as_deref().expect("seen-via recorded");
        assert!(seen_via.contains("conda"), "{seen_via}");
        assert!(seen_via.contains("python"), "{seen_via}");
        // The richest identity survives.
        assert_eq!(
            numpy.purl.as_deref(),
            Some("pkg:conda/numpy@1.26.4?subdir=linux-64")
        );
        // The genuinely different component is untouched.
        let libzlib = merged.iter().find(|p| p.name == "libzlib").expect("kept");
        assert_eq!(libzlib.purl, None);
    }

    #[test]
    fn alias_linked_dist_info_merges_and_the_survivor_names_the_conda_package() {
        let scope = opencv_scope();
        let packages = vec![
            pkg(
                "opencv-python",
                "4.9.0",
                Some("pkg:pypi/opencv-python@4.9.0"),
                Some("python"),
            ),
            pkg(
                "py-opencv",
                "4.9.0",
                Some("pkg:conda/py-opencv@4.9.0?subdir=linux-64"),
                None,
            ),
        ];
        let merged = merge_artifact_packages(packages, &scope);
        assert_eq!(merged.len(), 1);
        let survivor = &merged[0];
        // The reader holds the CONDA package; the row names that identity.
        assert_eq!(survivor.name, "py-opencv");
        assert_eq!(
            survivor.purl.as_deref(),
            Some("pkg:conda/py-opencv@4.9.0?subdir=linux-64")
        );
        assert_eq!(survivor.source_target.as_deref(), Some("python"));
    }

    #[test]
    fn a_vendored_native_that_is_not_the_artifact_stays_separate() {
        // numpy vendors libwebp: the vendored row shares NOTHING with the
        // artifact identity and must not merge.
        let scope = numpy_scope();
        let packages = vec![
            pkg(
                "numpy",
                "1.26.4",
                Some("pkg:conda/numpy@1.26.4?subdir=linux-64"),
                Some("conda"),
            ),
            pkg("libwebp", "1.3.2", None, Some("binary")),
            pkg(
                "numpy",
                "1.26.4",
                Some("pkg:pypi/numpy@1.26.4"),
                Some("python"),
            ),
        ];
        let merged = merge_artifact_packages(packages, &scope);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|p| p.name == "libwebp"));
    }

    #[test]
    fn same_name_at_a_different_version_is_a_different_component() {
        // The guidance's own example: name alone is never enough. A payload
        // row naming the artifact at another version is a genuinely
        // different component (a vendored second copy) and both rows stay.
        let scope = numpy_scope();
        let packages = vec![
            pkg(
                "numpy",
                "1.26.4",
                Some("pkg:conda/numpy@1.26.4?subdir=linux-64"),
                Some("conda"),
            ),
            pkg(
                "numpy",
                "1.21.0",
                Some("pkg:pypi/numpy@1.21.0"),
                Some("python"),
            ),
        ];
        let merged = merge_artifact_packages(packages, &scope);
        assert_eq!(merged.len(), 2, "false merge is worse than false dup");
    }

    #[test]
    fn versionless_rows_never_merge() {
        let scope = numpy_scope();
        let mut packages = vec![
            pkg(
                "numpy",
                "1.26.4",
                Some("pkg:conda/numpy@1.26.4?subdir=linux-64"),
                Some("conda"),
            ),
            RawPackage {
                name: "numpy".to_string(),
                version: None,
                purl: None,
                license: None,
                source_target: Some("python".to_string()),
            },
        ];
        let merged = merge_artifact_packages(std::mem::take(&mut packages), &scope);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_is_order_independent() {
        let scope = opencv_scope();
        let rows = [
            pkg(
                "opencv-python",
                "4.9.0",
                Some("pkg:pypi/opencv-python@4.9.0"),
                Some("python"),
            ),
            pkg("libzlib", "1.3", None, Some("binary")),
            pkg(
                "py-opencv",
                "4.9.0",
                Some("pkg:conda/py-opencv@4.9.0?subdir=linux-64"),
                Some("conda"),
            ),
        ];
        let baseline = merge_artifact_packages(rows.to_vec(), &scope);
        // Every permutation must produce the same SURVIVOR CONTENT.
        for perm in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let shuffled: Vec<RawPackage> = perm.iter().map(|&i| rows[i].clone()).collect();
            let merged = merge_artifact_packages(shuffled, &scope);
            let mut a: Vec<RawPackage> = baseline.clone();
            let mut b: Vec<RawPackage> = merged;
            let key = |p: &RawPackage| (p.name.clone(), p.version.clone());
            a.sort_by_key(key);
            b.sort_by_key(key);
            assert_eq!(a, b, "permutation {perm:?} changed the merge result");
        }
    }

    #[test]
    fn a_single_matching_row_is_left_exactly_as_reported() {
        let scope = numpy_scope();
        let packages = vec![pkg("numpy", "1.26.4", None, Some("conda"))];
        let merged = merge_artifact_packages(packages.clone(), &scope);
        assert_eq!(merged, packages, "nothing to merge, nothing to change");
    }

    // =======================================================================
    // Within-scan finding merge
    // =======================================================================

    /// The DependencyScanner can report the artifact's own component twice
    /// in one scan: once as the conda package (via alias/unscoped) and once
    /// as a vendored component recovered from the payload. One component,
    /// one finding — with BOTH paths on the survivor.
    #[test]
    fn within_scan_duplicate_artifact_self_findings_merge_keeping_max_severity_and_both_paths() {
        let scope = ArtifactComponentScope::for_artifact(
            "conda",
            "libwebp",
            Some("1.3.2"),
            &AliasMap::builtin_only(),
        )
        .expect("libwebp scope");
        let mut high = finding(
            Severity::High,
            "CVE-2023-4863",
            "libwebp",
            "1.3.2",
            "osv (vendored)",
        );
        high.fixed_version = None;
        let critical = finding(
            Severity::Critical,
            "CVE-2023-4863",
            "libwebp",
            "1.3.2",
            "github (conda alias)",
        );
        let merged = merge_artifact_self_findings(vec![high, critical], &scope);
        assert_eq!(merged.len(), 1, "one real component, one finding");
        let survivor = &merged[0];
        assert_eq!(
            survivor.severity,
            Severity::Critical,
            "max severity retained"
        );
        assert_eq!(survivor.affected_component.as_deref(), Some("libwebp"));
        // Mutation-check: BOTH discovery paths recorded on the survivor.
        let source = survivor.source.as_deref().expect("source recorded");
        assert!(source.contains("conda alias"), "{source}");
        assert!(source.contains("vendored"), "{source}");
        let description = survivor.description.as_deref().expect("description");
        assert!(description.contains("Also discovered via"), "{description}");
        // The fix version the less-severe path lacked fills from the other.
        assert_eq!(survivor.fixed_version.as_deref(), Some("9.9.9"));
    }

    #[test]
    fn findings_about_other_components_pass_through_untouched() {
        let scope = numpy_scope();
        let findings = vec![
            finding(Severity::High, "CVE-2024-0001", "libzlib", "1.3", "grype"),
            finding(Severity::High, "CVE-2024-0001", "numpy", "1.21.0", "grype"),
            finding(
                Severity::Medium,
                "CVE-2024-0002",
                "numpy",
                "1.26.4",
                "grype",
            ),
        ];
        let merged = merge_artifact_self_findings(findings, &scope);
        // Different vulnerability identities and different versions never
        // merge; only exact (vuln, component, version) identity does.
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn finding_merge_is_order_independent() {
        let scope = numpy_scope();
        let a = finding(Severity::High, "CVE-2024-4242", "numpy", "1.26.4", "grype");
        let b = finding(
            Severity::Medium,
            "CVE-2024-4242",
            "numpy",
            "1.26.4",
            "osv (conda alias)",
        );
        let baseline = merge_artifact_self_findings(vec![a.clone(), b.clone()], &scope);
        let flipped = merge_artifact_self_findings(vec![b, a], &scope);
        assert_eq!(baseline.len(), 1);
        assert_eq!(flipped.len(), 1);
        assert_eq!(baseline[0].severity, flipped[0].severity);
        assert_eq!(baseline[0].source, flipped[0].source);
        assert_eq!(baseline[0].description, flipped[0].description);
    }

    // =======================================================================
    // Cross-scan coverage suppression
    // =======================================================================

    #[test]
    fn covered_artifact_self_findings_are_suppressed_and_unique_ones_kept() {
        let scope = opencv_scope();
        let covered: HashSet<ArtifactSelfFindingKey> = [ArtifactSelfFindingKey {
            vuln: "cve:CVE-2024-1111".to_string(),
            version: "4.9.0".to_string(),
        }]
        .into_iter()
        .collect();

        let duplicate = finding(
            Severity::High,
            "CVE-2024-1111",
            "opencv-python",
            "4.9.0",
            "grype",
        );
        let unique = finding(
            Severity::Critical,
            "CVE-2024-2222",
            "opencv-python",
            "4.9.0",
            "grype",
        );
        let other_component = finding(Severity::High, "CVE-2024-1111", "libzlib", "1.3", "grype");

        let (kept, suppressed) =
            partition_covered_findings(vec![duplicate, unique, other_component], &scope, &covered);
        assert_eq!(suppressed.len(), 1, "the proven duplicate only");
        assert_eq!(kept.len(), 2, "unique coverage and other components stay");
        assert!(kept
            .iter()
            .any(|f| f.cve_id.as_deref() == Some("CVE-2024-2222")));
        assert!(kept
            .iter()
            .any(|f| f.affected_component.as_deref() == Some("libzlib")));
    }

    #[test]
    fn the_coverage_key_matches_across_discovery_spellings() {
        // The advisory scan names the conda package; the catalog scan names
        // the PyPI distribution. The SAME key must fall out of both.
        let scope = opencv_scope();
        let advisory_finding = finding(
            Severity::High,
            "CVE-2024-1111",
            "py-opencv",
            "4.9.0",
            "osv (conda alias)",
        );
        let catalog_finding = finding(
            Severity::High,
            "CVE-2024-1111",
            "opencv-python",
            "4.9.0",
            "grype",
        );
        let from_row = covered_row_key(
            advisory_finding.cve_id.as_deref(),
            &advisory_finding.title,
            advisory_finding.source.as_deref(),
            advisory_finding.affected_component.as_deref(),
            advisory_finding.affected_version.as_deref(),
            &scope,
        )
        .expect("advisory row keys");
        let from_finding =
            artifact_self_finding_key(&catalog_finding, &scope).expect("catalog finding keys");
        assert_eq!(from_row, from_finding);
    }

    // =======================================================================
    // Rescan stability (acceptance #2)
    // =======================================================================

    /// Scan 1 catalogs the conda component only; scan 2 catalogs MORE (the
    /// dist-info appears) and matches the same CVE against it. The merged
    /// component set and the surviving finding set must be IDENTICAL.
    #[test]
    fn counts_are_stable_when_a_rescan_catalogs_more() {
        let scope = opencv_scope();

        // The advisory scan output is the same on both runs.
        let advisory_findings = || {
            vec![finding(
                Severity::High,
                "CVE-2024-1111",
                "py-opencv",
                "4.9.0",
                "osv (conda alias)",
            )]
        };

        // Run 1: grype sees only the conda component, finds nothing.
        let run1_packages = merge_artifact_packages(
            vec![pkg(
                "py-opencv",
                "4.9.0",
                Some("pkg:conda/py-opencv@4.9.0?subdir=linux-64"),
                Some("conda"),
            )],
            &scope,
        );
        let covered: HashSet<ArtifactSelfFindingKey> = advisory_findings()
            .iter()
            .filter_map(|f| artifact_self_finding_key(f, &scope))
            .collect();
        let run1_grype: Vec<RawFinding> = vec![];

        // Run 2: grype additionally catalogs the dist-info and matches the
        // same CVE against it.
        let run2_packages = merge_artifact_packages(
            vec![
                pkg(
                    "py-opencv",
                    "4.9.0",
                    Some("pkg:conda/py-opencv@4.9.0?subdir=linux-64"),
                    Some("conda"),
                ),
                pkg(
                    "opencv-python",
                    "4.9.0",
                    Some("pkg:pypi/opencv-python@4.9.0"),
                    Some("python"),
                ),
            ],
            &scope,
        );
        let (run2_grype, suppressed) = partition_covered_findings(
            vec![finding(
                Severity::High,
                "CVE-2024-1111",
                "opencv-python",
                "4.9.0",
                "grype",
            )],
            &scope,
            &covered,
        );

        assert_eq!(run1_packages.len(), 1);
        assert_eq!(run2_packages.len(), 1, "component count stable");
        assert_eq!(run1_packages[0].name, run2_packages[0].name);
        assert_eq!(run1_packages[0].purl, run2_packages[0].purl);
        assert_eq!(suppressed.len(), 1, "the duplicate is recorded, not hidden");
        assert_eq!(
            run1_grype.len(),
            run2_grype.len(),
            "finding count stable across the rescan"
        );
    }
}
