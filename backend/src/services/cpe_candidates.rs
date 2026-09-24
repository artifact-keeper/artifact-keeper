//! Map vendored native component identities to candidate CPEs (#4043).
//!
//! The native libraries recovered by package analysis (recipe-derived
//! sources, wheel auditwheel layouts) are C/C++ projects. Their advisories
//! live in NVD, which is keyed on CPE, not on package names — so a component
//! named `libwebp` is discovered and then matched against nothing until its
//! identity is restated as something like `cpe:2.3:a:webmproject:libwebp`.
//!
//! That restatement is a *guess* with a provenance problem: several vendors
//! publish the same product name (`openssl` vs `openssl_project`), and the
//! wrong vendor matches confidently and wrongly. This module therefore
//! produces **candidates, plural, each carrying the rule that produced it
//! and a confidence**, and refuses to collapse an ambiguous set into one
//! answer. A wrong candidate is traceable to its rule (`rule_id`); an
//! ambiguous set is reported as ambiguous ([`is_ambiguous`]) rather than
//! resolved arbitrarily ([`dt_cpe`] returns `None` for it).
//!
//! Three rules, strongest first:
//!
//! 1. [`RULE_KNOWN_CPE_TABLE`] — the component's normalized name is a key in
//!    the vendored table of well-known libraries (`libwebp` →
//!    `webmproject:libwebp`). High confidence: vendor and product are the
//!    values NVD itself uses for that library.
//! 2. [`RULE_SOURCE_URL_VENDOR`] — the component's `source_url`/`git_url`
//!    names a repository whose name matches the component on a known forge;
//!    the forge owner becomes the vendor. Medium confidence: the owner is
//!    evidence, but NVD's vendor string is not obliged to equal it.
//! 3. [`RULE_NAME_AS_PRODUCT`] — nothing else fired; the name itself is
//!    offered as both vendor and product, plus the `<name>_project` vendor
//!    variant. Low confidence, and deliberately two candidates: this is the
//!    rule that surfaces vendor/product ambiguity instead of hiding it.
//!
//! Rule 3 has a **confidence floor**: a name too short or too malformed to
//! be a real upstream product (`ab`, `{{ name }}`) produces no candidates
//! at all. An invented CPE is worse than none — it matches advisories for
//! a different piece of software and renders as a real finding.
//!
//! # Where the candidates go
//!
//! * The package-analysis API carries the full set per component, with
//!   confidences and rule ids — ambiguity is surfaced to the reviewer, not
//!   resolved for them.
//! * The Dependency-Track submission carries a component `cpe` **only when
//!   the top-confidence tier holds exactly one candidate** ([`dt_cpe`]).
//!   CycloneDX has a single-valued `cpe` field; writing one of several
//!   equally-ranked guesses into it would be the arbitrary resolution this
//!   module exists to prevent. DT then matches that CPE against NVD itself.
//! * [`match_advisories`] evaluates candidates against NVD-shaped
//!   `cpeMatch` criteria (version ranges included). Production NVD matching
//!   happens inside Dependency-Track; this matcher exists so the matching
//!   semantics are testable offline against a fixture advisory set, and so
//!   a future in-tree NVD feed has an evaluator ready.

/// Rule id attached to candidates produced by the curated table lookup.
pub const RULE_KNOWN_CPE_TABLE: &str = "cpe-known-table-v1";
/// Rule id attached to candidates whose vendor was derived from a forge URL.
pub const RULE_SOURCE_URL_VENDOR: &str = "cpe-source-url-vendor-v1";
/// Rule id attached to candidates guessed from the component name alone.
pub const RULE_NAME_AS_PRODUCT: &str = "cpe-name-as-product-v1";

/// How much the producing rule's evidence is worth.
///
/// Ordering is significant: `Low < Medium < High`, and the *top tier* of a
/// candidate set is what [`is_ambiguous`] and [`dt_cpe`] judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateConfidence {
    /// Name-only guess. Several vendors publish the same product name, so a
    /// Low candidate is a lead, not an identity.
    Low,
    /// The vendor was derived from the component's own source URL. Real
    /// evidence, but NVD's vendor string is not obliged to match a forge
    /// owner.
    Medium,
    /// Curated table hit: vendor and product are the values NVD uses.
    High,
}

impl CandidateConfidence {
    /// The stable wire form used by the API response.
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateConfidence::Low => "low",
            CandidateConfidence::Medium => "medium",
            CandidateConfidence::High => "high",
        }
    }
}

/// One candidate CPE for a vendored component, with its provenance.
///
/// `rule_id` is not decoration: it is what makes a wrong candidate
/// traceable to the mapping rule that produced it. `version` is the
/// component's recovered upstream release, folded into `cpe` when known and
/// rendered `*` when not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeCandidate {
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
    /// The full CPE 2.3 formatted string, e.g.
    /// `cpe:2.3:a:webmproject:libwebp:1.3.0:*:*:*:*:*:*:*`.
    pub cpe: String,
    pub confidence: CandidateConfidence,
    pub rule_id: &'static str,
}

/// The identity signals a mapping rule may use.
///
/// Everything here comes straight from `package_vendored_components` — the
/// same row the package-analysis API already serves. `purl` is not an
/// input: every vendored purl is synthesized as `pkg:generic/<name>@<ver>`
/// from the same fields, so it carries nothing the name and version do not.
#[derive(Debug, Clone, Copy, Default)]
pub struct ComponentIdentity<'a> {
    pub name: &'a str,
    pub version: Option<&'a str>,
    pub source_url: Option<&'a str>,
    pub git_url: Option<&'a str>,
}

/// Compute every candidate CPE for one vendored component.
///
/// Returns them best-first (confidence descending, then vendor/product for
/// determinism), deduplicated on `(vendor, product)` keeping the highest
/// confidence. An empty result is a real answer — "no rule had enough
/// evidence" — and must not be padded with weaker guesses: that padding is
/// exactly the below-floor invention the floor exists to forbid.
pub fn candidates(identity: &ComponentIdentity) -> Vec<CpeCandidate> {
    let Some(name) = normalize_name(identity.name) else {
        return Vec::new();
    };
    let version = identity
        .version
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);

    // Rule 1: the curated table. A hit is authoritative — vendor and product
    // are the values NVD uses — so name guesses add nothing but noise, and
    // the URL rule would only re-derive what the table states. The table may
    // legitimately hold two vendors for one name; both are returned, and
    // `is_ambiguous` reports the set as what it is.
    let table_hits: Vec<CpeCandidate> = KNOWN_CPES
        .iter()
        .filter(|(key, _, _)| *key == name)
        .map(|(_, vendor, product)| {
            make_candidate(
                vendor,
                product,
                version.as_deref(),
                CandidateConfidence::High,
                RULE_KNOWN_CPE_TABLE,
            )
        })
        .collect();
    if !table_hits.is_empty() {
        return table_hits;
    }

    let mut out: Vec<CpeCandidate> = Vec::new();

    // Rule 2: the component's own source/git URL names a forge repository
    // whose name matches the component. The forge owner is real evidence of
    // the publisher — but NVD's vendor string is not obliged to equal a
    // forge owner, so this is Medium, not High.
    for url in [identity.source_url, identity.git_url]
        .into_iter()
        .flatten()
    {
        if let Some((owner, repo)) = forge_owner_repo(url) {
            if repo == name {
                push_candidate(
                    &mut out,
                    make_candidate(
                        &owner,
                        &repo,
                        version.as_deref(),
                        CandidateConfidence::Medium,
                        RULE_SOURCE_URL_VENDOR,
                    ),
                );
            }
        }
    }

    // Rule 3: name alone, with the floor. A name too short or too malformed
    // to be a real upstream product produces no guess at all — an invented
    // CPE matches a DIFFERENT project's advisories, which is worse than no
    // candidate. Both vendor spellings are offered: the name itself and
    // `<name>_project`. Two vendors publish the same product name often
    // enough (`openssl` vs `openssl_project`) that offering only one would
    // be the arbitrary resolution this module exists to prevent.
    if above_guess_floor(&name) {
        push_candidate(
            &mut out,
            make_candidate(
                &name,
                &name,
                version.as_deref(),
                CandidateConfidence::Low,
                RULE_NAME_AS_PRODUCT,
            ),
        );
        let project_vendor = format!("{name}_project");
        push_candidate(
            &mut out,
            make_candidate(
                &project_vendor,
                &name,
                version.as_deref(),
                CandidateConfidence::Low,
                RULE_NAME_AS_PRODUCT,
            ),
        );
    }

    out
}

/// Whether the candidate set is ambiguous: more than one candidate sits in
/// the highest confidence tier present.
///
/// A set of one High plus two Low guesses is NOT ambiguous — the table hit
/// outranks the guesses, and the guesses are carried only as provenance. A
/// set of two Low guesses IS: nothing distinguishes them, and picking one
/// would be a coin flip presented as a fact. An empty set is not ambiguous;
/// it is unanswered.
pub fn is_ambiguous(candidates: &[CpeCandidate]) -> bool {
    let Some(top) = candidates.iter().map(|c| c.confidence).max() else {
        return false;
    };
    candidates.iter().filter(|c| c.confidence == top).count() > 1
}

/// The single CPE worth handing to Dependency-Track, or `None`.
///
/// CycloneDX `component.cpe` is single-valued, and DT treats it as
/// authoritative for NVD matching. `Some` exactly when the top-confidence
/// tier holds one candidate; `None` when the set is empty or ambiguous, so
/// an ambiguous identity is submitted with no CPE (DT falls back to purl /
/// name matching) rather than with an arbitrary one.
pub fn dt_cpe(candidates: &[CpeCandidate]) -> Option<String> {
    let top = candidates.iter().map(|c| c.confidence).max()?;
    let mut tier = candidates.iter().filter(|c| c.confidence == top);
    match (tier.next(), tier.next()) {
        (Some(only), None) => Some(only.cpe.clone()),
        _ => None,
    }
}

/// One NVD `cpeMatch` node: a CPE 2.3 criteria string plus optional version
/// range bounds.
///
/// This is the shape of NVD's `configurations[].nodes[].cpeMatch[]` — the
/// fixture shape the matcher is tested against, and the shape a future
/// NVD feed sync would deserialize directly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvdCpeMatch {
    pub criteria: String,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

impl NvdCpeMatch {
    /// A criteria string with no range bounds: matches the CPE's own
    /// version semantics (a `*` version criterion matches every version).
    pub fn new(criteria: &str) -> Self {
        Self {
            criteria: criteria.to_string(),
            ..Default::default()
        }
    }

    pub fn end_excluding(mut self, version: &str) -> Self {
        self.version_end_excluding = Some(version.to_string());
        self
    }

    pub fn end_including(mut self, version: &str) -> Self {
        self.version_end_including = Some(version.to_string());
        self
    }

    pub fn start_including(mut self, version: &str) -> Self {
        self.version_start_including = Some(version.to_string());
        self
    }

    pub fn start_excluding(mut self, version: &str) -> Self {
        self.version_start_excluding = Some(version.to_string());
        self
    }
}

/// A hit: one advisory matched through one candidate.
///
/// The candidate rides along in full — including its `rule_id` — so the
/// answer to "why does the scanner think CVE-2023-4863 applies here?" names
/// both the CPE that matched and the mapping rule that proposed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateMatch {
    pub advisory_id: String,
    pub candidate: CpeCandidate,
}

/// Evaluate every candidate against every advisory's match criteria.
///
/// Pure and offline: `advisories` is `(advisory_id, cpeMatch nodes)` in the
/// NVD shape, which in tests is a fixture set and in production is what a
/// feed sync would hand over. One advisory can match through several
/// candidates (the ambiguous case); each pairing is returned, never
/// collapsed, so the caller sees the ambiguity the matcher saw.
pub fn match_advisories(
    candidates: &[CpeCandidate],
    advisories: &[(&str, Vec<NvdCpeMatch>)],
) -> Vec<CandidateMatch> {
    let mut hits = Vec::new();
    for (advisory_id, nodes) in advisories {
        for candidate in candidates {
            if nodes
                .iter()
                .any(|node| candidate_matches_node(candidate, node))
            {
                hits.push(CandidateMatch {
                    advisory_id: (*advisory_id).to_string(),
                    candidate: candidate.clone(),
                });
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// The mapping table and the rules' internals.
// ---------------------------------------------------------------------------

/// The curated floor: well-known native libraries and the vendor/product
/// pair NVD uses for them, keyed by normalized component name.
///
/// This is deliberately a small in-tree table rather than a synced copy of
/// NVD's official CPE dictionary: the dictionary is tens of megabytes and
/// mostly irrelevant to what packages actually vendor, while every row here
/// is one a reviewer can audit. A name absent from the table falls through
/// to the evidence rules — it is not "safe", it is unmapped, and the
/// response says so by carrying only Low candidates or none.
static KNOWN_CPES: &[(&str, &str, &str)] = &[
    // (component name, NVD vendor, NVD product)
    ("brotli", "google", "brotli"),
    ("bzip2", "bzip", "bzip2"),
    ("curl", "haxx", "curl"),
    ("expat", "libexpat_project", "libexpat"),
    ("ffmpeg", "ffmpeg", "ffmpeg"),
    ("freetype", "freetype", "freetype"),
    ("harfbuzz", "harfbuzz_project", "harfbuzz"),
    ("libjpeg-turbo", "libjpeg-turbo", "libjpeg-turbo"),
    ("libpng", "libpng", "libpng"),
    ("libssh2", "libssh2", "libssh2"),
    ("libwebp", "webmproject", "libwebp"),
    ("libxml2", "xmlsoft", "libxml2"),
    ("nghttp2", "nghttp2", "nghttp2"),
    ("openssl", "openssl", "openssl"),
    ("pcre", "pcre", "pcre"),
    ("sqlite", "sqlite", "sqlite"),
    ("xz", "tukaani", "xz"),
    ("zlib", "zlib", "zlib"),
];

/// Normalize a component name for rule input: lowercase, `_` → `-`.
///
/// `None` means the name is unusable for ANY rule — empty, whitespace, or
/// carrying characters no upstream product name has (template braces,
/// whitespace, control bytes). Even the curated table may not be keyed on
/// garbage.
fn normalize_name(raw: &str) -> Option<String> {
    let lowered = raw.trim().to_lowercase().replace('_', "-");
    if lowered.is_empty()
        || lowered
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')))
    {
        return None;
    }
    Some(lowered)
}

/// The confidence floor for the name-guessing rule: at least three
/// characters, starting with a letter.
///
/// Below this a name is too generic to guess from — `ab`, `x` — and a
/// guess would collide with unrelated software in NVD. Note the floor
/// applies to the GUESS only: `xz` is two characters and resolves through
/// the curated table, because a table hit is not a guess.
fn above_guess_floor(normalized_name: &str) -> bool {
    normalized_name.len() >= 3
        && normalized_name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
}

/// Parse `https://github.com/<owner>/<repo>[.git][/...]`, the scp-like
/// `git@github.com:<owner>/<repo>.git`, and the same for gitlab.com.
///
/// Owner and repo come back normalized the same way component names are, so
/// the caller compares like with like. Any other host yields `None` — a
/// tarball URL on a download mirror says nothing about the publisher.
fn forge_owner_repo(url: &str) -> Option<(String, String)> {
    const FORGE_HOSTS: &[&str] = &["github.com", "gitlab.com"];

    let path = if let Some(rest) = url.strip_prefix("git@") {
        // git@github.com:owner/repo.git — host is up to the first ':'.
        let (host, path) = rest.split_once(':')?;
        if !FORGE_HOSTS.contains(&host) {
            return None;
        }
        path
    } else {
        let after_scheme = url.split_once("://").map(|(_, rest)| rest)?;
        let (host, path) = after_scheme.split_once('/')?;
        if !FORGE_HOSTS.contains(&host) {
            return None;
        }
        path
    };

    let mut segments = path.split('/');
    let owner = segments.next().unwrap_or_default();
    let repo = segments.next().unwrap_or_default();
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let owner = normalize_name(owner)?;
    let repo = normalize_name(repo)?;
    Some((owner, repo))
}

fn make_candidate(
    vendor: &str,
    product: &str,
    version: Option<&str>,
    confidence: CandidateConfidence,
    rule_id: &'static str,
) -> CpeCandidate {
    CpeCandidate {
        vendor: vendor.to_string(),
        product: product.to_string(),
        version: version.map(str::to_string),
        cpe: build_cpe(vendor, product, version),
        confidence,
        rule_id,
    }
}

/// Insert keeping the highest-confidence candidate per `(vendor, product)`,
/// and keeping the vec ordered best-first (confidence, then vendor/product)
/// so the API renders a deterministic list.
fn push_candidate(out: &mut Vec<CpeCandidate>, candidate: CpeCandidate) {
    if let Some(existing) = out
        .iter_mut()
        .find(|c| c.vendor == candidate.vendor && c.product == candidate.product)
    {
        if candidate.confidence > existing.confidence {
            *existing = candidate;
        }
    } else {
        out.push(candidate);
    }
    out.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.vendor.cmp(&b.vendor))
            .then_with(|| a.product.cmp(&b.product))
    });
}

/// The CPE 2.3 formatted string. All eleven attributes are present: part
/// `a` (application), then vendor/product/version, then `*` wildcards.
///
/// Vendor, product and version are normalized rule output (lowercase,
/// restricted alphabet), so no escaping is needed — the alphabet excludes
/// every character CPE 2.3 quoting exists for.
fn build_cpe(vendor: &str, product: &str, version: Option<&str>) -> String {
    format!(
        "cpe:2.3:a:{vendor}:{product}:{}:*:*:*:*:*:*:*",
        version.unwrap_or("*")
    )
}

/// Split a CPE 2.3 formatted string on UNESCAPED colons.
///
/// NVD criteria escape `:` inside attribute values as `\:`, and a naive
/// `split(':')` would shred such a criterion into wrong fields.
fn split_cpe(cpe: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in cpe.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    fields.push(current);
    fields
}

/// CPE attribute equality: `*` matches anything (CPE "ANY"); otherwise
/// case-insensitive equality. `-` ("N/A") matches nothing a real component
/// carries, so it falls out of the equality arm on its own.
fn cpe_attr_matches(criterion: &str, value: &str) -> bool {
    criterion == "*" || criterion.eq_ignore_ascii_case(value)
}

/// Whether one candidate satisfies one NVD `cpeMatch` node.
fn candidate_matches_node(candidate: &CpeCandidate, node: &NvdCpeMatch) -> bool {
    let fields = split_cpe(&node.criteria);
    // cpe:2.3:<part>:<vendor>:<product>[:<version>...] — a well-formed
    // CPE 2.3 formatted string always has all eleven attributes, but NVD
    // has shipped truncated criteria; require the five we read.
    if fields.len() < 5 || fields[0] != "cpe" || fields[1] != "2.3" {
        return false;
    }
    // Vendored native libraries are applications; a criterion scoped to an
    // OS or hardware product is not about them.
    if !cpe_attr_matches(&fields[2], "a") {
        return false;
    }
    if !cpe_attr_matches(&fields[3], &candidate.vendor)
        || !cpe_attr_matches(&fields[4], &candidate.product)
    {
        return false;
    }

    let criterion_version = fields.get(5).map(String::as_str).unwrap_or("*");
    let has_bounds = node.version_start_including.is_some()
        || node.version_start_excluding.is_some()
        || node.version_end_including.is_some()
        || node.version_end_excluding.is_some();

    let Some(version) = candidate.version.as_deref() else {
        // No version to compare. Matches only an unbounded wildcard: with
        // bounds present, answering either way would be a fabrication.
        return criterion_version == "*" && !has_bounds;
    };

    match criterion_version {
        // N/A: the criterion is about a product with no version. A
        // versioned component is definitionally not that.
        "-" => return false,
        // A specific version criterion matches exactly that version. (NVD
        // pairs range bounds with `*` criteria; bounds with a specific
        // version are applied too, harmlessly, by the checks below.)
        v if v != "*" && compare_versions(version, v) != std::cmp::Ordering::Equal => {
            return false;
        }
        _ => {}
    }

    if let Some(start) = &node.version_start_including {
        if compare_versions(version, start) == std::cmp::Ordering::Less {
            return false;
        }
    }
    if let Some(start) = &node.version_start_excluding {
        if compare_versions(version, start) != std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(end) = &node.version_end_including {
        if compare_versions(version, end) == std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(end) = &node.version_end_excluding {
        if compare_versions(version, end) != std::cmp::Ordering::Less {
            return false;
        }
    }
    true
}

/// Compare two dotted versions segment-wise, numerically where both
/// segments are numeric (`1.10.0` > `1.9.0`), lexicographically otherwise.
/// Missing trailing segments read as `0`, so `1.3` == `1.3.0`.
///
/// This is not a full semver/pre-release implementation — NVD version
/// bounds on C-library releases are dotted numerics in practice, and the
/// matcher's fixture tests pin the boundary semantics both directions.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    fn segments(v: &str) -> Vec<&str> {
        v.split(['.', '-', '_', '+']).collect()
    }
    let sa = segments(a);
    let sb = segments(b);
    for i in 0..sa.len().max(sb.len()) {
        let x = sa.get(i).copied().unwrap_or("0");
        let y = sb.get(i).copied().unwrap_or("0");
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(nx), Ok(ny)) => nx.cmp(&ny),
            _ => x.cmp(y),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn identity<'a>(
        name: &'a str,
        version: Option<&'a str>,
        source_url: Option<&'a str>,
        git_url: Option<&'a str>,
    ) -> ComponentIdentity<'a> {
        ComponentIdentity {
            name,
            version,
            source_url,
            git_url,
        }
    }

    // ------------------------------------------------------------------
    // Acceptance 1: a vendored library with a known NVD advisory matches
    // via a candidate CPE.
    // ------------------------------------------------------------------

    /// libwebp 1.3.0 vs CVE-2023-4863's real NVD criterion
    /// (`cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*`, vulnerable up to
    /// but not including 1.3.2). This is the exact case the issue names:
    /// the component was discovered, and without a candidate CPE it was
    /// matched against nothing.
    #[test]
    fn known_library_matches_via_candidate_cpe() {
        let cands = candidates(&identity("libwebp", Some("1.3.0"), None, None));

        assert_eq!(cands.len(), 1, "curated table hit must not add guesses");
        let c = &cands[0];
        assert_eq!(c.vendor, "webmproject");
        assert_eq!(c.product, "libwebp");
        assert_eq!(c.cpe, "cpe:2.3:a:webmproject:libwebp:1.3.0:*:*:*:*:*:*:*");
        assert_eq!(c.confidence, CandidateConfidence::High);
        assert_eq!(c.rule_id, RULE_KNOWN_CPE_TABLE);
        assert!(!is_ambiguous(&cands));

        let advisories = vec![(
            "CVE-2023-4863",
            vec![
                NvdCpeMatch::new("cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*")
                    .end_excluding("1.3.2"),
            ],
        )];
        let hits = match_advisories(&cands, &advisories);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].advisory_id, "CVE-2023-4863");
        // Acceptance 3 at the matching layer: the hit names the rule that
        // proposed the CPE that matched.
        assert_eq!(hits[0].candidate.rule_id, RULE_KNOWN_CPE_TABLE);
    }

    /// Mutation check on the range comparison: both sides of the
    /// `versionEndExcluding` boundary must be asserted, so flipping `<=`
    /// to `<`, comparing the wrong fields, or dropping the bound entirely
    /// each fail a test.
    #[test]
    fn match_respects_version_range_boundary() {
        let advisories = vec![(
            "CVE-2023-4863",
            vec![
                NvdCpeMatch::new("cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*")
                    .end_excluding("1.3.2"),
            ],
        )];

        let affected = candidates(&identity("libwebp", Some("1.3.1"), None, None));
        assert_eq!(
            match_advisories(&affected, &advisories).len(),
            1,
            "1.3.1 is below 1.3.2 and must match"
        );

        let fixed = candidates(&identity("libwebp", Some("1.3.2"), None, None));
        assert!(
            match_advisories(&fixed, &advisories).is_empty(),
            "1.3.2 is the fixed release and must NOT match an end-excluding bound"
        );

        let later = candidates(&identity("libwebp", Some("1.4.0"), None, None));
        assert!(
            match_advisories(&later, &advisories).is_empty(),
            "1.4.0 is past the bound and must NOT match"
        );
    }

    /// A criterion that pins an exact vulnerable version must match only
    /// that version — the other direction of the version comparison.
    #[test]
    fn exact_version_criterion_matches_only_that_version() {
        let advisories = vec![(
            "CVE-1999-0001",
            vec![NvdCpeMatch::new(
                "cpe:2.3:a:webmproject:libwebp:1.2.4:*:*:*:*:*:*:*",
            )],
        )];

        let exact = candidates(&identity("libwebp", Some("1.2.4"), None, None));
        assert_eq!(match_advisories(&exact, &advisories).len(), 1);

        let other = candidates(&identity("libwebp", Some("1.2.3"), None, None));
        assert!(match_advisories(&other, &advisories).is_empty());
    }

    /// Both range bounds together, including the start side.
    #[test]
    fn start_and_end_bounds_are_both_enforced() {
        let advisories = vec![(
            "CVE-2024-0001",
            vec![
                NvdCpeMatch::new("cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*")
                    .start_including("1.2.0")
                    .end_excluding("1.3.2"),
            ],
        )];
        let hits = |v: &str| {
            match_advisories(
                &candidates(&identity("libwebp", Some(v), None, None)),
                &advisories,
            )
            .len()
        };
        assert_eq!(hits("1.1.9"), 0, "before the start bound");
        assert_eq!(hits("1.2.0"), 1, "start bound is inclusive");
        assert_eq!(hits("1.3.0"), 1);
        assert_eq!(hits("1.3.2"), 0, "end bound is exclusive");
    }

    // ------------------------------------------------------------------
    // Acceptance 2: ambiguous matches are surfaced as ambiguous.
    // ------------------------------------------------------------------

    /// A name with no table entry and no URL evidence produces the two
    /// classic vendor spellings — itself and `<name>_project` — both Low,
    /// and the set is flagged ambiguous. Nothing picks one.
    #[test]
    fn ambiguous_name_yields_multiple_candidates_flagged_ambiguous() {
        let cands = candidates(&identity("somecodec", Some("2.0"), None, None));

        assert_eq!(cands.len(), 2);
        assert!(
            cands
                .iter()
                .all(|c| c.confidence == CandidateConfidence::Low
                    && c.rule_id == RULE_NAME_AS_PRODUCT),
            "both guesses must be Low name-rule candidates: {cands:?}"
        );
        let pairs: Vec<(&str, &str)> = cands
            .iter()
            .map(|c| (c.vendor.as_str(), c.product.as_str()))
            .collect();
        assert!(pairs.contains(&("somecodec", "somecodec")));
        assert!(pairs.contains(&("somecodec_project", "somecodec")));
        assert!(is_ambiguous(&cands));

        // Ambiguity is not resolved arbitrarily, for any consumer.
        assert_eq!(dt_cpe(&cands), None);
    }

    /// The classic case verbatim: `openssl` the vendor vs
    /// `openssl_project` the vendor. openssl has a curated table entry, so
    /// the table WINS and there is no ambiguity for the well-known library —
    /// but a name without a table entry keeps both spellings in play.
    #[test]
    fn table_hit_outranks_name_guesses() {
        let cands = candidates(&identity("openssl", Some("3.0.8"), None, None));
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].vendor, "openssl");
        assert_eq!(cands[0].confidence, CandidateConfidence::High);
        assert!(!is_ambiguous(&cands));
        assert_eq!(
            dt_cpe(&cands).as_deref(),
            Some("cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*")
        );
    }

    /// An ambiguous set matched against advisories from BOTH vendors keeps
    /// both pairings. Collapsing to one would hide the ambiguity at exactly
    /// the layer where a reviewer needs to see it (#4088 lesson: this is
    /// the mutation-checked path — one assertion per pairing).
    #[test]
    fn ambiguous_match_keeps_every_candidate_pairing() {
        let cands = candidates(&identity("somecodec", Some("2.0"), None, None));
        assert!(is_ambiguous(&cands));

        let advisories = vec![
            (
                "CVE-2024-1111",
                vec![NvdCpeMatch::new(
                    "cpe:2.3:a:somecodec:somecodec:*:*:*:*:*:*:*:*",
                )],
            ),
            (
                "CVE-2024-2222",
                vec![NvdCpeMatch::new(
                    "cpe:2.3:a:somecodec_project:somecodec:*:*:*:*:*:*:*:*",
                )],
            ),
            // A third advisory against an unrelated vendor must not match.
            (
                "CVE-2024-3333",
                vec![NvdCpeMatch::new(
                    "cpe:2.3:a:other:somecodec:*:*:*:*:*:*:*:*",
                )],
            ),
        ];

        let hits = match_advisories(&cands, &advisories);
        assert_eq!(hits.len(), 2);
        let by_advisory: Vec<(&str, &str)> = hits
            .iter()
            .map(|h| (h.advisory_id.as_str(), h.candidate.vendor.as_str()))
            .collect();
        assert!(by_advisory.contains(&("CVE-2024-1111", "somecodec")));
        assert!(by_advisory.contains(&("CVE-2024-2222", "somecodec_project")));
    }

    // ------------------------------------------------------------------
    // Acceptance 3: every candidate records its producing rule.
    // ------------------------------------------------------------------

    /// Exercise one component per rule and pin each rule id. If a rule is
    /// ever bypassed or re-labelled, the wrong candidate can no longer be
    /// traced, which is the failure this acceptance criterion forbids.
    #[test]
    fn every_candidate_records_its_producing_rule() {
        let table = candidates(&identity("libwebp", Some("1.3.0"), None, None));
        assert!(table.iter().all(|c| c.rule_id == RULE_KNOWN_CPE_TABLE));

        let url = candidates(&identity(
            "somecodec",
            Some("2.0"),
            Some("https://github.com/acme/somecodec"),
            None,
        ));
        let url_cand = url
            .iter()
            .find(|c| c.vendor == "acme")
            .expect("URL-derived vendor candidate must exist");
        assert_eq!(url_cand.rule_id, RULE_SOURCE_URL_VENDOR);

        let name_only = candidates(&identity("somecodec", Some("2.0"), None, None));
        assert!(
            !name_only.is_empty() && name_only.iter().all(|c| c.rule_id == RULE_NAME_AS_PRODUCT)
        );

        // And none of them may carry an empty or unknown rule id.
        for c in table.iter().chain(url.iter()).chain(name_only.iter()) {
            assert!(
                matches!(
                    c.rule_id,
                    RULE_KNOWN_CPE_TABLE | RULE_SOURCE_URL_VENDOR | RULE_NAME_AS_PRODUCT
                ),
                "candidate carries an unrecognised rule id: {}",
                c.rule_id
            );
        }
    }

    // ------------------------------------------------------------------
    // Confidence floor: no candidate is invented below it.
    // ------------------------------------------------------------------

    /// A name too short or too malformed to be a real upstream product
    /// yields NOTHING. Inventing `cpe:2.3:a:ab:ab` would match advisories
    /// for a different piece of software and render as a real finding —
    /// worse than the empty answer it replaces.
    #[test]
    fn no_candidate_invented_below_confidence_floor() {
        for bad in [
            "",
            "  ",
            "ab",
            "x",
            "{{ name }}",
            "{name}",
            "???",
            "lib%20x",
        ] {
            let cands = candidates(&identity(bad, Some("1.0"), None, None));
            assert!(
                cands.is_empty(),
                "name {bad:?} is below the floor and must produce no candidates, got {cands:?}"
            );
        }

        // The floor applies to the GUESSING rule only: a short name with a
        // curated table entry still resolves. `xz` is the regression case.
        let xz = candidates(&identity("xz", Some("5.4.1"), None, None));
        assert_eq!(xz.len(), 1);
        assert_eq!(xz[0].rule_id, RULE_KNOWN_CPE_TABLE);
        assert_eq!(xz[0].vendor, "tukaani");
    }

    /// A version-less component still gets candidates (with `*` in the CPE
    /// version slot) from evidence-bearing rules — but the name-guess rule
    /// stays available too, since the vendor/product ambiguity question
    /// does not depend on the version.
    #[test]
    fn versionless_component_keeps_candidates_with_wildcard_version() {
        let cands = candidates(&identity("libwebp", None, None, None));
        assert_eq!(cands.len(), 1);
        assert_eq!(
            cands[0].cpe,
            "cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*"
        );
        assert_eq!(cands[0].version, None);
    }

    // ------------------------------------------------------------------
    // The source-url rule.
    // ------------------------------------------------------------------

    /// A forge URL whose repo name matches the component derives the vendor
    /// from the owner at Medium confidence. It outranks the name guesses
    /// (so the set is NOT ambiguous and `dt_cpe` answers) — but the Low
    /// guesses are still carried as provenance.
    #[test]
    fn source_url_vendor_outranks_name_guess() {
        let cands = candidates(&identity(
            "somecodec",
            Some("2.0"),
            Some("https://github.com/acme/somecodec"),
            None,
        ));

        let top = &cands[0];
        assert_eq!(top.vendor, "acme");
        assert_eq!(top.product, "somecodec");
        assert_eq!(top.confidence, CandidateConfidence::Medium);
        assert_eq!(top.rule_id, RULE_SOURCE_URL_VENDOR);
        assert!(
            cands.len() > 1,
            "name-guess candidates stay as provenance: {cands:?}"
        );
        assert!(
            !is_ambiguous(&cands),
            "a single Medium candidate outranks the Low guesses"
        );
        assert_eq!(
            dt_cpe(&cands).as_deref(),
            Some("cpe:2.3:a:acme:somecodec:2.0:*:*:*:*:*:*:*")
        );
    }

    /// git URLs work too, including the scp-like form and a `.git` suffix.
    #[test]
    fn git_url_forms_are_understood() {
        for url in [
            "https://github.com/acme/somecodec.git",
            "git@github.com:acme/somecodec.git",
            "https://gitlab.com/acme/somecodec",
        ] {
            let cands = candidates(&identity("somecodec", Some("2.0"), None, Some(url)));
            assert!(
                cands
                    .iter()
                    .any(|c| c.vendor == "acme" && c.rule_id == RULE_SOURCE_URL_VENDOR),
                "git url {url:?} must yield the acme candidate: {cands:?}"
            );
        }
    }

    /// A URL whose repo name does NOT match the component must not
    /// contribute a vendor: `https://github.com/acme/mirror-of-everything`
    /// says nothing about who publishes `somecodec` in NVD.
    #[test]
    fn unrelated_repo_name_contributes_no_vendor() {
        let cands = candidates(&identity(
            "somecodec",
            Some("2.0"),
            Some("https://github.com/acme/mirror-of-everything"),
            None,
        ));
        assert!(
            cands.iter().all(|c| c.rule_id != RULE_SOURCE_URL_VENDOR),
            "no vendor may be invented from a non-matching repo: {cands:?}"
        );
    }

    // ------------------------------------------------------------------
    // Table coverage sanity: every well-known library the issue and the
    // extraction work actually name.
    // ------------------------------------------------------------------

    #[test]
    fn known_table_covers_the_well_known_native_libraries() {
        let cases: &[(&str, &str, &str)] = &[
            ("libwebp", "webmproject", "libwebp"),
            ("zlib", "zlib", "zlib"),
            ("openssl", "openssl", "openssl"),
            ("libpng", "libpng", "libpng"),
            ("libjpeg-turbo", "libjpeg-turbo", "libjpeg-turbo"),
            ("freetype", "freetype", "freetype"),
            ("harfbuzz", "harfbuzz_project", "harfbuzz"),
            ("curl", "haxx", "curl"),
            ("sqlite", "sqlite", "sqlite"),
            ("libxml2", "xmlsoft", "libxml2"),
            ("expat", "libexpat_project", "libexpat"),
            ("ffmpeg", "ffmpeg", "ffmpeg"),
            ("xz", "tukaani", "xz"),
            ("brotli", "google", "brotli"),
        ];
        for (name, vendor, product) in cases {
            let cands = candidates(&identity(name, None, None, None));
            assert!(
                cands.iter().any(|c| c.vendor == *vendor
                    && c.product == *product
                    && c.confidence == CandidateConfidence::High
                    && c.rule_id == RULE_KNOWN_CPE_TABLE),
                "{name} must hit the curated table as {vendor}:{product}, got {cands:?}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Version comparison corners, exercised through the matcher.
    // ------------------------------------------------------------------

    /// `1.10.0` sorts after `1.9.0` numerically, not lexicographically; a
    /// string compare gets this wrong in both directions.
    #[test]
    fn version_comparison_is_numeric_not_lexicographic() {
        let advisories = vec![(
            "CVE-2024-0002",
            vec![
                NvdCpeMatch::new("cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*")
                    .end_excluding("1.10.0"),
            ],
        )];
        let hits = |v: &str| {
            match_advisories(
                &candidates(&identity("libwebp", Some(v), None, None)),
                &advisories,
            )
            .len()
        };
        assert_eq!(hits("1.9.0"), 1);
        assert_eq!(hits("1.10.0"), 0);
        assert_eq!(hits("1.10.1"), 0);
    }

    /// A version-less candidate matches only an unbounded wildcard
    /// criterion. With range bounds present there is no version to compare,
    /// and guessing one would fabricate both false positives and false
    /// negatives — so the honest answer is no match, and the component's
    /// "not queried" status comes from the advisory layer that already
    /// refuses version-less queries.
    #[test]
    fn versionless_candidate_matches_only_unbounded_criteria() {
        let cands = candidates(&identity("libwebp", None, None, None));
        assert_eq!(cands.len(), 1);

        let unbounded = vec![(
            "CVE-2024-0003",
            vec![NvdCpeMatch::new(
                "cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*",
            )],
        )];
        assert_eq!(match_advisories(&cands, &unbounded).len(), 1);

        let bounded = vec![(
            "CVE-2023-4863",
            vec![
                NvdCpeMatch::new("cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*")
                    .end_excluding("1.3.2"),
            ],
        )];
        assert!(match_advisories(&cands, &bounded).is_empty());
    }

    /// A wildcard vendor/product criterion (`cpe:2.3:a:*:libwebp:...`)
    /// matches through any candidate naming that product.
    #[test]
    fn wildcard_vendor_criterion_matches_any_vendor() {
        let cands = candidates(&identity("somecodec", Some("2.0"), None, None));
        let advisories = vec![(
            "CVE-2024-4444",
            vec![NvdCpeMatch::new("cpe:2.3:a:*:somecodec:*:*:*:*:*:*:*:*")],
        )];
        let hits = match_advisories(&cands, &advisories);
        assert_eq!(
            hits.len(),
            2,
            "both vendor spellings match a wildcard-vendor criterion"
        );
    }

    /// Empty inputs: no candidates, no advisories, or both must produce no
    /// hits and never panic.
    #[test]
    fn match_with_nothing_is_nothing() {
        assert!(match_advisories(&[], &[]).is_empty());
        let cands = candidates(&identity("libwebp", Some("1.3.0"), None, None));
        assert!(match_advisories(&cands, &[]).is_empty());
        let advisories = vec![(
            "CVE-1",
            vec![NvdCpeMatch::new(
                "cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*",
            )],
        )];
        assert!(match_advisories(&[], &advisories).is_empty());
    }

    /// Confidence ordering: Low < Medium < High, and the wire forms are
    /// stable — the API serializes these verbatim.
    #[test]
    fn confidence_orders_and_serializes() {
        assert!(CandidateConfidence::Low < CandidateConfidence::Medium);
        assert!(CandidateConfidence::Medium < CandidateConfidence::High);
        assert_eq!(CandidateConfidence::Low.as_str(), "low");
        assert_eq!(CandidateConfidence::Medium.as_str(), "medium");
        assert_eq!(CandidateConfidence::High.as_str(), "high");
    }

    /// dt_cpe answers for a single-candidate set and for a set whose top
    /// tier holds exactly one candidate; never for an empty or ambiguous
    /// set.
    #[test]
    fn dt_cpe_only_when_unambiguous() {
        assert_eq!(dt_cpe(&[]), None);

        let single = candidates(&identity("libwebp", Some("1.3.0"), None, None));
        assert!(dt_cpe(&single).is_some());

        let dominated = candidates(&identity(
            "somecodec",
            Some("2.0"),
            Some("https://github.com/acme/somecodec"),
            None,
        ));
        assert!(
            dt_cpe(&dominated).is_some(),
            "one Medium over Low guesses is a decision, not a coin flip"
        );

        let ambiguous = candidates(&identity("somecodec", Some("2.0"), None, None));
        assert_eq!(dt_cpe(&ambiguous), None);
    }

    /// Candidate order is deterministic: confidence descending, then
    /// vendor/product. The API renders this list, so its order is part of
    /// the contract.
    #[test]
    fn candidate_order_is_deterministic() {
        let a = candidates(&identity("somecodec", Some("2.0"), None, None));
        let b = candidates(&identity("somecodec", Some("2.0"), None, None));
        assert_eq!(a, b);
        assert!(
            a.windows(2).all(|w| w[0].confidence >= w[1].confidence),
            "best-first order: {a:?}"
        );
    }
}
