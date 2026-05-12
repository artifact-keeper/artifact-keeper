//! SPDX license identifier validation (#1152).
//!
//! Trivy returns license arrays per package; the scan_packages persistence
//! path joins multi-license entries with " OR " (a valid SPDX operator)
//! without verifying each element is a valid SPDX identifier. A package
//! shipping `Licenses: ["MIT", "Custom Commercial - see LICENSE"]` would
//! produce `"MIT OR Custom Commercial - see LICENSE"`, which a lenient
//! license-policy check reads as "MIT-licensed if you pick that arm" --
//! a green light despite the commercial restriction. A hostile package
//! author who controls a lockfile's license field can also smuggle a
//! pre-joined expression like `"MIT OR Apache-2.0"` as a single array
//! element, defeating per-element validation entirely.
//!
//! This module exposes [`is_valid_spdx_identifier`] and the helper
//! [`sanitize_license_term`] used by `convert_trivy_packages`. Unknown
//! terms are wrapped as `LicenseRef-...` per SPDX 2.3 section 10
//! ("License References"), which preserves the input for forensic /
//! audit purposes but prevents a downstream SPDX-aware policy engine
//! from interpreting the string as a known permissive license.
//!
//! The identifier list is a curated subset of the SPDX license registry
//! (https://spdx.org/licenses/) covering the licenses commonly seen in
//! OSS lockfiles. It is intentionally vendored rather than fetched at
//! build time so an offline / air-gapped build does not regress to "no
//! validation". When a new license needs to be recognised, add it here.

use once_cell::sync::Lazy;
use regex::Regex;

/// Curated subset of the SPDX license identifier list (v3.24+, deduplicated).
///
/// Source: https://spdx.org/licenses/ -- the entries below cover every
/// license that has appeared in artifact-keeper's production Trivy reports
/// as of 2026-05 plus the SPDX-recommended "popular" set. Sorted alphabetically
/// for ease of human auditing; the runtime lookup uses a HashSet.
const SPDX_IDENTIFIERS: &[&str] = &[
    "0BSD",
    "AAL",
    "AFL-1.1",
    "AFL-1.2",
    "AFL-2.0",
    "AFL-2.1",
    "AFL-3.0",
    "AGPL-1.0",
    "AGPL-1.0-only",
    "AGPL-1.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-1.0",
    "Apache-1.1",
    "Apache-2.0",
    "APSL-1.0",
    "APSL-1.1",
    "APSL-1.2",
    "APSL-2.0",
    "Artistic-1.0",
    "Artistic-1.0-Perl",
    "Artistic-1.0-cl8",
    "Artistic-2.0",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-2-Clause-Patent",
    "BSD-2-Clause-Views",
    "BSD-3-Clause",
    "BSD-3-Clause-Attribution",
    "BSD-3-Clause-Clear",
    "BSD-3-Clause-LBNL",
    "BSD-3-Clause-Modification",
    "BSD-3-Clause-No-Nuclear-License",
    "BSD-3-Clause-No-Nuclear-License-2014",
    "BSD-3-Clause-No-Nuclear-Warranty",
    "BSD-4-Clause",
    "BSD-4-Clause-UC",
    "BSD-Source-Code",
    "BSL-1.0",
    "Beerware",
    "CC-BY-1.0",
    "CC-BY-2.0",
    "CC-BY-2.5",
    "CC-BY-3.0",
    "CC-BY-4.0",
    "CC-BY-SA-1.0",
    "CC-BY-SA-2.0",
    "CC-BY-SA-2.5",
    "CC-BY-SA-3.0",
    "CC-BY-SA-4.0",
    "CC-BY-NC-1.0",
    "CC-BY-NC-2.0",
    "CC-BY-NC-2.5",
    "CC-BY-NC-3.0",
    "CC-BY-NC-4.0",
    "CC-BY-NC-ND-1.0",
    "CC-BY-NC-ND-2.0",
    "CC-BY-NC-ND-2.5",
    "CC-BY-NC-ND-3.0",
    "CC-BY-NC-ND-4.0",
    "CC-BY-NC-SA-1.0",
    "CC-BY-NC-SA-2.0",
    "CC-BY-NC-SA-2.5",
    "CC-BY-NC-SA-3.0",
    "CC-BY-NC-SA-4.0",
    "CC-BY-ND-1.0",
    "CC-BY-ND-2.0",
    "CC-BY-ND-2.5",
    "CC-BY-ND-3.0",
    "CC-BY-ND-4.0",
    "CC-PDDC",
    "CC0-1.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "CECILL-1.0",
    "CECILL-1.1",
    "CECILL-2.0",
    "CECILL-2.1",
    "CECILL-B",
    "CECILL-C",
    "CNRI-Python",
    "CPAL-1.0",
    "CPL-1.0",
    "CUA-OPL-1.0",
    "ECL-1.0",
    "ECL-2.0",
    "EFL-1.0",
    "EFL-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "EUDatagrid",
    "EUPL-1.0",
    "EUPL-1.1",
    "EUPL-1.2",
    "Fair",
    "Frameworx-1.0",
    "GFDL-1.1",
    "GFDL-1.1-only",
    "GFDL-1.1-or-later",
    "GFDL-1.2",
    "GFDL-1.2-only",
    "GFDL-1.2-or-later",
    "GFDL-1.3",
    "GFDL-1.3-only",
    "GFDL-1.3-or-later",
    "GPL-1.0",
    "GPL-1.0+",
    "GPL-1.0-only",
    "GPL-1.0-or-later",
    "GPL-2.0",
    "GPL-2.0+",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-2.0-with-autoconf-exception",
    "GPL-2.0-with-bison-exception",
    "GPL-2.0-with-classpath-exception",
    "GPL-2.0-with-font-exception",
    "GPL-2.0-with-GCC-exception",
    "GPL-3.0",
    "GPL-3.0+",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "GPL-3.0-with-autoconf-exception",
    "GPL-3.0-with-GCC-exception",
    "HPND",
    "IPA",
    "IPL-1.0",
    "ISC",
    "JSON",
    "LGPL-2.0",
    "LGPL-2.0+",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1",
    "LGPL-2.1+",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0+",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "LPL-1.0",
    "LPL-1.02",
    "LPPL-1.0",
    "LPPL-1.1",
    "LPPL-1.2",
    "LPPL-1.3a",
    "LPPL-1.3c",
    "MIT",
    "MIT-0",
    "MIT-CMU",
    "MIT-feh",
    "MIT-Modern-Variant",
    "MITNFA",
    "MPL-1.0",
    "MPL-1.1",
    "MPL-2.0",
    "MPL-2.0-no-copyleft-exception",
    "MS-PL",
    "MS-RL",
    "MulanPSL-1.0",
    "MulanPSL-2.0",
    "NASA-1.3",
    "NCSA",
    "NPL-1.0",
    "NPL-1.1",
    "NPOSL-3.0",
    "NTP",
    "OFL-1.0",
    "OFL-1.1",
    "OLDAP-2.8",
    "OSL-1.0",
    "OSL-1.1",
    "OSL-2.0",
    "OSL-2.1",
    "OSL-3.0",
    "PHP-3.0",
    "PHP-3.01",
    "PostgreSQL",
    "Python-2.0",
    "Python-2.0.1",
    "QPL-1.0",
    "RPL-1.1",
    "RPL-1.5",
    "RPSL-1.0",
    "Ruby",
    "SISSL",
    "Sleepycat",
    "SPL-1.0",
    "Unicode-DFS-2015",
    "Unicode-DFS-2016",
    "Unicode-TOU",
    "Unlicense",
    "UPL-1.0",
    "Vim",
    "W3C",
    "W3C-19980720",
    "W3C-20150513",
    "WTFPL",
    "X11",
    "Xnet",
    "ZPL-1.1",
    "ZPL-2.0",
    "ZPL-2.1",
    "Zend-2.0",
    "Zlib",
    "zlib-acknowledgement",
];

/// Lowercase-keyed lookup so `apache-2.0` and `Apache-2.0` both validate.
/// SPDX 2.3 says identifiers MUST be case-sensitive, but Trivy and many
/// scanners normalize case inconsistently; matching case-insensitively
/// here trades strict SPDX compliance for not blackholing legitimate
/// licenses that arrive as `apache-2.0`. The output term is the canonical
/// (original-case) SPDX identifier so the persisted value stays compliant.
static SPDX_CANONICAL: Lazy<std::collections::HashMap<String, &'static str>> = Lazy::new(|| {
    SPDX_IDENTIFIERS
        .iter()
        .map(|id| (id.to_lowercase(), *id))
        .collect()
});

/// Characters legal inside an SPDX `LicenseRef-` identifier per SPDX 2.3:
/// idstring = 1*(ALPHA / DIGIT / "-" / "."). Anything else gets stripped.
static LICENSEREF_FILTER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[^A-Za-z0-9.\-]+").expect("static LICENSEREF_FILTER regex"));

/// Detect smuggled SPDX expressions inside a single array element.
/// Hostile `package.json` files can ship `"MIT OR Apache-2.0"` as a single
/// element so that per-element validation against a known-identifier list
/// still produces a green light against any permissive policy arm. The
/// presence of a whitespace-bounded `OR`/`AND`/`WITH` token at the top
/// level signals this case; we refuse to treat the element as a known
/// identifier even if a substring would match.
static EMBEDDED_OPERATOR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|\s)(?:OR|AND|WITH)(?:\s|$)").expect("static EMBEDDED_OPERATOR regex")
});

/// True when `term` is exactly a SPDX 2.3 license identifier (case-
/// insensitive against the vendored list). False when the term contains
/// any whitespace-delimited operator like ` OR `, ` AND `, ` WITH `
/// (those must arrive as separate array elements; smuggling them as a
/// single element bypasses per-element validation).
pub fn is_valid_spdx_identifier(term: &str) -> bool {
    let trimmed = term.trim();
    if trimmed.is_empty() {
        return false;
    }
    if EMBEDDED_OPERATOR.is_match(trimmed) {
        return false;
    }
    SPDX_CANONICAL.contains_key(&trimmed.to_lowercase())
}

/// Normalize a single license term emitted by a scanner into a SPDX-safe
/// token suitable for joining into an expression with ` OR `.
///
/// - Empty / whitespace input -> `None` (caller filters before joining).
/// - Known SPDX identifier (case-insensitive match) -> canonical-case
///   form from [`SPDX_IDENTIFIERS`].
/// - Anything else -> `LicenseRef-<sanitised-input>` per SPDX 2.3
///   section 10. The sanitiser strips characters illegal inside an
///   idstring and truncates to 64 chars so a hostile multi-MB license
///   field can't blow up the persisted column.
///
/// The `LicenseRef-` prefix is deliberately conservative: a downstream
/// SPDX-aware policy engine will not silently classify a LicenseRef
/// token as permissive, which is the precise behaviour the issue calls
/// out as a green-lighting hazard.
pub fn sanitize_license_term(term: &str) -> Option<String> {
    let trimmed = term.trim();
    if trimmed.is_empty() {
        return None;
    }

    if !EMBEDDED_OPERATOR.is_match(trimmed) {
        if let Some(canonical) = SPDX_CANONICAL.get(&trimmed.to_lowercase()) {
            return Some((*canonical).to_string());
        }
    }

    // Wrap unknown / smuggled terms as a LicenseRef so a SPDX-aware
    // consumer cannot interpret them as a permissive arm.
    let stripped = LICENSEREF_FILTER.replace_all(trimmed, "-");
    let stripped = stripped.trim_matches('-');
    if stripped.is_empty() {
        return Some("LicenseRef-NOASSERTION".to_string());
    }
    let truncated: String = stripped.chars().take(64).collect();
    Some(format!("LicenseRef-{}", truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_identifiers_validate() {
        assert!(is_valid_spdx_identifier("MIT"));
        assert!(is_valid_spdx_identifier("Apache-2.0"));
        assert!(is_valid_spdx_identifier("apache-2.0"));
        assert!(is_valid_spdx_identifier("GPL-3.0-or-later"));
        assert!(is_valid_spdx_identifier("BSD-3-Clause"));
    }

    #[test]
    fn unknown_identifiers_do_not_validate() {
        assert!(!is_valid_spdx_identifier(""));
        assert!(!is_valid_spdx_identifier("   "));
        assert!(!is_valid_spdx_identifier("Custom Commercial - see LICENSE"));
        assert!(!is_valid_spdx_identifier("Proprietary"));
    }

    #[test]
    fn embedded_operators_are_rejected() {
        // Smuggled expressions must not validate as single identifiers.
        assert!(!is_valid_spdx_identifier("MIT OR Apache-2.0"));
        assert!(!is_valid_spdx_identifier("MIT AND Apache-2.0"));
        assert!(!is_valid_spdx_identifier(
            "GPL-2.0 WITH Classpath-exception-2.0"
        ));
    }

    #[test]
    fn sanitize_passes_known_through_canonical() {
        assert_eq!(sanitize_license_term("MIT"), Some("MIT".to_string()));
        // Lowercase input promotes to canonical case.
        assert_eq!(
            sanitize_license_term("apache-2.0"),
            Some("Apache-2.0".to_string())
        );
    }

    #[test]
    fn sanitize_wraps_unknown_as_licenseref() {
        let out = sanitize_license_term("Custom Commercial - see LICENSE").unwrap();
        assert!(out.starts_with("LicenseRef-"), "got {out}");
        // No spaces, no operator characters.
        assert!(!out.contains(' '));
    }

    #[test]
    fn sanitize_wraps_smuggled_expression() {
        // The hostile-lockfile case: a single element pretending to be
        // a SPDX expression. Must NOT collapse to plain "MIT".
        let out = sanitize_license_term("MIT OR Apache-2.0").unwrap();
        assert!(
            out.starts_with("LicenseRef-"),
            "smuggled expression must not pass through as plain MIT; got {out}"
        );
    }

    #[test]
    fn sanitize_truncates_oversized_input() {
        let huge = "A".repeat(2048);
        let out = sanitize_license_term(&huge).unwrap();
        // "LicenseRef-" prefix + at most 64 chars of body.
        assert!(out.len() <= "LicenseRef-".len() + 64);
        assert!(out.starts_with("LicenseRef-"));
    }

    #[test]
    fn sanitize_empty_input_is_none() {
        assert_eq!(sanitize_license_term(""), None);
        assert_eq!(sanitize_license_term("   "), None);
    }
}
