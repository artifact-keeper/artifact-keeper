//! Security regression tests.
//!
//! One test per advisory we have patched. These run as a Cargo integration
//! test (i.e. they consume the crate from outside, the same vantage point an
//! attacker has via HTTP), so they catch refactors that accidentally drop a
//! check from the public surface — even when the in-module unit tests still
//! pass against the now-orphaned helper.
//!
//! Live database is intentionally NOT required: every test below targets a
//! pure helper function that encodes the security invariant. If a future
//! refactor splits a check into a helper that bypasses these seams, add a
//! new test here rather than weakening these.

use artifact_keeper_backend::api::handlers::goproxy::is_sumdb_host_allowed;
use artifact_keeper_backend::api::handlers::maven::{escape_like_literal, snapshot_like_pattern};
use artifact_keeper_backend::api::middleware::auth::require_auth_basic;
use artifact_keeper_backend::api::validation::validate_outbound_url;

// ---------------------------------------------------------------------------
// Bug 1 — GHSA-mc8p-6758-jfp2 (PR #879)
// Class:  SSRF via go module checksum-database proxy
// Seam:   `is_sumdb_host_allowed`
// What:   The Go toolchain fetches `$GOPROXY/sumdb/<host>/<path>`. Without
//         a host allowlist, a client could request
//         `sumdb/169.254.169.254/...` and force the server to fetch IMDSv1
//         instance metadata (or any other internal HTTP endpoint).
// Asserts: only `sum.golang.org` and `sum.golang.google.cn` are allowed;
//         IPv4 cloud metadata, IPv6 link-local, plain wrong hosts, and
//         lookalike hostnames are rejected.
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_mc8p_6758_jfp2_sumdb_host_allowlist() {
    // Golden path: official sumdb hosts are allowed (case-insensitive).
    assert!(is_sumdb_host_allowed("sum.golang.org"));
    assert!(is_sumdb_host_allowed("sum.golang.google.cn"));
    assert!(is_sumdb_host_allowed("SUM.GOLANG.ORG"));

    // The original SSRF payload — AWS/OpenStack IMDSv1.
    assert!(
        !is_sumdb_host_allowed("169.254.169.254"),
        "AWS instance metadata IP must never be a permitted sumdb upstream"
    );

    // GCP & Azure metadata aliases.
    assert!(!is_sumdb_host_allowed("metadata.google.internal"));
    assert!(!is_sumdb_host_allowed("metadata.azure.com"));

    // IPv6 link-local (covers IPv6 metadata bypass attempts).
    assert!(!is_sumdb_host_allowed("[fe80::1]"));
    assert!(!is_sumdb_host_allowed("fe80::1"));

    // Plain wrong hosts and lookalikes that suffix/prefix-match attacks
    // would smuggle through naive `contains()` checks.
    assert!(!is_sumdb_host_allowed("evil.com"));
    assert!(!is_sumdb_host_allowed("localhost"));
    assert!(!is_sumdb_host_allowed("127.0.0.1"));
    assert!(!is_sumdb_host_allowed("sum.golang.org.evil.com"));
    assert!(!is_sumdb_host_allowed("evil.com.sum.golang.org"));
}

// ---------------------------------------------------------------------------
// Bug 2 — GHSA-7f39-724h-cccm (PR #880)
// Class:  SQL LIKE wildcard injection in Maven SNAPSHOT lookup
// Seam:   `escape_like_literal` + composing helper `snapshot_like_pattern`
// What:   User-controlled artifact path segments were interpolated into a
//         SQL LIKE pattern. An attacker who could upload an artifact named
//         `%` (or similar) could match unrelated rows and exfiltrate
//         artifact metadata or serve the wrong file to an unrelated client.
// Asserts: `%`, `_`, and `\` are escaped to `\%`, `\_`, `\\`; the only
//         unescaped `%` in the composed pattern is the trusted timestamp
//         wildcard introduced by the helper itself.
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_7f39_724h_cccm_maven_like_escape() {
    // Pure helper: every LIKE metacharacter is preceded by `\`.
    assert_eq!(escape_like_literal("a%b"), "a\\%b");
    assert_eq!(escape_like_literal("a_b"), "a\\_b");
    assert_eq!(escape_like_literal("a\\b"), "a\\\\b");
    // No-op for plain text.
    assert_eq!(escape_like_literal("plain"), "plain");
    // Adversarial combined input.
    assert_eq!(
        escape_like_literal("100%_off\\everything"),
        "100\\%\\_off\\\\everything"
    );

    // Composed helper: a path with attacker-supplied wildcards must produce
    // a pattern where only the helper's trusted `-%` survives unescaped.
    // Input filename contains a literal `%` — it must be escaped to `\%`.
    let pat = snapshot_like_pattern("com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT%.jar")
        .expect("snapshot path should produce a pattern");
    // The trusted timestamp wildcard `-%` is present...
    assert!(
        pat.contains("-%"),
        "trusted timestamp wildcard must remain in pattern; got {pat}"
    );
    // ...and the user-supplied `%` is escaped.
    assert!(
        pat.contains("\\%"),
        "user-supplied %% must be escaped to \\%%; got {pat}"
    );
}

// ---------------------------------------------------------------------------
// Bug 3 — GHSA-93ch-hrfh-5wcw (PR #881)
// Class:  SSRF — IPv6 + extra cloud-metadata IP bypasses
// Seam:   `validate_outbound_url` (the gatekeeper used by every outbound
//         fetcher: cargo proxy, webhooks, remote replication, ...)
// What:   The original blocker only inspected IPv4 literals. An attacker
//         could request `http://[::ffff:169.254.169.254]/` (IPv4-mapped
//         IPv6) or `http://[fe80::...]/` (IPv6 link-local) and bypass the
//         metadata block. Oracle (192.0.0.192) and Alibaba (100.100.100.200)
//         metadata endpoints were also missing from the deny-list.
// Asserts: each of those four bypass classes is rejected, and at least one
//         legitimate external URL is still accepted (no over-blocking).
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_93ch_hrfh_5wcw_outbound_url_ssrf() {
    // IPv4-mapped IPv6 → AWS metadata IP. Pre-fix this slipped through.
    assert!(
        validate_outbound_url("http://[::ffff:169.254.169.254]/latest/meta-data", "Test URL")
            .is_err(),
        "IPv4-mapped IPv6 form of AWS metadata IP must be blocked"
    );

    // IPv6 link-local — fe80::/10 is the IPv6 equivalent of 169.254.0.0/16.
    assert!(
        validate_outbound_url("http://[fe80::1]/api", "Test URL").is_err(),
        "IPv6 link-local must be blocked"
    );

    // Oracle Cloud Infrastructure metadata.
    assert!(
        validate_outbound_url("http://192.0.0.192/opc/v2/instance", "Test URL").is_err(),
        "Oracle Cloud metadata IP 192.0.0.192 must be blocked"
    );

    // Alibaba Cloud metadata (in the CGNAT range, so the broader CGNAT
    // block being off must NOT let this through).
    assert!(
        validate_outbound_url("http://100.100.100.200/latest/meta-data", "Test URL").is_err(),
        "Alibaba Cloud metadata IP 100.100.100.200 must be blocked even with CGNAT block off"
    );

    // Sanity floor: a real public host must still validate, otherwise we
    // are over-blocking and would break cargo proxy / replication entirely.
    assert!(
        validate_outbound_url("https://crates.io/", "Test URL").is_ok(),
        "Legit public registry must still be reachable"
    );
}

// ---------------------------------------------------------------------------
// Bug 4 — GHSA-cxcr-cmqm-6rrw (PR #984)
// Class:  SQL LIKE wildcard injection across package handlers
// Seam:   The escape helper. PR #984 promotes this to a shared
//         `crate::api::handlers::escape_like_literal`; until that PR lands
//         the canonical implementation lives at
//         `crate::api::handlers::maven::escape_like_literal` and is what
//         every SNAPSHOT-style lookup ultimately calls. We test the
//         canonical implementation here — once #984 merges and moves the
//         function, just re-point the import (the assertions stay valid
//         because the contract is identical).
// What:   Same shape as Bug 2 but for non-Maven format handlers — anywhere
//         a user-supplied artifact path/version is fed into a `LIKE`
//         predicate, `%`, `_`, and `\` must all be escaped.
// Asserts: full adversarial input round-trips through the escaper with
//         every LIKE metacharacter quoted.
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_cxcr_cmqm_6rrw_handlers_like_escape() {
    // Each metacharacter individually — covers single-char regression.
    assert_eq!(escape_like_literal("%"), "\\%");
    assert_eq!(escape_like_literal("_"), "\\_");
    assert_eq!(escape_like_literal("\\"), "\\\\");

    // Combined adversarial payload: every wildcard plus a backslash that
    // would otherwise let an attacker terminate the escape sequence.
    let attacker = "evil%name_with\\wild%cards_";
    let escaped = escape_like_literal(attacker);
    assert_eq!(
        escaped, "evil\\%name\\_with\\\\wild\\%cards\\_",
        "adversarial combined input must escape every LIKE metacharacter"
    );

    // Property check: walk the escaped output expecting every `%`, `_`,
    // or `\` to appear as the second char of a `\X` pair. This holds
    // because escape_like_literal emits `\\` for `\`, `\%` for `%`, and
    // `\_` for `_`. A bare metacharacter would indicate a regression.
    let chars: Vec<char> = escaped.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\\' {
            assert!(
                i + 1 < chars.len() && matches!(chars[i + 1], '\\' | '%' | '_'),
                "stray backslash at byte {i} of {escaped:?}"
            );
            i += 2; // consume the escape pair
        } else {
            assert!(
                !matches!(ch, '%' | '_'),
                "bare metacharacter {ch:?} at byte {i} of {escaped:?} — escape regression"
            );
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Bug 5 — GHSA-m597-h769-6qgp (PR #985)
// Class:  Broken access control — Git LFS lock listing was unauthenticated
// Seam:   `require_auth_basic` (the canonical 401 gate every locks handler
//         and most format handlers route through)
// What:   `GET /lfs/:repo/locks` did not call `require_auth_basic`, so an
//         anonymous client could enumerate every active lock — including
//         lock owner names and paths inside private repos. The fix wires
//         the existing auth gate into the handler. We test the gate
//         itself: it MUST return Err when given no AuthExtension, with a
//         WWW-Authenticate challenge for the supplied realm.
// Asserts: `require_auth_basic(None, "git-lfs")` returns Err and the
//         response is a 401 with the right WWW-Authenticate header.
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_m597_h769_6qgp_gitlfs_list_locks_auth() {
    let result = require_auth_basic(None, "git-lfs");
    let response = result.expect_err("missing auth must produce a 401, not pass through");

    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "auth gate must return HTTP 401 when no AuthExtension is present"
    );

    let challenge = response
        .headers()
        .get("WWW-Authenticate")
        .expect("401 must include a WWW-Authenticate challenge")
        .to_str()
        .expect("WWW-Authenticate header must be ASCII");
    assert!(
        challenge.contains("Basic"),
        "challenge must advertise the Basic scheme; got {challenge}"
    );
    assert!(
        challenge.contains("git-lfs"),
        "challenge must echo the realm passed by the caller; got {challenge}"
    );
}
