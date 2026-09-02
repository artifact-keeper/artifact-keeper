//! Adversarial red-team suite for attestation verification (#2955, Stage 4).
//!
//! Fully OFFLINE: every test runs against the pinned vendored trusted root and
//! the Stage-1 captured fixtures (plus locally-minted self-signed certs for the
//! two cases the spike could not capture) — no network. The plan's 12-row
//! attack matrix is implemented here; every hostile input must yield
//! `verified=false` with the *specific* failing check, and never panic (a panic
//! fails the test by definition).
//!
//! Key property proven by rows 4c–4f: `Verifier::verify_digest` ALONE accepts
//! forged inclusion proofs (it skips Rekor inclusion). The verdict shows the
//! crate's crypto check passing while OUR Rekor glue rejects — so both are
//! mandatory, exactly as the issue requires.
//!
//! Which row proves which mechanism matters, because three of the four reject at
//! different depths. Rows 4c and 4f mangle the checkpoint envelope as well as the
//! proof, so the glue rejects them at checkpoint *decode*; only **row 4d** (proof
//! hashes rewritten, checkpoint intact) exercises the RFC 6962 Merkle
//! recomputation, and only **row 4e** (rootHash rewritten, checkpoint intact)
//! exercises the checkpoint↔proof root binding. Those two assert on the specific
//! error so they cannot be satisfied by an incidental parse failure.

use super::*;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::Value;

const GOOD_BUNDLE: &str = include_str!("testdata/pypi-sigstore-4.5.0-whl-bundle-v0.3.json");
const WHL_PROVENANCE: &str = include_str!("testdata/pypi-sigstore-4.5.0-whl-provenance.json");
const WHL: &[u8] = include_bytes!("testdata/pypi-sigstore-4.5.0-py3-none-any.whl");
const SDIST: &[u8] = include_bytes!("testdata/pypi-sigstore-4.5.0.tar.gz");

const M_FLIPPED_SIG: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--flipped-signature-byte.json");
const M_FLIPPED_PAYLOAD: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--flipped-payload-byte.json");
const M_FORGED_INCLUSION: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--forged-inclusion-proof.json");
const M_FORGED_MERKLE: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--forged-merkle-path.json");
const M_ROOTHASH_MISMATCH: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--roothash-vs-checkpoint-mismatch.json");
const M_FORGED_SET: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--forged-set-and-proof.json");
const M_NO_INCLUSION: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--no-inclusion-proof.json");
const M_TAMPERED_TLOG: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--tampered-tlog-body.json");
const M_TIME_OOW: &str =
    include_str!("testdata/mutations/pypi-whl-bundle--integrated-time-out-of-window.json");

const WHL_FILENAME: &str = "sigstore-4.5.0-py3-none-any.whl";
const CLAIMED_REPO: &str = "sigstore/sigstore-python";
const GH_ISSUER: &str = "https://token.actions.githubusercontent.com";

fn allowlist() -> Vec<String> {
    vec![GH_ISSUER.to_string()]
}
fn trust() -> TrustRoot {
    TrustRoot::vendored().expect("vendored trusted root loads")
}
fn good_bundle() -> Value {
    serde_json::from_str(GOOD_BUNDLE).unwrap()
}
fn load(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}
fn inp<'a>(
    bytes: &'a [u8],
    filename: &'a str,
    claimed: &'a str,
    al: &'a [String],
) -> PypiVerifyInput<'a> {
    PypiVerifyInput {
        artifact_bytes: bytes,
        expected_filename: filename,
        claimed_repository: claimed,
        issuer_allowlist: al,
    }
}
/// Verify the good-bundle default: whl bytes, real filename/claim/allowlist.
async fn verify_default(bundle: &Value) -> AttestationVerdict {
    let al = allowlist();
    verify_pypi_bundle(bundle, &inp(WHL, WHL_FILENAME, CLAIMED_REPO, &al), &trust()).await
}
fn has(v: &AttestationVerdict, check: Check) -> bool {
    v.checks_passed & check.bit() != 0
}

// A locally-minted self-signed (non-Fulcio) leaf certificate DER — rows 3/8,
// which the Stage-1 fixtures could not capture.
fn self_signed_der() -> Vec<u8> {
    let ck = rcgen::generate_simple_self_signed(vec!["evil.example".to_string()])
        .expect("mint self-signed cert");
    ck.cert.der().to_vec()
}

// ============================================================= CONTROL (12) ==

#[tokio::test]
async fn row12_happy_path_pypi_verifies_true() {
    let v = verify_default(&good_bundle()).await;
    assert!(v.is_verified(), "good PyPI bundle must verify: {v:?}");
    assert_eq!(v.checks_passed, all_mask());
    assert_eq!(v.owner.as_deref(), Some("sigstore"));
    assert_eq!(v.repository.as_deref(), Some("sigstore/sigstore-python"));
    assert_eq!(v.issuer.as_deref(), Some(GH_ISSUER));
    assert_eq!(v.state.as_str(), "verified");
}

#[tokio::test]
async fn row12_happy_path_via_provenance_document() {
    let al = allowlist();
    let prov = load(WHL_PROVENANCE);
    let v = verify_pypi_provenance(&prov, WHL, WHL_FILENAME, &al, &trust()).await;
    assert!(v.is_verified(), "provenance-doc path must verify: {v:?}");
    assert_eq!(v.owner.as_deref(), Some("sigstore"));
}

// ================================================== ROW 1: theater / presence ==

#[tokio::test]
async fn row1_structural_presence_only_no_valid_envelope() {
    // A bundle that is structurally "there" but has no valid DSSE envelope —
    // the attestation-theater blob the issue was filed about.
    let mut b = good_bundle();
    b["dsseEnvelope"] = serde_json::json!({});
    let v = verify_default(&b).await;
    assert!(!v.is_verified());
    assert_eq!(v.state, AttestationState::Failed);
    assert!(
        !has(&v, Check::BundleWellFormed),
        "no valid envelope: {v:?}"
    );
}

// ================================================ ROW 2: flipped sig / payload ==

#[tokio::test]
async fn row2a_flipped_signature_fails_crypto() {
    let v = verify_default(&load(M_FLIPPED_SIG)).await;
    assert!(!v.is_verified());
    // Subject matched (payload intact); crypto/signature is the failure.
    assert!(has(&v, Check::SubjectDigestBound));
    assert!(
        !has(&v, Check::CryptoAndChain),
        "flipped sig must fail crypto: {v:?}"
    );
    assert!(v.error.as_deref().unwrap().contains("signature"));
}

#[tokio::test]
async fn row2b_flipped_payload_fails_subject_binding() {
    // The payload flip alters the subject digest, so our subject-binding check
    // (run before the crypto, deliberately) catches it with a precise reason
    // rather than the crate's misleading transparency error.
    let v = verify_default(&load(M_FLIPPED_PAYLOAD)).await;
    assert!(!v.is_verified());
    assert!(!has(&v, Check::SubjectDigestBound), "{v:?}");
    assert!(v.error.as_deref().unwrap().contains("subject"));
}

// ============================================= ROW 3: non-Fulcio / self-signed ==

#[tokio::test]
async fn row3_self_signed_non_fulcio_chain_rejected() {
    let mut b = good_bundle();
    b["verificationMaterial"]["certificate"]["rawBytes"] =
        serde_json::json!(B64.encode(self_signed_der()));
    let v = verify_default(&b).await;
    assert!(
        !v.is_verified(),
        "self-signed chain must be rejected: {v:?}"
    );
    // Subject still matches (real whl + intact payload); the chain is the wall.
    assert!(!has(&v, Check::CryptoAndChain), "{v:?}");
}

// ===================================== ROW 4: stripped / tampered / forged log ==

#[tokio::test]
async fn row4a_inclusion_proof_stripped_rejected() {
    let v = verify_default(&load(M_NO_INCLUSION)).await;
    assert!(!v.is_verified());
    assert!(
        !has(&v, Check::CryptoAndChain),
        "stripped proof rejected: {v:?}"
    );
    assert!(v.error.as_deref().unwrap().contains("inclusion"));
}

#[tokio::test]
async fn row4b_tampered_tlog_body_rejected() {
    let v = verify_default(&load(M_TAMPERED_TLOG)).await;
    assert!(!v.is_verified());
    assert!(!has(&v, Check::CryptoAndChain), "{v:?}");
}

#[tokio::test]
async fn row4c_forged_inclusion_proof_caught_by_our_glue_not_the_crate() {
    // THE headline case: the crate's verify_digest ACCEPTS this forged proof
    // (it skips Rekor inclusion). Our glue must reject it. The verdict proves
    // it: CryptoAndChain (crate) passed, RekorInclusion (us) failed.
    let v = verify_default(&load(M_FORGED_INCLUSION)).await;
    assert!(!v.is_verified(), "forged inclusion proof must fail: {v:?}");
    assert!(
        has(&v, Check::CryptoAndChain),
        "the crate's verify_digest accepts the forged proof (that is the bug): {v:?}"
    );
    assert!(
        !has(&v, Check::RekorInclusion),
        "OUR Rekor glue must be the check that rejects it: {v:?}"
    );
    assert!(v.error.as_deref().unwrap().contains("Rekor"));
}

#[tokio::test]
async fn row4d_forged_merkle_path_rejected_by_glue() {
    let v = verify_default(&load(M_FORGED_MERKLE)).await;
    assert!(!v.is_verified());
    assert!(
        has(&v, Check::CryptoAndChain) && !has(&v, Check::RekorInclusion),
        "{v:?}"
    );
    // Pin the MECHANISM, not just the check that failed. This fixture keeps the
    // checkpoint intact and rewrites only the proof hashes, so the rejection must
    // come from the RFC 6962 recomputation disagreeing with the signed root — not
    // from an incidental parse error. Rows 4c/4f also mangle the checkpoint
    // envelope, so they are rejected at checkpoint decode; this row and 4e are the
    // ones that actually exercise the Merkle arithmetic.
    let e = v.error.as_deref().unwrap();
    assert!(
        e.contains("Inclusion Proof error") && e.contains("MismatchedRoot"),
        "expected an RFC 6962 inclusion-proof root mismatch, got: {e}"
    );
}

#[tokio::test]
async fn row4e_roothash_vs_checkpoint_mismatch_rejected_by_glue() {
    let v = verify_default(&load(M_ROOTHASH_MISMATCH)).await;
    assert!(!v.is_verified());
    assert!(
        has(&v, Check::CryptoAndChain) && !has(&v, Check::RekorInclusion),
        "{v:?}"
    );
    // This fixture rewrites ONLY the proof's rootHash, leaving the signed
    // checkpoint alone, so the rejection must come from `is_valid_for_proof`
    // binding the proof's root to the log's signed root. Anything else would mean
    // the checkpoint is not actually pinning the tree the proof claims.
    let e = v.error.as_deref().unwrap();
    assert!(
        e.contains("Consistency proof error") && e.contains("MismatchedRoot"),
        "expected the signed checkpoint to reject the proof's root hash, got: {e}"
    );
}

#[tokio::test]
async fn row4f_forged_set_and_proof_rejected_by_glue() {
    let v = verify_default(&load(M_FORGED_SET)).await;
    assert!(!v.is_verified());
    assert!(
        has(&v, Check::CryptoAndChain) && !has(&v, Check::RekorInclusion),
        "{v:?}"
    );
    // Since #3231 the SET is verified in its own right, and this fixture forges
    // it — so the rejection must now come from the SET check, BEFORE the
    // inclusion proof is even looked at. Pin that, so a regression that drops
    // SET verification cannot hide behind the proof check catching the same
    // fixture for an unrelated reason.
    assert!(!has(&v, Check::RekorSet), "{v:?}");
    let e = v.error.as_deref().unwrap();
    assert!(
        e.contains("Rekor SET") && e.contains("signed entry timestamp"),
        "expected a SET verification failure, got: {e}"
    );
}

// ============================================ #3231: SET / integratedTime ====

/// The point of the SET check: `integratedTime` is what the certificate's
/// validity window is compared against, and before #3231 nothing authenticated
/// it. This drives the glue directly at the fixture whose only change is a
/// rewritten `integratedTime` and asserts the log's signature catches it.
#[test]
fn set_verification_rejects_a_rewritten_integrated_time() {
    let t = trust();
    let good = good_bundle();
    rekor_glue::verify_signed_entry_timestamp(&good, t.bytes())
        .expect("the captured PyPI bundle carries a genuine Rekor SET");

    let e = rekor_glue::verify_signed_entry_timestamp(&load(M_TIME_OOW), t.bytes())
        .expect_err("a rewritten integratedTime must not verify");
    assert!(
        format!("{e:#}").contains("signed entry timestamp"),
        "unexpected error: {e:#}"
    );
}

/// Fail-closed on a *missing* promise: an entry with no SET carries no
/// authenticated timestamp at all, which must be a rejection rather than a
/// silent downgrade to the pre-#3231 behaviour.
#[test]
fn set_verification_fails_closed_when_the_promise_is_absent() {
    let mut b = good_bundle();
    b["verificationMaterial"]["tlogEntries"][0]
        .as_object_mut()
        .unwrap()
        .remove("inclusionPromise");
    let e = rekor_glue::verify_signed_entry_timestamp(&b, trust().bytes())
        .expect_err("a missing inclusionPromise must fail closed");
    assert!(
        format!("{e:#}").contains("unauthenticated"),
        "unexpected error: {e:#}"
    );
}

/// A bundle whose log id is not in the trusted root cannot be SET-verified —
/// the key lookup, not the signature, is the wall (fail closed).
#[test]
fn set_verification_rejects_an_unknown_log_id() {
    let mut b = good_bundle();
    b["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"] =
        serde_json::json!(B64.encode([0u8; 32]));
    let e = rekor_glue::verify_signed_entry_timestamp(&b, trust().bytes())
        .expect_err("an unknown log id must fail closed");
    assert!(
        format!("{e:#}").contains("not in the trusted root"),
        "unexpected error: {e:#}"
    );
}

/// The whole-verifier consequence: a bundle with no SET never reaches
/// `verified`, and the verdict names the SET check.
#[tokio::test]
async fn bundle_without_a_set_cannot_verify() {
    let mut b = good_bundle();
    b["verificationMaterial"]["tlogEntries"][0]
        .as_object_mut()
        .unwrap()
        .remove("inclusionPromise");
    let v = verify_default(&b).await;
    assert!(!v.is_verified(), "{v:?}");
    assert!(
        has(&v, Check::CryptoAndChain) && !has(&v, Check::RekorSet),
        "the crate's verify_digest accepts a promise-less entry; OUR SET check must reject: {v:?}"
    );
    assert!(
        !has(&v, Check::RekorInclusion),
        "the SET check runs first, so inclusion must not have been reached: {v:?}"
    );
}

// ============================================= ROW 5 & 6: replay (wrong bytes) ==

#[tokio::test]
async fn row5_cross_package_replay_wrong_artifact_digest() {
    // Valid wheel attestation presented for the SDIST bytes.
    let al = allowlist();
    let v = verify_pypi_bundle(
        &good_bundle(),
        &inp(SDIST, WHL_FILENAME, CLAIMED_REPO, &al),
        &trust(),
    )
    .await;
    assert!(!v.is_verified(), "replay must fail: {v:?}");
    assert!(!has(&v, Check::SubjectDigestBound), "{v:?}");
    assert!(v.error.as_deref().unwrap().contains("subject"));
}

#[tokio::test]
async fn row6_cross_version_replay_filename_and_digest_mismatch() {
    // Old-version attestation vs new artifact bytes: both the subject digest and
    // the filename disagree; our subject-binding check catches it.
    let al = allowlist();
    let v = verify_pypi_bundle(
        &good_bundle(),
        &inp(SDIST, "sigstore-4.5.0.tar.gz", CLAIMED_REPO, &al),
        &trust(),
    )
    .await;
    assert!(!v.is_verified());
    assert!(!has(&v, Check::SubjectDigestBound), "{v:?}");
}

// ================================================= ROW 7: wrong claimed owner ==

#[tokio::test]
async fn row7_wrong_identity_claimed_microsoft() {
    // Genuinely-signed sigstore bundle, but the claimed publisher says Microsoft.
    let al = allowlist();
    let v = verify_pypi_bundle(
        &good_bundle(),
        &inp(WHL, WHL_FILENAME, "Microsoft/evil", &al),
        &trust(),
    )
    .await;
    assert!(!v.is_verified(), "owner-binding must fail: {v:?}");
    // Everything up to the owner binding passed.
    assert!(has(&v, Check::RekorInclusion) && has(&v, Check::IssuerAllowlisted));
    assert!(!has(&v, Check::PublisherOwnerBound), "{v:?}");
    assert!(v.error.as_deref().unwrap().contains("owner"));
}

// ==================================================== ROW 8: wrong issuer =====

#[tokio::test]
async fn row8_non_allowlisted_issuer_rejected() {
    // Same good bundle, but the operator allowlist excludes GitHub Actions.
    let al = vec!["https://gitlab.example/oidc".to_string()];
    let v = verify_pypi_bundle(
        &good_bundle(),
        &inp(WHL, WHL_FILENAME, CLAIMED_REPO, &al),
        &trust(),
    )
    .await;
    assert!(!v.is_verified(), "non-allowlisted issuer must fail: {v:?}");
    assert!(has(&v, Check::IdentityExtracted));
    assert!(!has(&v, Check::IssuerAllowlisted), "{v:?}");
    assert!(v.error.as_deref().unwrap().contains("issuer"));
}

#[tokio::test]
async fn row8b_self_signed_cert_with_no_fulcio_issuer_is_rejected() {
    // A valid-shape self-signed cert carries no Fulcio issuer extension; even if
    // it reached the issuer gate it would be empty/non-allowlisted. It is
    // rejected fail-closed (chain first — even stronger). No panic.
    let mut b = good_bundle();
    b["verificationMaterial"]["certificate"]["rawBytes"] =
        serde_json::json!(B64.encode(self_signed_der()));
    let v = verify_pypi_bundle(
        &b,
        &inp(WHL, WHL_FILENAME, CLAIMED_REPO, &allowlist()),
        &trust(),
    )
    .await;
    assert!(!v.is_verified());
}

// =============================================== ROW 9: cert time vs integrated ==

#[tokio::test]
async fn row9_cert_outside_validity_at_integrated_time() {
    let v = verify_default(&load(M_TIME_OOW)).await;
    assert!(!v.is_verified());
    assert!(!has(&v, Check::CryptoAndChain), "{v:?}");
    let e = v.error.as_deref().unwrap();
    assert!(e.contains("certificate") || e.contains("expired"), "{e}");
}

// ================================================= ROW 10: stale / missing root ==

#[test]
fn row10_stale_or_missing_trust_root_fails_closed() {
    // A stale/empty/garbage root must be REFUSED at construction — the caller
    // then gets no verifier and the rule Flags (never Allows, never an outage).
    assert!(TrustRoot::from_bytes(b"{}".to_vec()).is_err());
    assert!(TrustRoot::from_bytes(b"not-json".to_vec()).is_err());
    // A well-formed-but-keyless trusted root (stale: all keys time-expired and
    // dropped) is also refused.
    let keyless = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [], "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []
    });
    assert!(TrustRoot::from_bytes(serde_json::to_vec(&keyless).unwrap()).is_err());
}

// ================================================= ROW 11: degenerate inputs ====

#[tokio::test]
async fn row11_degenerate_inputs_never_panic() {
    let al = allowlist();
    let t = trust();

    // Empty bundle object.
    let v = verify_pypi_bundle(
        &serde_json::json!({}),
        &inp(WHL, WHL_FILENAME, CLAIMED_REPO, &al),
        &t,
    )
    .await;
    assert!(!v.is_verified());

    // 32 MiB junk DSSE payload (size bomb).
    let mut big = good_bundle();
    big["dsseEnvelope"]["payload"] = serde_json::json!(B64.encode(vec![b'A'; 32 * 1024 * 1024]));
    let v = verify_pypi_bundle(&big, &inp(WHL, WHL_FILENAME, CLAIMED_REPO, &al), &t).await;
    assert!(!v.is_verified());

    // Deeply nested JSON as a bundle.
    let mut nested = String::new();
    for _ in 0..2000 {
        nested.push('[');
    }
    nested.push('1');
    for _ in 0..2000 {
        nested.push(']');
    }
    let deep: Value = serde_json::from_str(&nested)
        .unwrap_or(serde_json::json!({"mediaType": "x", "junk": "recursion-limited"}));
    let bomb = serde_json::json!({ "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "junk": deep });
    let v = verify_pypi_bundle(&bomb, &inp(WHL, WHL_FILENAME, CLAIMED_REPO, &al), &t).await;
    assert!(!v.is_verified());

    // Two tlog entries (must be exactly one).
    let mut dup = good_bundle();
    let te = dup["verificationMaterial"]["tlogEntries"][0].clone();
    dup["verificationMaterial"]["tlogEntries"] = serde_json::json!([te.clone(), te]);
    let v = verify_pypi_bundle(&dup, &inp(WHL, WHL_FILENAME, CLAIMED_REPO, &al), &t).await;
    assert!(!v.is_verified());
    assert!(!has(&v, Check::BundleWellFormed), "two tlog entries: {v:?}");
}

// ================================================ STRUCTURAL / PROPERTY GUARDS ==

#[test]
fn success_requires_every_check() {
    // The ONLY place that mints Verified is from_mask, only at all_mask().
    // Clearing any single check must forbid Verified — the non-short-circuit
    // property guard the plan requires.
    let full = all_mask();
    let id = fake_verified_identity();
    assert!(AttestationVerdict::from_mask(full, &id).is_verified());
    for c in ALL_CHECKS {
        let missing = full & !c.bit();
        let v = AttestationVerdict::from_mask(missing, &id);
        assert!(
            !v.is_verified(),
            "clearing {c:?} must not yield Verified (mask {missing:#b})"
        );
    }
}

#[test]
fn every_check_has_a_distinct_bit() {
    let mut seen = 0u16;
    for c in ALL_CHECKS {
        assert_eq!(seen & c.bit(), 0, "duplicate bit for {c:?}");
        seen |= c.bit();
    }
    assert_eq!(seen, all_mask());
}

fn fake_verified_identity() -> identity::CertIdentity {
    identity::CertIdentity {
        san: vec!["https://github.com/o/r/.github/workflows/x.yml@refs/tags/v1".into()],
        issuer: Some(GH_ISSUER.into()),
        gh_workflow_repository: Some("o/r".into()),
        ..Default::default()
    }
}

#[test]
fn npm_never_overclaims() {
    let v = verify_npm_unsupported();
    assert!(!v.is_verified());
    assert_eq!(v.state, AttestationState::Failed);
    assert!(v.error.as_deref().unwrap().contains("npm sha512"));
}

// ============================================== npm FAILS SAFE, not silently ==

const NPM_BUNDLE: &str = include_str!("testdata/npm-sigstore-5.0.0-slsa-bundle-v0.3.json");
const NPM_ATTESTATIONS: &str = include_str!("testdata/npm-sigstore-5.0.0-attestations.json");

/// npm's real, genuinely-signed SLSA provenance must FAIL SAFE — it must not be
/// silently treated as verified, and it must not be reachable by the only code
/// path that can mint a `Verified` verdict.
///
/// `verify_npm_unsupported` above only proves that a hardcoded stub returns
/// `Failed`; it says nothing about the real material, which is what an operator
/// actually has. This drives the captured `sigstore@5.0.0` npm bundle through
/// every door into the verifier and asserts none of them opens.
#[tokio::test]
async fn npm_real_bundle_cannot_reach_a_verified_state() {
    let al = allowlist();
    let t = trust();

    // POSITIVE CONTROL, same fixture harness: the PyPI bundle DOES verify here.
    // Without this the assertions below are satisfied by any breakage that makes
    // everything fail (a bad trust root, an unloadable fixture directory).
    let control = verify_default(&good_bundle()).await;
    assert!(
        control.is_verified(),
        "control must verify or the negative assertions below prove nothing: {control:?}"
    );

    // The premise: npm binds its subject with sha512 and names it by purl, so
    // there is no sha256 for the artifact digest to bind against. Assert the
    // fixture really has that shape, so this test cannot pass because the file
    // is simply malformed.
    let npm_bundle: Value = load(NPM_BUNDLE);
    let stmt = bundle_convert::statement_of(&npm_bundle).expect("npm statement decodes");
    let subject = &stmt["subject"][0];
    assert!(
        subject["digest"]["sha512"].is_string(),
        "fixture must carry the sha512 subject binding: {subject}"
    );
    assert!(
        subject["digest"]["sha256"].is_null(),
        "fixture must NOT carry a sha256 subject: {subject}"
    );

    // Door 1 — the bundle path, against several artifact byte strings. No input
    // can make it verify, because the statement never binds a sha256.
    for (label, bytes) in [("whl", WHL), ("sdist", SDIST), ("empty", b"" as &[u8])] {
        let v = verify_pypi_bundle(
            &npm_bundle,
            &inp(bytes, "sigstore-5.0.0.tgz", "sigstore/sigstore-js", &al),
            &t,
        )
        .await;
        assert!(
            !v.is_verified(),
            "npm bundle verified against {label}: {v:?}"
        );
        assert_eq!(v.state, AttestationState::Failed, "{label}");
        assert!(
            !has(&v, Check::SubjectDigestBound),
            "npm must die at the sha256 subject binding ({label}): {v:?}"
        );
        // The load-bearing consequence: no marker means the evaluation loop
        // cannot inject trust, so the publisher stays unverified.
        assert!(
            verified_marker(&v).is_none(),
            "a non-verified verdict must never produce a marker ({label}): {v:?}"
        );
    }

    // Door 2 — the provenance-document path. npm's attestations document uses
    // `attestations[]`, not PEP 740's `attestation_bundles[]`, so the converter
    // yields nothing and the verdict is a failure, never an empty success.
    let atts: Value = load(NPM_ATTESTATIONS);
    assert!(
        bundle_convert::provenance_to_bundles(&atts).is_empty(),
        "npm attestations must not convert to PEP 740 bundles"
    );
    let v = verify_pypi_provenance(&atts, WHL, "sigstore-5.0.0.tgz", &al, &t).await;
    assert!(!v.is_verified(), "{v:?}");
    assert_eq!(v.state, AttestationState::Failed);
    assert!(verified_marker(&v).is_none());
}

/// End-to-end: an npm package whose registry document advertises sigstore
/// provenance is labeled `Attestation` but never `verified`, so
/// `publisher_trust match:attestation` keeps it on the fail-safe review path.
#[test]
fn npm_provenance_ingestion_never_yields_a_verified_publisher() {
    use crate::services::curation::publisher_source::{
        extract_publisher, PublisherSource, VERIFICATION_MARKER,
    };
    use crate::services::curation_sync::build_npm_curation_entry;

    let packument: Value = load(include_str!("testdata/npm-sigstore-packument.json"));
    let version_doc = &packument["versions"]["5.0.0"];
    assert!(
        !version_doc["dist"]["attestations"].is_null(),
        "fixture must advertise provenance or this proves nothing"
    );

    let entry = build_npm_curation_entry("sigstore", "5.0.0", version_doc).expect("npm entry");
    assert!(
        entry.metadata.get(VERIFICATION_MARKER).is_none(),
        "the ingestion builder must not carry a verification marker"
    );

    let id = extract_publisher("npm", &entry.metadata).expect("npm publisher extracted");
    assert_eq!(
        id.source,
        PublisherSource::Attestation,
        "provenance presence is a labeling signal"
    );
    assert!(
        !id.verified,
        "npm provenance presence must never equal verification: {id:?}"
    );
}

// ====================== #3230: the persisted record is read back, not write-only ==

use chrono::{Duration, Utc};

fn record<'a>(
    state: &'a str,
    identity: Option<&'a str>,
    issuer: Option<&'a str>,
    owner: Option<&'a str>,
    verified_at: Option<chrono::DateTime<Utc>>,
) -> AttestationRecord<'a> {
    AttestationRecord {
        state,
        identity,
        issuer,
        owner,
        verified_at,
        upstream_updated_at: None,
    }
}

fn fresh_record<'a>() -> AttestationRecord<'a> {
    record(
        "verified",
        Some("https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v4.5.0"),
        Some(GH_ISSUER),
        Some("sigstore"),
        Some(Utc::now() - Duration::hours(1)),
    )
}

/// The property the issue is about: a verification must survive the tick that
/// computed it. A live verification's own outputs, written to the record columns
/// and read back, must reproduce the same trust marker — otherwise every
/// re-evaluation silently returns an `approved` package to `review`.
#[tokio::test]
async fn a_persisted_verification_reproduces_the_live_marker() {
    let live = verify_default(&good_bundle()).await;
    assert!(live.is_verified(), "control must verify: {live:?}");

    // Exactly what `record_attestation` persists, read back as the row would be.
    let rec = record(
        live.state.as_str(),
        live.identity.as_deref(),
        live.issuer.as_deref(),
        live.owner.as_deref(),
        Some(Utc::now()),
    );
    let rehydrated =
        reusable_verdict(&rec, &allowlist(), Utc::now()).expect("a fresh record must be reusable");

    assert!(rehydrated.is_verified());
    assert_eq!(rehydrated.owner, live.owner);
    assert_eq!(rehydrated.identity, live.identity);
    assert_eq!(rehydrated.issuer, live.issuer);
    assert_eq!(
        verified_marker(&rehydrated),
        verified_marker(&live),
        "the re-evaluation marker must be identical to the one the live tick injected"
    );
}

/// Every guard, one at a time. Each returns `None`, which means "verify again" —
/// at most today's behaviour, never false trust.
#[test]
fn an_unusable_record_is_never_reused() {
    let al = allowlist();
    let now = Utc::now();
    let id = fresh_record().identity;

    // Positive control: the unmodified record IS reusable, so the assertions
    // below cannot be satisfied by a guard that rejects everything.
    assert!(reusable_verdict(&fresh_record(), &al, now).is_some());

    // 1. Not a success. `failed` includes the npm-unsupported case, and
    //    `unverified` is the default every row carries.
    for state in ["unverified", "failed", "", "VERIFIED"] {
        let mut r = fresh_record();
        r.state = state;
        assert!(
            reusable_verdict(&r, &al, now).is_none(),
            "state `{state}` must not be reusable"
        );
    }

    // 2. A `verified` row missing (or blank in) any cert-bound value is a
    //    partial write, not a verification.
    for r in [
        record(
            "verified",
            None,
            Some(GH_ISSUER),
            Some("sigstore"),
            Some(now),
        ),
        record("verified", id, None, Some("sigstore"), Some(now)),
        record("verified", id, Some(GH_ISSUER), None, Some(now)),
        record("verified", id, Some(GH_ISSUER), Some("   "), Some(now)),
        record(
            "verified",
            Some(""),
            Some(GH_ISSUER),
            Some("sigstore"),
            Some(now),
        ),
    ] {
        assert!(reusable_verdict(&r, &al, now).is_none(), "{r:?}");
    }

    // 3. The recorded issuer is no longer on the operator's allowlist: a
    //    narrowed allowlist must take effect at the next evaluation, not at the
    //    next re-verification window.
    let narrowed = vec!["https://gitlab.example/oidc".to_string()];
    assert!(reusable_verdict(&fresh_record(), &narrowed, now).is_none());

    // 4. No timestamp at all, and a record older than the reuse window.
    let mut undated = fresh_record();
    undated.verified_at = None;
    assert!(reusable_verdict(&undated, &al, now).is_none());

    let mut stale = fresh_record();
    stale.verified_at = Some(now - Duration::days(VERIFIED_RECORD_MAX_AGE_DAYS + 1));
    assert!(reusable_verdict(&stale, &al, now).is_none());

    // Just inside the window is still reusable (the boundary, from both sides).
    let mut edge = fresh_record();
    edge.verified_at =
        Some(now - Duration::days(VERIFIED_RECORD_MAX_AGE_DAYS) + Duration::minutes(1));
    assert!(reusable_verdict(&edge, &al, now).is_some());

    // 5. The row was re-ingested from the upstream after the record was written,
    //    so the record describes content the row no longer carries.
    let mut moved = fresh_record();
    moved.verified_at = Some(now - Duration::hours(2));
    moved.upstream_updated_at = Some(now - Duration::hours(1));
    assert!(reusable_verdict(&moved, &al, now).is_none());

    // An upsert that predates the verification is fine.
    let mut older_upsert = fresh_record();
    older_upsert.verified_at = Some(now - Duration::hours(1));
    older_upsert.upstream_updated_at = Some(now - Duration::hours(2));
    assert!(reusable_verdict(&older_upsert, &al, now).is_some());
}

/// The marker helper both evaluation paths share: a stored row can only ever
/// carry a marker it asserted about itself, so it is dropped unconditionally,
/// and a marker is injected only for a verified verdict.
#[test]
fn apply_verified_marker_strips_then_injects() {
    use crate::services::curation::publisher_source::VERIFICATION_MARKER;

    let planted = serde_json::json!({
        "name": "evil",
        VERIFICATION_MARKER: {"state": "verified", "owner": "Microsoft"},
    });

    // No verdict: the planted marker is dropped and nothing replaces it.
    let mut m = planted.clone();
    assert!(apply_verified_marker(&mut m, None));
    assert!(m.get(VERIFICATION_MARKER).is_none());

    // A failed verdict cannot inject one either.
    let mut m = planted.clone();
    let failed = verify_npm_unsupported();
    assert!(apply_verified_marker(&mut m, Some(&failed)));
    assert!(m.get(VERIFICATION_MARKER).is_none());

    // A verified verdict replaces it with OUR cert-bound values.
    let mut m = planted.clone();
    let verdict = reusable_verdict(&fresh_record(), &allowlist(), Utc::now()).unwrap();
    assert!(apply_verified_marker(&mut m, Some(&verdict)));
    assert_eq!(
        m[VERIFICATION_MARKER]["owner"],
        serde_json::json!("sigstore"),
        "the planted owner must not survive: {m}"
    );

    // Nothing planted: no drop reported, marker still injected.
    let mut clean = serde_json::json!({"name": "sigstore"});
    assert!(!apply_verified_marker(&mut clean, Some(&verdict)));
    assert_eq!(
        clean[VERIFICATION_MARKER]["owner"],
        serde_json::json!("sigstore")
    );
}
