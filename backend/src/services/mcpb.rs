//! MCPB bundles (#5253, Phase 3): the `manifest.json` inside a bundle and
//! its signature.
//!
//! A bundle (`.mcpb`, formerly `.dxt`) is a ZIP archive with a
//! `manifest.json` at its root. The `@anthropic-ai/mcpb` signer
//! (`src/node/sign.ts` in `modelcontextprotocol/mcpb`) appends a signature
//! block to the archive:
//!
//! ```text
//! <zip> "MCPB_SIG_V1" <u32 LE length> <PKCS#7 SignedData, DER, detached> "MCPB_SIG_END"
//! ```
//!
//! The SignedData signs the archive bytes as they were before signing
//! (SHA-256, signed attributes `contentType`, `messageDigest`,
//! `signingTime`). Since upstream #194 the signer also grows the ZIP
//! end-of-central-directory comment length by the block length, so the
//! bytes in front of the block differ from the signed bytes in that one
//! field; [`signed_content_candidates`] undoes it (bundles signed before #194
//! are accepted as well).
//!
//! Verification is pure (no outbound connection, no trust store): the
//! signature must verify with the certificate the block carries (RSA
//! PKCS#1 v1.5 with SHA-256, the only scheme the upstream signer produces)
//! and that certificate must be valid at signing time. Whether the
//! certificate chains to a trusted root is not decided here; the result
//! records the signer, issuer, fingerprint and whether it is self-signed.

use std::borrow::Cow;
use std::io::Read;

use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Largest bundle accepted on upload.
pub const MCPB_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Largest `manifest.json` read out of a bundle.
pub const MANIFEST_MAX_BYTES: u64 = 1024 * 1024;
/// Largest manifest kept in metadata (the rest of the bundle is not parsed).
pub const MANIFEST_KEEP_MAX_BYTES: usize = 64 * 1024;

const SIG_HEADER: &[u8] = b"MCPB_SIG_V1";
const SIG_FOOTER: &[u8] = b"MCPB_SIG_END";
const EOCD_MAGIC: &[u8] = b"PK\x05\x06";
const EOCD_MIN: usize = 22;

// OID contents (without tag and length).
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_SHA256_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SIGNING_TIME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];

/// A bundle that cannot be accepted (400 `mcp_bundle_invalid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError(pub String);

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn bad(msg: impl Into<String>) -> BundleError {
    BundleError(msg.into())
}

// ---------------------------------------------------------------------------
// Signature block
// ---------------------------------------------------------------------------

/// A bundle split into its archive bytes and signature block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitBundle<'a> {
    /// The bytes in front of the signature block (the whole file if none).
    pub archive: &'a [u8],
    /// The PKCS#7 DER, when a block is present.
    pub signature: Option<&'a [u8]>,
    /// Length of the whole block (header, length, DER, footer).
    pub block_len: usize,
    /// A block is present but its framing is broken.
    pub malformed: bool,
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Split `bytes` the way upstream `extractSignatureBlock` does: the last
/// footer, the nearest header before it, and the length in between. A
/// block whose length does not reach exactly to its footer, or that is not
/// at the end of the file, is malformed (present, so never "unsigned").
pub fn split_signature(bytes: &[u8]) -> SplitBundle<'_> {
    let unsigned = SplitBundle {
        archive: bytes,
        signature: None,
        block_len: 0,
        malformed: false,
    };
    let Some(footer) = rfind(bytes, SIG_FOOTER) else {
        return unsigned;
    };
    let Some(header) = rfind(&bytes[..footer], SIG_HEADER) else {
        return unsigned;
    };
    let start = header + SIG_HEADER.len();
    let malformed = SplitBundle {
        archive: &bytes[..header],
        signature: None,
        block_len: bytes.len() - header,
        malformed: true,
    };
    let Some(len_bytes) = bytes.get(start..start + 4) else {
        return malformed;
    };
    let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let der_start = start + 4;
    if der_start.checked_add(len) != Some(footer) || footer + SIG_FOOTER.len() != bytes.len() {
        return malformed;
    }
    SplitBundle {
        archive: &bytes[..header],
        signature: Some(&bytes[der_start..footer]),
        block_len: bytes.len() - header,
        malformed: false,
    }
}

/// The bytes the signer may have signed: the archive with its EOCD comment
/// length restored (current signer) and the archive as it is (signers
/// before upstream #194).
pub fn signed_content_candidates<'a>(split: &SplitBundle<'a>) -> Vec<Cow<'a, [u8]>> {
    let mut out = Vec::with_capacity(2);
    let archive = split.archive;
    if let Some(eocd) = rfind(archive, EOCD_MAGIC).filter(|&i| i + EOCD_MIN <= archive.len()) {
        let at = eocd + 20;
        let current = u16::from_le_bytes([archive[at], archive[at + 1]]) as usize;
        if let Some(orig) = current.checked_sub(split.block_len) {
            let mut restored = archive.to_vec();
            restored[at..at + 2].copy_from_slice(&(orig as u16).to_le_bytes());
            out.push(Cow::Owned(restored));
        }
    }
    out.push(Cow::Borrowed(archive));
    out
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Read `manifest.json` from the archive bytes of a bundle. The manifest must
/// be a JSON object with a string `name` and `version`.
pub fn read_manifest(archive: &[u8]) -> Result<serde_json::Value, BundleError> {
    read_manifest_from(std::io::Cursor::new(archive))
}

fn read_manifest_from(
    archive: impl std::io::Read + std::io::Seek,
) -> Result<serde_json::Value, BundleError> {
    let mut zip =
        zip::ZipArchive::new(archive).map_err(|e| bad(format!("not a ZIP archive: {e}")))?;
    let mut entry = zip
        .by_name("manifest.json")
        .map_err(|_| bad("the bundle has no manifest.json at its root"))?;
    if entry.size() > MANIFEST_MAX_BYTES {
        return Err(bad("manifest.json is larger than 1 MiB"));
    }
    let mut raw = Vec::new();
    entry
        .by_ref()
        .take(MANIFEST_MAX_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| bad(format!("manifest.json could not be read: {e}")))?;
    if raw.len() as u64 > MANIFEST_MAX_BYTES {
        return Err(bad("manifest.json is larger than 1 MiB"));
    }
    if crate::formats::mcp::json_depth_exceeds(&raw, crate::formats::mcp::MAX_DEPTH) {
        return Err(bad("manifest.json nests too deeply"));
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| bad(format!("manifest.json: {e}")))?;
    for field in ["name", "version"] {
        if !manifest.get(field).is_some_and(|v| v.is_string()) {
            return Err(bad(format!("manifest.json has no string `{field}`")));
        }
    }
    Ok(manifest)
}

/// The manifest kept in `metadata.bundles[].manifest`: the whole manifest
/// when it is small, else its identity, tools and prompts only.
pub fn manifest_for_metadata(manifest: &serde_json::Value) -> serde_json::Value {
    let size = serde_json::to_vec(manifest).map(|v| v.len()).unwrap_or(0);
    if size <= MANIFEST_KEEP_MAX_BYTES {
        return manifest.clone();
    }
    let mut out = serde_json::Map::new();
    for key in [
        "manifest_version",
        "dxt_version",
        "name",
        "display_name",
        "version",
        "description",
        "tools",
        "prompts",
        "tools_generated",
        "prompts_generated",
    ] {
        if let Some(v) = manifest.get(key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    out.insert("truncated".into(), true.into());
    serde_json::Value::Object(out)
}

// ---------------------------------------------------------------------------
// DER reading (just enough for CMS SignedData)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// The whole element, header included.
    raw: &'a [u8],
}

fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), BundleError> {
    let err = || bad("malformed signature (DER)");
    let tag = *input.first().ok_or_else(err)?;
    if tag & 0x1F == 0x1F {
        return Err(err());
    }
    let first = *input.get(1).ok_or_else(err)?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(err());
        }
        let bytes = input.get(2..2 + n).ok_or_else(err)?;
        (
            bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize),
            2 + n,
        )
    };
    let end = hdr.checked_add(len).ok_or_else(err)?;
    let raw = input.get(..end).ok_or_else(err)?;
    Ok((
        Tlv {
            tag,
            value: &raw[hdr..],
            raw,
        },
        &input[end..],
    ))
}

/// Every element of a constructed value, in order.
fn children(value: &[u8]) -> Result<Vec<Tlv<'_>>, BundleError> {
    let mut out = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (t, r) = read_tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

fn expect(t: Tlv<'_>, tag: u8) -> Result<Tlv<'_>, BundleError> {
    if t.tag == tag {
        Ok(t)
    } else {
        Err(bad("unexpected signature structure"))
    }
}

/// The OID contents of an `AlgorithmIdentifier`.
fn algorithm_oid<'a>(t: &Tlv<'a>) -> Result<&'a [u8], BundleError> {
    let parts = children(expect(*t, 0x30)?.value)?;
    Ok(expect(*parts.first().ok_or_else(|| bad("empty algorithm"))?, 0x06)?.value)
}

/// `YYMMDDHHMMSSZ` (UTCTime) or `YYYYMMDDHHMMSSZ` (GeneralizedTime).
fn parse_der_time(t: &Tlv<'_>) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(t.value).ok()?.strip_suffix('Z')?;
    let (year, rest) = match t.tag {
        0x17 if s.len() == 12 => {
            let yy: i32 = s[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        0x18 if s.len() == 14 => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| rest.get(i..i + 2)?.parse::<u32>().ok();
    Utc.with_ymd_and_hms(year, n(0)?, n(2)?, n(4)?, n(6)?, n(8)?)
        .single()
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// `metadata.bundles[].signature.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureState {
    Valid,
    Unsigned,
    Invalid,
}

/// What signature verification found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    pub state: SignatureState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// SHA-256 of the signing certificate (DER), lower-case hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<DateTime<Utc>>,
    /// Why an `invalid` signature was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SignatureInfo {
    fn unsigned() -> Self {
        Self {
            state: SignatureState::Unsigned,
            signer: None,
            issuer: None,
            fingerprint: None,
            self_signed: None,
            signed_at: None,
            reason: None,
        }
    }

    fn invalid(reason: impl Into<String>) -> Self {
        Self {
            state: SignatureState::Invalid,
            reason: Some(reason.into()),
            ..Self::unsigned()
        }
    }
}

/// The parts of a SignerInfo the verification needs.
struct Signer<'a> {
    issuer_raw: Option<&'a [u8]>,
    serial: Option<&'a [u8]>,
    digest_alg: &'a [u8],
    signed_attrs: &'a [u8],
    signature_alg: &'a [u8],
    signature: &'a [u8],
}

/// `(certificates, signer)` of a DER ContentInfo holding SignedData.
fn parse_signed_data(der: &[u8]) -> Result<(Vec<&[u8]>, Signer<'_>), BundleError> {
    let (ci, rest) = read_tlv(der)?;
    if !rest.is_empty() {
        return Err(bad("trailing bytes after the signature"));
    }
    let ci = children(expect(ci, 0x30)?.value)?;
    if ci.len() < 2 || expect(ci[0], 0x06)?.value != OID_SIGNED_DATA {
        return Err(bad("the signature is not CMS SignedData"));
    }
    let inner = children(expect(ci[1], 0xA0)?.value)?;
    let sd = children(expect(*inner.first().ok_or_else(|| bad("empty SignedData"))?, 0x30)?.value)?;
    // version, digestAlgorithms, encapContentInfo, [0] certs?, [1] crls?, signerInfos
    if sd.len() < 4 {
        return Err(bad("incomplete SignedData"));
    }
    let encap = children(expect(sd[2], 0x30)?.value)?;
    if encap.first().map(|t| t.value) != Some(OID_DATA) || encap.len() > 1 {
        return Err(bad("the signature must be detached over data"));
    }
    let mut certs = Vec::new();
    for t in &sd[3..sd.len() - 1] {
        if t.tag == 0xA0 {
            for c in children(t.value)? {
                if c.tag == 0x30 {
                    certs.push(c.raw);
                }
            }
        }
    }
    let infos = children(expect(sd[sd.len() - 1], 0x31)?.value)?;
    if infos.len() != 1 {
        return Err(bad("exactly one signer is supported"));
    }
    let si = children(expect(infos[0], 0x30)?.value)?;
    // version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature, [1]?
    if si.len() < 6 {
        return Err(bad("the signer has no signed attributes"));
    }
    let (issuer_raw, serial) = match si[1].tag {
        0x30 => {
            let ias = children(si[1].value)?;
            (
                ias.first().map(|t| t.raw),
                ias.get(1).filter(|t| t.tag == 0x02).map(|t| t.value),
            )
        }
        _ => (None, None),
    };
    Ok((
        certs,
        Signer {
            issuer_raw,
            serial,
            digest_alg: algorithm_oid(&si[2])?,
            signed_attrs: expect(si[3], 0xA0)?.value,
            signature_alg: algorithm_oid(&si[4])?,
            signature: expect(si[5], 0x04)?.value,
        },
    ))
}

/// `(contentType, messageDigest, signingTime)` of the signed attributes.
type SignedAttributes<'a> = (Option<&'a [u8]>, Option<&'a [u8]>, Option<DateTime<Utc>>);

fn signed_attributes(attrs: &[u8]) -> Result<SignedAttributes<'_>, BundleError> {
    let (mut ct, mut md, mut at) = (None, None, None);
    for attr in children(attrs)? {
        let parts = children(expect(attr, 0x30)?.value)?;
        let (Some(oid), Some(values)) = (parts.first(), parts.get(1)) else {
            continue;
        };
        let first = children(expect(*values, 0x31)?.value)?.into_iter().next();
        match (expect(*oid, 0x06)?.value, first) {
            (OID_CONTENT_TYPE, Some(v)) if v.tag == 0x06 => ct = Some(v.value),
            (OID_MESSAGE_DIGEST, Some(v)) if v.tag == 0x04 => md = Some(v.value),
            (OID_SIGNING_TIME, Some(v)) => at = parse_der_time(&v),
            _ => {}
        }
    }
    Ok((ct, md, at))
}

fn common_name(name: &x509_cert::name::Name) -> String {
    use x509_cert::der::Decode;
    const CN: x509_cert::der::asn1::ObjectIdentifier =
        x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid != CN {
                continue;
            }
            let raw = x509_cert::der::Encode::to_der(&atv.value).unwrap_or_default();
            if let Ok(s) = x509_cert::der::asn1::Utf8StringRef::from_der(&raw) {
                return s.to_string();
            }
            if let Ok(s) = x509_cert::der::asn1::PrintableStringRef::from_der(&raw) {
                return s.to_string();
            }
        }
    }
    name.to_string()
}

/// Verify the signature of a split bundle (pure).
pub fn verify_signature(split: &SplitBundle<'_>) -> SignatureInfo {
    if split.malformed {
        return SignatureInfo::invalid("the signature block is malformed");
    }
    let Some(der) = split.signature else {
        return SignatureInfo::unsigned();
    };
    match verify_der(der, &signed_content_candidates(split)) {
        Ok(info) => info,
        Err(e) => SignatureInfo::invalid(e.0),
    }
}

fn verify_der(der: &[u8], contents: &[Cow<'_, [u8]>]) -> Result<SignatureInfo, BundleError> {
    let digests: Vec<Option<[u8; 32]>> = contents
        .iter()
        .map(|c| Some(Sha256::digest(&c[..]).into()))
        .collect();
    verify_der_digests(der, &digests)
}

fn verify_der_digests(
    der: &[u8],
    contents: &[Option<[u8; 32]>],
) -> Result<SignatureInfo, BundleError> {
    use x509_cert::der::{Decode, Encode};
    let (certs, signer) = parse_signed_data(der)?;
    if signer.digest_alg != OID_SHA256 {
        return Err(bad("unsupported digest algorithm (SHA-256 is required)"));
    }
    if !matches!(signer.signature_alg, OID_RSA | OID_SHA256_RSA) {
        return Err(bad("unsupported signature algorithm (RSA is required)"));
    }
    let (content_type, digest, signed_at) = signed_attributes(signer.signed_attrs)?;
    if content_type != Some(OID_DATA) {
        return Err(bad("the signed content type is not data"));
    }
    let digest = digest.ok_or_else(|| bad("the signature has no message digest"))?;
    if !contents.iter().flatten().any(|c| c.as_slice() == digest) {
        return Err(bad("the bundle was changed after it was signed"));
    }
    let parsed: Vec<(x509_cert::Certificate, &[u8])> = certs
        .iter()
        .filter_map(|raw| {
            x509_cert::Certificate::from_der(raw)
                .ok()
                .map(|c| (c, *raw))
        })
        .collect();
    let (cert, cert_raw) = parsed
        .iter()
        .find(|(c, _)| {
            let issuer = c.tbs_certificate.issuer.to_der().unwrap_or_default();
            signer.issuer_raw == Some(issuer.as_slice())
                && signer.serial == Some(c.tbs_certificate.serial_number.as_bytes())
        })
        .or_else(|| parsed.first())
        .ok_or_else(|| bad("the signature carries no signing certificate"))?;
    // The signature covers the DER of the attributes as a SET (RFC 5652
    // 5.4): the received encoding with the [0] tag replaced.
    verify_rsa(cert, &as_der_set(signer.signed_attrs), signer.signature)?;
    let validity = &cert.tbs_certificate.validity;
    let at = signed_at.unwrap_or_else(Utc::now);
    let from = validity.not_before.to_unix_duration().as_secs() as i64;
    let to = validity.not_after.to_unix_duration().as_secs() as i64;
    if at.timestamp() < from || at.timestamp() > to {
        return Err(bad(
            "the signing certificate was not valid when the bundle was signed",
        ));
    }
    let subject = &cert.tbs_certificate.subject;
    let issuer = &cert.tbs_certificate.issuer;
    Ok(SignatureInfo {
        state: SignatureState::Valid,
        signer: Some(common_name(subject)),
        issuer: Some(common_name(issuer)),
        fingerprint: Some(hex::encode(Sha256::digest(cert_raw))),
        self_signed: Some(subject.to_der().ok() == issuer.to_der().ok()),
        signed_at,
        reason: None,
    })
}

/// `contents` re-tagged as a DER `SET` (tag `0x31`, definite length).
fn as_der_set(contents: &[u8]) -> Vec<u8> {
    let mut out = vec![0x31u8];
    let n = contents.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = (n as u32).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

fn verify_rsa(
    cert: &x509_cert::Certificate,
    message: &[u8],
    signature: &[u8],
) -> Result<(), BundleError> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use x509_cert::der::Encode;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| bad("unreadable signing key"))?;
    let key = rsa::RsaPublicKey::from_public_key_der(&spki)
        .map_err(|_| bad("unsupported signing key (RSA is required)"))?;
    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| bad("malformed signature value"))?;
    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
        .verify(message, &sig)
        .map_err(|_| bad("the signature does not verify"))
}

// ---------------------------------------------------------------------------
// One bundle
// ---------------------------------------------------------------------------

/// Everything AK records about an uploaded bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleFacts {
    pub file_sha256: String,
    pub size: u64,
    pub signature: SignatureInfo,
    pub manifest: serde_json::Value,
}

/// Inspect a bundle: hash it, verify its signature, read its manifest. The
/// manifest of a bundle whose signature block is present is read from the
/// archive in front of the block (signers before upstream #194), or from the
/// whole file: the current signer grows the ZIP comment length over the
/// block, so only the whole file is a well-formed archive.
pub fn inspect(bytes: &[u8]) -> Result<BundleFacts, BundleError> {
    let split = split_signature(bytes);
    let manifest = read_manifest(split.archive).or_else(|e| {
        if split.block_len == 0 {
            return Err(e);
        }
        read_manifest(bytes)
    })?;
    Ok(BundleFacts {
        file_sha256: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
        signature: verify_signature(&split),
        manifest: manifest_for_metadata(&manifest),
    })
}

/// How much of a file's end [`inspect_file`] reads to find the signature
/// block and the ZIP end record (a signature block is a few KiB).
const TAIL_BYTES: u64 = 1024 * 1024;

/// A `Read + Seek` view of the first `len` bytes of a file.
struct Window<R> {
    inner: R,
    len: u64,
    pos: u64,
}

impl<R: std::io::Read + std::io::Seek> std::io::Read for Window<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.len.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(left) as usize;
        if n == 0 {
            return Ok(0);
        }
        let got = self.inner.read(&mut buf[..n])?;
        self.pos += got as u64;
        Ok(got)
    }
}

impl<R: std::io::Read + std::io::Seek> std::io::Seek for Window<R> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let target = match to {
            std::io::SeekFrom::Start(n) => n as i64,
            std::io::SeekFrom::End(d) => self.len as i64 + d,
            std::io::SeekFrom::Current(d) => self.pos as i64 + d,
        };
        if target < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = (target as u64).min(self.len);
        self.inner.seek(std::io::SeekFrom::Start(self.pos))?;
        Ok(self.pos)
    }
}

/// [`inspect`] for a staged file, without reading it into memory: the
/// signature block and ZIP end record are found in the file's last
/// [`TAIL_BYTES`], the manifest is read through a window over the archive,
/// and the digests are streamed. `file_sha256` is the caller's (computed
/// while staging).
pub fn inspect_file(path: &std::path::Path, file_sha256: &str) -> Result<BundleFacts, BundleError> {
    use std::io::{Seek, SeekFrom};
    let io = |e: std::io::Error| bad(format!("the bundle could not be read: {e}"));
    let mut file = std::fs::File::open(path).map_err(io)?;
    let size = file.metadata().map_err(io)?.len();
    let tail_start = size.saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(tail_start)).map_err(io)?;
    let mut tail = Vec::new();
    (&mut file)
        .take(TAIL_BYTES)
        .read_to_end(&mut tail)
        .map_err(io)?;
    let split = split_signature(&tail);
    let archive_len = tail_start + split.archive.len() as u64;
    // As in [`inspect`]: the archive in front of the block, else the whole
    // file (the current signer's comment length covers the block).
    let mut read_window = |len: u64| -> Result<serde_json::Value, BundleError> {
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        read_manifest_from(Window {
            inner: std::io::BufReader::new(&mut file),
            len,
            pos: 0,
        })
    };
    let manifest = match read_window(archive_len) {
        Ok(m) => m,
        Err(_) if split.block_len > 0 => read_window(size)?,
        Err(e) => return Err(e),
    };
    let signature = if split.malformed {
        SignatureInfo::invalid("the signature block is malformed")
    } else if let Some(der) = split.signature {
        // The EOCD sits in the tail; stream both candidate digests.
        let fix = rfind(split.archive, EOCD_MAGIC)
            .filter(|&i| i + EOCD_MIN <= split.archive.len())
            .and_then(|i| {
                let at = i + 20;
                let cur = u16::from_le_bytes([split.archive[at], split.archive[at + 1]]) as usize;
                cur.checked_sub(split.block_len)
                    .map(|orig| (tail_start + at as u64, (orig as u16).to_le_bytes()))
            });
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        let (restored, as_is) = stream_digests(&mut file, archive_len, fix).map_err(io)?;
        match verify_der_digests(der, &[restored, Some(as_is)]) {
            Ok(info) => info,
            Err(e) => SignatureInfo::invalid(e.0),
        }
    } else {
        SignatureInfo::unsigned()
    };
    Ok(BundleFacts {
        file_sha256: file_sha256.to_string(),
        size,
        signature,
        manifest: manifest_for_metadata(&manifest),
    })
}

/// SHA-256 of the first `len` bytes as they are, and with the two bytes at
/// `fix.0` replaced by `fix.1` (when given).
fn stream_digests(
    r: &mut impl std::io::Read,
    len: u64,
    fix: Option<(u64, [u8; 2])>,
) -> std::io::Result<(Option<[u8; 32]>, [u8; 32])> {
    let mut as_is = Sha256::new();
    let mut restored = fix.map(|_| Sha256::new());
    let mut buf = vec![0u8; 64 * 1024];
    let mut pos = 0u64;
    let mut r = r.take(len);
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        as_is.update(&*chunk);
        if let (Some(h), Some((at, bytes))) = (restored.as_mut(), fix) {
            for (k, b) in bytes.iter().enumerate() {
                let p = at + k as u64;
                if p >= pos && p < pos + n as u64 {
                    chunk[(p - pos) as usize] = *b;
                }
            }
            h.update(&*chunk);
        }
        pos += n as u64;
    }
    Ok((
        restored.map(|h| h.finalize().into()),
        as_is.finalize().into(),
    ))
}

/// Whether `file` is an acceptable bundle file name: `<name>.mcpb`, letters,
/// digits, `.`, `_`, `-`, at most 200 characters, not starting with `.`.
pub fn valid_file_name(file: &str) -> bool {
    file.len() <= 200
        && file.len() > ".mcpb".len()
        && file.ends_with(".mcpb")
        && !file.starts_with('.')
        && file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    const UNSIGNED: &[u8] = include_bytes!("../../tests/fixtures/mcpb/echo-unsigned.mcpb");
    const SIGNED: &[u8] = include_bytes!("../../tests/fixtures/mcpb/echo-signed.mcpb");
    const LEGACY: &[u8] = include_bytes!("../../tests/fixtures/mcpb/echo-signed-legacy.mcpb");
    const TAMPERED: &[u8] = include_bytes!("../../tests/fixtures/mcpb/echo-tampered.mcpb");

    #[test]
    fn unsigned_bundle_is_read_and_labelled_unsigned() {
        let facts = inspect(UNSIGNED).unwrap();
        assert_eq!(facts.signature.state, SignatureState::Unsigned);
        assert_eq!(facts.manifest["name"], "echo-mcpb");
        assert_eq!(facts.manifest["tools"][0]["name"], "echo");
        assert_eq!(facts.size, UNSIGNED.len() as u64);
        assert_eq!(facts.file_sha256, hex::encode(Sha256::digest(UNSIGNED)));
    }

    #[test]
    fn signed_bundles_verify_in_both_layouts() {
        for (label, bytes) in [("current", SIGNED), ("legacy", LEGACY)] {
            let facts = inspect(bytes).unwrap();
            let sig = &facts.signature;
            assert_eq!(
                sig.state,
                SignatureState::Valid,
                "{label}: {:?}",
                sig.reason
            );
            assert_eq!(sig.signer.as_deref(), Some("Acme Test Signer"));
            assert_eq!(sig.issuer.as_deref(), Some("Acme Test Signer"));
            assert_eq!(sig.self_signed, Some(true));
            assert_eq!(sig.fingerprint.as_ref().map(String::len), Some(64));
            assert!(sig.signed_at.is_some());
            assert_eq!(facts.manifest["version"], "1.0.0");
        }
        let json = serde_json::to_value(inspect(SIGNED).unwrap().signature).unwrap();
        assert_eq!(json["state"], "valid");
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn tampered_or_broken_signatures_are_invalid() {
        let sig = inspect(TAMPERED).unwrap().signature;
        assert_eq!(sig.state, SignatureState::Invalid);
        assert!(sig.reason.unwrap().contains("changed after it was signed"));

        // A block whose length does not reach its footer.
        let mut broken = SIGNED.to_vec();
        let h = rfind(&broken, SIG_HEADER).unwrap() + SIG_HEADER.len();
        broken[h] = broken[h].wrapping_add(1);
        let split = split_signature(&broken);
        assert!(split.malformed);
        assert_eq!(verify_signature(&split).state, SignatureState::Invalid);

        // A signature value flipped: framing intact, RSA check fails.
        let mut flipped = SIGNED.to_vec();
        let footer = rfind(&flipped, SIG_FOOTER).unwrap();
        flipped[footer - 3] ^= 0xFF;
        let sig = verify_signature(&split_signature(&flipped));
        assert_eq!(sig.state, SignatureState::Invalid);

        // Garbage DER inside a well-framed block.
        let mut garbage = UNSIGNED.to_vec();
        garbage.extend_from_slice(SIG_HEADER);
        garbage.extend_from_slice(&3u32.to_le_bytes());
        garbage.extend_from_slice(&[0x30, 0x01, 0x00]);
        garbage.extend_from_slice(SIG_FOOTER);
        assert_eq!(
            verify_signature(&split_signature(&garbage)).state,
            SignatureState::Invalid
        );
    }

    #[test]
    fn manifests_are_required_and_bounded() {
        assert!(read_manifest(b"not a zip").is_err());
        let zip_of = |name: &str, body: &[u8]| {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut z = zip::ZipWriter::new(&mut buf);
                z.start_file(name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                std::io::Write::write_all(&mut z, body).unwrap();
                z.finish().unwrap();
            }
            buf.into_inner()
        };
        assert!(read_manifest(&zip_of("other.json", b"{}"))
            .unwrap_err()
            .0
            .contains("no manifest.json"));
        assert!(read_manifest(&zip_of("manifest.json", b"[1]")).is_err());
        assert!(read_manifest(&zip_of("manifest.json", br#"{"name":"x"}"#)).is_err());
        assert!(read_manifest(&zip_of("manifest.json", b"{nope")).is_err());
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        assert!(read_manifest(&zip_of("manifest.json", deep.as_bytes())).is_err());
        assert!(read_manifest(&zip_of("manifest.json", br#"{"name":"x","version":"1"}"#)).is_ok());

        let big = serde_json::json!({
            "name": "x", "version": "1", "tools": [{"name": "t"}],
            "long_description": "a".repeat(MANIFEST_KEEP_MAX_BYTES + 1),
        });
        let kept = manifest_for_metadata(&big);
        assert_eq!(kept["truncated"], true);
        assert_eq!(kept["tools"][0]["name"], "t");
        assert!(kept.get("long_description").is_none());
    }

    #[test]
    fn der_helpers() {
        assert!(read_tlv(&[]).is_err());
        assert!(read_tlv(&[0x1F, 0x00]).is_err());
        assert!(read_tlv(&[0x30, 0x85, 0, 0, 0, 0, 1]).is_err());
        assert!(read_tlv(&[0x30, 0x05, 0x00]).is_err());
        let (t, rest) = read_tlv(&[0x04, 0x81, 0x01, 0xAA, 0x01]).unwrap();
        assert_eq!((t.tag, t.value, rest), (0x04, &[0xAA][..], &[0x01][..]));
        let utc = Tlv {
            tag: 0x17,
            value: b"261104023227Z",
            raw: &[],
        };
        assert_eq!(
            parse_der_time(&utc).unwrap().to_rfc3339(),
            "2026-11-04T02:32:27+00:00"
        );
        let gen = Tlv {
            tag: 0x18,
            value: b"19991231235959Z",
            raw: &[],
        };
        assert_eq!(parse_der_time(&gen).unwrap().timestamp(), 946684799);
        let bad_time = Tlv {
            tag: 0x17,
            value: b"2611",
            raw: &[],
        };
        assert!(parse_der_time(&bad_time).is_none());
        assert!(parse_signed_data(&[0x30, 0x00, 0x00]).is_err());
        assert_eq!(as_der_set(&[1, 2]), vec![0x31, 2, 1, 2]);
        let long = as_der_set(&[0u8; 300]);
        assert_eq!(&long[..4], &[0x31, 0x82, 0x01, 0x2C]);
    }

    #[test]
    fn inspect_file_matches_in_memory_inspection() {
        let dir = tempfile::tempdir().unwrap();
        for (label, bytes) in [
            ("unsigned", UNSIGNED),
            ("signed", SIGNED),
            ("legacy", LEGACY),
            ("tampered", TAMPERED),
        ] {
            let path = dir.path().join(format!("{label}.mcpb"));
            std::fs::write(&path, bytes).unwrap();
            let sha = hex::encode(Sha256::digest(bytes));
            let from_file = inspect_file(&path, &sha).unwrap();
            assert_eq!(from_file, inspect(bytes).unwrap(), "{label}");
        }
        let path = dir.path().join("junk.mcpb");
        std::fs::write(&path, b"junk").unwrap();
        assert!(inspect_file(&path, "x").is_err());
        assert!(inspect_file(&dir.path().join("missing"), "x").is_err());
    }

    #[test]
    fn file_names() {
        for ok in ["echo.mcpb", "echo-1.0.0_linux.mcpb"] {
            assert!(valid_file_name(ok), "{ok}");
        }
        for bad in [
            ".mcpb",
            ".x.mcpb",
            "echo.zip",
            "server.json",
            "a/b.mcpb",
            "a b.mcpb",
            "..mcpb",
        ] {
            assert!(!valid_file_name(bad), "{bad}");
        }
        assert!(!valid_file_name(&format!("{}.mcpb", "a".repeat(200))));
    }
}
