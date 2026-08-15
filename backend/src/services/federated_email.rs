//! Synthetic address derivation shared by the federated login paths.
//!
//! `users.email` is `VARCHAR(255) UNIQUE NOT NULL`
//! (`backend/migrations/001_users.sql:8`), but every federated protocol treats
//! the user's address as optional: OIDC releases the `email` claim only when
//! the scope is granted and the IdP chooses to disclose it, and a SAML IdP is
//! free to assert no email attribute at all. Something has to be stored
//! regardless, and whatever is stored has to satisfy the unique index.
//!
//! Each login path grew its own answer to that, which is how the same defect
//! shipped twice: OIDC defaulted every claim-less user to a shared `""`
//! (#3119, fixed in #3161) and SAML defaulted to `{username}@unknown`, built
//! from the *pre-uniquification* username, so two NameIDs whose username
//! attribute matched collided on `users_email_key` (#3167), and LDAP defaulted
//! to `{username}@unknown` in two more places (#3416). This module is the
//! single implementation all of them now call, so a new variant cannot drift.
//!
//! A synthetic address must satisfy four properties. Getting any one wrong
//! reintroduces a bug rather than fixing one:
//!
//! 1. **Unique per identity.** A shared sentinel lets only the first
//!    address-less user provision; every later one dies on `users_email_key`.
//! 2. **Stable across logins.** Re-login writes `email` back to the row. A
//!    value that changes per login (a random nonce, a timestamp) rewrites the
//!    user every time, and on the provisioning path would mint a *new* account
//!    per login — orphaning that user's uploads, quota and permissions. This
//!    is strictly worse than the collision it would "fix".
//! 3. **Keyed on the IdP's subject**, never on a username or display name.
//!    Those are self-settable at many IdPs, so keying on them lets one user
//!    choose a value that collides with another's — turning an availability
//!    defect into a targeted one. The subject is also the value each service
//!    already stores as `users.external_id`, which makes the synthetic address
//!    exactly as unique and exactly as stable as the account row itself.
//! 4. **Non-routable.** `.invalid` is reserved by RFC 2606 and can never
//!    resolve, so a synthetic address can neither be confused with a real
//!    mailbox nor collide against one.

use sha2::{Digest, Sha256};

/// Domain for the synthetic address stored when an OIDC provider releases no
/// usable `email` claim.
pub(crate) const OIDC_NO_EMAIL_DOMAIN: &str = "no-email.oidc.invalid";

/// Domain for the synthetic address stored when a SAML IdP asserts no usable
/// email attribute.
pub(crate) const SAML_NO_EMAIL_DOMAIN: &str = "no-email.saml.invalid";

/// Domain for the synthetic address stored when an LDAP directory entry
/// carries no usable mail attribute (#3416).
///
/// The stable subject for LDAP is the entry's **DN**, not the username: the DN
/// is what `LdapService::get_or_create_user` stores in `users.external_id` and
/// looks the account up by, whereas the username is run through
/// `generate_unique_username` afterwards — so two directory entries whose
/// username attribute matches are stored as `alice` and `alice_1` while both
/// would derive the same username-keyed address and collide on
/// `users_email_key`.
pub(crate) const LDAP_NO_EMAIL_DOMAIN: &str = "no-email.ldap.invalid";

/// Longest sanitized subject prefix kept in the synthetic local-part. Bounds
/// the result well inside `users.email VARCHAR(255)` for arbitrarily long
/// subjects.
const MAX_SYNTHETIC_LOCAL_PREFIX: usize = 48;

/// Resolve the address to store in `users.email` for a federated user.
///
/// Returns a provider-supplied address verbatim. Falls back to a per-subject
/// synthetic address when the provider supplied nothing — or supplied a blank
/// value, which some IdPs send for machine identities and which collides
/// exactly the same way a missing one does.
///
/// `subject` must be the IdP's stable per-user identifier: the OIDC `sub`, the
/// SAML `NameID`, or the LDAP entry's DN. See the module docs for why nothing
/// else will do.
pub(crate) fn resolve_federated_email(claim: Option<&str>, subject: &str, domain: &str) -> String {
    match claim.map(str::trim).filter(|s| !s.is_empty()) {
        Some(email) => email.to_string(),
        None => synthetic_email_for_subject(subject, domain),
    }
}

/// Build a stable, unique, non-routable address for a subject with no address.
///
/// The subject is opaque: it may contain characters that are invalid in an
/// address local-part and may be longer than the column allows. Keep a
/// sanitized, human-recognizable prefix for operators, then append a digest of
/// the *raw* subject so two distinct subjects can never sanitize down to the
/// same address.
pub(crate) fn synthetic_email_for_subject(subject: &str, domain: &str) -> String {
    let fingerprint = hex::encode(&Sha256::digest(subject.as_bytes())[..8]);

    let sanitized: String = subject
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .take(MAX_SYNTHETIC_LOCAL_PREFIX)
        .collect();
    let prefix = sanitized.trim_matches(|c| matches!(c, '.' | '-' | '_'));
    let prefix = if prefix.is_empty() { "user" } else { prefix };

    format!("{}.{}@{}", prefix, fingerprint, domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_supplied_address_is_returned_verbatim() {
        assert_eq!(
            resolve_federated_email(Some("carol@example.com"), "sub", OIDC_NO_EMAIL_DOMAIN),
            "carol@example.com"
        );
    }

    #[test]
    fn blank_claim_is_treated_as_missing() {
        assert_eq!(
            resolve_federated_email(Some("   "), "sub", SAML_NO_EMAIL_DOMAIN),
            resolve_federated_email(None, "sub", SAML_NO_EMAIL_DOMAIN)
        );
    }

    #[test]
    fn distinct_subjects_get_distinct_addresses() {
        assert_ne!(
            synthetic_email_for_subject("subject-a", SAML_NO_EMAIL_DOMAIN),
            synthetic_email_for_subject("subject-b", SAML_NO_EMAIL_DOMAIN)
        );
    }

    #[test]
    fn one_subject_gets_one_stable_address() {
        assert_eq!(
            synthetic_email_for_subject("subject-a", SAML_NO_EMAIL_DOMAIN),
            synthetic_email_for_subject("subject-a", SAML_NO_EMAIL_DOMAIN)
        );
    }

    #[test]
    fn subjects_that_sanitize_alike_still_differ() {
        // Sanitization is lossy — both of these reduce to `a-b`. The digest of
        // the raw subject is what keeps them apart.
        assert_ne!(
            synthetic_email_for_subject("a b", SAML_NO_EMAIL_DOMAIN),
            synthetic_email_for_subject("a/b", SAML_NO_EMAIL_DOMAIN)
        );
    }

    #[test]
    fn hostile_subject_still_fits_the_column() {
        let hostile = format!("{}@evil.example/ ünïcode", "x".repeat(400));
        let email = synthetic_email_for_subject(&hostile, SAML_NO_EMAIL_DOMAIN);

        assert!(
            email.len() <= 255,
            "must fit users.email VARCHAR(255), got {} chars: {}",
            email.len(),
            email
        );
        assert_eq!(email.matches('@').count(), 1, "exactly one @: {}", email);
        assert!(email.ends_with(SAML_NO_EMAIL_DOMAIN));
    }

    #[test]
    fn every_provider_uses_a_distinct_reserved_domain() {
        let domains = [
            OIDC_NO_EMAIL_DOMAIN,
            SAML_NO_EMAIL_DOMAIN,
            LDAP_NO_EMAIL_DOMAIN,
        ];
        for domain in domains {
            assert!(
                domain.ends_with(".invalid"),
                "{} must sit under the RFC 2606 reserved TLD so it can never \
                 resolve to, or collide with, a real mailbox",
                domain
            );
        }
        let mut unique = domains.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            domains.len(),
            "each provider needs its own domain, so an operator reading a \
             synthetic address can tell which directory it came from"
        );
    }

    /// The same subject under two different providers must not collide: the
    /// domain is the only thing separating them, so it has to be load-bearing.
    #[test]
    fn one_subject_under_two_providers_yields_two_addresses() {
        assert_ne!(
            synthetic_email_for_subject("shared-subject", LDAP_NO_EMAIL_DOMAIN),
            synthetic_email_for_subject("shared-subject", OIDC_NO_EMAIL_DOMAIN)
        );
    }

    /// LDAP subjects are DNs, which are long and full of characters that are
    /// invalid in an address local-part. Two DNs differing only past the
    /// sanitized prefix must still get distinct, column-sized addresses.
    #[test]
    fn ldap_dns_are_distinct_and_fit_the_column() {
        let a = synthetic_email_for_subject(
            "uid=alice,ou=engineering,ou=people,dc=corp,dc=example,dc=com",
            LDAP_NO_EMAIL_DOMAIN,
        );
        let b = synthetic_email_for_subject(
            "uid=alice,ou=support,ou=people,dc=corp,dc=example,dc=com",
            LDAP_NO_EMAIL_DOMAIN,
        );
        assert_ne!(a, b, "two DNs for two identities must not share an address");
        for email in [&a, &b] {
            assert!(email.len() <= 255, "must fit users.email: {}", email);
            assert!(email.ends_with(LDAP_NO_EMAIL_DOMAIN));
        }
    }
}
