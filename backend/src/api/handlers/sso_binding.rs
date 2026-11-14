//! Browser binding for the SSO login flows (#5486).
//!
//! An OIDC `state`, a SAML AuthnRequest id and the exchange code a callback
//! hands the frontend were bearer values: whoever held one could complete the
//! login in any browser. An attacker could start a login, authenticate at the
//! IdP as themselves, and send a victim's browser to the callback (or to the
//! frontend `/callback?code=`), signing the victim in to the attacker's account
//! (login CSRF).
//!
//! The login start now sets a short-lived cookie in the browser that started
//! it, and every later step requires it:
//!
//! * the cookie value is `HMAC(JWT_SECRET, state)`, so any replica can check it
//!   against the `state` (or SAML request id) without storing anything, and
//!   nobody without the server secret can mint one;
//! * one cookie per login (`ak_sso_bind_<prefix>`), so two logins running in
//!   one browser (two tabs, the silent `prompt=none` probe) do not overwrite
//!   each other;
//! * `HttpOnly`, `SameSite=Lax` (sent on the top-level GET navigations the
//!   IdP redirects back with, never on a cross-site POST or subresource),
//!   `Path=/api/v1/auth/sso`, `Max-Age` = the SSO session lifetime;
//! * the exchange code carries a MAC over the binding, so `/exchange` (and the
//!   SAML completion step) accept it only from the browser holding the cookie.
//!
//! A command-line client (`ak auth login --sso`) asks for its own mode with
//! `?client=cli` on the login URL. It reads the binding cookie off the login
//! response itself, prints the IdP URL for the user to open in a browser, and
//! sends the cookie on `/exchange`. Such a login's `state` (OIDC) or request id
//! (SAML) carries a fixed prefix, so its callback knows not to look for a
//! cookie in the browser. In exchange the callback never sets a session in the
//! browser: it only shows the exchange code, which is bound to the client's
//! binding and so cannot be redeemed by the browser (or anyone else). Starting
//! a login in this mode therefore never helps a login CSRF: the browser it is
//! completed in ends up signed in to nothing.
//!
//! `state` and the SAML request id stay single-use (`sso_sessions` rows are
//! deleted on use), and the exchange code is single-use and expires after 60
//! seconds, as before.

use axum::http::{header::COOKIE, header::SET_COOKIE, HeaderMap};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{AppError, Result};

/// Name prefix of the per-login binding cookies.
pub const BINDING_COOKIE_PREFIX: &str = "ak_sso_bind_";

/// The cookie is only ever needed by the public SSO routes.
pub const BINDING_COOKIE_PATH: &str = "/api/v1/auth/sso";

/// Lifetime of the cookie: the `sso_sessions` expiry (migration 037).
pub const BINDING_COOKIE_MAX_AGE_SECS: u64 = 600;

/// Length of the random half of an exchange code, in hex digits. The other
/// half is the binding tag; together they fill `sso_exchange_codes.code`
/// (`VARCHAR(64)`).
const EXCHANGE_NONCE_HEX: usize = 32;
const EXCHANGE_TAG_BYTES: usize = 16;

/// Characters of the binding value used in the cookie name.
const NAME_SUFFIX_LEN: usize = 16;

/// Prefix of the OIDC `state` of a login started with `?client=cli`.
pub const CLI_OIDC_STATE_PREFIX: &str = "cli-";

/// Prefix of the SAML AuthnRequest id of a login started with `?client=cli`
/// (still an `xs:ID`, like the browser flow's `_id…`).
pub const CLI_SAML_REQUEST_PREFIX: &str = "_cli-";

/// Who started a login: a browser, or a command-line client (`?client=cli`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginClient {
    Browser,
    Cli,
}

impl LoginClient {
    /// Parse the login URL's optional `client` parameter. Only `cli` is
    /// accepted besides the default.
    #[allow(clippy::result_large_err)]
    pub fn from_query(client: Option<&str>) -> Result<Self> {
        match client {
            None | Some("") | Some("browser") => Ok(Self::Browser),
            Some("cli") => Ok(Self::Cli),
            Some(other) => Err(AppError::Validation(format!(
                "Unsupported client '{other}': expected 'cli' or no client parameter"
            ))),
        }
    }

    /// Who started the login whose `state` (OIDC) or AuthnRequest id (SAML)
    /// is `state`. The server mints every state, so the prefix is only ever
    /// present when the login was started in command-line mode; the callback
    /// still requires the state's `sso_sessions` row.
    pub fn of_state(state: &str) -> Self {
        if state.starts_with(CLI_OIDC_STATE_PREFIX) || state.starts_with(CLI_SAML_REQUEST_PREFIX) {
            Self::Cli
        } else {
            Self::Browser
        }
    }
}

fn mac(secret: &str, label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any size");
    mac.update(label);
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The binding value for a login whose `state` (OIDC) or AuthnRequest id
/// (SAML) is `state`: 64 hex digits.
pub fn binding_value(secret: &str, state: &str) -> String {
    hex::encode(mac(
        secret,
        b"ak-sso-browser-binding/v1",
        &[state.as_bytes()],
    ))
}

/// `(name, value)` of the binding cookie for `state`.
pub fn binding_cookie(secret: &str, state: &str) -> (String, String) {
    let value = binding_value(secret, state);
    (
        format!("{BINDING_COOKIE_PREFIX}{}", &value[..NAME_SUFFIX_LEN]),
        value,
    )
}

/// Append the `Set-Cookie` that binds the login for `state` to this browser.
/// `secure` is the auth cookies' `Secure` decision for this request.
pub fn set_binding_cookie(headers: &mut HeaderMap, secret: &str, state: &str, secure: bool) {
    let (name, value) = binding_cookie(secret, state);
    append_cookie(headers, &name, &value, BINDING_COOKIE_MAX_AGE_SECS, secure);
}

/// Expire the binding cookie holding `value` (after the login completed).
pub fn clear_binding_cookie(headers: &mut HeaderMap, value: &str, secure: bool) {
    if value.len() < NAME_SUFFIX_LEN {
        return;
    }
    let name = format!("{BINDING_COOKIE_PREFIX}{}", &value[..NAME_SUFFIX_LEN]);
    append_cookie(headers, &name, "", 0, secure);
}

fn append_cookie(headers: &mut HeaderMap, name: &str, value: &str, max_age: u64, secure: bool) {
    let secure = if secure { " Secure;" } else { "" };
    let cookie = format!(
        "{name}={value}; HttpOnly;{secure} SameSite=Lax; Path={BINDING_COOKIE_PATH}; \
         Max-Age={max_age}"
    );
    // Only hex digits and fixed ASCII: always a valid header value.
    if let Ok(v) = cookie.parse() {
        headers.append(SET_COOKIE, v);
    }
}

/// Every binding cookie value the request carries.
fn presented_bindings(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|cookies| cookies.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .filter(|(name, _)| name.starts_with(BINDING_COOKIE_PREFIX))
        .map(|(_, value)| value)
        .collect()
}

fn not_this_browser() -> AppError {
    AppError::Authentication(
        "This sign-in was not started in this browser (SSO browser binding missing or \
         mismatched). Start the sign-in again."
            .to_string(),
    )
}

/// Require the binding cookie of the login for `state`. Returns the binding
/// value, which the callback carries into the exchange code it mints.
#[allow(clippy::result_large_err)]
pub fn require_state_binding(headers: &HeaderMap, secret: &str, state: &str) -> Result<String> {
    let expected = binding_value(secret, state);
    if presented_bindings(headers)
        .iter()
        .any(|v| ct_eq(v.as_bytes(), expected.as_bytes()))
    {
        Ok(expected)
    } else {
        Err(not_this_browser())
    }
}

/// The binding the callback for `state` mints its exchange code for.
///
/// A browser login requires the browser's binding cookie for `state`. A
/// command-line login (see [`LoginClient::of_state`]) holds its cookie in the
/// client, not in the browser the callback arrives in, so nothing is required
/// here; the callback then sets no session and the code it mints can only be
/// redeemed with the client's cookie.
#[allow(clippy::result_large_err)]
pub fn callback_binding(
    headers: &HeaderMap,
    secret: &str,
    state: &str,
) -> Result<(String, LoginClient)> {
    match LoginClient::of_state(state) {
        LoginClient::Cli => Ok((binding_value(secret, state), LoginClient::Cli)),
        LoginClient::Browser => {
            require_state_binding(headers, secret, state).map(|b| (b, LoginClient::Browser))
        }
    }
}

fn exchange_tag(secret: &str, nonce: &str, binding: &str) -> String {
    let full = mac(
        secret,
        b"ak-sso-exchange-code/v1",
        &[nonce.as_bytes(), binding.as_bytes()],
    );
    hex::encode(&full[..EXCHANGE_TAG_BYTES])
}

/// A fresh exchange code bound to `binding`: 32 random hex digits followed by
/// a 32-hex-digit MAC over them and the binding.
pub fn mint_exchange_code(secret: &str, binding: &str) -> String {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    debug_assert_eq!(nonce.len(), EXCHANGE_NONCE_HEX);
    let tag = exchange_tag(secret, &nonce, binding);
    format!("{nonce}{tag}")
}

/// Require that `code` was minted for a binding cookie this request carries.
/// Returns that binding value. Checked before the code is consumed, so a
/// request from another browser cannot burn it.
#[allow(clippy::result_large_err)]
pub fn require_exchange_binding(headers: &HeaderMap, secret: &str, code: &str) -> Result<String> {
    if code.len() != EXCHANGE_NONCE_HEX + 2 * EXCHANGE_TAG_BYTES || !code.is_ascii() {
        return Err(not_this_browser());
    }
    let (nonce, tag) = code.split_at(EXCHANGE_NONCE_HEX);
    presented_bindings(headers)
        .into_iter()
        .find(|binding| {
            ct_eq(
                exchange_tag(secret, nonce, binding).as_bytes(),
                tag.as_bytes(),
            )
        })
        .map(str::to_owned)
        .ok_or_else(not_this_browser)
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "binding-test-secret-0123456789abcdef";

    fn cookie_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let joined = pairs
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        headers.insert(COOKIE, joined.parse().unwrap());
        headers
    }

    #[test]
    fn binding_cookie_is_httponly_lax_scoped_and_short_lived_5486() {
        let mut headers = HeaderMap::new();
        set_binding_cookie(&mut headers, SECRET, "state-1", true);
        let cookie = headers[SET_COOKIE].to_str().unwrap();
        let (name, value) = binding_cookie(SECRET, "state-1");
        assert!(cookie.starts_with(&format!("{name}={value};")), "{cookie}");
        assert!(name.starts_with(BINDING_COOKIE_PREFIX));
        for attr in [
            "HttpOnly;",
            "Secure;",
            "SameSite=Lax;",
            "Path=/api/v1/auth/sso;",
            "Max-Age=600",
        ] {
            assert!(cookie.contains(attr), "{attr} missing: {cookie}");
        }

        let mut plain = HeaderMap::new();
        set_binding_cookie(&mut plain, SECRET, "state-1", false);
        assert!(!plain[SET_COOKIE].to_str().unwrap().contains("Secure"));

        let mut cleared = HeaderMap::new();
        clear_binding_cookie(&mut cleared, &value, false);
        let cleared = cleared[SET_COOKIE].to_str().unwrap();
        assert!(cleared.starts_with(&format!("{name}=;")), "{cleared}");
        assert!(cleared.contains("Max-Age=0"));
    }

    #[test]
    fn state_binding_requires_this_logins_cookie_5486() {
        let (name, value) = binding_cookie(SECRET, "state-1");
        let ok = cookie_headers(&[("other", "x"), (&name, &value)]);
        assert_eq!(
            require_state_binding(&ok, SECRET, "state-1").unwrap(),
            value
        );

        // No cookie, another login's cookie, a forged value, another secret.
        let (other_name, other_value) = binding_cookie(SECRET, "state-2");
        let (_, foreign) = binding_cookie("another-secret-0123456789abcdef", "state-1");
        for headers in [
            HeaderMap::new(),
            cookie_headers(&[(&other_name, &other_value)]),
            cookie_headers(&[(&name, "00")]),
            cookie_headers(&[(&name, &foreign)]),
        ] {
            assert!(matches!(
                require_state_binding(&headers, SECRET, "state-1"),
                Err(AppError::Authentication(_))
            ));
        }

        // Two logins in one browser: each finds its own cookie.
        let both = cookie_headers(&[(&other_name, &other_value), (&name, &value)]);
        assert!(require_state_binding(&both, SECRET, "state-1").is_ok());
        assert!(require_state_binding(&both, SECRET, "state-2").is_ok());
    }

    #[test]
    fn login_client_comes_from_the_query_and_the_state_prefix_5486() {
        assert_eq!(LoginClient::from_query(None).unwrap(), LoginClient::Browser);
        assert_eq!(
            LoginClient::from_query(Some("cli")).unwrap(),
            LoginClient::Cli
        );
        assert!(matches!(
            LoginClient::from_query(Some("mobile")),
            Err(AppError::Validation(_))
        ));
        assert_eq!(LoginClient::of_state("cli-1234"), LoginClient::Cli);
        assert_eq!(LoginClient::of_state("_cli-1234"), LoginClient::Cli);
        assert_eq!(
            LoginClient::of_state("2f6a0f3e-0000-4000-8000-000000000000"),
            LoginClient::Browser
        );
        assert_eq!(LoginClient::of_state("_id1234"), LoginClient::Browser);
    }

    #[test]
    fn callback_binding_requires_the_browser_cookie_except_for_cli_logins_5486() {
        // A browser login: refused without its cookie.
        assert!(matches!(
            callback_binding(&HeaderMap::new(), SECRET, "state-1"),
            Err(AppError::Authentication(_))
        ));
        let (name, value) = binding_cookie(SECRET, "state-1");
        assert_eq!(
            callback_binding(&cookie_headers(&[(&name, &value)]), SECRET, "state-1").unwrap(),
            (value, LoginClient::Browser)
        );

        // A command-line login: no browser cookie, and the code is bound to
        // the client's cookie, which the browser does not hold.
        let state = format!("{CLI_OIDC_STATE_PREFIX}abc");
        let (binding, client) = callback_binding(&HeaderMap::new(), SECRET, &state).unwrap();
        assert_eq!(client, LoginClient::Cli);
        assert_eq!(binding, binding_value(SECRET, &state));
        let code = mint_exchange_code(SECRET, &binding);
        assert!(require_exchange_binding(&HeaderMap::new(), SECRET, &code).is_err());
        let (cli_name, cli_value) = binding_cookie(SECRET, &state);
        assert!(require_exchange_binding(
            &cookie_headers(&[(&cli_name, &cli_value)]),
            SECRET,
            &code
        )
        .is_ok());
    }

    #[test]
    fn exchange_code_is_bound_to_the_binding_cookie_5486() {
        let (name, value) = binding_cookie(SECRET, "state-1");
        let code = mint_exchange_code(SECRET, &value);
        assert_eq!(code.len(), 64, "fits sso_exchange_codes.code VARCHAR(64)");
        assert!(code.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(code, mint_exchange_code(SECRET, &value), "codes are random");

        let ok = cookie_headers(&[(&name, &value)]);
        assert_eq!(require_exchange_binding(&ok, SECRET, &code).unwrap(), value);

        let (other_name, other_value) = binding_cookie(SECRET, "state-2");
        let mut tampered = code.clone();
        tampered.replace_range(..1, if code.starts_with('0') { "1" } else { "0" });
        for (headers, code) in [
            (HeaderMap::new(), code.as_str()),
            (
                cookie_headers(&[(&other_name, &other_value)]),
                code.as_str(),
            ),
            (ok.clone(), tampered.as_str()),
            // A pre-1.12 (unbound) code, and garbage.
            (ok.clone(), "0123456789abcdef0123456789abcdef"),
            (ok.clone(), "é"),
        ] {
            assert!(matches!(
                require_exchange_binding(&headers, SECRET, code),
                Err(AppError::Authentication(_))
            ));
        }
    }
}
