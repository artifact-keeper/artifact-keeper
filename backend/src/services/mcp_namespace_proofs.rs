//! Administrator-initiated MCP namespace proofs (#5253, Phase 3).
//!
//! An administrator opens a challenge for a reverse-DNS namespace
//! (`com.acme` <-> domain `acme.com`; `io.github.acme` <-> `acme.github.io`),
//! the domain's owner publishes the challenge token, and an administrator
//! asks AK to check it:
//!
//! - `dns`: a TXT record at `_ak-mcp-challenge.<domain>` whose value is
//!   `ak-mcp-verification=<token>`, looked up over DNS-over-HTTPS (JSON API,
//!   `MCP_NAMESPACE_PROOF_DOH_URL`, default Cloudflare's resolver);
//! - `http`: `https://<domain>/.well-known/ak-mcp-challenge` containing the
//!   line `ak-mcp-verification=<token>`.
//!
//! Every fetch is admin-initiated only (never on a read or publish path),
//! validated with `validate_outbound_url`, resolved through the
//! `SsrfGuardResolver` client, with redirects disabled, a 64 KiB body cap
//! and a 10 s timeout. A verified proof is evidence recorded and audited
//! (`MCP_NAMESPACE_PROOF_VERIFIED` / `_FAILED`); it grants nothing.

use std::time::Duration;

use rand::RngExt as _;

/// TXT record label prefix.
pub const DNS_LABEL: &str = "_ak-mcp-challenge";
/// HTTP well-known path.
pub const HTTP_PATH: &str = "/.well-known/ak-mcp-challenge";
/// What the record or file must carry.
pub const VALUE_PREFIX: &str = "ak-mcp-verification=";
pub const DEFAULT_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";
pub const MAX_BODY: usize = 64 * 1024;
pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const METHODS: &[&str] = &["dns", "http"];

/// The domain a reverse-DNS namespace names: labels reversed. Refuses
/// anything that is not 2..=16 DNS labels (`[a-z0-9-]`, no leading or
/// trailing `-`, at most 63 characters each); case is folded.
pub fn domain_of(namespace: &str) -> Result<String, String> {
    let ns = namespace.trim().to_ascii_lowercase();
    let labels: Vec<&str> = ns.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if !(2..=16).contains(&labels.len()) || !labels.iter().all(label_ok) {
        return Err(format!(
            "`{namespace}` is not a reverse-DNS namespace (for example com.acme)"
        ));
    }
    Ok(labels.into_iter().rev().collect::<Vec<_>>().join("."))
}

/// A fresh challenge token (32 random bytes, hex).
pub fn new_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// The value the owner publishes.
pub fn expected_value(token: &str) -> String {
    format!("{VALUE_PREFIX}{token}")
}

/// Where the owner publishes it, for the API response.
pub fn instructions(method: &str, domain: &str, token: &str) -> serde_json::Value {
    match method {
        "dns" => serde_json::json!({
            "type": "TXT",
            "name": format!("{DNS_LABEL}.{domain}"),
            "value": expected_value(token),
        }),
        _ => serde_json::json!({
            "url": format!("https://{domain}{HTTP_PATH}"),
            "content": expected_value(token),
        }),
    }
}

/// Whether a DNS-over-HTTPS JSON answer (`application/dns-json`) carries
/// `expected` in a TXT record (type 16). Quoted character-strings of one
/// record are joined, as RFC 7208 reads a long TXT value.
pub fn doh_answer_matches(answer: &serde_json::Value, expected: &str) -> bool {
    answer["Status"].as_i64() == Some(0)
        && answer["Answer"].as_array().is_some_and(|records| {
            records.iter().any(|r| {
                r["type"].as_i64() == Some(16)
                    && r["data"].as_str().is_some_and(|d| txt_value(d) == expected)
            })
        })
}

/// The value of one TXT record as a resolver renders it: its quoted
/// character-strings joined, or the bare text when it is unquoted.
pub fn txt_value(data: &str) -> String {
    if !data.contains('"') {
        return data.trim().to_string();
    }
    data.split('"').skip(1).step_by(2).collect()
}

/// Whether a well-known file carries `expected` on a line of its own.
pub fn http_body_matches(body: &[u8], expected: &str) -> bool {
    String::from_utf8_lossy(body)
        .lines()
        .any(|l| l.trim() == expected)
}

fn client() -> Result<reqwest::Client, String> {
    crate::services::http_client::base_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| format!("could not build the HTTP client: {e}"))
}

async fn fetch_capped(req: reqwest::RequestBuilder) -> Result<Vec<u8>, String> {
    let resp = req
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("answered HTTP {}", resp.status().as_u16()));
    }
    crate::services::http_client::read_body_capped(resp, MAX_BODY).await
}

/// Look `expected` up in TXT records of `_ak-mcp-challenge.<domain>` through
/// the DNS-over-HTTPS JSON endpoint `doh_url`.
pub async fn check_dns_via(doh_url: &str, domain: &str, token: &str) -> Result<(), String> {
    crate::api::validation::validate_outbound_url(doh_url, "DNS-over-HTTPS resolver")
        .map_err(|e| e.to_string())?;
    let name = format!("{DNS_LABEL}.{domain}");
    let body = fetch_capped(
        client()?
            .get(doh_url)
            .query(&[("name", name.as_str()), ("type", "TXT")])
            .header(reqwest::header::ACCEPT, "application/dns-json"),
    )
    .await?;
    let answer: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| "the resolver answer is not JSON".to_string())?;
    if doh_answer_matches(&answer, &expected_value(token)) {
        Ok(())
    } else {
        Err(format!(
            "no TXT record at {name} carries the challenge value"
        ))
    }
}

/// Fetch `url` (the well-known file) and look for the challenge line.
pub async fn check_http_via(url: &str, token: &str) -> Result<(), String> {
    crate::api::validation::validate_outbound_url(url, "Namespace proof URL")
        .map_err(|e| e.to_string())?;
    let body = fetch_capped(client()?.get(url)).await?;
    if http_body_matches(&body, &expected_value(token)) {
        Ok(())
    } else {
        Err(format!("{url} does not carry the challenge value"))
    }
}

/// Run the check a proof's `method` names against its `domain`.
pub async fn check(method: &str, domain: &str, token: &str) -> Result<(), String> {
    match method {
        "dns" => {
            let doh = std::env::var("MCP_NAMESPACE_PROOF_DOH_URL")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_DOH_URL.to_string());
            check_dns_via(&doh, domain, token).await
        }
        _ => check_http_via(&format!("https://{domain}{HTTP_PATH}"), token).await,
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_map_to_domains() {
        assert_eq!(domain_of("com.acme").unwrap(), "acme.com");
        assert_eq!(
            domain_of("IO.GitHub.acme-labs").unwrap(),
            "acme-labs.github.io"
        );
        for bad in [
            "acme",
            "com..acme",
            "com.-acme",
            "com.acme_x",
            "com.acme/x",
            "",
        ] {
            assert!(domain_of(bad).is_err(), "{bad}");
        }
        assert!(domain_of(&vec!["a"; 17].join(".")).is_err());
    }

    #[test]
    fn tokens_and_instructions() {
        let t = new_token();
        assert_eq!(t.len(), 64);
        assert_ne!(t, new_token());
        let dns = instructions("dns", "acme.com", "abc");
        assert_eq!(dns["name"], "_ak-mcp-challenge.acme.com");
        assert_eq!(dns["value"], "ak-mcp-verification=abc");
        let http = instructions("http", "acme.com", "abc");
        assert_eq!(http["url"], "https://acme.com/.well-known/ak-mcp-challenge");
    }

    #[test]
    fn answers_and_bodies_match_only_the_value() {
        let want = expected_value("abc");
        let ok = serde_json::json!({"Status": 0, "Answer": [
            {"type": 5, "data": "ak-mcp-verification=abc"},
            {"type": 16, "data": "\"ak-mcp-verification=\" \"abc\""},
        ]});
        assert!(doh_answer_matches(&ok, &want));
        let bare = serde_json::json!({"Status": 0, "Answer": [{"type": 16, "data": "ak-mcp-verification=abc"}]});
        assert!(doh_answer_matches(&bare, &want));
        let wrong = serde_json::json!({"Status": 0, "Answer": [{"type": 16, "data": "\"ak-mcp-verification=abd\""}]});
        assert!(!doh_answer_matches(&wrong, &want));
        assert!(!doh_answer_matches(
            &serde_json::json!({"Status": 3}),
            &want
        ));
        assert_eq!(txt_value("\"a\" \"b\""), "ab");
        assert_eq!(txt_value(" plain "), "plain");
        assert!(http_body_matches(b"x\n  ak-mcp-verification=abc \n", &want));
        assert!(!http_body_matches(b"ak-mcp-verification=abcd", &want));
    }

    #[tokio::test]
    async fn checks_fetch_through_the_guarded_client() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};
        let (server, _guard) =
            crate::api::handlers::test_db_helpers::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "_ak-mcp-challenge.acme.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Status": 0, "Answer": [{"type": 16, "data": "\"ak-mcp-verification=tok\""}],
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(HTTP_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string("ak-mcp-verification=tok\n"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/moved"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", HTTP_PATH))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_string("a".repeat(MAX_BODY + 1)))
            .mount(&server)
            .await;
        let base = server.uri();
        let doh = format!("{base}/dns-query");
        assert!(check_dns_via(&doh, "acme.com", "tok").await.is_ok());
        assert!(check_dns_via(&doh, "acme.com", "other").await.is_err());
        assert!(check_http_via(&format!("{base}{HTTP_PATH}"), "tok")
            .await
            .is_ok());
        assert!(check_http_via(&format!("{base}{HTTP_PATH}"), "nope")
            .await
            .is_err());
        // No redirects are followed; bodies are capped.
        let moved = check_http_via(&format!("{base}/moved"), "tok")
            .await
            .unwrap_err();
        assert!(moved.contains("302"), "{moved}");
        assert!(check_http_via(&format!("{base}/big"), "tok").await.is_err());
        // Internal targets are refused before any connection.
        assert!(check_http_via("http://127.0.0.1:1/x", "tok").await.is_err());
        assert!(check_http_via("http://169.254.169.254/latest", "tok")
            .await
            .is_err());
    }
}
