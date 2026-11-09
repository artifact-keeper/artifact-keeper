//! Package-source checks for npm and PyPI guests (#5446).
//!
//! An npm or PyPI guest installs its package with `npx` or `uvx` from the
//! AK repository the job was served from. What a publisher controls that
//! would make `npx`/`uvx` fetch the package from elsewhere is checked here,
//! before any guest starts, and refused rather than stripped:
//!
//! * `registryBaseUrl` is parsed as a URL and compared with the job's AK base
//!   URL by scheme, host (lower-cased, IDNA-normalised), effective port and
//!   path (`<AK base path>/<npm|pypi>/<repository>`), never by string prefix.
//!   Userinfo, percent-encoding, backslashes, dot segments, whitespace, a
//!   query or a fragment are refused outright; the spec carries the URL's
//!   canonical form, not the submitted string;
//! * the package name and version must be a plain name and an exact version
//!   (npm: `name` / `@scope/name` and SemVer without build metadata; PyPI: a
//!   PEP 508 name and a PEP 440 version), so neither can be a URL, path, git,
//!   alias, range or direct-reference spec;
//! * `environmentVariables` may not name a variable the guest's package
//!   manager reads for its registry, index or configuration
//!   ([`NPM_SOURCE_ENV_PREFIXES`], [`PYPI_SOURCE_ENV_PREFIXES`]): they would
//!   override the pinned registry;
//! * a source option with a URL, `git+` or `file:` value in
//!   `packageArguments` or `runtimeArguments` ([`NPM_URL_FLAGS`],
//!   [`PYPI_URL_FLAGS`]) is refused. `npx`/`uvx` stop parsing options at the
//!   package spec, so these only matter if the command line is ever built
//!   differently; any other argument is guest data.
//!
//! What the installed package itself pulls in (a `git+` or tarball
//! dependency, an install script) is not decided here: the guest's network,
//! which reaches only AK, contains it.
//!
//! Every refusal is a [`SandboxError::Invalid`] naming the field and the
//! rule; it never echoes a submitted name or value, which may carry a
//! credential.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
use url::Url;

use super::SandboxError;

/// The longest `registryBaseUrl` considered.
pub const MAX_URL: usize = 2048;
/// The longest package name and version considered.
pub const MAX_NPM_NAME: usize = 214;
pub const MAX_PYPI_NAME: usize = 200;
pub const MAX_VERSION: usize = 256;

/// `npx`/`npm` long options (without `--`; compared in lower case, `_` read
/// as `-`) that name a registry. `--@<scope>:registry` counts too. Refused
/// only with a URL, `git+` or `file:` value.
pub const NPM_URL_FLAGS: &[&str] = &["registry"];

/// `uvx`/`uv`, `pip` and `pipx` long options that name an index, a links
/// source or an extra package source. Refused only with a URL, `git+` or
/// `file:` value.
pub const PYPI_URL_FLAGS: &[&str] = &[
    "index-url",
    "extra-index-url",
    "find-links",
    "default-index",
    "index",
    "from",
    "with",
    "with-requirements",
    "with-editable",
];

/// `pip`/`uv` short forms of `--index-url` and `--find-links`: `-i <v>`,
/// `-i=<v>` or `-i<v>`.
pub const PYPI_URL_SHORT_FLAGS: &[&str] = &["-i", "-f"];

/// Environment variable prefixes (any case) npm reads for its registry and
/// configuration (`npm_config_*` / `NPM_CONFIG_*`: `NPM_CONFIG_REGISTRY`,
/// `NPM_CONFIG_USERCONFIG`, ...), yarn's, pnpm's and corepack's equivalents,
/// and `NODE_OPTIONS`, which preloads code into `npx` before npm reads its
/// configuration. Refused for an npm job; for a PyPI job they are dropped.
pub const NPM_SOURCE_ENV_PREFIXES: &[&str] =
    &["NPM_CONFIG", "YARN_", "PNPM_", "COREPACK_", "NODE_OPTIONS"];

/// Environment variable prefixes (any case) uv, pip and pipx read for their
/// index and configuration (`UV_INDEX_URL`, `UV_DEFAULT_INDEX`, `UV_INDEX`,
/// `UV_CONFIG_FILE`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`,
/// `PIP_FIND_LINKS`, `PIP_CONFIG_FILE`, `PIP_TRUSTED_HOST`, ...). `UV_INDEX`
/// beats `--default-index`, so these must not reach a PyPI guest. Refused for
/// a PyPI job; for an npm job they are dropped.
pub const PYPI_SOURCE_ENV_PREFIXES: &[&str] = &["UV_", "PIP_", "PIPX_"];

/// The last `_`/`-` separated word(s) of a name that make it a credential:
/// its value is replaced by a placeholder even when the publisher did not
/// mark it secret. `MAX_TOKENS` or `TOKENIZER` do not match.
const CREDENTIAL_SUFFIXES: &[&[&str]] = &[
    &["TOKEN"],
    &["SECRET"],
    &["PASSWORD"],
    &["PASSWD"],
    &["APIKEY"],
    &["API", "KEY"],
    &["ACCESS", "KEY"],
    &["PRIVATE", "KEY"],
];

static NPM_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?i:@[a-z0-9~-][a-z0-9._~-]*/)?(?i:[a-z0-9~-][a-z0-9._~-]*)$").expect("regex")
});
/// SemVer 2.0.0, exactly one version, without build metadata (registry
/// versions carry none, and npm reads `1.2.3+x.tgz` as a file).
static SEMVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$",
    )
    .expect("regex")
});
/// A PEP 508 project name.
static PYPI_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?i:[a-z0-9]|[a-z0-9][a-z0-9._-]*[a-z0-9])$").expect("regex"));
/// A PEP 440 version (the `packaging` grammar), exactly one version.
static PEP440: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?i:v?([0-9]+!)?[0-9]+(\.[0-9]+)*([-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?((-[0-9]+)|([-_.]?(post|rev|r)[-_.]?[0-9]*))?([-_.]?dev[-_.]?[0-9]*)?(\+[a-z0-9]+([-_.][a-z0-9]+)*)?)$",
    )
    .expect("regex")
});

fn invalid(field: &str, m: &str) -> SandboxError {
    SandboxError::Invalid(format!("{field}: {m}"))
}

/// Whether an argument or variable name ends in a credential word
/// (`GITHUB_TOKEN`, `--password`, `MY_API_KEY`, `token`).
pub fn looks_like_credential(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let words: Vec<&str> = upper.split(['_', '-']).filter(|w| !w.is_empty()).collect();
    CREDENTIAL_SUFFIXES
        .iter()
        .any(|suffix| words.ends_with(suffix))
}

/// The job's AK base URL, parsed. It must name a host and carry no
/// userinfo, query or fragment: it is copied into every spec.
pub fn ak_base(ak_base_url: &str) -> Result<Url, SandboxError> {
    let url = Url::parse(ak_base_url)
        .map_err(|_| SandboxError::Invalid("AK base URL is not a URL".into()))?;
    if url.host_str().is_none() {
        return Err(SandboxError::Invalid("AK base URL has no host".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("AK base URL", "userinfo is not allowed"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("AK base URL", "a query or fragment is not allowed"));
    }
    Ok(url)
}

/// What `validate_repository_key` accepts for a repository key.
fn valid_repo_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !key.starts_with('.')
        && !key.starts_with('-')
        && !key.contains("..")
}

/// The canonical AK registry URL of an npm or PyPI job (`kind`): the
/// package's `registryBaseUrl` when it is exactly an AK `<kind>`
/// repository of `ak_base_url`, without a trailing slash.
pub fn registry_url(
    kind: &str,
    given: Option<&str>,
    ak_base_url: &str,
) -> Result<String, SandboxError> {
    let bad = |m: &str| invalid("registryBaseUrl", m);
    let raw = given
        .filter(|r| !r.is_empty())
        .ok_or_else(|| bad("missing; the package must be served by this AK instance"))?;
    if raw.len() > MAX_URL {
        return Err(bad("longer than 2048 bytes"));
    }
    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad("whitespace or control characters are not allowed"));
    }
    if raw.contains('\\') {
        return Err(bad("a backslash is not allowed"));
    }
    if raw.contains('%') {
        return Err(bad("percent-encoding is not allowed"));
    }
    if raw.contains('@') {
        return Err(bad("userinfo (`user@`) is not allowed"));
    }
    if raw.contains('?') || raw.contains('#') {
        return Err(bad("a query or fragment is not allowed"));
    }
    let url = Url::parse(raw).map_err(|_| bad("not a URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(bad("the scheme must be http or https"));
    }
    // `https:host/...` and `https:///host/...` parse, leniently, as
    // `https://host/...`: only the plain `<scheme>://<authority>/` form is
    // taken.
    let prefix_len = url.scheme().len() + 3;
    let after = raw
        .get(..prefix_len)
        .filter(|p| p.eq_ignore_ascii_case(&format!("{}://", url.scheme())))
        .and(raw.get(prefix_len..))
        .ok_or_else(|| bad("not a `<scheme>://<host>/` URL"))?;
    let mut parts = after.split('/');
    if parts.next().is_none_or(str::is_empty) {
        return Err(bad("not a `<scheme>://<host>/` URL"));
    }
    if parts.any(|seg| seg == "." || seg == "..") {
        return Err(bad("dot segments are not allowed"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("userinfo (`user@`) is not allowed"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(bad("a query or fragment is not allowed"));
    }
    let ak = ak_base(ak_base_url)?;
    if url.scheme() != ak.scheme() {
        return Err(bad("the scheme is not this AK instance's"));
    }
    if url.host() != ak.host() {
        return Err(bad("the host is not this AK instance"));
    }
    if url.port_or_known_default() != ak.port_or_known_default() {
        return Err(bad("the port is not this AK instance's"));
    }
    let base = format!("{}/{kind}/", ak.path().trim_end_matches('/'));
    let key = url
        .path()
        .strip_prefix(&base)
        .map(|k| k.strip_suffix('/').unwrap_or(k))
        .filter(|k| valid_repo_key(k))
        .ok_or_else(|| {
            bad(&format!(
                "the path is not an AK {kind} repository (`<AK base URL>/{kind}/<repository>`)"
            ))
        })?;
    let mut canonical = url.clone();
    canonical.set_path(&format!("{base}{key}"));
    Ok(canonical.to_string())
}

/// The package name and, when given, the version of an npm or PyPI job:
/// a plain name and one exact version, so neither names another source.
pub fn check_coordinates(
    kind: &str,
    identifier: &str,
    version: Option<&str>,
) -> Result<(), SandboxError> {
    let (name_ok, what) = match kind {
        "npm" => (
            identifier.len() <= MAX_NPM_NAME && NPM_NAME.is_match(identifier),
            "an npm package name (`name` or `@scope/name`)",
        ),
        _ => (
            identifier.len() <= MAX_PYPI_NAME && PYPI_NAME.is_match(identifier),
            "a PyPI project name",
        ),
    };
    if !name_ok {
        return Err(invalid(
            "package identifier",
            &format!("not {what}; a URL, path, git, alias or direct-reference spec is not allowed"),
        ));
    }
    let Some(v) = version.filter(|v| !v.is_empty()) else {
        return Ok(());
    };
    let (version_ok, what) = match kind {
        "npm" => (
            SEMVER.is_match(v),
            "an exact SemVer version without build metadata",
        ),
        _ => (PEP440.is_match(v), "an exact PEP 440 version"),
    };
    // npm takes a spec ending in `.tgz`/`.tar`/`.tar.gz` as a file to open.
    let lower = v.to_ascii_lowercase();
    let archive = [".tgz", ".tar", ".tar.gz"]
        .iter()
        .any(|x| lower.ends_with(x));
    let version_ok = version_ok && v.len() <= MAX_VERSION && !archive;
    if !version_ok {
        return Err(invalid(
            "package version",
            &format!("not {what}; a range, tag, URL, path or alias is not allowed"),
        ));
    }
    Ok(())
}

/// A package-source reference: an absolute URL, a `git+` or a `file:` spec.
fn is_source_ref(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    lower.contains("://") || lower.starts_with("git+") || lower.starts_with("file:")
}

/// If `token` is a source option of `kind`: the rule it matches and its
/// attached value (`--flag=<v>`, `-i<v>`), if any.
fn source_option<'a>(kind: &str, token: &'a str) -> Option<(&'static str, Option<&'a str>)> {
    if let Some(rest) = token.strip_prefix("--") {
        let (name, value) = match rest.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (rest, None),
        };
        let name = name.to_ascii_lowercase().replace('_', "-");
        let rule = if kind == "npm" {
            if name.starts_with('@') && name.ends_with(":registry") {
                Some("npm scoped registry")
            } else {
                NPM_URL_FLAGS
                    .contains(&name.as_str())
                    .then_some("npm registry")
            }
        } else {
            PYPI_URL_FLAGS
                .contains(&name.as_str())
                .then_some("Python index or package source")
        };
        return rule.map(|r| (r, value));
    }
    if kind != "pypi" {
        return None;
    }
    PYPI_URL_SHORT_FLAGS.iter().find_map(|f| {
        let rest = token.strip_prefix(*f)?;
        let value = match rest.strip_prefix('=') {
            Some(v) => Some(v),
            None if rest.is_empty() => None,
            // `-ihttps://...`; `-info` is another option.
            None if is_source_ref(rest) => Some(rest),
            None => return None,
        };
        Some(("Python index or package source", value))
    })
}

/// Refuse a source option of `kind` whose value (attached, or the next
/// token) is a URL, `git+` or `file:` reference, among `tokens` (an argument
/// list of `field`).
pub fn check_args(kind: &str, field: &str, tokens: &[String]) -> Result<(), SandboxError> {
    for (i, t) in tokens.iter().enumerate() {
        let Some((rule, attached)) = source_option(kind, t) else {
            continue;
        };
        let value = attached.or_else(|| tokens.get(i + 1).map(String::as_str));
        if value.is_some_and(is_source_ref) {
            return Err(invalid(
                field,
                &format!(
                    "a source option ({rule}) with a URL, git or file value selects a \
                     package source; only this AK instance is used"
                ),
            ));
        }
    }
    Ok(())
}

/// Every string a publisher's argument list carries (`name`, `value`,
/// `default`), in order, rendered or not.
pub fn raw_arg_tokens(package: &Value, field: &str) -> Vec<String> {
    package
        .get(field)
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .flat_map(|a| {
            ["name", "value", "default"]
                .into_iter()
                .filter_map(|k| a.get(k).and_then(|v| v.as_str()).map(String::from))
        })
        .collect()
}

/// Refuse an `environmentVariables` entry the package manager of `kind`
/// reads for its registry, index or configuration. The error names the
/// rule, not the submitted name.
pub fn check_env(kind: &str, package: &Value) -> Result<(), SandboxError> {
    let prefixes = if kind == "npm" {
        NPM_SOURCE_ENV_PREFIXES
    } else {
        PYPI_SOURCE_ENV_PREFIXES
    };
    let vars = package
        .get("environmentVariables")
        .and_then(|e| e.as_array())
        .into_iter()
        .flatten();
    for var in vars {
        let Some(name) = var.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let upper = name.trim().to_ascii_uppercase();
        if let Some(p) = prefixes.iter().find(|p| upper.starts_with(**p)) {
            return Err(invalid(
                "environmentVariables",
                &format!(
                    "a `{}*` variable configures the package manager's source; only this \
                     AK instance is used",
                    p.trim_end_matches('_')
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    //! The sanitized RT-06 fixture matrix (#5446): every form the
    //! assessment reported, for npm and for PyPI, is refused by
    //! `guest_spec` before a runner sees it; the canonical controls render
    //! with only the canonical AK registry in argv and environment.
    use super::super::{guest_spec, GuestSpec, Images, SandboxError};
    use super::*;
    use serde_json::{json, Value};

    const AK: &str = "https://ak.example.test";
    const KINDS: [&str; 2] = ["npm", "pypi"];

    fn canonical_package(kind: &str) -> Value {
        match kind {
            "npm" => json!({"registryType": "npm", "identifier": "@acme/weather",
                "version": "1.2.3", "registryBaseUrl": "https://ak.example.test/npm/npm-virtual",
                "transport": {"type": "stdio"}}),
            _ => json!({"registryType": "pypi", "identifier": "acme-mcp", "version": "2.0.1",
                "registryBaseUrl": "https://ak.example.test/pypi/pypi-remote",
                "transport": {"type": "stdio"}}),
        }
    }

    /// The canonical package of `kind` with `patch`'s members set.
    fn job(kind: &str, patch: Value) -> Value {
        let mut p = canonical_package(kind);
        for (k, v) in patch.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"type": "package", "index": 0, "registryType": kind, "package": p})
    }

    fn render(target: &Value, ak: &str) -> Result<GuestSpec, SandboxError> {
        guest_spec("j", target, ak, &Images::default())
    }

    fn other(kind: &str) -> &'static str {
        if kind == "npm" {
            "pypi"
        } else {
            "npm"
        }
    }

    /// `registryBaseUrl` forms that must not select a source: string
    /// prefix, userinfo, encoded authority, non-default port, encoded path,
    /// dot segments, query/fragment, scheme, wrong format path, lenient
    /// parses, and foreign hosts.
    fn bad_registries(k: &str) -> Vec<String> {
        let o = other(k);
        vec![
            // String-prefix confusion.
            format!("https://ak.example.test.evil.test/{k}/r"),
            format!("https://ak.example.testevil.test/{k}/r"),
            format!("https://ak.example.test-evil.test/{k}/r"),
            // Userinfo.
            format!("https://ak.example.test@evil.test/{k}/r"),
            format!("https://user:pass@ak.example.test/{k}/r"),
            format!("https://user@ak.example.test/{k}/r"),
            // Encoded authority delimiters.
            format!("https://ak.example.test%40evil.test/{k}/r"),
            format!("https://evil.test%2F.ak.example.test/{k}/r"),
            format!("https://ak.example.test%3A443.evil.test/{k}/r"),
            format!("https://evil.test%2Fak.example.test/{k}/r"),
            // Encoded path.
            format!("https://ak.example.test/{k}/r%2F..%2F..%2Fevil"),
            format!("https://ak.example.test/{k}/%2e%2e/evil"),
            format!("https://ak.example.test/%{k}/r"),
            // Dot segments (the parser would resolve them).
            format!("https://ak.example.test/{k}/./r"),
            format!("https://ak.example.test/{o}/../{k}/r"),
            format!("https://ak.example.test/{k}/x/../r"),
            // Another origin's port, scheme.
            format!("https://ak.example.test:8443/{k}/r"),
            format!("https://ak.example.test:80/{k}/r"),
            format!("http://ak.example.test/{k}/r"),
            format!("ftp://ak.example.test/{k}/r"),
            format!("file:///{k}/r"),
            format!("git+https://ak.example.test/{k}/r"),
            // Query or fragment on the endpoint.
            format!("https://ak.example.test/{k}/r?registry=https://evil.test"),
            format!("https://ak.example.test/{k}/r?"),
            format!("https://ak.example.test/{k}/r#frag"),
            format!("https://ak.example.test/{k}/r#"),
            // A path that is not `<base>/<kind>/<repository>`.
            format!("https://ak.example.test/{o}/r"),
            format!("https://ak.example.test/{k}/r/extra"),
            format!("https://ak.example.test/{k}/"),
            format!("https://ak.example.test/{k}"),
            format!("https://ak.example.test//{k}/r"),
            format!("https://ak.example.test/{k}x/r"),
            format!("https://ak.example.test/{k}/.r"),
            format!("https://ak.example.test/api/{k}/r"),
            // Lenient parses, whitespace, backslashes.
            format!("https:ak.example.test/{k}/r"),
            format!("https:///ak.example.test/{k}/r"),
            format!("https://ak.exa\tmple.test/{k}/r"),
            format!("https://ak.example.test/{k}/r\n"),
            format!(" https://ak.example.test/{k}/r"),
            format!("https:\\\\evil.test/{k}/r"),
            format!("https://ak.example.test\\@evil.test/{k}/r"),
            // Other hosts: a trailing-dot FQDN, IP literals, the public
            // registries (the detector's foreign-host negative control).
            format!("https://ak.example.test./{k}/r"),
            format!("https://203.0.113.10/{k}/r"),
            format!("https://[::1]/{k}/r"),
            "https://registry.npmjs.org".to_string(),
            "https://pypi.org/simple".to_string(),
            format!("https://evil.test/{k}/r"),
            // Missing.
            String::new(),
        ]
    }

    fn bad_coordinates(k: &str) -> Vec<Value> {
        match k {
            "npm" => vec![
                json!({"identifier": "evil@https://evil.test/x.tgz"}),
                json!({"identifier": "git+https://evil.test/x.git"}),
                json!({"identifier": "git://evil.test/x.git"}),
                json!({"identifier": "file:../x"}),
                json!({"identifier": "https://evil.test/x.tgz"}),
                json!({"identifier": "github:acme/x"}),
                json!({"identifier": "acme/x"}),
                json!({"identifier": "x@npm:evil"}),
                json!({"identifier": "@acme/x@1.0.0"}),
                json!({"identifier": "x --registry=https://evil.test"}),
                json!({"identifier": "x#main"}),
                json!({"identifier": "../x"}),
                json!({"version": "https://evil.test/x.tgz"}),
                json!({"version": "npm:evil@1.0.0"}),
                json!({"version": "git+https://evil.test/x.git"}),
                json!({"version": "github:acme/x"}),
                json!({"version": "file:../x"}),
                json!({"version": "^1.2.3"}),
                json!({"version": "latest"}),
                json!({"version": "1"}),
                json!({"version": ">=1.0.0"}),
                json!({"version": "1.2.3 || 2.0.0"}),
                json!({"version": "1.2.3 --registry=https://evil.test"}),
                json!({"version": "1.2.3#evil"}),
                json!({"version": "v1.2.3"}),
                json!({"version": "1.2.x"}),
                json!({"version": "1.2.3+evil.tgz"}),
                json!({"version": "1.2.3-evil.tgz"}),
                json!({"version": "1.2.3+build.5"}),
                json!({"version": "1.2.3-x.tar"}),
            ],
            _ => vec![
                json!({"identifier": "acme-mcp @ https://evil.test/x.whl"}),
                json!({"identifier": "acme-mcp@https://evil.test/x.whl"}),
                json!({"identifier": "git+https://evil.test/x.git"}),
                json!({"identifier": "https://evil.test/x.whl"}),
                json!({"identifier": "./local"}),
                json!({"identifier": "/abs/path"}),
                json!({"identifier": "file:///x"}),
                json!({"identifier": "acme-mcp[extra]"}),
                json!({"identifier": "acme-mcp --index-url https://evil.test/simple"}),
                json!({"identifier": "acme-mcp==1.0"}),
                json!({"identifier": "acme-mcp;python_version>'3'"}),
                json!({"version": "1.0 @ https://evil.test/x.whl"}),
                json!({"version": "https://evil.test/x.whl"}),
                json!({"version": ">=1.0"}),
                json!({"version": "==1.0"}),
                json!({"version": "1.0,<2"}),
                json!({"version": "1.*"}),
                json!({"version": "1.0; python_version>'3'"}),
                json!({"version": "../x"}),
                json!({"version": "1.0 --index-url https://evil.test/simple"}),
                json!({"version": "latest"}),
                json!({"version": "1.0+evil.tar.gz"}),
            ],
        }
    }

    /// Source options with a URL, `git+` or `file:` value, as
    /// `packageArguments` and as `runtimeArguments`, named or positional.
    fn bad_args(k: &str) -> Vec<Value> {
        let named = |n: &str, v: &str| json!({"type": "named", "name": n, "value": v});
        let pos = |v: &str| json!({"type": "positional", "value": v});
        let flags: Vec<Value> = match k {
            "npm" => vec![
                named("--registry", "https://evil.test"),
                pos("--registry=https://evil.test"),
                pos("--REGISTRY=https://evil.test"),
                pos("--@acme:registry=https://evil.test"),
                named("--@acme:registry", "https://evil.test"),
                named("--registry", "git+https://evil.test/x.git"),
                named("--Registry", "file:///tmp/registry"),
                json!({"type": "named", "name": "--verbose", "value": "--registry=https://evil.test"}),
                json!({"type": "named", "name": "--registry", "default": "https://evil.test"}),
            ],
            _ => vec![
                named("--index-url", "https://evil.test/simple"),
                pos("--index-url=https://evil.test/simple"),
                pos("--INDEX_URL=https://evil.test/simple"),
                named("-i", "https://evil.test/simple"),
                pos("-ihttps://evil.test/simple"),
                pos("-i=https://evil.test/simple"),
                named("--extra-index-url", "https://evil.test/simple"),
                named("--find-links", "https://evil.test/links"),
                named("--find-links", "file:///tmp/wheels"),
                named("-f", "https://evil.test/links"),
                pos("-ffile:///tmp/wheels"),
                named("--default-index", "https://evil.test/simple"),
                named("--index", "https://evil.test/simple"),
                named("--from", "git+https://evil.test/x.git"),
                named("--with", "git+https://evil.test/y.git"),
                named("--with-requirements", "https://evil.test/req.txt"),
                named("--with-editable", "file:///tmp/src"),
            ],
        };
        let mut out = Vec::new();
        for f in flags {
            out.push(json!({"packageArguments": [f.clone()]}));
            out.push(json!({"runtimeArguments": [f]}));
        }
        out
    }

    fn bad_env_names(k: &str) -> Vec<&'static str> {
        match k {
            "npm" => vec![
                "NPM_CONFIG_REGISTRY",
                "npm_config_registry",
                "Npm_Config_Registry",
                "npm_config_@acme:registry",
                "NPM_CONFIG_USERCONFIG",
                "npm_config_globalconfig",
                "npm_config_//npm.example/:_authToken",
                "npm_config_https_proxy",
                "NPM_CONFIG_PROXY",
                "npm_config_replace_registry_host",
                "NPM_CONFIG_CAFILE",
                "NODE_OPTIONS",
                "node_options",
                "COREPACK_NPM_REGISTRY",
                "Corepack_Npm_Registry",
                "YARN_NPM_REGISTRY_SERVER",
                "yarn_registry",
                "PNPM_HOME",
                "PNPM_CONFIG_REGISTRY",
            ],
            _ => vec![
                "PIP_INDEX_URL",
                "PIP_EXTRA_INDEX_URL",
                "PIP_FIND_LINKS",
                "PIP_CONFIG_FILE",
                "PIP_TRUSTED_HOST",
                "pip_index_url",
                "Pip_No_Index",
                "UV_INDEX_URL",
                "UV_DEFAULT_INDEX",
                "UV_EXTRA_INDEX_URL",
                "UV_INDEX",
                "UV_CONFIG_FILE",
                "uv_find_links",
                "UV_PYTHON_INSTALL_MIRROR",
                "UV_INSECURE_HOST",
                "UV_INDEX_STRATEGY",
                "UV_NO_CONFIG",
                "PIPX_DEFAULT_PYTHON",
                "PIPX_HOME",
            ],
        }
    }

    /// The refusal is a bounded `Invalid` that never echoes any of
    /// `submitted` (names and values, which may carry a credential).
    fn assert_refused_without(kind: &str, target: &Value, what: &str, submitted: &[&str]) {
        match render(target, AK) {
            Err(SandboxError::Invalid(m)) => {
                assert!(m.len() < 256, "{kind} {what}: {m}");
                assert!(!m.contains("evil.test"), "{kind} {what}: {m}");
                for x in submitted.iter().filter(|x| x.len() > 1) {
                    assert!(!m.contains(x), "{kind} {what}: `{x}` echoed in {m}");
                }
            }
            other => panic!("{kind} {what} was not refused: {other:?}"),
        }
    }

    /// Every string member of every object in `v` (the fixture's submitted
    /// names and values).
    fn strings(v: &Value) -> Vec<String> {
        match v {
            Value::String(s) => vec![s.clone()],
            Value::Array(a) => a.iter().flat_map(strings).collect(),
            Value::Object(o) => o
                .iter()
                .filter(|(k, _)| *k != "type")
                .flat_map(|(_, v)| strings(v))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn assert_refused(kind: &str, target: &Value, what: &str) {
        let submitted = strings(&target["package"]);
        let canonical = strings(&canonical_package(kind));
        // The canonical package's own members (`npm`, `stdio`, ...) are not
        // what is being tested.
        let submitted: Vec<&str> = submitted
            .iter()
            .filter(|s| !canonical.contains(s))
            .map(String::as_str)
            .collect();
        assert_refused_without(kind, target, what, &submitted);
    }

    #[test]
    fn registry_forms_are_refused() {
        for k in KINDS {
            let bad = bad_registries(k);
            assert_eq!(bad.len(), 48, "{k}");
            for r in bad {
                assert_refused(k, &job(k, json!({"registryBaseUrl": r})), &r);
            }
            // No registryBaseUrl at all.
            let mut t = job(k, json!({}));
            t["package"]
                .as_object_mut()
                .unwrap()
                .remove("registryBaseUrl");
            assert_refused(k, &t, "missing registryBaseUrl");
            // The length limit.
            let base = format!("https://ak.example.test/{k}/");
            let long = format!("{base}{}", "r".repeat(MAX_URL + 1 - base.len()));
            assert_eq!(long.len(), MAX_URL + 1);
            assert!(render(&job(k, json!({"registryBaseUrl": long})), AK)
                .unwrap_err()
                .to_string()
                .contains("longer than"));
        }
    }

    #[test]
    fn coordinate_and_version_smuggling_is_refused() {
        for (k, n) in [("npm", 30), ("pypi", 22)] {
            let bad = bad_coordinates(k);
            assert_eq!(bad.len(), n, "{k}");
            for patch in bad {
                assert_refused(k, &job(k, patch.clone()), &patch.to_string());
            }
        }
        // Length limits: at the limit renders, one over is refused.
        let npm_at = "a".repeat(MAX_NPM_NAME);
        let pypi_at = "a".repeat(MAX_PYPI_NAME);
        let semver_at = format!("1.0.0-{}", "a".repeat(MAX_VERSION - 6));
        let pep_at = format!("1.0+{}", "a".repeat(MAX_VERSION - 4));
        for (k, ok, over) in [
            (
                "npm",
                json!({"identifier": npm_at}),
                json!({"identifier": format!("{npm_at}a")}),
            ),
            (
                "pypi",
                json!({"identifier": pypi_at}),
                json!({"identifier": format!("{pypi_at}a")}),
            ),
            (
                "npm",
                json!({"version": semver_at}),
                json!({"version": format!("{semver_at}a")}),
            ),
            (
                "pypi",
                json!({"version": pep_at}),
                json!({"version": format!("{pep_at}a")}),
            ),
        ] {
            assert!(render(&job(k, ok.clone()), AK).is_ok(), "{k} {ok}");
            assert!(render(&job(k, over.clone()), AK).is_err(), "{k} {over}");
        }
    }

    #[test]
    fn url_valued_source_arguments_are_refused() {
        for (k, n) in [("npm", 18), ("pypi", 34)] {
            let bad = bad_args(k);
            assert_eq!(bad.len(), n, "{k}");
            for patch in bad {
                assert_refused(k, &job(k, patch.clone()), &patch.to_string());
            }
        }
        // Every deny-list entry, attached and as the next token.
        for (k, flags) in [("npm", NPM_URL_FLAGS), ("pypi", PYPI_URL_FLAGS)] {
            for f in flags {
                for field in ["packageArguments", "runtimeArguments"] {
                    let attached = json!({field: [
                        {"type": "positional", "value": format!("--{f}=https://evil.test/x")}]});
                    assert_refused(k, &job(k, attached), f);
                    let next = json!({field: [
                        {"type": "named", "name": format!("--{f}"), "value": "https://evil.test/x"}]});
                    assert_refused(k, &job(k, next), f);
                    // Not a URL: guest data.
                    let plain = json!({field: [
                        {"type": "named", "name": format!("--{f}"), "value": "products"}]});
                    assert!(render(&job(k, plain), AK).is_ok(), "{k} --{f} products");
                }
            }
        }
        for f in PYPI_URL_SHORT_FLAGS {
            for v in [
                format!("{f}https://evil.test/x"),
                format!("{f}=https://evil.test/x"),
                format!("{f}git+https://evil.test/x.git"),
                format!("{f}=file:///tmp/x"),
            ] {
                let t = job(
                    "pypi",
                    json!({"packageArguments": [{"type": "positional", "value": v}]}),
                );
                assert_refused("pypi", &t, &v);
            }
        }
    }

    /// Options that only look like source options are guest data: `npx` and
    /// `uvx` never parse what follows the package spec.
    #[test]
    fn non_url_options_are_guest_data() {
        let named = |n: &str, v: &str| json!({"type": "named", "name": n, "value": v});
        let pos = |v: &str| json!({"type": "positional", "value": v});
        let cases = [
            ("npm", named("--config-file", "x.yaml")),
            ("npm", named("--proxy", "http://proxy.example:3128")),
            ("npm", named("--package", "foo")),
            ("npm", named("--userconfig", "/tmp/npmrc")),
            ("npm", named("--index-url", "https://api.example.com")),
            ("npm", pos("--registry")),
            ("pypi", named("--config-file", "x.yaml")),
            ("pypi", named("--index", "products")),
            ("pypi", named("-f", "out.json")),
            ("pypi", pos("--from=2024-01-01")),
            ("pypi", named("--python", "3.12")),
            ("pypi", named("--spec", "openapi.yaml")),
            ("pypi", named("--trusted-host", "api.example.com")),
            ("pypi", named("--registry", "https://api.example.com")),
            ("pypi", pos("-info")),
            ("pypi", pos("-i")),
        ];
        for (k, a) in cases {
            for field in ["packageArguments", "runtimeArguments"] {
                let t = job(k, json!({field: [a.clone()]}));
                let spec = render(&t, AK).unwrap_or_else(|e| panic!("{k} {field} {a}: {e}"));
                if field == "runtimeArguments" {
                    assert!(spec.notes.iter().any(|n| n == "runtimeArguments ignored"));
                }
            }
        }
    }

    #[test]
    fn source_selecting_environment_is_refused() {
        for k in KINDS {
            let bad = bad_env_names(k);
            assert_eq!(bad.len(), 19, "{k}");
            let prefixes = if k == "npm" {
                NPM_SOURCE_ENV_PREFIXES
            } else {
                PYPI_SOURCE_ENV_PREFIXES
            };
            for name in bad {
                // The error names the rule: a name that is the rule itself
                // (`NODE_OPTIONS`) is the only one it may contain.
                let is_rule = prefixes.iter().any(|p| name.eq_ignore_ascii_case(p));
                let shown: &[&str] = if is_rule { &[] } else { &[name] };
                let value = "https://u:not-a-real-value@evil.test/";
                let t = job(
                    k,
                    json!({"environmentVariables": [{"name": name, "value": value}]}),
                );
                assert_refused_without(k, &t, name, &[shown, &[value]].concat());
                // A secret or templated value is refused all the same.
                let t = job(
                    k,
                    json!({"environmentVariables": [{"name": name, "isSecret": true}]}),
                );
                assert_refused_without(k, &t, name, shown);
            }
        }
    }

    /// The other manager's knobs, proxies, `HOME` and the XDG directories
    /// are dropped with a note, as before, not refused.
    #[test]
    fn other_environment_is_dropped_not_refused() {
        let cases = [
            ("npm", "UV_THREADPOOL_SIZE"),
            ("npm", "PIP_INDEX_URL"),
            ("pypi", "NPM_CONFIG_REGISTRY"),
            ("pypi", "NODE_OPTIONS"),
            ("npm", "HTTPS_PROXY"),
            ("pypi", "https_proxy"),
            ("npm", "HOME"),
            ("pypi", "XDG_CONFIG_HOME"),
            ("npm", "PYTHONPATH"),
        ];
        for (k, name) in cases {
            let t = job(
                k,
                json!({"environmentVariables": [{"name": name, "value": "x"}]}),
            );
            let spec = render(&t, AK).unwrap_or_else(|e| panic!("{k} {name}: {e}"));
            assert!(spec.notes.iter().any(|n| n.contains(name)), "{k} {name}");
            assert!(
                !spec.env.iter().any(|(n, v)| n == name && v == "x"),
                "{k} {name}"
            );
        }
    }

    /// Everything in a rendered spec that can name a URL.
    fn urls(spec: &GuestSpec) -> Vec<String> {
        spec.argv
            .iter()
            .chain(spec.env.iter().map(|(_, v)| v))
            .flat_map(|s| s.split(['=', ' ']))
            .filter(|s| s.contains("://"))
            .map(String::from)
            .collect()
    }

    fn assert_pinned(kind: &str, spec: &GuestSpec, registry: &str) {
        match kind {
            "npm" => {
                assert_eq!(spec.argv[2], format!("--registry={registry}"));
                let regs: Vec<_> = spec
                    .env
                    .iter()
                    .filter(|(k, _)| k.to_ascii_lowercase().starts_with("npm_config_registry"))
                    .collect();
                assert_eq!(regs.len(), 1, "{:?}", spec.env);
                assert_eq!(regs[0].1, registry);
            }
            _ => {
                assert_eq!(spec.argv[2], "--default-index");
                assert_eq!(spec.argv[3], format!("{registry}/simple"));
            }
        }
        for u in urls(spec) {
            assert!(
                u == registry
                    || u == format!("{registry}/simple")
                    || u.starts_with("https://api.example.com"),
                "{kind}: {u} in {spec:?}"
            );
        }
    }

    #[test]
    fn canonical_controls_render_with_the_canonical_registry() {
        for k in KINDS {
            // (AK base URL, registryBaseUrl, canonical registry)
            let cases = [
                (
                    AK,
                    format!("https://ak.example.test/{k}/r"),
                    format!("https://ak.example.test/{k}/r"),
                ),
                (
                    AK,
                    format!("https://ak.example.test/{k}/r/"),
                    format!("https://ak.example.test/{k}/r"),
                ),
                (
                    AK,
                    format!("https://AK.Example.TEST/{k}/r"),
                    format!("https://ak.example.test/{k}/r"),
                ),
                (
                    AK,
                    format!("HTTPS://ak.example.test/{k}/r"),
                    format!("https://ak.example.test/{k}/r"),
                ),
                (
                    AK,
                    format!("https://ak.example.test:443/{k}/r"),
                    format!("https://ak.example.test/{k}/r"),
                ),
                (
                    AK,
                    format!("https://ak.example.test:/{k}/r"),
                    format!("https://ak.example.test/{k}/r"),
                ),
                (
                    "https://ak.example.test/",
                    format!("https://ak.example.test/{k}/My_Repo.1"),
                    format!("https://ak.example.test/{k}/My_Repo.1"),
                ),
                (
                    "https://ak.example.test:8443",
                    format!("https://ak.example.test:8443/{k}/r"),
                    format!("https://ak.example.test:8443/{k}/r"),
                ),
                (
                    "http://ak.example.test",
                    format!("http://ak.example.test:80/{k}/r"),
                    format!("http://ak.example.test/{k}/r"),
                ),
                (
                    "https://ak.example.test/ak/",
                    format!("https://ak.example.test/ak/{k}/r"),
                    format!("https://ak.example.test/ak/{k}/r"),
                ),
                (
                    "https://b\u{fc}cher.example",
                    format!("https://B\u{dc}CHER.example/{k}/r"),
                    format!("https://xn--bcher-kva.example/{k}/r"),
                ),
            ];
            for (ak, given, want) in cases {
                let spec = render(&job(k, json!({"registryBaseUrl": given})), ak)
                    .unwrap_or_else(|e| panic!("{k} {given}: {e}"));
                assert_pinned(k, &spec, &want);
            }
            // A path prefix on the AK base URL is not optional.
            assert!(render(
                &job(
                    k,
                    json!({"registryBaseUrl": format!("https://ak.example.test/{k}/r")})
                ),
                "https://ak.example.test/ak"
            )
            .is_err());
        }
    }

    #[test]
    fn canonical_controls_keep_benign_coordinates_arguments_and_environment() {
        let benign_args = json!([
            {"type": "named", "name": "--port", "value": "8080"},
            {"type": "named", "name": "--config", "value": "./config.json"},
            {"type": "named", "name": "--api-url", "value": "https://api.example.com/v1"},
            {"type": "positional", "value": "-info"},
            {"type": "positional", "value": "serve"},
        ]);
        let benign_env = json!([
            {"name": "LOG_LEVEL", "value": "debug"},
            {"name": "API_BASE_URL", "value": "https://api.example.com"},
            {"name": "NODE_ENV", "value": "production"},
        ]);
        let versions: &[(&str, &[&str])] = &[
            (
                "npm",
                &[
                    "1.2.3",
                    "0.0.1",
                    "1.2.3-beta.1",
                    "1.2.3-rc.1.tgzx",
                    "10.20.30",
                ],
            ),
            (
                "pypi",
                &[
                    "2.0.1",
                    "2.0",
                    "1.0rc1",
                    "1!2.0.post1.dev3+local.7",
                    "2024.11.8",
                ],
            ),
        ];
        for (k, vs) in versions {
            for v in *vs {
                let t = job(
                    k,
                    json!({"version": v, "packageArguments": benign_args,
                    "environmentVariables": benign_env}),
                );
                let spec = render(&t, AK).unwrap_or_else(|e| panic!("{k} {v}: {e}"));
                assert_pinned(
                    k,
                    &spec,
                    &format!(
                        "https://ak.example.test/{}",
                        if *k == "npm" {
                            "npm/npm-virtual"
                        } else {
                            "pypi/pypi-remote"
                        }
                    ),
                );
                assert!(spec.argv.iter().any(|a| a.ends_with(&format!("@{v}"))));
                assert!(spec.argv.iter().any(|a| a == "-info"));
                let env: std::collections::HashMap<_, _> = spec.env.iter().cloned().collect();
                assert_eq!(env["LOG_LEVEL"], "debug");
            }
        }
        for id in [
            "weather",
            "@acme/weather",
            "acme.mcp_server-2",
            "JSONStream",
            "@a/b~c",
        ] {
            assert!(
                render(&job("npm", json!({"identifier": id})), AK).is_ok(),
                "{id}"
            );
        }
        for id in ["acme-mcp", "Acme.MCP_server", "a", "mcp-server-fetch"] {
            assert!(
                render(&job("pypi", json!({"identifier": id})), AK).is_ok(),
                "{id}"
            );
        }
        // Benign runtimeArguments are still dropped, with a note.
        let t = job(
            "npm",
            json!({"runtimeArguments": [{"type": "positional", "value": "-y"}]}),
        );
        let spec = render(&t, AK).unwrap();
        assert!(!spec.argv.iter().any(|a| a == "-y"));
        assert!(spec.notes.iter().any(|n| n == "runtimeArguments ignored"));
    }

    /// No value from the job that names a credential reaches the spec:
    /// secrets, inputs whose name ends in a credential word, and a registry
    /// with userinfo (refused) all stay out. Names that merely contain such
    /// a word, and value hints, are left alone.
    #[test]
    fn no_credential_reaches_the_spec() {
        for k in KINDS {
            let t = job(
                k,
                json!({
                    "packageArguments": [
                        {"type": "named", "name": "--api-token", "value": "not-a-real-value-1"},
                        {"type": "named", "name": "--password", "default": "not-a-real-value-2"},
                        {"type": "named", "name": "--access-key", "value": "not-a-real-value-3"},
                        {"type": "named", "name": "--max-tokens", "value": "4096"},
                        {"type": "positional", "valueHint": "token_count", "value": "10"},
                    ],
                    "environmentVariables": [
                        {"name": "GITHUB_TOKEN", "value": "not-a-real-value-4"},
                        {"name": "CLIENT_SECRET", "default": "not-a-real-value-5"},
                        {"name": "MY_API_KEY", "value": "not-a-real-value-6", "isSecret": false},
                        {"name": "DB_PASSWORD", "isSecret": true, "value": "not-a-real-value-7"},
                        {"name": "token", "value": "not-a-real-value-8"},
                        {"name": "MAX_TOKENS", "value": "4096"},
                        {"name": "TOKEN_LIMIT", "value": "10"},
                        {"name": "TOKENIZER", "value": "cl100k"},
                        {"name": "SECRET_SCANNING_ENABLED", "value": "true"},
                        {"name": "GOOGLE_APPLICATION_CREDENTIALS", "value": "/app/sa.json"},
                    ],
                }),
            );
            let spec = render(&t, AK).unwrap();
            let all = serde_json::to_string(&spec).unwrap();
            assert!(!all.contains("not-a-real-value"), "{k}: {all}");
            let env: std::collections::HashMap<_, _> = spec.env.iter().cloned().collect();
            assert_eq!(env["GITHUB_TOKEN"], "AK_PLACEHOLDER_GITHUB_TOKEN");
            assert_eq!(env["MAX_TOKENS"], "4096");
            assert_eq!(env["TOKEN_LIMIT"], "10");
            assert_eq!(env["TOKENIZER"], "cl100k");
            assert_eq!(env["SECRET_SCANNING_ENABLED"], "true");
            assert_eq!(env["GOOGLE_APPLICATION_CREDENTIALS"], "/app/sa.json");
            let max = spec.argv.iter().position(|a| a == "--max-tokens").unwrap();
            assert_eq!(spec.argv[max + 1], "4096");
            assert!(spec.argv.iter().any(|a| a == "10"));
            let t = job(
                k,
                json!({"registryBaseUrl":
                format!("https://ak:not-a-real-value@ak.example.test/{k}/r")}),
            );
            match render(&t, AK) {
                Err(e) => assert!(!e.to_string().contains("not-a-real-value"), "{e}"),
                Ok(s) => panic!("{k}: userinfo rendered: {s:?}"),
            }
        }
        // An OCI guest keeps main's rule: only `isSecret`, required values
        // without a default and templates are placeholders.
        let oci = json!({"package": {"registryType": "oci",
            "identifier": format!("ak.example.test/oci/acme/mcp@sha256:{}", "a".repeat(64)),
            "environmentVariables": [{"name": "GITHUB_TOKEN", "value": "public-default"}]}});
        let spec = render(&oci, AK).unwrap();
        assert!(spec
            .env
            .iter()
            .any(|(n, v)| n == "GITHUB_TOKEN" && v == "public-default"));
        // The AK base URL itself carries no credential into a spec.
        assert!(render(&job("npm", json!({})), "https://u:p@ak.example.test").is_err());
        assert!(render(&job("npm", json!({})), "https://ak.example.test?x=1").is_err());
    }

    #[test]
    fn credential_names_match_whole_trailing_words() {
        for yes in [
            "GITHUB_TOKEN",
            "--token",
            "token",
            "--api-token",
            "CLIENT_SECRET",
            "DB_PASSWORD",
            "--passwd",
            "MY_API_KEY",
            "--api-key",
            "OPENAI_APIKEY",
            "AWS_ACCESS_KEY",
            "SSH_PRIVATE_KEY",
        ] {
            assert!(looks_like_credential(yes), "{yes}");
        }
        for no in [
            "MAX_TOKENS",
            "TOKEN_LIMIT",
            "TOKENIZER",
            "SECRET_SCANNING_ENABLED",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "--max-tokens",
            "token_count",
            "KEY",
            "API",
            "PASSWORD_MIN_LENGTH",
            "MYTOKEN",
        ] {
            assert!(!looks_like_credential(no), "{no}");
        }
    }
}
