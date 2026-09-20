//! Parser for conda build recipes (`info/recipe/meta.yaml` and
//! `info/recipe/recipe.yaml`) that extracts the *vendored native components*
//! a package was built from.
//!
//! A conda package is a pre-built binary. `info/index.json` only lists
//! conda-level dependencies and says nothing about the C/C++ libraries
//! compiled into the payload, which is where the CVEs live (`pillow` vendors
//! libjpeg-turbo/libwebp/zlib, for example). The recipe's `source:` block is
//! the recipe's statement of what was actually downloaded and built in:
//! upstream URLs, versions, checksums and applied patches.
//!
//! Two recipe formats exist in the wild:
//!
//! * Classic `meta.yaml` (conda-build): YAML with Jinja2 templating, which is
//!   not valid YAML until the template is rendered. Note that conda-build
//!   ships the *rendered* recipe as `info/recipe/meta.yaml` and the raw
//!   template as `info/recipe/meta.yaml.template`, so packages built by
//!   conda-build usually contain no Jinja at all. Feedstock checkouts do.
//! * `recipe.yaml` (rattler-build, "v1"): real YAML with a `context:` block
//!   and `${{ }}` expressions.
//! * `rendered_recipe.yaml` (rattler-build): what it actually built from,
//!   serialized after evaluation: the recipe with templates and selectors
//!   resolved under `recipe:`, plus `finalized_sources:` listing the sources
//!   as fetched. Best source of truth when present; see
//!   [`preferred_recipe_files`].
//!
//! This module never shells out, never panics on hostile input, and never
//! emits a confidently-wrong version: anything that could not be resolved is
//! reported as [`SourceConfidence::Unresolved`] with the raw expression kept
//! in [`ParsedRecipe::unresolved_expressions`].

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use thiserror::Error;

/// Upper bound on recipe size. Real recipes are a few KiB; anything past this
/// is hostile or misidentified input and is rejected before any regex work.
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum nesting depth of parenthesised sub-expressions the template
/// evaluator will follow before giving up (and marking the expression
/// unresolved). Guards the recursive-descent evaluator's stack.
const MAX_EXPR_DEPTH: usize = 32;

/// How much trust to place in a [`VendoredComponent`]'s identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceConfidence {
    /// The recipe's own `package:` name/version, corroborated by the source
    /// locator (URL basename, git tag, ...).
    Declared,
    /// Name and/or version were derived heuristically from the source URL,
    /// git repository name, tag, or folder, and are not stated by the recipe.
    Inferred,
    /// A template expression in the source could not be evaluated. `version`
    /// is `None`; the raw expression is in `ParsedRecipe::unresolved_expressions`.
    Unresolved,
}

/// One upstream source the recipe built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendoredComponent {
    pub name: String,
    pub version: Option<String>,
    /// `pkg:generic/<name>@<version>` when both are known and resolved.
    pub purl: Option<String>,
    pub source_url: Option<String>,
    pub git_url: Option<String>,
    pub git_rev: Option<String>,
    pub sha256: Option<String>,
    pub patches: Vec<String>,
    pub confidence: SourceConfidence,
    /// Owning output for multi-output recipes. `None` means the source is
    /// declared at the top level and shared by every output.
    pub output: Option<String>,
}

/// The recipe's `about:` block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeAbout {
    pub license: Option<String>,
    pub license_family: Option<String>,
    pub summary: Option<String>,
    pub home: Option<String>,
    pub dev_url: Option<String>,
}

/// Everything extracted from one recipe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedRecipe {
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub sources: Vec<VendoredComponent>,
    pub outputs: Vec<String>,
    pub about: RecipeAbout,
    /// Diagnostics: template expressions that could not be evaluated,
    /// control-flow tags that were skipped, platform selectors on source
    /// lines, and structural oddities. Never silently dropped.
    pub unresolved_expressions: Vec<String>,
}

/// Which recipe dialect a byte buffer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipeFormat {
    /// conda-build `meta.yaml` (Jinja2 + YAML).
    MetaYaml,
    /// rattler-build `recipe.yaml` (v1).
    RecipeYaml,
    /// rattler-build `rendered_recipe.yaml`: the fully evaluated recipe
    /// wrapped with build configuration and finalized sources.
    RenderedRecipeYaml,
}

/// The files a caller should look for inside `info/recipe/`, best source of
/// truth first: take the first one present.
///
/// A rendered file always beats a raw template: the builder has already
/// evaluated every template expression and applied the platform selectors,
/// so nothing is `Unresolved` and no other platform's sources leak in. The
/// two toolchains never ship each other's files, so the relative order of
/// `meta.yaml` and `recipe.yaml` only matters for a hand-assembled recipe
/// directory.
pub fn preferred_recipe_files() -> &'static [(&'static str, RecipeFormat)] {
    &[
        // rattler-build: evaluated recipe plus `finalized_sources`, the list
        // of what was actually fetched (git refs resolved to commits).
        ("rendered_recipe.yaml", RecipeFormat::RenderedRecipeYaml),
        // conda-build: despite the name this is the RENDERED recipe (Jinja
        // evaluated, selectors applied); the raw template is saved separately.
        ("meta.yaml", RecipeFormat::MetaYaml),
        // rattler-build: the raw v1 recipe. Only useful when a very old
        // rattler-build did not write the rendered file. Templates and
        // selectors are unevaluated.
        ("recipe.yaml", RecipeFormat::RecipeYaml),
        // conda-build: the raw Jinja template. Worst case: every platform
        // branch is emitted, so a Linux package lists Windows-only sources.
        ("meta.yaml.template", RecipeFormat::MetaYaml),
    ]
}

/// Errors from [`parse_recipe`]. Partially-resolvable templates are *not*
/// errors; they surface as diagnostics on the returned [`ParsedRecipe`].
#[derive(Debug, Error)]
pub enum RecipeError {
    #[error("recipe is empty")]
    Empty,
    #[error("recipe is {size} bytes, larger than the {max} byte limit")]
    TooLarge { size: usize, max: usize },
    #[error("recipe is not valid YAML after template preprocessing: {0}")]
    Yaml(String),
    #[error("recipe top level is not a mapping")]
    NotAMapping,
    #[error("rendered recipe has no `recipe:` mapping")]
    NoRecipeBlock,
}

/// Sniff which format a recipe is, from its bytes.
///
/// Returns `None` when the buffer does not look like a conda recipe at all.
/// Callers that know the filename (`meta.yaml` vs `recipe.yaml`) should
/// prefer that over sniffing: a rendered `meta.yaml` with no Jinja left in
/// it and a `recipe.yaml` with no `${{ }}` are only distinguishable by
/// their key vocabulary.
pub fn detect_format(bytes: &[u8]) -> Option<RecipeFormat> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
        return None;
    }
    let text = String::from_utf8_lossy(bytes);
    if text.contains('\u{0}') {
        return None;
    }
    // rattler-build's rendered output: the recipe nested under `recipe:`
    // next to build/finalization blocks that no hand-written recipe has.
    if re_top_key_recipe().is_match(&text) && re_top_key_rendered().is_match(&text) {
        return Some(RecipeFormat::RenderedRecipeYaml);
    }
    let has_jinja_tag = text.contains("{%");
    let has_jinja_expr = has_bare_double_brace(&text);
    if has_jinja_tag || has_jinja_expr {
        return Some(RecipeFormat::MetaYaml);
    }
    if text.contains("${{") || re_top_key_v1().is_match(&text) {
        return Some(RecipeFormat::RecipeYaml);
    }
    if !re_top_key_common().is_match(&text) {
        return None;
    }
    // Plain YAML either way: decide on the `about:` vocabulary.
    let v1_about = has_key(&text, &["homepage", "repository"]);
    let v0_about = has_key(&text, &["home", "dev_url", "doc_url"]);
    if v1_about && !v0_about {
        Some(RecipeFormat::RecipeYaml)
    } else {
        Some(RecipeFormat::MetaYaml)
    }
}

/// Parse a recipe. Never panics. Returns diagnostics rather than failing on
/// partially-resolvable templates.
///
/// Which file is fed in matters. Inside a package's `info/recipe/`:
///
/// * rattler-build ships `rendered_recipe.yaml` (templates evaluated,
///   selectors applied for the target platform, git refs resolved to commits)
///   next to the raw `recipe.yaml`. Prefer the rendered file.
/// * conda-build ships the *rendered* recipe as `meta.yaml` (Jinja evaluated,
///   selectors applied) and the raw template as `meta.yaml.template`. Prefer
///   `meta.yaml`. Selectors cannot be evaluated here, so feeding the template
///   emits every platform branch: a Linux package would list its
///   Windows-only sources.
///
/// [`preferred_recipe_files`] gives the lookup order.
pub fn parse_recipe(bytes: &[u8], format: RecipeFormat) -> Result<ParsedRecipe, RecipeError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(RecipeError::TooLarge {
            size: bytes.len(),
            max: MAX_INPUT_BYTES,
        });
    }
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return Err(RecipeError::Empty);
    }
    let mut diags = Diagnostics::default();
    let root = match format {
        RecipeFormat::MetaYaml => preprocess_meta_yaml(&text, &mut diags)?,
        RecipeFormat::RecipeYaml | RecipeFormat::RenderedRecipeYaml => {
            preprocess_recipe_yaml(&text, &mut diags)?
        }
    };
    let root = root.as_mapping().ok_or(RecipeError::NotAMapping)?;
    let mut recipe = match format {
        RecipeFormat::RenderedRecipeYaml => extract_rendered(root, &mut diags)?,
        _ => extract(root, &mut diags),
    };
    recipe.unresolved_expressions = diags.into_vec();
    Ok(recipe)
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Ordered, de-duplicated diagnostics.
#[derive(Default)]
struct Diagnostics {
    items: Vec<String>,
    seen: std::collections::HashSet<String>,
}

impl Diagnostics {
    fn push(&mut self, s: impl Into<String>) {
        let s = s.into();
        if self.seen.insert(s.clone()) {
            self.items.push(s);
        }
    }

    fn into_vec(self) -> Vec<String> {
        self.items
    }
}

// ---------------------------------------------------------------------------
// Regexes
// ---------------------------------------------------------------------------

macro_rules! regex {
    ($name:ident, $re:literal) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($re).expect("static regex is valid"))
        }
    };
}

regex!(re_jinja_comment, r"(?s)\{#.*?#\}");
regex!(
    re_jinja_set,
    r"(?s)\{%-?\s*set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*-?%\}"
);
regex!(re_jinja_tag, r"(?s)\{%-?\s*(.*?)\s*-?%\}");
regex!(re_jinja_expr, r"\{\{(.*?)\}\}");
regex!(re_v1_expr, r"\$\{\{(.*?)\}\}");
regex!(re_marker, r"__AK_UNRESOLVED_(\d+)__");
regex!(re_selector, r"^(.*?)\s+#\s*\[([^\]]*)\]\s*$");
regex!(
    re_source_line,
    r"^\s*(?:-\s+)?(?:url|git_url|git_rev|git|rev|tag|branch|path|sha256|md5|sha1|folder|fn|target_directory|patches):|^\s*-\s+\S+\.(?:patch|diff)$"
);
regex!(re_key_prefix, r"^([A-Za-z0-9_.\-/]+):(\s+)");
// Top-level keys both formats share, and keys only recipe.yaml v1 has.
regex!(
    re_top_key_common,
    r"(?m)^(package|source|outputs|build|requirements|about):"
);
regex!(re_top_key_v1, r"(?m)^(context|schema_version|recipe):");
regex!(re_top_key_recipe, r"(?m)^recipe:");
regex!(
    re_top_key_rendered,
    r"(?m)^(build_configuration|finalized_sources|finalized_dependencies):"
);
regex!(
    re_archive_ext,
    r"(?i)\.(?:tar\.(?:gz|bz2|xz|zst|lz|lzma|z)|tgz|tbz2?|txz|zip|tar|7z|gz|bz2|xz|whl|jar|crate|gem|exe|msi|dmg|deb|rpm)$"
);
regex!(re_pure_version, r"^v?(\d+(?:[.\-_+~]?[A-Za-z0-9]+)*)$");
regex!(
    re_name_version,
    r"^(.+?)[-_]v?(\d+(?:[.\-_+~]?[A-Za-z0-9]+)*)$"
);
regex!(re_template_chunk, r"\$?\{\{.*?\}\}");
regex!(re_hex, r"^[0-9a-fA-F]+$");

fn has_bare_double_brace(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(pos) = text[i..].find("{{") {
        let at = i + pos;
        if at == 0 || bytes[at - 1] != b'$' {
            return true;
        }
        i = at + 2;
    }
    false
}

fn has_key(text: &str, keys: &[&str]) -> bool {
    text.lines().any(|l| {
        let t = l.trim_start();
        keys.iter()
            .any(|k| t.starts_with(k) && t[k.len()..].starts_with(':'))
    })
}

fn yaml_from_str(s: &str) -> Result<Value, RecipeError> {
    serde_yaml::from_str::<Value>(s).map_err(|e| RecipeError::Yaml(e.to_string()))
}

// ---------------------------------------------------------------------------
// meta.yaml (Jinja2) preprocessing
// ---------------------------------------------------------------------------

/// Turn a Jinja-templated `meta.yaml` into a YAML value.
///
/// Pipeline: strip `{# #}` comments; evaluate and remove `{% set %}`; strip
/// every other `{% %}` tag (control flow we cannot evaluate, recorded as a
/// diagnostic); then per line: strip `# [selector]`, substitute `{{ }}`
/// (unresolvable expressions become opaque markers), and quote scalars that
/// YAML would otherwise turn into numbers. After parsing, markers are
/// restored to their original `{{ expr }}` text so consumers see what was
/// there.
fn preprocess_meta_yaml(text: &str, diags: &mut Diagnostics) -> Result<Value, RecipeError> {
    let text = re_jinja_comment().replace_all(text, "");

    let mut env = Env::default();
    let text = re_jinja_set().replace_all(&text, |caps: &regex::Captures| {
        let name = caps[1].to_string();
        let expr = caps[2].to_string();
        match eval_expr(&expr, &env) {
            Ok(v) => {
                env.vars.insert(name, v);
            }
            Err(e) => diags.push(format!("{{% set {name} = {expr} %}} ({e})")),
        }
        String::new()
    });

    let text = re_jinja_tag().replace_all(&text, |caps: &regex::Captures| {
        diags.push(format!("{{% {} %}}", caps[1].trim()));
        String::new()
    });

    let mut markers: Vec<String> = Vec::new();
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let (line, selector) = split_selector(line);
        if let Some(sel) = selector {
            if re_source_line().is_match(line) {
                diags.push(format!("# [{sel}] on: {}", line.trim()));
            }
        }
        let line = re_jinja_expr().replace_all(line, |caps: &regex::Captures| {
            let expr = caps[1].trim();
            match eval_expr(expr, &env) {
                Ok(Val::Str(s)) => Ok(s),
                Ok(Val::List(_)) => Err(EvalErr::Unsupported("list value".into())),
                Err(e) => Err(e),
            }
            .unwrap_or_else(|e| {
                let raw = format!("{{{{ {expr} }}}}");
                diags.push(format!("{raw} ({e})"));
                markers.push(raw);
                format!("__AK_UNRESOLVED_{}__", markers.len() - 1)
            })
        });
        out.push_str(&protect_scalar(&line));
        out.push('\n');
    }

    let mut value = yaml_from_str(&out)?;
    if !markers.is_empty() {
        walk_strings(&mut value, &mut |s: &mut String| {
            if s.contains("__AK_UNRESOLVED_") {
                *s = re_marker()
                    .replace_all(s, |caps: &regex::Captures| {
                        caps[1]
                            .parse::<usize>()
                            .ok()
                            .and_then(|i| markers.get(i).cloned())
                            .unwrap_or_else(|| caps[0].to_string())
                    })
                    .into_owned();
            }
        });
    }
    Ok(value)
}

/// Split a trailing conda selector comment (`# [linux]`) off a line.
fn split_selector(line: &str) -> (&str, Option<&str>) {
    match re_selector().captures(line) {
        Some(caps) => {
            let body_len = caps.get(1).map(|m| m.end()).unwrap_or(0);
            let sel = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            (&line[..body_len], Some(sel))
        }
        None => (line, None),
    }
}

/// Quote a plain scalar value when YAML would otherwise read it as a number.
/// conda-build's `StringifyNumbersLoader` and rattler-build both keep numeric
/// scalars as strings, so `version: 1.10` must stay `"1.10"`, not become the
/// float `1.1`. Nulls and bools are left alone: `null` must stay null.
///
/// Values that already start with a YAML indicator (quotes, flow
/// collections, block scalars, anchors, tags) are left alone.
fn protect_scalar(line: &str) -> String {
    // Separate a trailing comment. Plain scalars cannot contain " #".
    let (body, comment) = match line.find(" #") {
        Some(i) if !line.trim_start().starts_with('#') => (&line[..i], &line[i..]),
        _ => {
            if line.trim_start().starts_with('#') {
                return line.to_string();
            }
            (line, "")
        }
    };
    let indent_len = body.len() - body.trim_start().len();
    let mut prefix = String::from(&body[..indent_len]);
    let mut rest = &body[indent_len..];

    let mut in_value_position = false;
    if let Some(after) = rest.strip_prefix('-') {
        if after.starts_with(' ') || after.starts_with('\t') {
            let ws_len = after.len() - after.trim_start().len();
            prefix.push('-');
            prefix.push_str(&after[..ws_len]);
            rest = &after[ws_len..];
            in_value_position = true;
        }
    }
    if let Some(caps) = re_key_prefix().captures(rest) {
        let full = caps.get(0).map(|m| m.end()).unwrap_or(0);
        prefix.push_str(&rest[..full]);
        rest = &rest[full..];
        in_value_position = true;
    }
    if !in_value_position {
        return line.to_string();
    }
    let value = rest.trim_end();
    if value.is_empty() {
        return line.to_string();
    }
    let first = value.chars().next().unwrap_or(' ');
    if "\"'[{|>&*!%@`".contains(first) {
        return line.to_string();
    }
    if value.contains(": ") || value.ends_with(':') || value.starts_with("- ") || value == "-" {
        return line.to_string();
    }
    if !parses_as_number(value) {
        return line.to_string();
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    format!("{prefix}{quoted}{comment}")
}

fn parses_as_number(value: &str) -> bool {
    let first = value.chars().next().unwrap_or(' ');
    if !(first.is_ascii_digit() || "+-.".contains(first)) {
        return false;
    }
    matches!(serde_yaml::from_str::<Value>(value), Ok(Value::Number(_)))
}

/// Apply `f` to every string scalar in the tree (values only, not keys).
/// serde_yaml caps nesting at 128, so recursion here is bounded.
fn walk_strings(value: &mut Value, f: &mut dyn FnMut(&mut String)) {
    match value {
        Value::String(s) => f(s),
        Value::Sequence(seq) => seq.iter_mut().for_each(|v| walk_strings(v, f)),
        Value::Mapping(map) => map.iter_mut().for_each(|(_, v)| walk_strings(v, f)),
        Value::Tagged(t) => walk_strings(&mut t.value, f),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// recipe.yaml (v1) preprocessing
// ---------------------------------------------------------------------------

/// Parse a rattler-build `recipe.yaml`: real YAML, `context:` bindings,
/// `${{ }}` expressions in string scalars. Unresolvable expressions are left
/// verbatim (and recorded) so they are visible downstream.
fn preprocess_recipe_yaml(text: &str, diags: &mut Diagnostics) -> Result<Value, RecipeError> {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        out.push_str(&protect_scalar(line));
        out.push('\n');
    }
    let mut value = yaml_from_str(&out)?;

    let mut env = Env::default();
    if let Some(ctx) = value.get("context").and_then(Value::as_mapping) {
        for (k, v) in ctx {
            let Some(key) = k.as_str() else { continue };
            match v {
                Value::String(s) => {
                    let (resolved, unresolved) = substitute_v1(s, &env, diags);
                    if !unresolved {
                        env.vars.insert(key.to_string(), Val::Str(resolved));
                    }
                }
                Value::Number(n) => {
                    env.vars.insert(key.to_string(), Val::Str(n.to_string()));
                }
                Value::Bool(b) => {
                    env.vars.insert(key.to_string(), Val::Str(b.to_string()));
                }
                Value::Sequence(seq) => {
                    let items: Option<Vec<String>> = seq.iter().map(scalar_to_string).collect();
                    if let Some(items) = items {
                        env.vars.insert(key.to_string(), Val::List(items));
                    } else {
                        diags.push(format!("context.{key}: unsupported list contents"));
                    }
                }
                _ => diags.push(format!("context.{key}: unsupported value type")),
            }
        }
    }

    walk_strings(&mut value, &mut |s: &mut String| {
        if s.contains("${{") {
            *s = substitute_v1(s, &env, diags).0;
        }
    });
    Ok(value)
}

/// Substitute `${{ expr }}` occurrences. Returns the new string and whether
/// anything was left unresolved.
fn substitute_v1(s: &str, env: &Env, diags: &mut Diagnostics) -> (String, bool) {
    let mut unresolved = false;
    let out = re_v1_expr().replace_all(s, |caps: &regex::Captures| {
        let expr = caps[1].trim();
        match eval_expr(expr, env) {
            Ok(Val::Str(v)) => Ok(v),
            Ok(Val::List(_)) => Err(EvalErr::Unsupported("list value".into())),
            Err(e) => Err(e),
        }
        .unwrap_or_else(|e| {
            unresolved = true;
            let raw = format!("${{{{ {expr} }}}}");
            diags.push(format!("{raw} ({e})"));
            raw
        })
    });
    (out.into_owned(), unresolved)
}

// ---------------------------------------------------------------------------
// Template expression evaluator (Jinja2 / minijinja subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Val {
    Str(String),
    List(Vec<String>),
}

#[derive(Default)]
struct Env {
    vars: HashMap<String, Val>,
}

/// Why an expression could not be evaluated. Rendered into the diagnostic
/// so a reader can tell "undefined variable" from "unsupported function".
#[derive(Debug)]
enum EvalErr {
    Undefined(String),
    Unsupported(String),
    Syntax,
    TooDeep,
}

impl std::fmt::Display for EvalErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalErr::Undefined(name) => write!(f, "undefined variable {name}"),
            EvalErr::Unsupported(what) => write!(f, "unsupported: {what}"),
            EvalErr::Syntax => f.write_str("syntax not understood"),
            EvalErr::TooDeep => f.write_str("expression nested too deeply"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Str(String),
    Num(String),
    Ident(String),
    Punct(char),
}

fn tokenize(s: &str) -> Result<Vec<Tok>, EvalErr> {
    let mut toks = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '"' || c == '\'' {
            let quote = c;
            i += 1;
            let mut lit = String::new();
            let mut closed = false;
            while i < chars.len() {
                let d = chars[i];
                if d == '\\' && i + 1 < chars.len() {
                    let e = chars[i + 1];
                    lit.push(match e {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    });
                    i += 2;
                } else if d == quote {
                    closed = true;
                    i += 1;
                    break;
                } else {
                    lit.push(d);
                    i += 1;
                }
            }
            if !closed {
                return Err(EvalErr::Syntax);
            }
            toks.push(Tok::Str(lit));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            toks.push(Tok::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            toks.push(Tok::Num(chars[start..i].iter().collect()));
        } else if "|.[]():,+~=-*/<>!%{}".contains(c) {
            toks.push(Tok::Punct(c));
            i += 1;
        } else {
            return Err(EvalErr::Syntax);
        }
    }
    Ok(toks)
}

fn eval_expr(expr: &str, env: &Env) -> Result<Val, EvalErr> {
    let toks = tokenize(expr)?;
    if toks.is_empty() {
        return Err(EvalErr::Syntax);
    }
    let mut p = Parser { toks, pos: 0, env };
    let v = p.expr(0)?;
    if p.pos != p.toks.len() {
        return Err(EvalErr::Syntax);
    }
    Ok(v)
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    env: &'a Env,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_at(&self, off: usize) -> Option<&Tok> {
        self.toks.get(self.pos + off)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, c: char) -> Result<(), EvalErr> {
        match self.next() {
            Some(Tok::Punct(p)) if p == c => Ok(()),
            _ => Err(EvalErr::Syntax),
        }
    }

    fn is_punct(&self, c: char) -> bool {
        matches!(self.peek(), Some(Tok::Punct(p)) if *p == c)
    }

    fn expr(&mut self, depth: usize) -> Result<Val, EvalErr> {
        if depth > MAX_EXPR_DEPTH {
            return Err(EvalErr::TooDeep);
        }
        let mut left = self.term(depth)?;
        while self.is_punct('+') || self.is_punct('~') {
            self.pos += 1;
            let right = self.term(depth)?;
            left = match (left, right) {
                (Val::Str(a), Val::Str(b)) => Val::Str(a + &b),
                _ => return Err(EvalErr::Unsupported("list concatenation".into())),
            };
        }
        Ok(left)
    }

    fn term(&mut self, depth: usize) -> Result<Val, EvalErr> {
        let v = match self.primary(depth) {
            Ok(v) => v,
            Err(EvalErr::Undefined(name)) => {
                // `undefined|default(x)` is the one place an undefined name
                // is legitimately fine.
                let is_default = self.is_punct('|')
                    && matches!(self.peek_at(1), Some(Tok::Ident(f)) if f == "default");
                if !is_default {
                    return Err(EvalErr::Undefined(name));
                }
                self.pos += 2;
                let args = self.args(depth)?;
                args.into_iter().next().ok_or(EvalErr::Syntax)?
            }
            Err(e) => return Err(e),
        };
        self.postfix(v, depth)
    }

    fn primary(&mut self, depth: usize) -> Result<Val, EvalErr> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(Val::Str(s)),
            Some(Tok::Num(n)) => Ok(Val::Str(n)),
            Some(Tok::Ident(name)) => {
                if self.is_punct('(') {
                    return Err(EvalErr::Unsupported(format!("function {name}()")));
                }
                self.env
                    .vars
                    .get(&name)
                    .cloned()
                    .ok_or(EvalErr::Undefined(name))
            }
            Some(Tok::Punct('(')) => {
                let v = self.expr(depth + 1)?;
                self.expect(')')?;
                Ok(v)
            }
            Some(Tok::Punct('[')) => {
                let mut items = Vec::new();
                loop {
                    if self.is_punct(']') {
                        self.pos += 1;
                        break;
                    }
                    match self.expr(depth + 1)? {
                        Val::Str(s) => items.push(s),
                        Val::List(_) => return Err(EvalErr::Unsupported("nested list".into())),
                    }
                    if self.is_punct(',') {
                        self.pos += 1;
                    } else {
                        self.expect(']')?;
                        break;
                    }
                }
                Ok(Val::List(items))
            }
            Some(Tok::Punct('-')) => match self.next() {
                Some(Tok::Num(n)) => Ok(Val::Str(format!("-{n}"))),
                _ => Err(EvalErr::Syntax),
            },
            _ => Err(EvalErr::Syntax),
        }
    }

    fn postfix(&mut self, mut v: Val, depth: usize) -> Result<Val, EvalErr> {
        loop {
            match self.peek() {
                Some(Tok::Punct('[')) => {
                    self.pos += 1;
                    v = self.index(v, depth)?;
                }
                Some(Tok::Punct('.')) => {
                    self.pos += 1;
                    let Some(Tok::Ident(name)) = self.next() else {
                        return Err(EvalErr::Syntax);
                    };
                    if !self.is_punct('(') {
                        return Err(EvalErr::Unsupported(format!("attribute .{name}")));
                    }
                    let args = self.args(depth)?;
                    v = apply_method(v, &name, args)?;
                }
                Some(Tok::Punct('|')) => {
                    self.pos += 1;
                    let Some(Tok::Ident(name)) = self.next() else {
                        return Err(EvalErr::Syntax);
                    };
                    let args = if self.is_punct('(') {
                        self.args(depth)?
                    } else {
                        Vec::new()
                    };
                    v = apply_filter(v, &name, args)?;
                }
                _ => return Ok(v),
            }
        }
    }

    fn args(&mut self, depth: usize) -> Result<Vec<Val>, EvalErr> {
        self.expect('(')?;
        let mut args = Vec::new();
        loop {
            if self.is_punct(')') {
                self.pos += 1;
                return Ok(args);
            }
            if matches!(self.peek(), Some(Tok::Ident(_)))
                && matches!(self.peek_at(1), Some(Tok::Punct('=')))
            {
                return Err(EvalErr::Unsupported("keyword argument".into()));
            }
            args.push(self.expr(depth + 1)?);
            if self.is_punct(',') {
                self.pos += 1;
            } else {
                self.expect(')')?;
                return Ok(args);
            }
        }
    }

    /// `[i]`, `[a:b]`, `[:b]`, `[a:]` with Python semantics. Opening `[` is
    /// already consumed.
    fn index(&mut self, v: Val, depth: usize) -> Result<Val, EvalErr> {
        let lo = if self.is_punct(':') {
            None
        } else {
            Some(to_int(&self.expr(depth + 1)?)?)
        };
        let is_slice = self.is_punct(':');
        let hi = if is_slice {
            self.pos += 1;
            if self.is_punct(']') {
                None
            } else {
                Some(to_int(&self.expr(depth + 1)?)?)
            }
        } else {
            None
        };
        self.expect(']')?;

        let items: Vec<String> = match &v {
            Val::Str(s) => s.chars().map(|c| c.to_string()).collect(),
            Val::List(l) => l.clone(),
        };
        let len = items.len() as i64;
        if is_slice {
            let norm = |x: Option<i64>, default: i64| -> usize {
                let x = x.unwrap_or(default);
                let x = if x < 0 { len + x } else { x };
                x.clamp(0, len) as usize
            };
            let a = norm(lo, 0);
            let b = norm(hi, len);
            let slice: Vec<String> = if a < b {
                items[a..b].to_vec()
            } else {
                Vec::new()
            };
            Ok(match v {
                Val::Str(_) => Val::Str(slice.concat()),
                Val::List(_) => Val::List(slice),
            })
        } else {
            let i = lo.ok_or(EvalErr::Syntax)?;
            let i = if i < 0 { len + i } else { i };
            if i < 0 || i >= len {
                return Err(EvalErr::Unsupported("index out of range".into()));
            }
            Ok(Val::Str(items[i as usize].clone()))
        }
    }
}

fn to_int(v: &Val) -> Result<i64, EvalErr> {
    match v {
        Val::Str(s) => s
            .trim()
            .parse::<i64>()
            .map_err(|_| EvalErr::Unsupported(format!("non-integer index {s:?}"))),
        Val::List(_) => Err(EvalErr::Unsupported("list as index".into())),
    }
}

fn arg_str(args: &[Val], i: usize) -> Result<&str, EvalErr> {
    match args.get(i) {
        Some(Val::Str(s)) => Ok(s),
        _ => Err(EvalErr::Syntax),
    }
}

fn apply_method(v: Val, name: &str, args: Vec<Val>) -> Result<Val, EvalErr> {
    let Val::Str(s) = v else {
        return Err(EvalErr::Unsupported(format!("list method .{name}()")));
    };
    Ok(match name {
        "lower" => Val::Str(s.to_lowercase()),
        "upper" => Val::Str(s.to_uppercase()),
        "strip" => Val::Str(s.trim().to_string()),
        "lstrip" => Val::Str(s.trim_start().to_string()),
        "rstrip" => Val::Str(s.trim_end().to_string()),
        "title" | "capitalize" => Val::Str(capitalize(&s)),
        "split" => Val::List(match args.first() {
            None => s.split_whitespace().map(str::to_string).collect(),
            Some(_) => s.split(arg_str(&args, 0)?).map(str::to_string).collect(),
        }),
        "replace" => Val::Str(s.replace(arg_str(&args, 0)?, arg_str(&args, 1)?)),
        "join" => match args.first() {
            Some(Val::List(items)) => Val::Str(items.join(&s)),
            _ => return Err(EvalErr::Syntax),
        },
        other => return Err(EvalErr::Unsupported(format!("method .{other}()"))),
    })
}

fn apply_filter(v: Val, name: &str, args: Vec<Val>) -> Result<Val, EvalErr> {
    Ok(match (name, v) {
        ("default", v) => v,
        ("lower", Val::Str(s)) => Val::Str(s.to_lowercase()),
        ("upper", Val::Str(s)) => Val::Str(s.to_uppercase()),
        ("trim", Val::Str(s)) => Val::Str(s.trim().to_string()),
        ("title" | "capitalize", Val::Str(s)) => Val::Str(capitalize(&s)),
        ("string", v) => v,
        ("int", Val::Str(s)) => Val::Str(
            s.trim()
                .parse::<i64>()
                .map_err(|_| EvalErr::Unsupported("int of non-integer".into()))?
                .to_string(),
        ),
        ("replace", Val::Str(s)) => Val::Str(s.replace(arg_str(&args, 0)?, arg_str(&args, 1)?)),
        ("split", Val::Str(s)) => Val::List(match args.first() {
            None => s.split_whitespace().map(str::to_string).collect(),
            Some(_) => s.split(arg_str(&args, 0)?).map(str::to_string).collect(),
        }),
        ("join", Val::List(items)) => Val::Str(
            items.join(
                args.first()
                    .map(|_| arg_str(&args, 0))
                    .transpose()?
                    .unwrap_or(""),
            ),
        ),
        ("first", Val::List(items)) => Val::Str(items.into_iter().next().ok_or(EvalErr::Syntax)?),
        ("last", Val::List(items)) => Val::Str(items.into_iter().last().ok_or(EvalErr::Syntax)?),
        ("first", Val::Str(s)) => Val::Str(
            s.chars()
                .next()
                .map(|c| c.to_string())
                .ok_or(EvalErr::Syntax)?,
        ),
        ("last", Val::Str(s)) => Val::Str(
            s.chars()
                .last()
                .map(|c| c.to_string())
                .ok_or(EvalErr::Syntax)?,
        ),
        ("length" | "count", Val::Str(s)) => Val::Str(s.chars().count().to_string()),
        ("length" | "count", Val::List(items)) => Val::Str(items.len().to_string()),
        ("list", Val::Str(s)) => Val::List(s.chars().map(|c| c.to_string()).collect()),
        ("list", v @ Val::List(_)) => v,
        (other, _) => return Err(EvalErr::Unsupported(format!("filter |{other}"))),
    })
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Extraction from the parsed YAML tree
// ---------------------------------------------------------------------------

/// A string scalar that still carries template syntax could not be resolved.
fn is_unresolved(s: &str) -> bool {
    s.contains("{{")
}

fn scalar_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn get_str(m: &Mapping, key: &str) -> Option<String> {
    m.get(key).and_then(scalar_to_string)
}

/// A string field, or `None` if missing or unresolved.
fn get_resolved(m: &Mapping, key: &str) -> Option<String> {
    get_str(m, key).filter(|s| !is_unresolved(s))
}

fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Sequence(_) => "list",
        Value::Mapping(_) => "mapping",
        Value::Tagged(_) => "tagged value",
    }
}

/// The package the sources are being compared against: the top-level
/// `package:` or, inside `outputs:`, that output's own name/version.
#[derive(Clone, Default)]
struct PkgCtx {
    name: Option<String>,
    version: Option<String>,
    /// Normalized git URL -> rev from `recipe.source` in a rendered recipe,
    /// used to recover a tag after `finalized_sources` replaced it with the
    /// resolved commit.
    git_rev_hints: HashMap<String, String>,
}

fn extract(root: &Mapping, diags: &mut Diagnostics) -> ParsedRecipe {
    // v1 multi-output recipes use `recipe:` instead of `package:`.
    let pkg = root
        .get("package")
        .and_then(Value::as_mapping)
        .or_else(|| root.get("recipe").and_then(Value::as_mapping));
    let package_name = pkg.and_then(|m| get_resolved(m, "name"));
    let package_version = pkg.and_then(|m| get_resolved(m, "version"));
    let ctx = PkgCtx {
        name: package_name.clone(),
        version: package_version.clone(),
        git_rev_hints: HashMap::new(),
    };

    let mut sources = Vec::new();
    if let Some(src) = root.get("source") {
        collect_sources(src, None, &ctx, diags, &mut sources);
    }

    let mut outputs = Vec::new();
    match root.get("outputs") {
        None | Some(Value::Null) => {}
        Some(Value::Sequence(items)) => {
            for item in items {
                let Some(m) = item.as_mapping() else {
                    diags.push(format!(
                        "outputs: entry is a {}, expected mapping",
                        kind_of(item)
                    ));
                    continue;
                };
                // v0: `name:`/`version:`; v1: `package: {name, version}`.
                let v1_pkg = m.get("package").and_then(Value::as_mapping);
                let name = v1_pkg
                    .and_then(|p| get_str(p, "name"))
                    .or_else(|| get_str(m, "name"));
                let version = v1_pkg
                    .and_then(|p| get_resolved(p, "version"))
                    .or_else(|| get_resolved(m, "version"))
                    .or_else(|| ctx.version.clone());
                let Some(name) = name else {
                    diags.push("outputs: entry without a name".to_string());
                    continue;
                };
                let out_ctx = PkgCtx {
                    name: if is_unresolved(&name) {
                        None
                    } else {
                        Some(name.clone())
                    },
                    version,
                    git_rev_hints: HashMap::new(),
                };
                if let Some(src) = m.get("source") {
                    collect_sources(src, Some(&name), &out_ctx, diags, &mut sources);
                }
                outputs.push(name);
            }
        }
        Some(other) => diags.push(format!(
            "outputs: expected a list, found {}",
            kind_of(other)
        )),
    }

    let about = match root.get("about") {
        Some(Value::Mapping(m)) => RecipeAbout {
            license: get_resolved(m, "license"),
            license_family: get_resolved(m, "license_family"),
            summary: get_resolved(m, "summary"),
            home: get_resolved(m, "home").or_else(|| get_resolved(m, "homepage")),
            dev_url: get_resolved(m, "dev_url").or_else(|| get_resolved(m, "repository")),
        },
        Some(Value::Null) | None => RecipeAbout::default(),
        Some(other) => {
            diags.push(format!(
                "about: expected a mapping, found {}",
                kind_of(other)
            ));
            RecipeAbout::default()
        }
    };

    ParsedRecipe {
        package_name,
        package_version,
        sources,
        outputs,
        about,
        unresolved_expressions: Vec::new(),
    }
}

/// rattler-build `rendered_recipe.yaml`: the evaluated recipe lives under
/// `recipe:`; `finalized_sources:` (when present) is the list of sources as
/// actually fetched and is preferred over `recipe.source`.
fn extract_rendered(root: &Mapping, diags: &mut Diagnostics) -> Result<ParsedRecipe, RecipeError> {
    let inner = root
        .get("recipe")
        .and_then(Value::as_mapping)
        .ok_or(RecipeError::NoRecipeBlock)?;
    let mut recipe = extract(inner, diags);

    match root.get("finalized_sources") {
        None | Some(Value::Null) => {}
        Some(Value::Sequence(items)) if items.is_empty() => {}
        Some(finalized @ Value::Sequence(_)) => {
            // fetch_sources rewrites git refs to the resolved commit, so the
            // tag that carries the version survives only in recipe.source.
            let git_rev_hints = recipe
                .sources
                .iter()
                .filter_map(|c| Some((norm_git_url(c.git_url.as_deref()?), c.git_rev.clone()?)))
                .collect();
            let ctx = PkgCtx {
                name: recipe.package_name.clone(),
                version: recipe.package_version.clone(),
                git_rev_hints,
            };
            let mut sources = Vec::new();
            collect_sources(finalized, None, &ctx, diags, &mut sources);
            if !sources.is_empty() {
                recipe.sources = sources;
            }
        }
        Some(other) => diags.push(format!(
            "finalized_sources: expected a list, found {}; using recipe.source",
            kind_of(other)
        )),
    }
    Ok(recipe)
}

fn norm_git_url(url: &str) -> String {
    url.trim()
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_string()
}

/// Walk a `source:` value (mapping, list of mappings, or v1 `if/then/else`
/// wrappers) and append one component per concrete source.
fn collect_sources(
    v: &Value,
    output: Option<&str>,
    ctx: &PkgCtx,
    diags: &mut Diagnostics,
    out: &mut Vec<VendoredComponent>,
) {
    match v {
        Value::Null => {}
        Value::Mapping(m) => {
            if let Some(branches) = if_then_else(m, diags) {
                for b in branches {
                    collect_sources(b, output, ctx, diags, out);
                }
            } else if let Some(c) = component_from_source(m, output, ctx, diags) {
                out.push(c);
            }
        }
        Value::Sequence(items) => {
            for item in items {
                match item {
                    Value::Mapping(_) => collect_sources(item, output, ctx, diags, out),
                    other => diags.push(format!(
                        "source: entry is a {}, expected mapping",
                        kind_of(other)
                    )),
                }
            }
        }
        other => diags.push(format!(
            "source: expected a mapping or list, found {}",
            kind_of(other)
        )),
    }
}

/// rattler-build conditional: `{if: <sel>, then: X, else: Y}`. We cannot
/// evaluate selectors, so both branches are returned and the condition is
/// recorded.
fn if_then_else<'a>(m: &'a Mapping, diags: &mut Diagnostics) -> Option<Vec<&'a Value>> {
    let cond = m.get("if")?;
    if !m.contains_key("then") {
        return None;
    }
    diags.push(format!(
        "if: {}",
        scalar_to_string(cond).unwrap_or_else(|| "<non-scalar condition>".into())
    ));
    let mut branches = Vec::new();
    for key in ["then", "else"] {
        match m.get(key) {
            Some(Value::Sequence(items)) => branches.extend(items.iter()),
            Some(Value::Null) | None => {}
            Some(other) => branches.push(other),
        }
    }
    Some(branches)
}

fn collect_patches(v: &Value, diags: &mut Diagnostics, out: &mut Vec<String>) {
    match v {
        Value::Null => {}
        Value::Sequence(items) => items.iter().for_each(|i| collect_patches(i, diags, out)),
        Value::Mapping(m) => match if_then_else(m, diags) {
            Some(branches) => branches.iter().for_each(|b| collect_patches(b, diags, out)),
            None => diags.push("patches: entry is a mapping, expected string".to_string()),
        },
        other => match scalar_to_string(other) {
            Some(s) if !s.is_empty() => out.push(s),
            _ => diags.push(format!("patches: entry is a {}", kind_of(other))),
        },
    }
}

fn component_from_source(
    m: &Mapping,
    output: Option<&str>,
    ctx: &PkgCtx,
    diags: &mut Diagnostics,
) -> Option<VendoredComponent> {
    // `url:` may be a list of mirrors; the first one is canonical.
    let source_url = match m.get("url") {
        Some(Value::Sequence(items)) => items.first().and_then(scalar_to_string),
        Some(other) => scalar_to_string(other),
        None => None,
    }
    .or_else(|| get_str(m, "hg_url"))
    .or_else(|| get_str(m, "svn_url"));
    // v0: git_url/git_rev. v1: git + rev|tag|branch.
    let git_url = get_str(m, "git_url").or_else(|| get_str(m, "git"));
    let git_rev = get_str(m, "git_rev")
        .or_else(|| get_str(m, "rev"))
        .or_else(|| get_str(m, "tag"))
        .or_else(|| get_str(m, "branch"));
    let path = get_str(m, "path");
    let folder = get_str(m, "folder").or_else(|| get_str(m, "target_directory"));
    // v0 `fn:` / v1 `file_name:` name the downloaded file, which is often
    // more informative than a URL like `.../download?id=42`.
    let file_name = get_str(m, "fn")
        .or_else(|| get_str(m, "file_name"))
        .filter(|f| !is_unresolved(f));
    let sha256 = get_resolved(m, "sha256").map(|s| s.to_ascii_lowercase());

    let mut patches = Vec::new();
    if let Some(p) = m.get("patches") {
        collect_patches(p, diags, &mut patches);
    }

    if source_url.is_none() && git_url.is_none() && path.is_none() {
        diags.push(format!(
            "source: entry has no url/git_url/path (keys: {})",
            m.keys()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        return None;
    }

    let unresolved = source_url.as_deref().is_some_and(is_unresolved)
        || git_url.as_deref().is_some_and(is_unresolved)
        || git_rev.as_deref().is_some_and(is_unresolved)
        || path.as_deref().is_some_and(is_unresolved);

    let (name, version, confidence) = if unresolved {
        let hint = source_url
            .as_deref()
            .or(git_url.as_deref())
            .and_then(name_hint_from_template_url);
        let name = hint
            .or_else(|| folder.clone())
            .or_else(|| ctx.name.clone())
            .unwrap_or_else(|| "unknown".to_string());
        (name, None, SourceConfidence::Unresolved)
    } else if let Some(url) = source_url.as_deref() {
        let (mut name, mut ver) = infer_from_url(url);
        if ver.is_none() {
            if let Some((fn_name, Some(fn_ver))) = file_name.as_deref().map(infer_from_basename) {
                name = fn_name.or(name);
                ver = Some(fn_ver);
            }
        }
        identify(name, ver, folder.as_deref(), ctx, true)
    } else if let Some(git) = git_url.as_deref() {
        let repo = repo_name_from_git_url(git);
        let ver = git_rev.as_deref().and_then(version_from_rev).or_else(|| {
            ctx.git_rev_hints
                .get(&norm_git_url(git))
                .and_then(|r| version_from_rev(r))
        });
        // A branch or commit hash is explicitly not a release: never borrow
        // the package version for it.
        identify(repo, ver, folder.as_deref(), ctx, false)
    } else {
        // Local path: the recipe's own source tree, i.e. the package itself.
        let name = ctx
            .name
            .clone()
            .or_else(|| folder.clone())
            .unwrap_or_else(|| "local-source".to_string());
        (name, ctx.version.clone(), SourceConfidence::Inferred)
    };

    let purl = match (&version, &confidence) {
        (Some(v), SourceConfidence::Declared | SourceConfidence::Inferred) => Some(format!(
            "pkg:generic/{}@{}",
            purl_encode(&name),
            purl_encode(v)
        )),
        _ => None,
    };

    Some(VendoredComponent {
        name,
        version,
        purl,
        source_url,
        git_url,
        git_rev,
        sha256,
        patches,
        confidence,
        output: output.map(str::to_string),
    })
}

/// Decide the component identity from what the locator says versus what the
/// recipe declares. Declared only when the locator corroborates the recipe.
///
/// `borrow_ctx_version`: when the locator names the package but carries no
/// version at all (`foo.tar.gz`), fall back to the recipe's version as an
/// `Inferred` guess. Off for git refs, where "no version" means a branch or
/// commit rather than an unversioned release.
fn identify(
    loc_name: Option<String>,
    loc_ver: Option<String>,
    folder: Option<&str>,
    ctx: &PkgCtx,
    borrow_ctx_version: bool,
) -> (String, Option<String>, SourceConfidence) {
    let names_match = match (&loc_name, &ctx.name) {
        (Some(a), Some(b)) => norm_name(a) == norm_name(b),
        _ => false,
    };
    let vers_match = match (&loc_ver, &ctx.version) {
        (Some(a), Some(b)) => norm_version(a) == norm_version(b),
        _ => false,
    };
    if names_match && vers_match {
        return (
            ctx.name.clone().unwrap_or_default(),
            ctx.version.clone(),
            SourceConfidence::Declared,
        );
    }
    match (loc_name, loc_ver) {
        (Some(n), Some(v)) => (n, Some(v), SourceConfidence::Inferred),
        (Some(n), None) if names_match && borrow_ctx_version => {
            (n, ctx.version.clone(), SourceConfidence::Inferred)
        }
        (Some(n), None) => (n, None, SourceConfidence::Inferred),
        (None, v) => {
            let n = folder
                .map(str::to_string)
                .or_else(|| ctx.name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            (n, v, SourceConfidence::Inferred)
        }
    }
}

fn norm_name(s: &str) -> String {
    s.trim()
        .trim_end_matches(".git")
        .to_ascii_lowercase()
        .replace('_', "-")
}

fn norm_version(s: &str) -> String {
    s.trim()
        .trim_start_matches('v')
        .to_ascii_lowercase()
        .replace('_', ".")
}

/// Path segments that are never a project name.
fn is_noise_segment(seg: &str) -> bool {
    const NOISE: &[&str] = &[
        "",
        "archive",
        "archives",
        "refs",
        "tags",
        "tag",
        "heads",
        "releases",
        "release",
        "download",
        "downloads",
        "files",
        "file",
        "src",
        "source",
        "sources",
        "dist",
        "get",
        "snapshot",
        "main",
        "master",
        "head",
        "trunk",
        "develop",
        "dev",
        "-",
        "+archive",
    ];
    NOISE.contains(&seg.to_ascii_lowercase().as_str()) || re_pure_version().is_match(seg)
}

/// Trailing basename chunks that are packaging noise, not part of a version.
fn is_noise_version_chunk(chunk: &str) -> bool {
    const NOISE: &[&str] = &[
        "src", "source", "sources", "orig", "release", "stable", "full", "bin", "binary", "dist",
        "win", "win32", "win64", "linux", "macos", "osx", "darwin", "amd64", "arm64", "x64", "x86",
    ];
    NOISE.contains(&chunk.to_ascii_lowercase().as_str())
}

/// Split a URL's archive basename into (name, version). Both are heuristics:
/// `libjpeg-turbo-3.0.1.tar.gz` -> (libjpeg-turbo, 3.0.1);
/// `.../repo/archive/refs/tags/v1.2.zip` -> (repo, 1.2).
fn infer_from_url(url: &str) -> (Option<String>, Option<String>) {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('/');
    let path = path.split("://").nth(1).unwrap_or(path);
    let segments: Vec<&str> = path.split('/').skip(1).collect();

    let mut idx = segments.len();
    let mut basename: Option<String> = None;
    let mut version: Option<String> = None;
    while idx > 0 {
        idx -= 1;
        let seg = segments[idx];
        let stripped = re_archive_ext().replace(seg, "");
        let stripped = stripped
            .trim_end_matches(".src")
            .trim_end_matches(".source");
        if version.is_none() {
            if let Some(caps) = re_pure_version().captures(stripped) {
                version = Some(caps[1].to_string());
                continue;
            }
        }
        if is_noise_segment(stripped) {
            continue;
        }
        basename = Some(stripped.to_string());
        break;
    }
    let Some(base) = basename else {
        return (None, version.map(strip_noise_version_chunks));
    };
    if version.is_some() {
        // A pure-version segment already gave the version; `base` is the
        // project/repo name.
        return (Some(base), version.map(strip_noise_version_chunks));
    }
    infer_from_basename(&base)
}

/// Split one archive filename into (name, version): `foo-1.2.tar.gz` ->
/// (foo, 1.2); `v1.2.zip` -> (None, 1.2); `blob.bin` -> (blob.bin, None).
fn infer_from_basename(seg: &str) -> (Option<String>, Option<String>) {
    let stripped = re_archive_ext().replace(seg, "");
    let stripped = stripped
        .trim_end_matches(".src")
        .trim_end_matches(".source");
    if stripped.is_empty() {
        return (None, None);
    }
    if let Some(caps) = re_pure_version().captures(stripped) {
        return (None, Some(strip_noise_version_chunks(caps[1].to_string())));
    }
    match re_name_version().captures(stripped) {
        Some(caps) => (
            Some(caps[1].to_string()),
            Some(strip_noise_version_chunks(caps[2].to_string())),
        ),
        None => (Some(stripped.to_string()), None),
    }
}

fn strip_noise_version_chunks(v: String) -> String {
    let mut v = v;
    while let Some(pos) = v.rfind(['-', '_']) {
        if pos == 0 || !is_noise_version_chunk(&v[pos + 1..]) {
            break;
        }
        v.truncate(pos);
    }
    v
}

/// For a URL that still contains template syntax, salvage a name from the
/// parts around the templates (`https://x/libfoo-{{ v }}.tar.gz` -> libfoo).
fn name_hint_from_template_url(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or("");
    let last = path.trim_end_matches('/').rsplit('/').next()?;
    let no_ext = re_archive_ext().replace(last, "");
    let cleaned = re_template_chunk().replace_all(&no_ext, "");
    let cleaned = cleaned.trim_matches(['-', '_', '.', ' ']);
    if cleaned.is_empty() || cleaned.contains('{') {
        None
    } else {
        Some(cleaned.to_string())
    }
}

fn repo_name_from_git_url(url: &str) -> Option<String> {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('/');
    let last = path.rsplit(['/', ':']).next()?;
    let name = last.trim_end_matches(".git");
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// A git rev is only a version if it looks like a tag: `v1.2.3`,
/// `release-1.2.3`. Commit hashes and branch names are not versions.
fn version_from_rev(rev: &str) -> Option<String> {
    let rev = rev.trim();
    if rev.len() >= 7 && re_hex().is_match(rev) {
        return None;
    }
    if is_noise_segment(rev) && !re_pure_version().is_match(rev) {
        return None;
    }
    if let Some(caps) = re_pure_version().captures(rev) {
        return Some(strip_noise_version_chunks(caps[1].to_string()));
    }
    re_name_version()
        .captures(rev)
        .map(|caps| strip_noise_version_chunks(caps[2].to_string()))
}

fn purl_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b".-_~+".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_meta(s: &str) -> ParsedRecipe {
        parse_recipe(s.as_bytes(), RecipeFormat::MetaYaml).expect("meta.yaml should parse")
    }

    fn parse_v1(s: &str) -> ParsedRecipe {
        parse_recipe(s.as_bytes(), RecipeFormat::RecipeYaml).expect("recipe.yaml should parse")
    }

    fn by_name<'a>(r: &'a ParsedRecipe, name: &str) -> &'a VendoredComponent {
        r.sources
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no component named {name} in {:#?}", r.sources))
    }

    // -- format detection ---------------------------------------------------

    #[test]
    fn detect_jinja_meta_yaml() {
        let s = "{% set version = \"1.0\" %}\npackage:\n  name: foo\n  version: {{ version }}\n";
        assert_eq!(detect_format(s.as_bytes()), Some(RecipeFormat::MetaYaml));
    }

    #[test]
    fn detect_rendered_meta_yaml_without_jinja() {
        // What conda-build actually ships inside a package.
        let s = "# This file created by conda-build 24.1.2\npackage:\n  name: foo\n  version: '1.0'\nsource:\n  url: https://x/foo-1.0.tar.gz\nabout:\n  home: https://x\n";
        assert_eq!(detect_format(s.as_bytes()), Some(RecipeFormat::MetaYaml));
    }

    #[test]
    fn detect_recipe_yaml_v1() {
        let s = "context:\n  version: \"1.0\"\npackage:\n  name: foo\n  version: ${{ version }}\n";
        assert_eq!(detect_format(s.as_bytes()), Some(RecipeFormat::RecipeYaml));
        let s = "schema_version: 1\npackage:\n  name: foo\n  version: 1.0\n";
        assert_eq!(detect_format(s.as_bytes()), Some(RecipeFormat::RecipeYaml));
    }

    #[test]
    fn detect_rejects_non_recipes() {
        assert_eq!(detect_format(b""), None);
        assert_eq!(detect_format(b"\x00\xff\xfe binary junk"), None);
        assert_eq!(detect_format(b"{\"name\": \"not a recipe\"}"), None);
        assert_eq!(detect_format(b"just some prose with no structure"), None);
    }

    // -- classic meta.yaml --------------------------------------------------

    const PILLOW_META: &str = r#"
{% set name = "pillow" %}
{% set version = "10.2.0" %}

package:
  name: {{ name|lower }}
  version: {{ version }}

source:
  url: https://pypi.io/packages/source/{{ name[0] }}/{{ name }}/{{ name }}-{{ version }}.tar.gz
  sha256: e87f0b2c78157e12d7686b27d63c070fd65d994e8ddae6f328e0dcf4a0cd007e
  patches:
    - 0001-fix-cve-2023-4863.patch
    - 0002-no-setuptools-upper-bound.patch  # [not win]

build:
  number: 0
  script: {{ PYTHON }} -m pip install . -vv

requirements:
  build:
    - {{ compiler('c') }}
  host:
    - python
    - libjpeg-turbo
    - libwebp-base

about:
  home: https://python-pillow.org
  license: HPND
  license_family: Other
  summary: Pillow is the friendly PIL fork by Alex Clark and Contributors
  dev_url: https://github.com/python-pillow/Pillow
"#;

    #[test]
    fn simple_meta_yaml_with_jinja() {
        let r = parse_meta(PILLOW_META);
        assert_eq!(r.package_name.as_deref(), Some("pillow"));
        assert_eq!(r.package_version.as_deref(), Some("10.2.0"));
        assert_eq!(r.sources.len(), 1);
        let c = &r.sources[0];
        assert_eq!(c.name, "pillow");
        assert_eq!(c.version.as_deref(), Some("10.2.0"));
        assert_eq!(c.confidence, SourceConfidence::Declared);
        assert_eq!(c.purl.as_deref(), Some("pkg:generic/pillow@10.2.0"));
        assert_eq!(
            c.source_url.as_deref(),
            Some("https://pypi.io/packages/source/p/pillow/pillow-10.2.0.tar.gz")
        );
        assert_eq!(
            c.sha256.as_deref(),
            Some("e87f0b2c78157e12d7686b27d63c070fd65d994e8ddae6f328e0dcf4a0cd007e")
        );
        assert_eq!(
            c.patches,
            vec![
                "0001-fix-cve-2023-4863.patch".to_string(),
                "0002-no-setuptools-upper-bound.patch".to_string()
            ]
        );
        assert_eq!(c.output, None);
        assert!(r.outputs.is_empty());
        assert_eq!(r.about.license.as_deref(), Some("HPND"));
        assert_eq!(r.about.license_family.as_deref(), Some("Other"));
        assert_eq!(r.about.home.as_deref(), Some("https://python-pillow.org"));
        assert_eq!(
            r.about.dev_url.as_deref(),
            Some("https://github.com/python-pillow/Pillow")
        );
        assert!(r.about.summary.as_deref().unwrap().starts_with("Pillow is"));
        // PYTHON and compiler('c') are build-time only; they must be reported
        // but must not affect the source data.
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("compiler('c')")));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("PYTHON")));
    }

    #[test]
    fn rendered_meta_yaml_as_shipped_in_packages() {
        // conda-build writes the rendered recipe; version strings that look
        // like floats are quoted by its YAML dumper, but we must survive the
        // unquoted form too (see numeric_looking_versions_stay_strings).
        let s = r#"
# This file created by conda-build 24.1.2
# meta.yaml template originally from:
# /home/conda/feedstock_root/recipe, last modified Thu Jan  4 12:00:00 2024
# ------------------------------------------------

package:
  name: libwebp-base
  version: 1.3.2
source:
  sha256: 2a499607df669e40258e436d3e8dfd2f0a5a7b45c4ab5c2c2d4a3e4a2e2b6e65
  url: https://github.com/webmproject/libwebp/archive/refs/tags/v1.3.2.tar.gz
build:
  number: 0
  string: h0dc2134_0
requirements:
  build:
    - cmake
  run_constrained:
    - libwebp 1.3.2
about:
  home: https://developers.google.com/speed/webp
  license: BSD-3-Clause
  license_family: BSD
  summary: WebP image library
extra:
  copy_test_source_files: true
  final: true
"#;
        let r = parse_meta(s);
        assert_eq!(r.package_name.as_deref(), Some("libwebp-base"));
        assert_eq!(r.package_version.as_deref(), Some("1.3.2"));
        let c = &r.sources[0];
        // GitHub tag archives: the basename is just the tag, the repo name is
        // two segments up. Package is "libwebp-base" but upstream is libwebp.
        assert_eq!(c.name, "libwebp");
        assert_eq!(c.version.as_deref(), Some("1.3.2"));
        assert_eq!(c.confidence, SourceConfidence::Inferred);
        assert_eq!(c.purl.as_deref(), Some("pkg:generic/libwebp@1.3.2"));
        assert!(
            r.unresolved_expressions.is_empty(),
            "{:?}",
            r.unresolved_expressions
        );
    }

    #[test]
    fn jinja_filters_methods_indexing_and_concatenation() {
        let s = r#"
{% set name = "OpenBLAS" %}
{% set version = "0.3.26" %}
{% set major = version.split(".")[0] %}
{% set minor = version.split('.')[1] %}
{% set compact = version|replace(".", "") %}
{% set tarball = name ~ "-" ~ version %}
{% set build = 0 %}

package:
  name: {{ name|lower }}
  version: {{ version }}

source:
  - url: https://github.com/OpenMathLib/{{ name }}/archive/v{{ version }}.tar.gz
    folder: {{ name.lower() }}-{{ major }}.{{ minor }}
    sha256: {{ "ABCDEF"|lower }}0000000000000000000000000000000000000000000000000000000000
  - url: https://example.org/{{ tarball|upper }}-{{ compact }}.zip
    folder: extra

build:
  number: {{ build }}
"#;
        let r = parse_meta(s);
        assert_eq!(r.package_name.as_deref(), Some("openblas"));
        assert_eq!(r.package_version.as_deref(), Some("0.3.26"));
        assert_eq!(r.sources.len(), 2, "{:#?}", r.sources);
        let a = &r.sources[0];
        assert_eq!(
            a.source_url.as_deref(),
            Some("https://github.com/OpenMathLib/OpenBLAS/archive/v0.3.26.tar.gz")
        );
        // Recipe name corroborated by the URL: the recipe's spelling wins.
        assert_eq!(a.name, "openblas");
        assert_eq!(a.version.as_deref(), Some("0.3.26"));
        assert_eq!(a.confidence, SourceConfidence::Declared);
        assert_eq!(
            a.sha256.as_deref(),
            Some("abcdef0000000000000000000000000000000000000000000000000000000000")
        );
        let b = &r.sources[1];
        assert_eq!(
            b.source_url.as_deref(),
            Some("https://example.org/OPENBLAS-0.3.26-0326.zip")
        );
        assert!(
            r.unresolved_expressions.is_empty(),
            "{:?}",
            r.unresolved_expressions
        );
    }

    #[test]
    fn numeric_looking_versions_stay_strings() {
        // conda-build's StringifyNumbersLoader makes 1.10 the string "1.10",
        // never the float 1.1. A wrong version here silently matches the
        // wrong CVEs.
        let s = r#"
{% set version = "1.10" %}
package:
  name: foo
  version: {{ version }}
source:
  url: https://x/foo-{{ version }}.tar.gz
"#;
        let r = parse_meta(s);
        assert_eq!(r.package_version.as_deref(), Some("1.10"));
        assert_eq!(r.sources[0].version.as_deref(), Some("1.10"));

        // Same hazard without any templating at all.
        let s = "package:\n  name: foo\n  version: 2.0\nsource:\n  url: https://x/foo-2.0.tar.gz\n";
        let r = parse_meta(s);
        assert_eq!(r.package_version.as_deref(), Some("2.0"));
        assert_eq!(r.sources[0].version.as_deref(), Some("2.0"));

        // And octal / hex / exponent lookalikes.
        let s = "package:\n  name: foo\n  version: 1e3\nsource:\n  url: https://x/foo-0x10.tar.gz\n  md5: 0123456789\n";
        let r = parse_meta(s);
        assert_eq!(r.package_version.as_deref(), Some("1e3"));

        // Nulls must stay nulls, not become the string "null".
        let s = "package:\n  name: foo\n  version: 1.0\nsource:\n  url: https://x/foo-1.0.tar.gz\n  folder: null\n  sha256: ~\n";
        let r = parse_meta(s);
        assert_eq!(r.sources[0].sha256, None);
        assert_eq!(r.sources[0].name, "foo");
    }

    #[test]
    fn multi_output_meta_yaml_shares_top_level_source() {
        // Shape of conda-forge's protobuf feedstock: top-level name is not the
        // upstream name, and the upstream version differs from the conda one.
        let s = r#"
{% set name = "protobuf" %}
{% set version = "4.25.3" %}
{% set libprotobuf_version = "25.3" %}

package:
  name: {{ name }}-split
  version: {{ version }}

source:
  url: https://github.com/protocolbuffers/protobuf/releases/download/v{{ libprotobuf_version }}/protobuf-{{ libprotobuf_version }}.tar.gz
  sha256: d19643d265b978383352b3143f04c0641eea75a75235c111cc01a1350173180e
  patches:
    - 0001-fix-build-with-abseil.patch

build:
  number: 0

outputs:
  - name: libprotobuf
    version: {{ libprotobuf_version }}
    script: build-lib.sh
  - name: protobuf
    script: build-py.sh
    requirements:
      host:
        - {{ pin_subpackage("libprotobuf", exact=True) }}
"#;
        let r = parse_meta(s);
        assert_eq!(r.package_name.as_deref(), Some("protobuf-split"));
        assert_eq!(r.package_version.as_deref(), Some("4.25.3"));
        assert_eq!(
            r.outputs,
            vec!["libprotobuf".to_string(), "protobuf".to_string()]
        );
        assert_eq!(r.sources.len(), 1);
        let c = &r.sources[0];
        // Top-level source is shared, not owned by one output.
        assert_eq!(c.output, None);
        // The URL disagrees with the package version, so the URL wins and the
        // result is Inferred, not Declared.
        assert_eq!(c.name, "protobuf");
        assert_eq!(c.version.as_deref(), Some("25.3"));
        assert_eq!(c.confidence, SourceConfidence::Inferred);
        assert_eq!(
            c.patches,
            vec!["0001-fix-build-with-abseil.patch".to_string()]
        );
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("pin_subpackage")));
    }

    #[test]
    fn list_form_sources_with_folders() {
        // opencv feedstock shape: two tarballs unpacked into folders.
        let s = r#"
{% set version = "4.9.0" %}
package:
  name: libopencv
  version: {{ version }}
source:
  - url: https://github.com/opencv/opencv/archive/{{ version }}.tar.gz
    fn: opencv-{{ version }}.tar.gz
    sha256: 1111111111111111111111111111111111111111111111111111111111111111
    patches:
      - 0001-Fix-ffmpeg.patch
  - url: https://github.com/opencv/opencv_contrib/archive/{{ version }}.tar.gz
    fn: opencv_contrib-{{ version }}.tar.gz
    sha256: 2222222222222222222222222222222222222222222222222222222222222222
    folder: opencv_contrib
"#;
        let r = parse_meta(s);
        assert_eq!(r.sources.len(), 2);
        let a = by_name(&r, "opencv");
        assert_eq!(a.version.as_deref(), Some("4.9.0"));
        assert_eq!(a.patches, vec!["0001-Fix-ffmpeg.patch".to_string()]);
        assert_eq!(a.confidence, SourceConfidence::Inferred);
        let b = by_name(&r, "opencv_contrib");
        assert_eq!(b.version.as_deref(), Some("4.9.0"));
        assert!(b.patches.is_empty());
        assert_eq!(b.sha256.as_deref().map(|s| s.len()), Some(64));
    }

    #[test]
    fn git_sources() {
        let s = r#"
package:
  name: libfoo
  version: 1.2.3
source:
  - git_url: https://github.com/example/libfoo.git
    git_rev: v1.2.3
    git_depth: 1
  - git_url: https://github.com/example/bar
    git_rev: 0a1b2c3d4e5f60718293a4b5c6d7e8f901234567
    folder: bar
    patches:
      - bar-cve-backport.patch
"#;
        let r = parse_meta(s);
        assert_eq!(r.sources.len(), 2);
        let a = by_name(&r, "libfoo");
        assert_eq!(
            a.git_url.as_deref(),
            Some("https://github.com/example/libfoo.git")
        );
        assert_eq!(a.git_rev.as_deref(), Some("v1.2.3"));
        assert_eq!(a.version.as_deref(), Some("1.2.3"));
        assert_eq!(a.source_url, None);
        // Repo name and tag match package name/version: corroborated.
        assert_eq!(a.confidence, SourceConfidence::Declared);
        assert_eq!(a.purl.as_deref(), Some("pkg:generic/libfoo@1.2.3"));
        let b = by_name(&r, "bar");
        // A commit hash is not a version. Never invent one.
        assert_eq!(b.version, None);
        assert_eq!(b.purl, None);
        assert_eq!(
            b.git_rev.as_deref(),
            Some("0a1b2c3d4e5f60718293a4b5c6d7e8f901234567")
        );
        assert_eq!(b.confidence, SourceConfidence::Inferred);
        assert_eq!(b.patches, vec!["bar-cve-backport.patch".to_string()]);
    }

    #[test]
    fn local_path_source_is_the_package_itself() {
        let s = "package:\n  name: mytool\n  version: 0.4.1\nsource:\n  path: ../\n";
        let r = parse_meta(s);
        assert_eq!(r.sources.len(), 1);
        let c = &r.sources[0];
        assert_eq!(c.name, "mytool");
        assert_eq!(c.version.as_deref(), Some("0.4.1"));
        assert_eq!(c.source_url, None);
        assert_eq!(c.confidence, SourceConfidence::Inferred);
    }

    #[test]
    fn url_mirror_list_takes_first() {
        let s = r#"
package:
  name: zlib
  version: 1.3.1
source:
  url:
    - https://zlib.net/zlib-1.3.1.tar.gz
    - https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
  sha256: 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
"#;
        let r = parse_meta(s);
        assert_eq!(r.sources.len(), 1);
        assert_eq!(
            r.sources[0].source_url.as_deref(),
            Some("https://zlib.net/zlib-1.3.1.tar.gz")
        );
        assert_eq!(r.sources[0].confidence, SourceConfidence::Declared);
    }

    #[test]
    fn selectors_are_stripped_and_recorded_on_source_lines() {
        let s = r#"
package:
  name: foo
  version: 1.0
source:
  - url: https://x/foo-1.0-win.zip  # [win]
    sha256: aaaa  # [win]
  - url: https://x/foo-1.0.tar.gz   # [not win]
    patches:
      - unix-only.patch  # [unix]
requirements:
  host:
    - python  # [py<38]
"#;
        let r = parse_meta(s);
        // We cannot evaluate platform selectors, so every branch is emitted.
        assert_eq!(r.sources.len(), 2);
        assert_eq!(r.sources[1].patches, vec!["unix-only.patch".to_string()]);
        assert!(r.unresolved_expressions.iter().any(|e| e.contains("[win]")));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("[not win]")));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("[unix]")));
        // Selectors on requirement lines are irrelevant noise.
        assert!(!r.unresolved_expressions.iter().any(|e| e.contains("py<38")));
    }

    #[test]
    fn jinja_control_flow_is_skipped_and_recorded() {
        let s = r#"
{% set version = "2.1" %}
{% if cuda_compiler_version != "None" %}
{% set build = 100 %}
{% else %}
{% set build = 0 %}
{% endif %}
{# a jinja comment: {{ not_a_template }} #}
package:
  name: foo
  version: {{ version }}
source:
  url: https://x/foo-{{ version }}.tar.gz
requirements:
  build:
{% for dep in ["a", "b"] %}
    - {{ dep }}
{% endfor %}
"#;
        let r = parse_meta(s);
        assert_eq!(r.package_version.as_deref(), Some("2.1"));
        assert_eq!(r.sources[0].version.as_deref(), Some("2.1"));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("cuda_compiler_version")));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("for dep in")));
        assert!(!r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("not_a_template")));
    }

    #[test]
    fn unresolvable_templates_never_produce_a_version() {
        let s = r#"
{% set data = load_setup_py_data() %}
{% set name = "mypkg" %}
package:
  name: {{ name }}
  version: {{ data.get('version') }}
source:
  url: https://x/{{ name }}-{{ environ.get("MYPKG_VERSION") }}.tar.gz
  sha256: {{ environ["MYPKG_SHA"] }}
"#;
        let r = parse_meta(s);
        assert_eq!(r.package_name.as_deref(), Some("mypkg"));
        assert_eq!(r.package_version, None);
        assert_eq!(r.sources.len(), 1);
        let c = &r.sources[0];
        assert_eq!(c.confidence, SourceConfidence::Unresolved);
        assert_eq!(c.version, None);
        assert_eq!(c.purl, None);
        assert_eq!(c.sha256, None);
        // The raw template is preserved in the URL so a human can see it.
        assert!(c
            .source_url
            .as_deref()
            .unwrap()
            .contains("{{ environ.get(\"MYPKG_VERSION\") }}"));
        for needle in [
            "load_setup_py_data()",
            "data.get('version')",
            "MYPKG_VERSION",
            "MYPKG_SHA",
        ] {
            assert!(
                r.unresolved_expressions.iter().any(|e| e.contains(needle)),
                "missing diagnostic for {needle}: {:?}",
                r.unresolved_expressions
            );
        }
    }

    #[test]
    fn undefined_variable_with_default_filter() {
        let s = r#"
{% set version = "3.0" %}
package:
  name: foo
  version: {{ version }}
source:
  url: https://x/foo-{{ version }}.tar.gz
build:
  number: {{ build_number|default(0) }}
  string: {{ variant|default("py") }}
"#;
        let r = parse_meta(s);
        assert_eq!(r.package_version.as_deref(), Some("3.0"));
        assert!(
            r.unresolved_expressions.is_empty(),
            "{:?}",
            r.unresolved_expressions
        );
    }

    #[test]
    fn quoted_template_values_and_version_in_url_path() {
        let s = r#"
{% set version = "1.6.40" %}
{% set major = version.split(".")[0:2]|join(".") %}
package:
  name: libpng
  version: "{{ version }}"
source:
  url: 'https://download.sourceforge.net/libpng/libpng-{{ version }}.tar.xz'
  sha256: "535b479b2467ff231a3ec6d92a525906fb8ef27978be4f66dbe05d3f3a01b3a1"
"#;
        let r = parse_meta(s);
        assert_eq!(r.package_version.as_deref(), Some("1.6.40"));
        let c = &r.sources[0];
        assert_eq!(c.name, "libpng");
        assert_eq!(c.version.as_deref(), Some("1.6.40"));
        assert_eq!(c.confidence, SourceConfidence::Declared);
        assert!(
            r.unresolved_expressions.is_empty(),
            "{:?}",
            r.unresolved_expressions
        );
    }

    #[test]
    fn name_inference_from_awkward_basenames() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            (
                "https://x/libjpeg-turbo-3.0.1.tar.gz",
                "libjpeg-turbo",
                Some("3.0.1"),
            ),
            ("https://x/boost_1_82_0.tar.bz2", "boost", Some("1_82_0")),
            ("https://x/SDL2-2.28.5.tar.gz", "SDL2", Some("2.28.5")),
            ("https://x/jpegsrc.v9e.tar.gz", "jpegsrc.v9e", None),
            (
                "https://x/ffmpeg-6.1.tar.xz?download=1",
                "ffmpeg",
                Some("6.1"),
            ),
            (
                "https://downloads.sourceforge.net/project/x/x-2.0.tar.gz/download",
                "x",
                Some("2.0"),
            ),
            (
                "https://github.com/org/repo/archive/1.2.3.tar.gz",
                "repo",
                Some("1.2.3"),
            ),
            (
                "https://github.com/org/repo/archive/refs/tags/v1.2.3.zip",
                "repo",
                Some("1.2.3"),
            ),
            (
                "https://cran.r-project.org/src/contrib/ggplot2_3.4.4.tar.gz",
                "ggplot2",
                Some("3.4.4"),
            ),
            ("https://x/foo-1.0-rc1.tar.gz", "foo", Some("1.0-rc1")),
            ("https://x/tarball", "tarball", None),
        ];
        for (url, name, ver) in cases {
            let s =
                format!("package:\n  name: unrelated\n  version: 9.9.9\nsource:\n  url: {url}\n");
            let r = parse_meta(&s);
            let c = &r.sources[0];
            assert_eq!(c.name, *name, "name for {url}");
            assert_eq!(c.version.as_deref(), *ver, "version for {url}");
            assert_eq!(c.confidence, SourceConfidence::Inferred, "{url}");
        }
    }

    // -- recipe.yaml v1 -----------------------------------------------------

    const PILLOW_V1: &str = r#"
schema_version: 1

context:
  name: pillow
  version: "10.2.0"
  major: ${{ version.split(".")[0] }}

package:
  name: ${{ name }}
  version: ${{ version }}

source:
  - url: https://pypi.io/packages/source/${{ name[0] }}/${{ name }}/${{ name }}-${{ version }}.tar.gz
    sha256: e87f0b2c78157e12d7686b27d63c070fd65d994e8ddae6f328e0dcf4a0cd007e
    patches:
      - fix-cve-2023-4863.patch
      - if: win
        then: win-only.patch

build:
  number: 0
  script: ${{ PYTHON }} -m pip install . -vv

requirements:
  build:
    - ${{ compiler('c') }}
  host:
    - python

about:
  homepage: https://python-pillow.org
  license: HPND
  summary: Pillow is the friendly PIL fork
  repository: https://github.com/python-pillow/Pillow
"#;

    #[test]
    fn recipe_yaml_v1_with_context() {
        let r = parse_v1(PILLOW_V1);
        assert_eq!(r.package_name.as_deref(), Some("pillow"));
        assert_eq!(r.package_version.as_deref(), Some("10.2.0"));
        assert_eq!(r.sources.len(), 1);
        let c = &r.sources[0];
        assert_eq!(c.name, "pillow");
        assert_eq!(c.version.as_deref(), Some("10.2.0"));
        assert_eq!(c.confidence, SourceConfidence::Declared);
        assert_eq!(
            c.source_url.as_deref(),
            Some("https://pypi.io/packages/source/p/pillow/pillow-10.2.0.tar.gz")
        );
        assert_eq!(
            c.patches,
            vec![
                "fix-cve-2023-4863.patch".to_string(),
                "win-only.patch".to_string()
            ]
        );
        assert_eq!(r.about.home.as_deref(), Some("https://python-pillow.org"));
        assert_eq!(
            r.about.dev_url.as_deref(),
            Some("https://github.com/python-pillow/Pillow")
        );
        assert_eq!(r.about.license.as_deref(), Some("HPND"));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("compiler('c')")));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("if: win")));
    }

    #[test]
    fn recipe_yaml_v1_multi_output_with_per_output_sources() {
        let s = r#"
context:
  version: "2.0.0"
  zlib_version: "1.3.1"

recipe:
  name: foo-split
  version: ${{ version }}

source:
  url: https://x/foo-${{ version }}.tar.gz
  sha256: 3333333333333333333333333333333333333333333333333333333333333333

outputs:
  - package:
      name: libfoo
      version: ${{ version }}
    build:
      script: build-lib.sh
  - package:
      name: foo-with-zlib
    source:
      - url: https://zlib.net/zlib-${{ zlib_version }}.tar.gz
        sha256: 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
        target_directory: zlib
        patches:
          - zlib-cve-2023-45853.patch
  - package:
      name: foo-git
    source:
      git: https://github.com/example/foo.git
      tag: v2.0.0
"#;
        let r = parse_v1(s);
        assert_eq!(r.package_name.as_deref(), Some("foo-split"));
        assert_eq!(r.package_version.as_deref(), Some("2.0.0"));
        assert_eq!(
            r.outputs,
            vec![
                "libfoo".to_string(),
                "foo-with-zlib".to_string(),
                "foo-git".to_string()
            ]
        );
        assert_eq!(r.sources.len(), 3, "{:#?}", r.sources);
        let top = by_name(&r, "foo");
        assert_eq!(top.output, None);
        assert_eq!(top.version.as_deref(), Some("2.0.0"));
        let z = by_name(&r, "zlib");
        assert_eq!(z.output.as_deref(), Some("foo-with-zlib"));
        assert_eq!(z.version.as_deref(), Some("1.3.1"));
        assert_eq!(z.confidence, SourceConfidence::Inferred);
        assert_eq!(z.patches, vec!["zlib-cve-2023-45853.patch".to_string()]);
        assert_eq!(z.purl.as_deref(), Some("pkg:generic/zlib@1.3.1"));
        let g = r
            .sources
            .iter()
            .find(|c| c.git_url.is_some())
            .expect("git source");
        assert_eq!(g.output.as_deref(), Some("foo-git"));
        assert_eq!(
            g.git_url.as_deref(),
            Some("https://github.com/example/foo.git")
        );
        assert_eq!(g.git_rev.as_deref(), Some("v2.0.0"));
        assert_eq!(g.version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn recipe_yaml_v1_if_then_else_sources_and_unresolved_context() {
        let s = r#"
context:
  version: "1.0"
  platform_tag: ${{ target_platform }}

package:
  name: foo
  version: ${{ version }}

source:
  - if: win
    then:
      url: https://x/foo-${{ version }}-win.zip
    else:
      - url: https://x/foo-${{ version }}.tar.gz
        sha256: 4444444444444444444444444444444444444444444444444444444444444444
  - url: https://x/blob-${{ platform_tag }}.tar.gz
"#;
        let r = parse_v1(s);
        assert_eq!(r.sources.len(), 3, "{:#?}", r.sources);
        assert_eq!(
            r.sources[0].source_url.as_deref(),
            Some("https://x/foo-1.0-win.zip")
        );
        assert_eq!(
            r.sources[1].source_url.as_deref(),
            Some("https://x/foo-1.0.tar.gz")
        );
        assert_eq!(r.sources[1].confidence, SourceConfidence::Declared);
        let blob = &r.sources[2];
        assert_eq!(blob.confidence, SourceConfidence::Unresolved);
        assert_eq!(blob.version, None);
        assert!(blob
            .source_url
            .as_deref()
            .unwrap()
            .contains("${{ platform_tag }}"));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("target_platform")));
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("if: win")));
    }

    #[test]
    fn recipe_yaml_v1_numeric_context_values() {
        let s = "context:\n  version: 1.10\npackage:\n  name: foo\n  version: ${{ version }}\nsource:\n  url: https://x/foo-${{ version }}.tar.gz\n";
        let r = parse_v1(s);
        assert_eq!(r.package_version.as_deref(), Some("1.10"));
        assert_eq!(r.sources[0].version.as_deref(), Some("1.10"));
    }

    // -- malformed / hostile input -----------------------------------------

    #[test]
    fn malformed_inputs_error_without_panicking() {
        for fmt in [RecipeFormat::MetaYaml, RecipeFormat::RecipeYaml] {
            assert!(matches!(parse_recipe(b"", fmt), Err(RecipeError::Empty)));
            assert!(matches!(
                parse_recipe(b"   \n\t\n", fmt),
                Err(RecipeError::Empty)
            ));
            // Non-UTF-8 is decoded lossily; either outcome is fine, panicking is not.
            let _ = parse_recipe(b"\xff\xfe\x00garbage\x00", fmt);
            assert!(matches!(
                parse_recipe(b"package: [unclosed", fmt),
                Err(RecipeError::Yaml(_))
            ));
            assert!(matches!(
                parse_recipe(b"- just\n- a\n- list\n", fmt),
                Err(RecipeError::NotAMapping)
            ));
            assert!(matches!(
                parse_recipe(b"just a scalar", fmt),
                Err(RecipeError::NotAMapping)
            ));
            // Deep nesting must not overflow the stack.
            let deep = "[".repeat(100_000);
            assert!(matches!(
                parse_recipe(deep.as_bytes(), fmt),
                Err(RecipeError::Yaml(_))
            ));
            let deep = "a:\n".to_string()
                + &(1..2000)
                    .map(|i| format!("{}b{i}:\n", " ".repeat(i)))
                    .collect::<String>();
            let _ = parse_recipe(deep.as_bytes(), fmt);
            // Multi-document streams are not recipes.
            assert!(parse_recipe(b"---\na: 1\n---\nb: 2\n", fmt).is_err());
        }
        let big = vec![b'a'; MAX_INPUT_BYTES + 1];
        assert!(matches!(
            parse_recipe(&big, RecipeFormat::MetaYaml),
            Err(RecipeError::TooLarge { .. })
        ));
    }

    #[test]
    fn hostile_templates_degrade_instead_of_panicking() {
        // Unterminated tags, pathological expression nesting, stray braces,
        // empty expressions, non-ASCII, and a wall of open braces.
        let inputs = [
            "{% set version = \"1.0\"\npackage:\n  name: foo\n  version: {{ version }}\n".to_string(),
            "package:\n  name: foo\n  version: {{ }}\nsource:\n  url: {{\n".to_string(),
            format!("{{% set v = {}\"1\"{} %}}\npackage:\n  name: foo\n  version: {{{{ v }}}}\n", "(".repeat(5000), ")".repeat(5000)),
            "{% set v = \"日本語\" %}\npackage:\n  name: {{ v }}\n  version: {{ v[0] }}\nsource:\n  url: https://x/{{ v|upper }}-1.0.tar.gz\n".to_string(),
            "{{".repeat(50_000),
            "{%".repeat(50_000),
            "package:\n  name: foo\n  version: {{ version.split(\".\")[9999999999999999999999] }}\n".to_string(),
            "{% set version = \"1.0\" %}\npackage:\n  name: foo\n  version: {{ version[-1] }}\n".to_string(),
            "{% set a = b %}{% set b = a %}\npackage:\n  name: {{ a }}\n  version: {{ b }}\n".to_string(),
            "package:\n  name: foo\n  version: 1.0\nsource: not-a-mapping\noutputs: 42\nabout: []\n".to_string(),
            "package: 17\nsource:\n  - 1\n  - [2]\n  - url: 3\n".to_string(),
        ];
        for input in &inputs {
            for fmt in [RecipeFormat::MetaYaml, RecipeFormat::RecipeYaml] {
                // Any Ok or Err is acceptable; a panic is not.
                let _ = parse_recipe(input.as_bytes(), fmt);
            }
        }
        // Mutually-referencing sets must not resolve to garbage.
        let r = parse_meta(
            "{% set a = b %}{% set b = a %}\npackage:\n  name: {{ a }}\n  version: {{ b }}\n",
        );
        assert_eq!(r.package_version, None);
    }

    #[test]
    fn scalar_source_and_wrong_types_are_reported_not_fatal() {
        let r = parse_meta("package:\n  name: foo\n  version: 1.0\nsource: https://x/foo.tar.gz\noutputs: 42\nabout: []\n");
        assert_eq!(r.package_name.as_deref(), Some("foo"));
        assert!(r.sources.is_empty());
        assert!(r.outputs.is_empty());
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("source")));
    }

    #[test]
    fn unresolved_expressions_are_deduplicated() {
        let s = "package:\n  name: foo\n  version: 1.0\nrequirements:\n  build:\n    - {{ compiler('c') }}\n    - {{ compiler('c') }}\n    - {{ compiler('cxx') }}\n";
        let r = parse_meta(s);
        let n = r
            .unresolved_expressions
            .iter()
            .filter(|e| e.contains("compiler('c')"))
            .count();
        assert_eq!(n, 1, "{:?}", r.unresolved_expressions);
    }

    #[test]
    fn serde_roundtrip_of_public_types() {
        let r = parse_meta(PILLOW_META);
        let json = serde_json::to_string(&r).unwrap();
        let back: ParsedRecipe = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn whitespace_control_tags_and_multiline_set() {
        let s = "{%- set name = \"foo\" -%}\n{%- set version = (\"1.\" ~\n   \"2.3\") -%}\npackage:\n  name: {{ name }}\n  version: {{ version }}\nsource:\n  url: https://x/{{ name }}-{{ version }}.tar.gz\n";
        let r = parse_meta(s);
        assert_eq!(r.package_version.as_deref(), Some("1.2.3"));
        assert_eq!(r.sources[0].confidence, SourceConfidence::Declared);
        assert!(
            r.unresolved_expressions.is_empty(),
            "{:?}",
            r.unresolved_expressions
        );
    }

    #[test]
    fn tagged_and_flow_scalars_are_left_alone() {
        let s = "package:\n  name: foo\n  version: !!str 1.0\nsource:\n  url: https://x/foo-1.0.tar.gz\n  patches: [a.patch, b.patch]\n";
        let r = parse_meta(s);
        assert_eq!(r.package_version.as_deref(), Some("1.0"));
        assert_eq!(
            r.sources[0].patches,
            vec!["a.patch".to_string(), "b.patch".to_string()]
        );
    }

    #[test]
    fn git_branch_names_are_not_versions() {
        for rev in [
            "main",
            "master",
            "HEAD",
            "develop",
            "1234567",
            "deadbeefcafe",
        ] {
            let s = format!("package:\n  name: foo\n  version: 1.0\nsource:\n  git_url: https://github.com/x/foo.git\n  git_rev: {rev}\n");
            let r = parse_meta(&s);
            assert_eq!(r.sources[0].version, None, "rev {rev}");
            assert_eq!(
                r.sources[0].confidence,
                SourceConfidence::Inferred,
                "rev {rev}"
            );
        }
        let s = "package:\n  name: foo\n  version: 1.0\nsource:\n  git_url: git@github.com:x/foo.git\n  git_rev: release-1.0\n";
        let r = parse_meta(s);
        assert_eq!(r.sources[0].name, "foo");
        assert_eq!(r.sources[0].version.as_deref(), Some("1.0"));
        assert_eq!(r.sources[0].confidence, SourceConfidence::Declared);
    }

    #[test]
    fn recipe_yaml_v1_source_mapping_that_is_a_conditional() {
        let s = "package:\n  name: foo\n  version: \"1.0\"\nsource:\n  if: unix\n  then:\n    url: https://x/foo-1.0.tar.gz\n  else:\n    url: https://x/foo-1.0.zip\n";
        let r = parse_v1(s);
        assert_eq!(r.sources.len(), 2);
        assert!(r
            .sources
            .iter()
            .all(|c| c.confidence == SourceConfidence::Declared));
        assert!(r.unresolved_expressions.iter().any(|e| e == "if: unix"));
    }

    #[test]
    fn platform_suffixes_are_not_part_of_the_version() {
        for (url, ver) in [
            ("https://x/foo-1.2.3-Source.tar.gz", "1.2.3"),
            ("https://x/foo-1.2.3-win64.zip", "1.2.3"),
            ("https://x/foo-1.2.3-rc1.tar.gz", "1.2.3-rc1"),
        ] {
            let s = format!("package:\n  name: bar\n  version: 0\nsource:\n  url: {url}\n");
            let r = parse_meta(&s);
            assert_eq!(r.sources[0].version.as_deref(), Some(ver), "{url}");
        }
    }

    #[test]
    fn diagnostics_carry_a_reason() {
        let r = parse_meta(
            "package:\n  name: foo\n  version: {{ nope }}\nbuild:\n  number: {{ compiler('c') }}\n",
        );
        assert!(
            r.unresolved_expressions
                .iter()
                .any(|e| e.contains("undefined variable nope")),
            "{:?}",
            r.unresolved_expressions
        );
        assert!(
            r.unresolved_expressions
                .iter()
                .any(|e| e.contains("unsupported: function compiler()")),
            "{:?}",
            r.unresolved_expressions
        );
    }

    // -- rendered_recipe.yaml (rattler-build output) ------------------------

    // Shape of rattler-build's `Output` struct as written to
    // info/recipe/rendered_recipe.yaml: the evaluated recipe under `recipe:`,
    // plus build configuration and the sources as actually fetched.
    const RENDERED_LIBWEBP: &str = r#"
recipe:
  schema_version: 1
  context:
    name: libwebp
    version: 1.3.2
  package:
    name: libwebp
    version: 1.3.2
  source:
    - url: https://github.com/webmproject/libwebp/archive/refs/tags/v1.3.2.tar.gz
      sha256: 2a499607df669e40258e436d3e8dfd2f0a5a7b45c4ab5c2c2d4a3e4a2e2b6e65
      file_name: libwebp-1.3.2.tar.gz
      patches:
        - 0001-cve-2023-4863.patch
  build:
    number: 0
    string: h1234567_0
    script:
      content:
        - cmake ${CMAKE_ARGS} -S . -B build
  requirements:
    build:
      - gcc_linux-64 13.*
      - cmake
    host: []
    run: []
    run_exports:
      weak:
        - libwebp >=1.3.2,<2.0a0
  about:
    homepage: https://developers.google.com/speed/webp
    repository: https://github.com/webmproject/libwebp
    license: BSD-3-Clause
    summary: WebP image library
build_configuration:
  target_platform: linux-64
  host_platform:
    platform: linux-64
    virtual_packages: []
  build_platform:
    platform: linux-64
    virtual_packages: []
  variant:
    c_compiler: gcc
    target_platform: linux-64
  hash:
    hash: 1234567
    prefix: h
    length: 7
  directories:
    host_prefix: /home/user/.cache/rattler-build/bld/rattler-build_libwebp_1700000000/host_env_placehold
    build_prefix: /home/user/.cache/rattler-build/bld/rattler-build_libwebp_1700000000/build_env
    work_dir: /home/user/.cache/rattler-build/bld/rattler-build_libwebp_1700000000/work
    build_dir: /home/user/.cache/rattler-build/bld/rattler-build_libwebp_1700000000
    recipe_dir: /home/user/recipe
    output_dir: /home/user/output
  channels:
    - https://conda.anaconda.org/conda-forge
  channel_priority: strict
  timestamp: 2024-01-01T00:00:00Z
  subpackages:
    libwebp:
      name: libwebp
      version: 1.3.2
      build_string: h1234567_0
  packaging_settings:
    archive_type: conda
    compression_level: 15
    compression_threads: 1
  store_recipe: true
  force_colors: true
finalized_dependencies:
  build:
    specs:
      - source: gcc_linux-64 13.*
    resolved:
      - name: gcc_linux-64
        version: 13.2.0
        build: h0dc2134_0
  host: null
  run:
    depends: []
    constraints: []
    run_exports: null
finalized_cache_dependencies: null
finalized_sources:
  - url: https://github.com/webmproject/libwebp/archive/refs/tags/v1.3.2.tar.gz
    sha256: 2a499607df669e40258e436d3e8dfd2f0a5a7b45c4ab5c2c2d4a3e4a2e2b6e65
    file_name: libwebp-1.3.2.tar.gz
    patches:
      - 0001-cve-2023-4863.patch
system_tools:
  rattler-build: 0.22.0
build_summary: {}
extra_meta: null
"#;

    fn parse_rendered(s: &str) -> ParsedRecipe {
        parse_recipe(s.as_bytes(), RecipeFormat::RenderedRecipeYaml)
            .expect("rendered_recipe.yaml should parse")
    }

    #[test]
    fn detect_rendered_recipe_yaml() {
        assert_eq!(
            detect_format(RENDERED_LIBWEBP.as_bytes()),
            Some(RecipeFormat::RenderedRecipeYaml)
        );
        // A v1 multi-output recipe.yaml also has a top-level `recipe:` key
        // but no build configuration; it must stay RecipeYaml.
        let s = "recipe:\n  name: foo-split\n  version: \"1.0\"\noutputs:\n  - package:\n      name: foo\n";
        assert_eq!(detect_format(s.as_bytes()), Some(RecipeFormat::RecipeYaml));
        let s = "recipe:\n  package:\n    name: foo\n    version: \"1.0\"\nbuild_configuration:\n  target_platform: noarch\n";
        assert_eq!(
            detect_format(s.as_bytes()),
            Some(RecipeFormat::RenderedRecipeYaml)
        );
    }

    #[test]
    fn rendered_recipe_yaml_prefers_finalized_sources() {
        let r = parse_rendered(RENDERED_LIBWEBP);
        assert_eq!(r.package_name.as_deref(), Some("libwebp"));
        assert_eq!(r.package_version.as_deref(), Some("1.3.2"));
        assert_eq!(r.sources.len(), 1, "{:#?}", r.sources);
        let c = &r.sources[0];
        assert_eq!(c.name, "libwebp");
        assert_eq!(c.version.as_deref(), Some("1.3.2"));
        assert_eq!(c.confidence, SourceConfidence::Declared);
        assert_eq!(c.purl.as_deref(), Some("pkg:generic/libwebp@1.3.2"));
        assert_eq!(
            c.sha256.as_deref(),
            Some("2a499607df669e40258e436d3e8dfd2f0a5a7b45c4ab5c2c2d4a3e4a2e2b6e65")
        );
        assert_eq!(c.patches, vec!["0001-cve-2023-4863.patch".to_string()]);
        assert_eq!(c.output, None);
        assert!(r.outputs.is_empty());
        assert_eq!(
            r.about.home.as_deref(),
            Some("https://developers.google.com/speed/webp")
        );
        assert_eq!(
            r.about.dev_url.as_deref(),
            Some("https://github.com/webmproject/libwebp")
        );
        assert_eq!(r.about.license.as_deref(), Some("BSD-3-Clause"));
        assert!(
            r.unresolved_expressions.is_empty(),
            "{:?}",
            r.unresolved_expressions
        );
        // Same bytes through the plain v1 path must not silently look clean.
        let v1 = parse_v1(RENDERED_LIBWEBP);
        assert!(v1.sources.is_empty());
    }

    #[test]
    fn rendered_recipe_yaml_finalized_sources_win_over_recipe_source() {
        // finalized_sources is what was actually fetched (selectors applied);
        // recipe.source may differ. When both exist, finalized wins.
        let s = r#"
recipe:
  package:
    name: foo
    version: 2.0
  source:
    - url: https://x/foo-2.0-win.zip
    - url: https://x/foo-2.0.tar.gz
build_configuration:
  target_platform: linux-64
finalized_sources:
  - url: https://x/foo-2.0.tar.gz
    sha256: 5555555555555555555555555555555555555555555555555555555555555555
  - url: https://zlib.net/zlib-1.3.1.tar.gz
    sha256: 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
    target_directory: zlib
"#;
        let r = parse_rendered(s);
        assert_eq!(r.sources.len(), 2, "{:#?}", r.sources);
        assert_eq!(
            r.sources[0].source_url.as_deref(),
            Some("https://x/foo-2.0.tar.gz")
        );
        assert_eq!(r.sources[0].confidence, SourceConfidence::Declared);
        let z = by_name(&r, "zlib");
        assert_eq!(z.version.as_deref(), Some("1.3.1"));
        // The URL is real, but the recipe never names this component: the
        // identity is still derived from the filename.
        assert_eq!(z.confidence, SourceConfidence::Inferred);
        assert!(
            r.unresolved_expressions.is_empty(),
            "{:?}",
            r.unresolved_expressions
        );
    }

    #[test]
    fn rendered_recipe_yaml_git_source_recovers_tag_from_recipe_source() {
        // fetch_sources replaces the tag with the resolved commit in
        // finalized_sources. The commit is kept as git_rev; the version comes
        // from the tag in recipe.source.
        let s = r#"
recipe:
  package:
    name: libfoo
    version: 1.2.3
  source:
    - git: https://github.com/example/libfoo.git
      tag: v1.2.3
      patches:
        - fix.patch
build_configuration:
  target_platform: linux-64
finalized_sources:
  - git: https://github.com/example/libfoo.git
    rev: 0a1b2c3d4e5f60718293a4b5c6d7e8f901234567
    patches:
      - fix.patch
"#;
        let r = parse_rendered(s);
        assert_eq!(r.sources.len(), 1, "{:#?}", r.sources);
        let c = &r.sources[0];
        assert_eq!(
            c.git_url.as_deref(),
            Some("https://github.com/example/libfoo.git")
        );
        assert_eq!(
            c.git_rev.as_deref(),
            Some("0a1b2c3d4e5f60718293a4b5c6d7e8f901234567")
        );
        assert_eq!(c.version.as_deref(), Some("1.2.3"));
        assert_eq!(c.confidence, SourceConfidence::Declared);
        assert_eq!(c.patches, vec!["fix.patch".to_string()]);

        // No tag anywhere: a commit is not a version.
        let s = s.replace("      tag: v1.2.3\n", "      branch: main\n");
        let r = parse_rendered(&s);
        assert_eq!(r.sources[0].version, None);
        assert_eq!(r.sources[0].confidence, SourceConfidence::Inferred);
    }

    #[test]
    fn rendered_recipe_yaml_without_finalized_sources_uses_recipe_source() {
        // Older rattler-build, or a null field: recipe.source in the rendered
        // file is already fully evaluated, so it is trusted equally.
        for tail in ["", "finalized_sources: null\n", "finalized_sources: []\n"] {
            let s = format!(
                "recipe:\n  package:\n    name: foo\n    version: \"1.0\"\n  source:\n    url: https://x/foo-1.0.tar.gz\n    sha256: 6666666666666666666666666666666666666666666666666666666666666666\nbuild_configuration:\n  target_platform: linux-64\n{tail}"
            );
            let r = parse_rendered(&s);
            assert_eq!(r.sources.len(), 1, "tail {tail:?}");
            assert_eq!(r.sources[0].confidence, SourceConfidence::Declared);
            assert!(
                r.unresolved_expressions.is_empty(),
                "{:?}",
                r.unresolved_expressions
            );
        }
    }

    #[test]
    fn rendered_recipe_yaml_malformed() {
        assert!(matches!(
            parse_recipe(
                b"build_configuration:\n  target_platform: linux-64\n",
                RecipeFormat::RenderedRecipeYaml
            ),
            Err(RecipeError::NoRecipeBlock)
        ));
        assert!(matches!(
            parse_recipe(
                b"recipe: 42\nbuild_configuration: {}\n",
                RecipeFormat::RenderedRecipeYaml
            ),
            Err(RecipeError::NoRecipeBlock)
        ));
        assert!(matches!(
            parse_recipe(b"- a\n- b\n", RecipeFormat::RenderedRecipeYaml),
            Err(RecipeError::NotAMapping)
        ));
        // Garbage finalized_sources: reported, then recipe.source is used.
        let s = "recipe:\n  package:\n    name: foo\n    version: \"1.0\"\n  source:\n    url: https://x/foo-1.0.tar.gz\nfinalized_sources: not-a-list\n";
        let r = parse_rendered(s);
        assert_eq!(r.sources.len(), 1);
        assert!(r
            .unresolved_expressions
            .iter()
            .any(|e| e.contains("finalized_sources")));
        let s = "recipe:\n  package:\n    name: foo\n    version: \"1.0\"\nfinalized_sources:\n  - 1\n  - [2]\n  - git: 3\n  - {}\n";
        let _ = parse_rendered(s);
        for input in [
            RENDERED_LIBWEBP,
            "recipe: {}\n",
            "recipe:\n  source: 7\nfinalized_sources: {}\n",
        ] {
            let _ = parse_recipe(input.as_bytes(), RecipeFormat::RenderedRecipeYaml);
        }
    }

    #[test]
    fn file_name_hint_improves_inference() {
        // v0 `fn:` and v1 `file_name:` name the downloaded file, which is
        // often the only place the upstream name/version appear.
        let cases = [
            (
                "url: https://example.org/download?id=42\n  fn: libfoo-1.2.tar.gz",
                "libfoo",
                Some("1.2"),
            ),
            (
                "url: https://example.org/foo.tar.gz\n  fn: foo-2.0.tar.gz",
                "foo",
                Some("2.0"),
            ),
            (
                "url: https://example.org/get/latest\n  file_name: bar-3.4.5.zip",
                "bar",
                Some("3.4.5"),
            ),
            // URL already informative: fn does not override it.
            (
                "url: https://example.org/baz-1.0.tar.gz\n  fn: renamed-9.9.tar.gz",
                "baz",
                Some("1.0"),
            ),
            // fn with no version adds nothing.
            (
                "url: https://example.org/get/latest\n  fn: blob.bin",
                "latest",
                None,
            ),
        ];
        for (body, name, ver) in cases {
            let s = format!("package:\n  name: unrelated\n  version: 0\nsource:\n  {body}\n");
            let r = parse_meta(&s);
            assert_eq!(r.sources[0].name, name, "{body}");
            assert_eq!(r.sources[0].version.as_deref(), ver, "{body}");
        }
    }

    #[test]
    fn preferred_recipe_files_order() {
        let files = preferred_recipe_files();
        assert_eq!(
            files[0],
            ("rendered_recipe.yaml", RecipeFormat::RenderedRecipeYaml)
        );
        assert_eq!(files[1], ("meta.yaml", RecipeFormat::MetaYaml));
        assert_eq!(files[2], ("recipe.yaml", RecipeFormat::RecipeYaml));
        assert_eq!(files[3], ("meta.yaml.template", RecipeFormat::MetaYaml));
        assert_eq!(files.len(), 4);
    }
}
