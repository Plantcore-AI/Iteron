//! Machine-check the contract shapes `docs/spec` prints against `crates/protocol`.
//!
//! A spec that contradicts the code does not sit still. `docs/spec/capability-mapping.md` printed a
//! pre-freeze field sketch and called it a normative shape, and three issue bodies were then written
//! from the rotted version, asking for `ContextRequest.kind`, `EffectProposal.effect_kind` and a
//! `CapabilityTier` that names nothing in this workspace. Implemented literally, that would have
//! minted shadow types and a conformance matrix would have certified them green.
//!
//! Nothing read those documents. `mkdocs build --strict` validates links and nav targets; it does
//! not parse a code block or compare a field name against anything. The divergences that *were*
//! known lived as comments in `crates/protocol/tests/abi_freeze.rs`, and a comment is as far as an
//! observation can travel.
//!
//! So this compares the shapes rather than the prose, at name-and-arity level: the docs legitimately
//! elide doc comments, derives and field types, and a reordered comment is not a defect. A missing
//! `#[serde(other)] Unknown` arm is, because it is the degrading arm the ABI's forward-compatibility
//! rule depends on.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SPEC_DIR: &str = "docs/spec";
const PROTOCOL_DIR: &str = "crates/protocol/src";
const MAX_SPEC_BYTES: u64 = 2 * 1024 * 1024;

/// The least number of spec types that must resolve against `crates/protocol`.
///
/// Anti-vacuity, in the manner of the effect-boundary gate: a checker that silently stops matching
/// is worse than no checker, because it reports success. A rename that drops the matched set below
/// this floor fails rather than passing quietly.
const MIN_MATCHED_TYPES: usize = 8;

/// A shape the spec prints and the code declares, compared at name-and-arity level.
#[derive(Debug, PartialEq, Eq)]
enum Shape {
    Unit,
    Tuple(usize),
    Fields(BTreeSet<String>),
    Variants(BTreeMap<String, Box<Shape>>),
}

impl Shape {
    fn describe(&self) -> String {
        match self {
            Self::Unit => "unit".to_owned(),
            Self::Tuple(arity) => format!("tuple arity {arity}"),
            Self::Fields(fields) => format!("{{{}}}", join(fields)),
            Self::Variants(variants) => format!(
                "{{{}}}",
                variants
                    .iter()
                    .map(|(name, shape)| match shape.as_ref() {
                        Shape::Unit => name.clone(),
                        Shape::Tuple(arity) => format!("{name}/{arity}"),
                        Shape::Fields(fields) => format!("{name}{{{}}}", join(fields)),
                        Shape::Variants(_) => name.clone(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// The member names at the top level, for reporting which side is missing what.
    fn members(&self) -> BTreeSet<String> {
        match self {
            Self::Unit => BTreeSet::new(),
            Self::Tuple(arity) => (0..*arity).map(|index| index.to_string()).collect(),
            Self::Fields(fields) => fields.clone(),
            Self::Variants(variants) => variants.keys().cloned().collect(),
        }
    }
}

fn join(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// A divergence the spec keeps on purpose, with the reason recorded here rather than in a comment.
///
/// These are the three that `crates/protocol/tests/abi_freeze.rs` used to restate in prose. Each
/// names the members that legitimately appear on only one side; anything else is a defect.
struct Divergence {
    ty: &'static str,
    /// Members the code declares and the spec's block omits.
    code_only: &'static [&'static str],
    /// Members the spec's block prints and the code does not declare.
    spec_only: &'static [&'static str],
    reason: &'static str,
}

/// No divergence is recorded today.
///
/// The three that `crates/protocol/tests/abi_freeze.rs` used to restate in prose were resolved by
/// correcting the spec, not by recording them: `ContextSelector` and `Producer` now print their
/// degrading arm, and `TaskInput` now prints `ContentSegments`. An entry here is for a divergence
/// that is *meant* to persist; `no_stale_divergence` fails the gate if one stops being live, so
/// this list cannot rot the way those comments did.
const DIVERGENCES: &[Divergence] = &[];

/// Identifiers that must not appear in code font anywhere under `docs/spec`.
///
/// The general rule is that an identifier a document prints in code font must resolve in the
/// workspace. This encodes the part of it that has already done damage: every token here was read
/// as normative, written into an issue body, and named nothing. A deny-list is the honest mechanism
/// — checking every backticked token would flag flags, paths and prose, and a gate that cries wolf
/// gets skimmed, which is the failure this issue exists to stop.
const DENIED_IDENTIFIERS: &[(&str, &str)] = &[
    (
        "CapabilityTier",
        "authority is a `CapabilitySet`, not a point on a tier ladder",
    ),
    (
        "proposed_tier",
        "no tier is proposed; a `ToolIntent` carries `admitted`",
    ),
    (
        "admitted_tier",
        "no tier is admitted; a `ToolIntent` carries `admitted`",
    ),
    (
        "capability_handle",
        "no handle type exists; capability is carried by value",
    ),
    ("effect_kind", "`EffectProposal` names its kind `kind`"),
    (
        "byte_ceiling",
        "context ceilings are named on the request, not as a bare ceiling",
    ),
    (
        "intent_id",
        "an intent is correlated by the tool-use id it carries",
    ),
    (
        "content_hash",
        "provenance uses a digest field, not a bare content hash",
    ),
    (
        "origin_taint",
        "trust is carried as `Trust`, not as a taint field",
    ),
];

pub(crate) fn validate(root: &Path) -> Result<()> {
    validate_with(root, DIVERGENCES)
}

fn validate_with(root: &Path, divergences: &[Divergence]) -> Result<()> {
    let declared = protocol_shapes(root)?;
    let printed = spec_shapes(root)?;

    let mut failures = Vec::new();
    let mut live: BTreeSet<&str> = BTreeSet::new();
    let mut matched = 0usize;

    for block in &printed {
        let Some(actual) = declared.get(&block.ty) else {
            continue;
        };
        matched += 1;
        let recorded = divergences.iter().find(|entry| entry.ty == block.ty);
        let code_only = difference(&actual.members(), &block.shape.members());
        let spec_only = difference(&block.shape.members(), &actual.members());
        if let Some(recorded) = recorded
            && (!code_only.is_empty() || !spec_only.is_empty())
        {
            live.insert(recorded.ty);
        }

        let unexplained_code_only =
            difference(&code_only, &owned(recorded.map_or(&[], |e| e.code_only)));
        let unexplained_spec_only =
            difference(&spec_only, &owned(recorded.map_or(&[], |e| e.spec_only)));
        if unexplained_code_only.is_empty() && unexplained_spec_only.is_empty() {
            continue;
        }

        let mut detail = String::new();
        if !unexplained_spec_only.is_empty() {
            detail.push_str(&format!(
                "\n    the block prints members the code does not declare: {}",
                join(&unexplained_spec_only)
            ));
        }
        if !unexplained_code_only.is_empty() {
            detail.push_str(&format!(
                "\n    the code declares members the block omits: {}",
                join(&unexplained_code_only)
            ));
        }
        failures.push(format!(
            "{}:{}: `{}` does not match `{PROTOCOL_DIR}`{detail}\n    real shape: {}\n    printed \
             shape: {}\n    if this divergence is deliberate, record it with a reason in \
             `DIVERGENCES` in xtask/src/spec_shapes.rs",
            block.file,
            block.line,
            block.ty,
            actual.describe(),
            block.shape.describe(),
        ));
    }

    for divergence in divergences {
        if !live.contains(divergence.ty) {
            failures.push(format!(
                "`{}` is recorded as a deliberate divergence, but the spec and the code now agree \
                 or the spec no longer prints it. Delete the entry: a recorded divergence that is \
                 not live is the stale comment this gate replaced. Reason it carried: {}",
                divergence.ty, divergence.reason
            ));
        }
    }

    if matched < MIN_MATCHED_TYPES {
        bail!(
            "spec shape gate matched only {matched} type(s) against `{PROTOCOL_DIR}`, below the \
             anti-vacuity floor of {MIN_MATCHED_TYPES}. A rename that stops the gate looking must \
             fail here rather than report success."
        );
    }

    failures.extend(denied_identifiers(root)?);

    if failures.is_empty() {
        // Diagnostics go to stderr: `tunables invariant-review-packet` and
        // `tunables check-invariant-reviews` run this gate before writing machine-readable
        // JSON to stdout, and a success line there corrupts the documented `> packet.json`.
        eprintln!(
            "spec shapes agree with `{PROTOCOL_DIR}`: {matched} types compared, {} recorded \
             divergences",
            divergences.len()
        );
        return Ok(());
    }
    bail!("spec contradicts the code:\n- {}", failures.join("\n- "));
}

fn owned(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn difference(left: &BTreeSet<String>, right: &BTreeSet<String>) -> BTreeSet<String> {
    left.difference(right).cloned().collect()
}

struct PrintedShape {
    file: String,
    line: usize,
    ty: String,
    shape: Shape,
}

/// Every `struct` or `enum` declared in a fenced Rust block under `docs/spec`.
fn spec_shapes(root: &Path) -> Result<Vec<PrintedShape>> {
    let mut shapes = Vec::new();
    for path in sorted_markdown(root.join(SPEC_DIR))? {
        let relative = relative(root, &path);
        let text = read_bounded(&path)?;
        for (line, block) in rust_blocks(&text) {
            // A block that declares a type has to be valid Rust; if it is not, the shape it prints
            // cannot be compared and the reader is being shown something that does not compile.
            let Ok(file) = syn::parse_file(&block) else {
                if declares_type(&block) {
                    bail!(
                        "{relative}:{line}: a fenced Rust block declares a type but does not parse \
                         as Rust, so its printed shape cannot be checked"
                    );
                }
                continue;
            };
            for item in file.items {
                if let Some((ty, shape)) = item_shape(&item) {
                    shapes.push(PrintedShape {
                        file: relative.clone(),
                        line,
                        ty,
                        shape,
                    });
                }
            }
        }
    }
    Ok(shapes)
}

fn declares_type(block: &str) -> bool {
    block.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("struct ")
            || line.starts_with("enum ")
            || line.starts_with("pub struct ")
            || line.starts_with("pub enum ")
    })
}

/// Every `struct` or `enum` declared anywhere under `crates/protocol/src`.
fn protocol_shapes(root: &Path) -> Result<BTreeMap<String, Shape>> {
    let mut shapes = BTreeMap::new();
    let mut pending = vec![root.join(PROTOCOL_DIR)];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .with_context(|| format!("cannot inspect {}", directory.display()))?;
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let text = read_bounded(&path)?;
            let file = syn::parse_file(&text)
                .with_context(|| format!("protocol source {} does not parse", path.display()))?;
            collect_items(&file.items, &mut shapes);
        }
    }
    Ok(shapes)
}

fn collect_items(items: &[syn::Item], shapes: &mut BTreeMap<String, Shape>) {
    for item in items {
        if let syn::Item::Mod(module) = item
            && let Some((_, inner)) = &module.content
        {
            collect_items(inner, shapes);
        }
        if let Some((ty, shape)) = item_shape(item) {
            shapes.entry(ty).or_insert(shape);
        }
    }
}

fn item_shape(item: &syn::Item) -> Option<(String, Shape)> {
    match item {
        syn::Item::Struct(item) => Some((item.ident.to_string(), fields_shape(&item.fields))),
        syn::Item::Enum(item) => {
            let variants = item
                .variants
                .iter()
                .map(|variant| {
                    (
                        variant.ident.to_string(),
                        Box::new(fields_shape(&variant.fields)),
                    )
                })
                .collect();
            Some((item.ident.to_string(), Shape::Variants(variants)))
        }
        _ => None,
    }
}

fn fields_shape(fields: &syn::Fields) -> Shape {
    match fields {
        syn::Fields::Unit => Shape::Unit,
        syn::Fields::Unnamed(unnamed) => Shape::Tuple(unnamed.unnamed.len()),
        syn::Fields::Named(named) => Shape::Fields(
            named
                .named
                .iter()
                .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
                .collect(),
        ),
    }
}

/// Identifiers that name nothing in this workspace, scanned inside fenced blocks only.
///
/// Prose is deliberately out of scope. The corrected spec now prints these very tokens in order to
/// say they do not exist — "全仓不存在名为 `CapabilityTier` 的类型", "内容寻址字段名为 `hash`,
/// 不是 `content_hash`" — and a gate that flagged those sentences would be demanding the removal of
/// the warning that keeps the mistake from being made again.
///
/// A fenced block is different: that is where `capability-mapping.md` printed a field sketch and
/// called it a normative shape, which is the damage this gate exists to stop.
fn denied_identifiers(root: &Path) -> Result<Vec<String>> {
    let mut failures = Vec::new();
    for path in sorted_markdown(root.join(SPEC_DIR))? {
        let relative = relative(root, &path);
        let text = read_bounded(&path)?;
        for (line, block) in fenced_blocks(&text) {
            for (offset, body) in block.lines().enumerate() {
                for (identifier, reason) in DENIED_IDENTIFIERS {
                    if word_appears(body, identifier) {
                        failures.push(format!(
                            "{relative}:{}: a fenced block prints `{identifier}`, which names \
                             nothing in this workspace: {reason}",
                            line + offset + 1
                        ));
                    }
                }
            }
        }
    }
    Ok(failures)
}

/// Whether `identifier` appears as a whole word, so `hash` does not match `content_hash`.
fn word_appears(line: &str, identifier: &str) -> bool {
    let boundary = |ch: char| !(ch.is_alphanumeric() || ch == '_');
    let mut rest = line;
    while let Some(index) = rest.find(identifier) {
        let before = rest[..index].chars().next_back().is_none_or(boundary);
        let after = rest[index + identifier.len()..]
            .chars()
            .next()
            .is_none_or(boundary);
        if before && after {
            return true;
        }
        rest = &rest[index + identifier.len()..];
    }
    false
}

fn fenced_blocks(text: &str) -> Vec<(usize, String)> {
    blocks(text, None)
}

fn rust_blocks(text: &str) -> Vec<(usize, String)> {
    blocks(text, Some(&["rust", "rust,ignore", "rust,no_run"]))
}

fn blocks(text: &str, languages: Option<&[&str]>) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut current: Option<(usize, Vec<&str>)> = None;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_end();
        match &mut current {
            None => {
                if let Some(language) = trimmed.strip_prefix("```").map(str::trim)
                    && languages.is_none_or(|allowed| allowed.contains(&language))
                {
                    current = Some((index + 1, Vec::new()));
                }
            }
            Some((start, body)) => {
                if trimmed == "```" {
                    blocks.push((*start, body.join("\n")));
                    current = None;
                } else {
                    body.push(line);
                }
            }
        }
    }
    blocks
}

fn sorted_markdown(directory: std::path::PathBuf) -> Result<Vec<std::path::PathBuf>> {
    let mut paths = std::fs::read_dir(&directory)
        .with_context(|| format!("cannot inspect {}", directory.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn read_bounded(path: &Path) -> Result<String> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    if metadata.len() > MAX_SPEC_BYTES {
        bail!("{} exceeds the {MAX_SPEC_BYTES}-byte bound", path.display());
    }
    std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
}

#[cfg(test)]
#[path = "spec_shapes_tests.rs"]
mod tests;
