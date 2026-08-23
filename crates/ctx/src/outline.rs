//! The localization ladder's first rung: a repo **skeleton** — the tree plus each code file's
//! top-level declarations, and nothing else. Agentless measured that feeding the skeleton
//! (declaration headers) beats feeding whole files by +5.3pp AND costs 7.5x less, because
//! "LLMs cannot handle long context very well, so providing the entire file contents can
//! confuse the model." This is the map the agent reads before it decides what to materialize.
//!
//! Language-agnostic by design (like SWE-agent's ACI): a small set of declaration patterns
//! across common languages, not a full parser. tree-sitter would be more precise and is the
//! documented upgrade path; the heuristic is cheap, dependency-light, and good enough to
//! localize. The map is fit to a token budget by dropping the least-signal files last.

use std::path::Path;
use walkdir::WalkDir;

use crate::instructions::suspicious_unicode;
use crate::source::{SourceScope, read_bounded_utf8};

mod outline_relevance {
    //! Deterministic task-aware ranking for the repository outline.
    //!
    //! This is deliberately a bounded lexical fallback, not a language parser. It retains the two
    //! semantic relations that transfer across languages without an index: declarations define
    //! names, and other files mentioning those names reference them. Query evidence personalizes
    //! a short, fixed graph walk so a map includes the likely definition and nearby callers/tests.

    use std::collections::{BTreeMap, BTreeSet};

    const MAX_TERMS_PER_FILE: usize = 512;
    const MAX_DEFINERS_PER_SYMBOL: usize = 8;
    const MAX_RELATION_EDGES: usize = 8_192;
    const PROPAGATION_ROUNDS: usize = 2;

    fn max_terms_per_file() -> usize {
        iteron_tunables::param_usize("ctx.outline.max_terms_per_file", MAX_TERMS_PER_FILE)
    }

    fn max_definers_per_symbol() -> usize {
        iteron_tunables::param_usize(
            "ctx.outline.max_definers_per_symbol",
            MAX_DEFINERS_PER_SYMBOL,
        )
    }

    fn max_relation_edges() -> usize {
        iteron_tunables::param_usize("ctx.outline.max_relation_edges", MAX_RELATION_EDGES)
    }

    fn propagation_rounds() -> usize {
        iteron_tunables::param_usize("ctx.outline.propagation_rounds", PROPAGATION_ROUNDS)
    }

    #[derive(Debug)]
    pub(super) struct FileSignals {
        path_terms: BTreeSet<String>,
        declaration_terms: BTreeSet<String>,
        definitions: BTreeSet<String>,
        references: BTreeSet<String>,
    }

    impl FileSignals {
        pub(super) fn extract(path: &str, declarations: &[String], source: &str) -> Self {
            let mut definitions = BTreeSet::new();
            for declaration in declarations {
                if let Some(symbol) = defined_symbol(declaration) {
                    definitions.insert(symbol.to_lowercase());
                }
            }
            Self {
                path_terms: terms(path, max_terms_per_file()),
                declaration_terms: terms(&declarations.join("\n"), max_terms_per_file()),
                definitions,
                references: terms(source, max_terms_per_file()),
            }
        }

        fn contains(&self, term: &str) -> bool {
            self.path_terms.contains(term)
                || self.declaration_terms.contains(term)
                || self.references.contains(term)
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(super) struct Relevance {
        pub(super) direct: u64,
        pub(super) related: u64,
        pub(super) centrality: usize,
    }

    /// Rank already-bounded files. Work is capped by the file count, per-file term count, relation
    /// edge ceiling, and fixed propagation depth; no model, provider, index daemon, or repository
    /// history participates.
    pub(super) fn rank<'a>(
        files: impl IntoIterator<Item = &'a FileSignals>,
        query: &str,
    ) -> Vec<Relevance> {
        let files = files.into_iter().collect::<Vec<_>>();
        let query_terms = terms(query, 64);
        let mut relevance = vec![Relevance::default(); files.len()];

        for term in &query_terms {
            let document_frequency = files.iter().filter(|file| file.contains(term)).count();
            if document_frequency == 0 {
                continue;
            }
            // Integer IDF-like weighting keeps rare task anchors stronger than generic issue prose.
            let rarity = files
                .len()
                .saturating_add(1)
                .saturating_mul(8)
                .checked_div(document_frequency.saturating_add(1))
                .unwrap_or(1)
                .clamp(1, 8) as u64;
            for (index, file) in files.iter().enumerate() {
                let field_weight: u64 = if file.definitions.contains(term) {
                    32
                } else if file.path_terms.contains(term) {
                    24
                } else if file.declaration_terms.contains(term) {
                    12
                } else if file.references.contains(term) {
                    2
                } else {
                    0
                };
                relevance[index].direct = relevance[index]
                    .direct
                    .saturating_add(field_weight.saturating_mul(rarity));
            }
        }

        let edges = relation_edges(&files);
        let mut neighbors = vec![Vec::<usize>::new(); files.len()];
        for &(caller, definer) in &edges {
            neighbors[caller].push(definer);
            neighbors[definer].push(caller);
            relevance[definer].centrality = relevance[definer].centrality.saturating_add(1);
        }
        for adjacent in &mut neighbors {
            adjacent.sort_unstable();
            adjacent.dedup();
        }

        // A tiny personalized graph walk. Definition and reference neighbors receive decaying
        // task evidence, but direct task matches remain the primary ordering key.
        let mut frontier = relevance
            .iter()
            .map(|score| score.direct)
            .collect::<Vec<_>>();
        for _ in 0..propagation_rounds() {
            let mut next = vec![0u64; files.len()];
            for (source, adjacent) in neighbors.iter().enumerate() {
                let degree = u64::try_from(adjacent.len()).unwrap_or(u64::MAX).max(1);
                let share = frontier[source].checked_div(degree).unwrap_or(0) / 2;
                for &target in adjacent {
                    next[target] = next[target].saturating_add(share);
                }
            }
            for (score, propagated) in relevance.iter_mut().zip(&next) {
                score.related = score.related.saturating_add(*propagated);
            }
            frontier = next;
        }
        relevance
    }

    fn relation_edges(files: &[&FileSignals]) -> BTreeSet<(usize, usize)> {
        let mut definitions = BTreeMap::<&str, Vec<usize>>::new();
        for (index, file) in files.iter().enumerate() {
            for symbol in &file.definitions {
                let definers = definitions.entry(symbol).or_default();
                if definers.len() < max_definers_per_symbol() {
                    definers.push(index);
                }
            }
        }

        let mut edges = BTreeSet::new();
        'files: for (caller, file) in files.iter().enumerate() {
            for reference in &file.references {
                let Some(definers) = definitions.get(reference.as_str()) else {
                    continue;
                };
                for &definer in definers {
                    if caller != definer {
                        edges.insert((caller, definer));
                        if edges.len() >= max_relation_edges() {
                            break 'files;
                        }
                    }
                }
            }
        }
        edges
    }

    fn defined_symbol(declaration: &str) -> Option<String> {
        let tokens = raw_tokens(declaration, 64);
        for (index, token) in tokens.iter().enumerate() {
            if matches!(
                token.as_str(),
                "class"
                    | "const"
                    | "def"
                    | "enum"
                    | "fn"
                    | "func"
                    | "function"
                    | "impl"
                    | "interface"
                    | "macro_rules"
                    | "mod"
                    | "module"
                    | "static"
                    | "struct"
                    | "trait"
                    | "type"
            ) {
                return tokens.get(index.saturating_add(1)).cloned();
            }
        }
        None
    }

    fn terms(text: &str, limit: usize) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for token in raw_tokens(text, limit) {
            insert_expanded(&mut out, &token, limit);
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    fn raw_tokens(text: &str, limit: usize) -> Vec<String> {
        text.split(|character: char| !(character.is_alphanumeric() || character == '_'))
            .filter(|token| token.chars().count() >= 3)
            .take(limit)
            .map(|token| token.chars().take(128).collect())
            .collect()
    }

    fn insert_expanded(out: &mut BTreeSet<String>, token: &str, limit: usize) {
        let mut segment = String::new();
        let mut previous: Option<char> = None;
        for character in token.chars().chain(std::iter::once('_')) {
            let boundary = character == '_'
                || previous.is_some_and(|prior| {
                    (prior.is_lowercase() && character.is_uppercase())
                        || (prior.is_alphabetic() != character.is_alphabetic())
                });
            if boundary {
                if segment.chars().count() >= 3 && out.len() < limit {
                    out.insert(segment.to_lowercase());
                }
                segment.clear();
            }
            if character != '_' {
                segment.push(character);
            }
            previous = Some(character);
        }
        if token.chars().count() >= 3 && out.len() < limit {
            out.insert(token.to_lowercase());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn camel_snake_and_path_terms_share_task_vocabulary() {
            let files = [
                FileSignals::extract(
                    "src/cache/token_store.ts",
                    &["export function invalidateTokenCache()".into()],
                    "export function invalidateTokenCache() {}",
                ),
                FileSignals::extract(
                    "src/unrelated.ts",
                    &["export function calculateReport()".into()],
                    "export function calculateReport() {}",
                ),
            ];
            let scores = rank(files.iter(), "repair token cache invalidation");
            assert!(scores[0].direct > scores[1].direct);
        }

        #[test]
        fn task_evidence_propagates_across_a_definition_reference_edge() {
            let files = [
                FileSignals::extract(
                    "src/service.rs",
                    &["pub struct PaymentGateway;".into()],
                    "pub struct PaymentGateway;",
                ),
                FileSignals::extract(
                    "tests/service_test.rs",
                    &["fn rejects_expired_card() {}".into()],
                    "fn rejects_expired_card() { let _ = PaymentGateway; }",
                ),
                FileSignals::extract(
                    "src/report.rs",
                    &["pub fn report() {}".into()],
                    "pub fn report() {}",
                ),
            ];
            let scores = rank(files.iter(), "PaymentGateway timeout");
            assert!(scores[0].direct > 0);
            assert!(scores[1].related > scores[2].related);
            assert!(scores[0].centrality > scores[2].centrality);
        }
    }
}

/// A skeleton needs declaration headers, never an entire large source file. Keep this ceiling
/// comfortably above ordinary code files while bounding allocation for model-invokable repo_map.
const MAX_OUTLINE_SOURCE_BYTES: usize = 256 * 1024;
const MAX_OUTLINE_QUERY_BYTES: usize = 8 * 1024;
/// Bound the complete discovery/read/sort pipeline, not just each individual file. The source-byte
/// ceiling is authoritative for retained declaration memory; the entry ceiling also bounds work
/// in repositories containing huge numbers of non-code files.
const MAX_OUTLINE_CODE_FILES: usize = 1_024;
const MAX_OUTLINE_TOTAL_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTLINE_ENTRIES: usize = 16_384;

/// Is this line a top-level declaration worth putting in the skeleton? Language-agnostic:
/// matches the common `def/class/fn/function/struct/impl/type/trait/interface/pub` shapes at a
/// shallow indent (top-level or one level in). Deliberately simple and inclusive.
#[cfg(test)]
fn is_decl(line: &str) -> bool {
    is_decl_with_keywords(
        line,
        iteron_tunables::param_str_list("ctx.outline.declaration_keywords", DECLARATION_KEYWORDS),
    )
}

const DECLARATION_KEYWORDS: &[&str] = &[
    "def ",
    "class ",
    "fn ",
    "pub fn ",
    "pub struct ",
    "struct ",
    "impl ",
    "trait ",
    "pub trait ",
    "enum ",
    "pub enum ",
    "type ",
    "pub type ",
    "mod ",
    "pub mod ",
    "const ",
    "pub const ",
    "static ",
    "pub static ",
    "macro_rules! ",
    "interface ",
    "function ",
    "func ",
    "public ",
    "export function ",
    "export class ",
    "export const ",
    "async def ",
    "module ",
];

fn is_decl_with_keywords(line: &str, keywords: &[&str]) -> bool {
    let t = line.trim_start();
    let indent = line.len() - t.len();
    if indent > 4 {
        return false; // only top-level-ish declarations
    }
    keywords.iter().any(|keyword| t.starts_with(keyword))
}

#[derive(Debug)]
struct OutlineFile {
    path: String,
    declarations: Vec<String>,
    signals: outline_relevance::FileSignals,
    relevance: outline_relevance::Relevance,
}

/// Preserve the tunable query envelope before the private ranker expands compound identifiers.
fn query_identifiers(query: &str) -> Vec<String> {
    const MAX_IDENTIFIERS: usize = 64;
    const MAX_IDENTIFIER_CHARS: usize = 128;
    let max_identifiers =
        iteron_tunables::param_usize("ctx.outline.max_identifiers", MAX_IDENTIFIERS);
    let max_identifier_chars =
        iteron_tunables::param_usize("ctx.outline.max_identifier_chars", MAX_IDENTIFIER_CHARS);
    let mut identifiers = Vec::new();
    for token in query
        .split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .filter(|token| token.chars().count() >= 3)
        .take(max_identifiers)
    {
        let identifier: String = token.chars().take(max_identifier_chars).collect();
        if !identifiers.contains(&identifier) {
            identifiers.push(identifier);
        }
    }
    identifiers
}

fn is_code_file(name: &str) -> bool {
    let ext = name.rsplit('.').next().unwrap_or("");
    matches!(
        ext,
        "rs" | "py"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "go"
            | "java"
            | "c"
            | "h"
            | "cpp"
            | "hpp"
            | "rb"
            | "php"
            | "cs"
            | "swift"
            | "kt"
            | "scala"
            | "ml"
            | "hs"
    )
}

fn is_ignored(name: &str) -> bool {
    name == ".iteron" || crate::source::is_default_pruned_component(name)
}

/// Build a skeleton of the repo rooted at `root`, fit to roughly `token_budget` tokens. Files
/// are included by a cheap signal ranking (shallower path + more declarations first) and the
/// budget is respected by stopping — a bounded, legible fitter, not a solver.
pub fn repo_outline(root: &Path, token_budget: usize) -> String {
    repo_outline_for_task(root, token_budget, "")
}

/// Build a skeleton with an optional task/query relevance hint. A declaration naming an
/// identifier from the query ranks ahead of unrelated files, even when those files contain more
/// declarations. The output remains a pure deterministic function of repository bytes + query.
pub fn repo_outline_for_task(root: &Path, token_budget: usize, query: &str) -> String {
    repo_outline_for_task_at_depth(root, 8, token_budget, query)
}

/// Runtime-bound repository skeleton. The caller supplies the immutable per-run limits; this
/// function still intersects them with the crate's fixed allocation ceilings.
pub fn repo_outline_for_task_with_limits(
    root: &Path,
    max_files: usize,
    depth: u8,
    token_budget: usize,
    query: &str,
) -> String {
    repo_outline_for_task_at_limits(root, max_files, depth, token_budget, query)
}

pub(crate) fn repo_outline_for_task_at_depth(
    root: &Path,
    depth: u8,
    token_budget: usize,
    query: &str,
) -> String {
    repo_outline_for_task_at_limits(
        root,
        iteron_tunables::param_usize("ctx.outline.max_outline_code_files", MAX_OUTLINE_CODE_FILES),
        depth,
        token_budget,
        query,
    )
}

fn repo_outline_for_task_at_limits(
    root: &Path,
    max_files: usize,
    depth: u8,
    token_budget: usize,
    query: &str,
) -> String {
    let max_outline_code_files =
        iteron_tunables::param_usize("ctx.outline.max_outline_code_files", MAX_OUTLINE_CODE_FILES);
    let max_outline_entries =
        iteron_tunables::param_usize("ctx.outline.max_outline_entries", MAX_OUTLINE_ENTRIES);
    let max_outline_source_bytes = iteron_tunables::param_usize(
        "ctx.outline.max_outline_source_bytes",
        iteron_tunables::param_integer(
            "ctx.outline.max_outline_source_bytes",
            MAX_OUTLINE_SOURCE_BYTES,
        ),
    );
    let max_outline_total_source_bytes = iteron_tunables::param_usize(
        "ctx.outline.max_outline_total_source_bytes",
        iteron_tunables::param_integer(
            "ctx.outline.max_outline_total_source_bytes",
            MAX_OUTLINE_TOTAL_SOURCE_BYTES,
        ),
    );
    let max_files = max_files.min(max_outline_code_files);
    let bounded_query = iteron_protocol::text::head(
        query,
        iteron_tunables::param_integer(
            "ctx.outline.max_outline_query_bytes",
            MAX_OUTLINE_QUERY_BYTES,
        ),
    );
    let declaration_keywords =
        iteron_tunables::param_str_list("ctx.outline.declaration_keywords", DECLARATION_KEYWORDS);
    let mut files: Vec<OutlineFile> = Vec::new();
    let mut rejected = 0usize;
    let mut bounded_omitted = 0usize;
    let mut total_source_bytes = 0usize;
    let mut source_budget_exhausted = false;
    let mut traversal_limited = false;
    let mut entries = WalkDir::new(root)
        .max_depth(usize::from(depth))
        .into_iter()
        .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")));
    for entry_index in 0..=max_outline_entries {
        let Some(entry) = entries.next() else {
            break;
        };
        if entry_index == max_outline_entries {
            traversal_limited = true;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                rejected = rejected.saturating_add(1);
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_str().unwrap_or("");
        if !is_code_file(name) {
            continue;
        }
        if files.len() >= max_files || source_budget_exhausted {
            bounded_omitted = bounded_omitted.saturating_add(1);
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .display()
            .to_string();
        if suspicious_unicode(&rel).is_some() {
            rejected = rejected.saturating_add(1);
            continue;
        }
        let content = match read_bounded_utf8(
            root,
            entry.path(),
            max_outline_source_bytes,
            SourceScope::Repository,
        ) {
            Ok(Some(content)) => content,
            Ok(None) | Err(_) => {
                rejected += 1;
                continue;
            }
        };
        if content.len() > max_outline_total_source_bytes.saturating_sub(total_source_bytes) {
            source_budget_exhausted = true;
            bounded_omitted = bounded_omitted.saturating_add(1);
            continue;
        }
        if suspicious_unicode(&content).is_some() {
            rejected = rejected.saturating_add(1);
            continue;
        }
        total_source_bytes += content.len();
        let declaration_lines: Vec<(usize, String)> = content
            .lines()
            .enumerate()
            .filter(|(_, line)| is_decl_with_keywords(line, declaration_keywords))
            .map(|(index, line)| (index.saturating_add(1), line.trim().to_owned()))
            .take(40) // cap per file so one large in-bound file can't dominate
            .collect();
        let raw_declarations = declaration_lines
            .iter()
            .map(|(_, declaration)| declaration.clone())
            .collect::<Vec<_>>();
        let signals = outline_relevance::FileSignals::extract(&rel, &raw_declarations, &content);
        let declarations = declaration_lines
            .into_iter()
            .map(|(line, declaration)| format!("  {line}: {declaration}"))
            .collect();
        files.push(OutlineFile {
            path: rel,
            declarations,
            signals,
            relevance: outline_relevance::Relevance::default(),
        });
    }
    // Canonicalize before the bounded graph is built so capped relation selection and final output
    // are independent of filesystem enumeration order.
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let task_query = query_identifiers(&bounded_query).join(" ");
    let relevance = outline_relevance::rank(files.iter().map(|file| &file.signals), &task_query);
    for (file, score) in files.iter_mut().zip(relevance) {
        file.relevance = score;
    }
    // Rank direct task evidence first, then task-neighbor relations and global definition
    // centrality. Declaration density and path depth remain deterministic fallback signals.
    files.sort_by(|a, b| {
        let depth_a = a.path.matches('/').count();
        let depth_b = b.path.matches('/').count();
        b.relevance
            .direct
            .cmp(&a.relevance.direct)
            .then(b.relevance.related.cmp(&a.relevance.related))
            .then(b.relevance.centrality.cmp(&a.relevance.centrality))
            .then(b.declarations.len().cmp(&a.declarations.len()))
            .then(depth_a.cmp(&depth_b))
            .then(a.path.cmp(&b.path))
    });

    let mut out =
        String::from("# Repository skeleton (declarations only; read a file for bodies)\n");
    let mut used = crate::estimate_tokens(&out);
    let mut dropped = 0;
    for file in files {
        let block = if file.declarations.is_empty() {
            format!("{}\n", file.path)
        } else {
            format!("{}\n{}\n", file.path, file.declarations.join("\n"))
        };
        let cost = crate::estimate_tokens(&block);
        if used + cost > token_budget {
            dropped += 1;
            continue;
        }
        out.push_str(&block);
        used += cost;
    }
    if dropped > 0 {
        // Never silently truncate: say what was omitted (the "no silent caps" rule).
        out.push_str(&format!(
            "\n[{dropped} more files omitted to fit the map budget; use list_dir/grep to reach them]\n"
        ));
    }
    if rejected > 0 {
        out.push_str(&format!(
            "\n[{rejected} code files omitted as unsafe, unreadable, non-UTF-8, symlinked, or over the {max_outline_source_bytes}-byte source limit]\n"
        ));
    }
    if bounded_omitted > 0 {
        out.push_str(&format!(
            "\n[{bounded_omitted} code files omitted at the {max_files}-file / {max_outline_total_source_bytes}-total-source-byte repo-map limits]\n"
        ));
    }
    if traversal_limited {
        out.push_str(&format!(
            "\n[additional repository entries omitted after the {max_outline_entries}-entry traversal limit]\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_decl_matches_common_shapes() {
        assert!(is_decl("def multiply(a, b):"));
        assert!(is_decl("pub fn run(&self) {"));
        assert!(is_decl("class Foo:"));
        assert!(is_decl("export function bar() {"));
        assert!(!is_decl("    x = a + b"));
        assert!(!is_decl("            def deeply_nested():")); // too indented
    }

    #[test]
    fn d6_07_outline_covers_rust_module_and_item_declarations() {
        let dir = std::env::temp_dir().join(format!(
            "iteron-ctx-declaration-shapes-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("shapes.rs"),
            concat!(
                "pub trait PublicTrait {}\n",
                "mod private_module;\n",
                "pub mod public_module;\n",
                "const PRIVATE_LIMIT: usize = 1;\n",
                "pub const PUBLIC_LIMIT: usize = 2;\n",
                "static PRIVATE_STATE: usize = 3;\n",
                "pub static PUBLIC_STATE: usize = 4;\n",
                "macro_rules! bounded_macro { () => {}; }\n",
            ),
        )
        .unwrap();

        let map = repo_outline(&dir, 10_000);
        for declaration in [
            "pub trait PublicTrait",
            "mod private_module",
            "pub mod public_module",
            "const PRIVATE_LIMIT",
            "pub const PUBLIC_LIMIT",
            "static PRIVATE_STATE",
            "pub static PUBLIC_STATE",
            "macro_rules! bounded_macro",
        ] {
            assert!(map.contains(declaration), "missing {declaration}:\n{map}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d6_07_named_identifier_outranks_unrelated_declaration_volume() {
        let dir = std::env::temp_dir().join(format!(
            "iteron-ctx-identifier-ranking-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let unrelated = (0..30)
            .map(|index| format!("pub fn unrelated_{index}() {{}}\n"))
            .collect::<String>();
        std::fs::write(dir.join("a_many.rs"), unrelated).unwrap();
        std::fs::write(
            dir.join("z_target.rs"),
            "pub struct NeedleType;\npub fn construct_needle() {}\n",
        )
        .unwrap();

        let first = repo_outline_for_task(&dir, 10_000, "fix NeedleType serialization");
        let second = repo_outline_for_task(&dir, 10_000, "fix NeedleType serialization");
        assert_eq!(first, second, "identical inputs must be byte-deterministic");
        assert!(
            first.find("z_target.rs").unwrap() < first.find("a_many.rs").unwrap(),
            "the defining file must outrank a larger unrelated file:\n{first}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn task_path_and_cross_file_reference_outrank_unrelated_declaration_volume() {
        let dir = std::env::temp_dir().join(format!(
            "iteron-ctx-task-graph-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("payments")).unwrap();
        let unrelated = (0..30)
            .map(|index| format!("pub fn unrelated_{index}() {{}}\n"))
            .collect::<String>();
        std::fs::write(dir.join("a_many.rs"), unrelated).unwrap();
        std::fs::write(
            dir.join("payments/gateway.rs"),
            "pub struct GatewayClient;\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("payments/gateway_test.rs"),
            "fn rejects_timeout() { let _ = GatewayClient; }\n",
        )
        .unwrap();

        let map = repo_outline_for_task(&dir, 10_000, "repair payment gateway timeout handling");
        let gateway = map.find("payments/gateway.rs").unwrap();
        let gateway_test = map.find("payments/gateway_test.rs").unwrap();
        let unrelated = map.find("a_many.rs").unwrap();
        assert!(gateway < unrelated, "task path must outrank volume:\n{map}");
        assert!(
            gateway_test < unrelated,
            "a task-neighbor reference must outrank unrelated volume:\n{map}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn outline_lists_declarations_and_respects_budget() {
        let dir = std::env::temp_dir().join(format!("iteron-ctx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("a.py"),
            "def foo():\n    pass\ndef bar():\n    pass\n",
        )
        .unwrap();
        std::fs::write(dir.join("b.rs"), "pub fn baz() {}\n").unwrap();
        let map = repo_outline(&dir, 10_000);
        assert!(map.contains("a.py"));
        assert!(map.contains("def foo"));
        assert!(map.contains("def bar"));
        assert!(map.contains("b.rs"));
        assert!(map.contains("pub fn baz"));
        assert_eq!(
            map,
            concat!(
                "# Repository skeleton (declarations only; read a file for bodies)\n",
                "a.py\n",
                "  1: def foo():\n",
                "  3: def bar():\n",
                "b.rs\n",
                "  1: pub fn baz() {}\n",
            )
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_code_file_is_rejected_before_reading_and_disclosed() {
        let dir = std::env::temp_dir().join(format!("iteron-ctx-large-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = std::fs::File::create(dir.join("huge.rs")).unwrap();
        file.set_len(MAX_OUTLINE_SOURCE_BYTES as u64 + 1).unwrap();

        let map = repo_outline(&dir, 10_000);
        assert!(!map.contains("huge.rs"));
        assert!(map.contains("1 code files omitted"));
        assert!(map.contains("262144-byte source limit"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repository_wide_file_collection_is_hard_bounded_and_disclosed() {
        let dir = std::env::temp_dir().join(format!(
            "iteron-ctx-many-files-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for index in 0..MAX_OUTLINE_CODE_FILES + 2 {
            std::fs::write(dir.join(format!("f{index:04}.rs")), "").unwrap();
        }

        let map = repo_outline(&dir, usize::MAX);
        let included = map.lines().filter(|line| line.ends_with(".rs")).count();
        assert_eq!(included, MAX_OUTLINE_CODE_FILES);
        assert!(map.contains("2 code files omitted"));
        assert!(map.contains("repo-map limits"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn suspicious_unicode_rejects_the_file_and_surfaces_the_omission() {
        let dir = std::env::temp_dir().join(format!("iteron-ctx-bidi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hostile.rs"), "pub fn safe_\u{202e}hidden() {}\n").unwrap();
        std::fs::write(
            dir.join("zero_width.rs"),
            "pub fn safe_\u{200b}hidden() {}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("hostile_\u{202e}_path.rs"),
            "pub fn safe_content() {}\n",
        )
        .unwrap();

        let map = repo_outline(&dir, 10_000);
        assert!(!map.contains('\u{202e}'));
        assert!(!map.contains('\u{200b}'));
        assert!(!map.contains("hostile.rs"));
        assert!(!map.contains("zero_width.rs"));
        assert!(!map.contains("safe_content"));
        assert!(map.contains("3 code files omitted"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d6_06_repo_outline_rejects_zero_width_word_joiner() {
        const ASSERTIONS_RAN: &str = "D6_06_ZERO_WIDTH_OUTLINE_ASSERTIONS_RAN";
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("iteron-ctx-d6-06-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("clean.rs"), "pub fn visible_declaration() {}\n").unwrap();
        std::fs::write(
            dir.join("hostile.rs"),
            "pub fn trusted_\u{2060}hidden() {}\n",
        )
        .unwrap();

        let map = repo_outline(&dir, 10_000);
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(
            map.contains("pub fn visible_declaration"),
            "a hostile neighbor must not suppress safe declarations:\n{map}"
        );
        assert!(
            !map.contains('\u{2060}') && !map.contains("trusted_"),
            "a declaration containing U+2060 WORD JOINER entered the outline:\n{map}"
        );
        assert!(
            map.to_ascii_lowercase().contains("omitted"),
            "the suspicious declaration or file omission was not surfaced:\n{map}"
        );
        println!("{ASSERTIONS_RAN}");
    }

    #[test]
    fn a_tiny_budget_drops_files_and_says_so() {
        let dir = std::env::temp_dir().join(format!("iteron-ctx-tiny-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..20 {
            std::fs::write(
                dir.join(format!("f{i}.py")),
                "def a():\n def b():\n def c():\n",
            )
            .unwrap();
        }
        let map = repo_outline(&dir, 60); // tiny budget forces drops
        assert!(
            map.contains("omitted"),
            "must disclose dropped files, never silently truncate"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
