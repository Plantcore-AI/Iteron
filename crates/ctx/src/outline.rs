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

/// Is this line a top-level declaration worth putting in the skeleton? Language-agnostic:
/// matches the common `def/class/fn/function/struct/impl/type/trait/interface/pub` shapes at a
/// shallow indent (top-level or one level in). Deliberately simple and inclusive.
fn is_decl(line: &str) -> bool {
    let t = line.trim_start();
    let indent = line.len() - t.len();
    if indent > 4 {
        return false; // only top-level-ish declarations
    }
    const KWS: &[&str] = &[
        "def ",
        "class ",
        "fn ",
        "pub fn ",
        "pub struct ",
        "struct ",
        "impl ",
        "trait ",
        "enum ",
        "pub enum ",
        "type ",
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
    KWS.iter().any(|k| t.starts_with(k))
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
    matches!(
        name,
        ".git"
            | "target"
            | "node_modules"
            | ".venv"
            | "venv"
            | "dist"
            | "build"
            | "__pycache__"
            | ".core"
    )
}

/// Build a skeleton of the repo rooted at `root`, fit to roughly `token_budget` tokens. Files
/// are included by a cheap signal ranking (shallower path + more declarations first) and the
/// budget is respected by stopping — a bounded, legible fitter, not a solver.
pub fn repo_outline(root: &Path, token_budget: usize) -> String {
    let mut files: Vec<(String, Vec<String>)> = Vec::new();
    for entry in WalkDir::new(root)
        .max_depth(8)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_str().unwrap_or("");
        if !is_code_file(name) {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .display()
            .to_string();
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            let decls: Vec<String> = content
                .lines()
                .enumerate()
                .filter(|(_, l)| is_decl(l))
                .map(|(i, l)| format!("  {}: {}", i + 1, l.trim()))
                .take(40) // cap per file so one huge file can't dominate
                .collect();
            files.push((rel, decls));
        }
    }
    // Rank: files with more declarations and shallower paths first (cheap signal).
    files.sort_by(|a, b| {
        let da = a.1.len();
        let db = b.1.len();
        let depth_a = a.0.matches('/').count();
        let depth_b = b.0.matches('/').count();
        db.cmp(&da).then(depth_a.cmp(&depth_b))
    });

    let mut out =
        String::from("# Repository skeleton (declarations only; read a file for bodies)\n");
    let mut used = crate::estimate_tokens(&out);
    let mut dropped = 0;
    for (rel, decls) in files {
        let block = if decls.is_empty() {
            format!("{rel}\n")
        } else {
            format!("{rel}\n{}\n", decls.join("\n"))
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
    fn outline_lists_declarations_and_respects_budget() {
        let dir = std::env::temp_dir().join(format!("core-ctx-{}", std::process::id()));
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
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_tiny_budget_drops_files_and_says_so() {
        let dir = std::env::temp_dir().join(format!("core-ctx-tiny-{}", std::process::id()));
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
