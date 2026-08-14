//! Typed hyperlink discovery for non-Markdown transcript blocks.
//!
//! The semantic renderer remains the sole owner of printable content. This module examines only
//! explicit path/URL fields and bounded documentation URLs, asks the session [`Policy`] to admit
//! every target, then attaches display-cell regions to the already-rendered rows. It never inserts
//! escape bytes or changes a visible span.

use super::BlockKind;
use crate::render::{HyperlinkRegion, RenderedLines};
use crate::tui::hyperlink::Policy;
use ratatui::text::Line;

const MAX_TYPED_LINKS_PER_BLOCK: usize = 64;
const MAX_TOOL_OUTPUT_SCAN_BYTES: usize = 64 * 1024;
const MAX_VISIBLE_LINK_SCAN_BYTES: usize = 64 * 1024;

const PATH_ARG_KEYS: [&str; 9] = [
    "path",
    "file",
    "file_path",
    "filename",
    "directory",
    "dir",
    "root",
    "workspace",
    "working_directory",
];
const URL_ARG_KEYS: [&str; 6] = [
    "url",
    "uri",
    "href",
    "docs_url",
    "documentation_url",
    "documentation",
];

fn path_arg_keys() -> &'static [&'static str] {
    iteron_tunables::param_str_list("cli.block.links.path_arg_keys", &PATH_ARG_KEYS)
}

fn url_arg_keys() -> &'static [&'static str] {
    iteron_tunables::param_str_list("cli.block.links.url_arg_keys", &URL_ARG_KEYS)
}

struct Candidate {
    label: String,
    target: String,
}

pub(super) fn annotate(
    kind: &BlockKind,
    lines: Vec<Line<'static>>,
    policy: &Policy,
) -> RenderedLines {
    let mut rendered = RenderedLines::plain(lines);
    if !policy.supports_osc8() {
        return rendered;
    }

    let mut candidates = Vec::new();
    match kind {
        BlockKind::Tool(card) => {
            collect_typed_args(&mut candidates, &card.args, policy);
            collect_documentation_urls(&mut candidates, &card.output, policy);
            if let Some(diff) = &card.diff {
                collect_diff_path(&mut candidates, &diff.path, policy);
            }
        }
        BlockKind::Diff(diff) => collect_diff_path(&mut candidates, &diff.path, policy),
        _ => {}
    }
    rendered.hyperlinks = visible_regions(&rendered.lines, &candidates);
    rendered
}

fn collect_typed_args(candidates: &mut Vec<Candidate>, args: &serde_json::Value, policy: &Policy) {
    let Some(object) = args.as_object() else {
        return;
    };
    for key in path_arg_keys()
        .iter()
        .copied()
        .chain(url_arg_keys().iter().copied())
    {
        if candidates.len()
            >= iteron_tunables::param_integer(
                "cli.block.links.max_typed_links_per_block",
                MAX_TYPED_LINKS_PER_BLOCK,
            )
        {
            return;
        }
        let Some(raw) = object.get(key).and_then(serde_json::Value::as_str) else {
            continue;
        };
        push_candidate(candidates, raw, raw, policy);
    }
}

fn collect_diff_path(candidates: &mut Vec<Candidate>, path: &str, policy: &Policy) {
    let before = candidates.len();
    push_candidate(candidates, path, path, policy);
    if candidates.len() == before {
        return;
    }
    let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if basename != path {
        // Inline edit summaries intentionally show only the basename. It still resolves through the
        // already-admitted full path rather than being reinterpreted relative to the workspace root.
        let target = candidates[before].target.clone();
        push_admitted_candidate(candidates, basename, target);
    }
}

fn collect_documentation_urls(candidates: &mut Vec<Candidate>, output: &str, policy: &Policy) {
    let output = bounded_prefix(
        output,
        iteron_tunables::param_integer(
            "cli.block.links.max_tool_output_scan_bytes",
            MAX_TOOL_OUTPUT_SCAN_BYTES,
        ),
    );
    let mut cursor = 0usize;
    while cursor < output.len()
        && candidates.len()
            < iteron_tunables::param_integer(
                "cli.block.links.max_typed_links_per_block",
                MAX_TYPED_LINKS_PER_BLOCK,
            )
    {
        let rest = &output[cursor..];
        let Some(relative_start) = next_web_scheme(rest) else {
            break;
        };
        let start = cursor.saturating_add(relative_start);
        let candidate = &output[start..];
        let end = candidate
            .char_indices()
            .find_map(|(offset, character)| {
                (offset > 0 && url_token_delimiter(character)).then_some(offset)
            })
            .unwrap_or(candidate.len());
        let raw = candidate[..end].trim_end_matches(url_trailing_punctuation);
        if !raw.is_empty() {
            push_candidate(candidates, raw, raw, policy);
        }
        // Always advance beyond the scheme, even when admission rejected the token.
        cursor = start.saturating_add(end.max("http://".len()));
    }
}

fn next_web_scheme(text: &str) -> Option<usize> {
    ["https://", "http://"]
        .into_iter()
        .filter_map(|scheme| text.find(scheme))
        .min()
}

fn url_token_delimiter(character: char) -> bool {
    character.is_whitespace()
        || character.is_control()
        || matches!(character, '<' | '>' | '"' | '\'' | '`')
}

fn url_trailing_punctuation(character: char) -> bool {
    matches!(
        character,
        '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}'
    )
}

fn bounded_prefix(text: &str, max_bytes: usize) -> &str {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    &text[..end]
}

fn push_candidate(candidates: &mut Vec<Candidate>, label: &str, raw: &str, policy: &Policy) {
    if candidates.len()
        >= iteron_tunables::param_integer(
            "cli.block.links.max_typed_links_per_block",
            MAX_TYPED_LINKS_PER_BLOCK,
        )
        || label.is_empty()
    {
        return;
    }
    let Some(target) = policy.admit_target(raw) else {
        return;
    };
    push_admitted_candidate(candidates, label, target);
}

fn push_admitted_candidate(candidates: &mut Vec<Candidate>, label: &str, target: String) {
    if candidates.len()
        >= iteron_tunables::param_integer(
            "cli.block.links.max_typed_links_per_block",
            MAX_TYPED_LINKS_PER_BLOCK,
        )
        || label.is_empty()
        || candidates
            .iter()
            .any(|candidate| candidate.label == label && candidate.target == target)
    {
        return;
    }
    candidates.push(Candidate {
        label: label.to_string(),
        target,
    });
}

fn visible_regions(lines: &[Line<'static>], candidates: &[Candidate]) -> Vec<HyperlinkRegion> {
    let mut regions = Vec::new();
    let mut remaining_scan_bytes = iteron_tunables::param_integer(
        "cli.block.links.max_visible_link_scan_bytes",
        MAX_VISIBLE_LINK_SCAN_BYTES,
    );
    let mut candidate_order = (0..candidates.len()).collect::<Vec<_>>();
    candidate_order.sort_unstable_by(|left, right| {
        candidates[*right]
            .label
            .len()
            .cmp(&candidates[*left].label.len())
            .then_with(|| left.cmp(right))
    });
    for (row, line) in lines.iter().enumerate() {
        if regions.len()
            >= iteron_tunables::param_integer(
                "cli.block.links.max_typed_links_per_block",
                MAX_TYPED_LINKS_PER_BLOCK,
            )
            || remaining_scan_bytes == 0
        {
            break;
        }
        let visible = bounded_line_text(line, remaining_scan_bytes);
        remaining_scan_bytes = remaining_scan_bytes.saturating_sub(visible.len());
        let mut offset = 0usize;
        let mut column = 0u16;
        while offset < visible.len()
            && regions.len()
                < iteron_tunables::param_integer(
                    "cli.block.links.max_typed_links_per_block",
                    MAX_TYPED_LINKS_PER_BLOCK,
                )
        {
            let rest = &visible[offset..];
            let matched = candidate_order
                .iter()
                .copied()
                .find(|candidate_index| rest.starts_with(&candidates[*candidate_index].label));
            if let Some(candidate_index) = matched {
                let candidate = &candidates[candidate_index];
                let width = display_width(&candidate.label);
                if width > 0 {
                    regions.push(HyperlinkRegion {
                        row,
                        col: column,
                        width,
                        target: candidate.target.clone(),
                    });
                }
                offset = offset.saturating_add(candidate.label.len());
                column = column.saturating_add(width);
            } else {
                let Some(character) = rest.chars().next() else {
                    break;
                };
                offset = offset.saturating_add(character.len_utf8());
                column = column.saturating_add(crate::tui::char_width(character));
            }
        }
    }
    regions
}

fn bounded_line_text(line: &Line<'static>, max_bytes: usize) -> String {
    let mut visible = String::new();
    for character in line.spans.iter().flat_map(|span| span.content.chars()) {
        if visible.len().saturating_add(character.len_utf8()) > max_bytes {
            break;
        }
        visible.push(character);
    }
    visible
}

fn display_width(text: &str) -> u16 {
    text.chars()
        .map(crate::tui::char_width)
        .fold(0u16, u16::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, ToolCard, ToolStatus};
    use crate::theme::Theme;
    use crate::tui::hyperlink::Capability;
    use iteron_protocol::FileDiff;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn workspace(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("core-block-links-{label}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).expect("create link test workspace");
        root
    }

    fn tool(args: serde_json::Value, output: impl Into<String>) -> Block {
        Block::new(
            1,
            BlockKind::Tool(ToolCard {
                name: "custom_tool".into(),
                args,
                status: ToolStatus::Ok,
                output: output.into(),
                diff: None,
                exit_code: None,
                started: Instant::now(),
                elapsed: Some(Duration::from_millis(10)),
                open: true,
            }),
        )
    }

    fn visible(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn capable_tool_links_typed_file_arg_and_documentation_url() {
        let root = workspace("tool");
        std::fs::write(root.join("src/lib.rs"), "pub fn linked() {}").expect("write linked file");
        let policy = Policy::new(Capability::Osc8, &root);
        let block = tool(
            serde_json::json!({"path": "src/lib.rs"}),
            "Docs: https://example.com/reference.",
        );

        let rendered = block.render_with_hyperlinks(120, &Theme::dark(), 0, &policy);
        let text = visible(&rendered.lines);
        assert!(text.contains("src/lib.rs"));
        assert!(text.contains("https://example.com/reference."));
        assert_eq!(rendered.hyperlinks.len(), 2);
        assert!(
            rendered
                .hyperlinks
                .iter()
                .any(|link| link.target.starts_with("file://") && link.width == 10)
        );
        assert!(
            rendered
                .hyperlinks
                .iter()
                .any(|link| link.target == "https://example.com/reference")
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn standalone_and_inline_diff_paths_resolve_to_confined_file() {
        let root = workspace("diff");
        std::fs::write(root.join("src/change.rs"), "before").expect("write diff target");
        let policy = Policy::new(Capability::Osc8, &root);
        let diff = FileDiff::from_replacement("src/change.rs", "before", "after");
        let standalone = Block::new(2, BlockKind::Diff(diff.clone())).render_with_hyperlinks(
            100,
            &Theme::dark(),
            0,
            &policy,
        );
        assert_eq!(
            standalone.hyperlinks.len(),
            2,
            "the visible diff title and hunk header both name the typed path"
        );
        assert!(
            standalone
                .hyperlinks
                .iter()
                .all(|link| link.width == 13 && link.target.starts_with("file://"))
        );

        let mut inline = tool(serde_json::json!({"path": "src/change.rs"}), "");
        let BlockKind::Tool(card) = &mut inline.kind else {
            unreachable!("test creates a tool")
        };
        card.diff = Some(diff);
        let inline = inline.render_with_hyperlinks(100, &Theme::dark(), 0, &policy);
        assert!(
            inline.hyperlinks.iter().any(|link| {
                link.target.starts_with("file://")
                    && visible(&inline.lines)[..].contains("change.rs")
            }),
            "tool header and basename result both remain linked to the admitted full path"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn incapable_terminal_is_exact_plain_render_and_invalid_targets_stay_unlinked() {
        let root = workspace("plain");
        std::fs::write(root.join("ok.rs"), "ok").expect("write valid path");
        let block = tool(
            serde_json::json!({"path": "ok.rs"}),
            concat!(
                "valid https://example.com/docs\n",
                "credentials https://user:secret@example.com/private\n",
                "script javascript:alert(1)"
            ),
        );
        let theme = Theme::dark();
        let disabled = Policy::disabled();
        let plain = block.render(100, &theme, 0);
        let rendered = block.render_with_hyperlinks(100, &theme, 0, &disabled);
        assert_eq!(visible(&rendered.lines), visible(&plain));
        assert!(rendered.hyperlinks.is_empty());

        let capable = Policy::new(Capability::Osc8, &root);
        let rendered = block.render_with_hyperlinks(100, &theme, 0, &capable);
        assert_eq!(visible(&rendered.lines), visible(&plain));
        assert_eq!(
            rendered
                .hyperlinks
                .iter()
                .filter(|link| link.target.starts_with("https://"))
                .count(),
            1,
            "credentialed and non-web targets are rejected by Policy"
        );

        let outside = tool(serde_json::json!({"path": "../outside.rs"}), "");
        assert!(
            outside
                .render_with_hyperlinks(100, &theme, 0, &capable)
                .hyperlinks
                .is_empty(),
            "workspace traversal is not linkable"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tool_output_scanning_and_regions_are_bounded() {
        let root = workspace("bounds");
        let policy = Policy::new(Capability::Osc8, &root);
        let output = (0..100)
            .map(|index| format!("https://example.com/docs/{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let rendered = tool(serde_json::json!({}), output).render_with_hyperlinks(
            120,
            &Theme::dark(),
            0,
            &policy,
        );
        assert_eq!(rendered.hyperlinks.len(), MAX_TYPED_LINKS_PER_BLOCK);
        assert!(
            rendered
                .hyperlinks
                .iter()
                .all(|link| link.row < rendered.lines.len())
        );

        let after_limit = format!(
            "{}https://example.com/not-scanned",
            "x".repeat(MAX_TOOL_OUTPUT_SCAN_BYTES)
        );
        let rendered = tool(serde_json::json!({}), after_limit).render_with_hyperlinks(
            120,
            &Theme::dark(),
            0,
            &policy,
        );
        assert!(rendered.hyperlinks.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }
}
