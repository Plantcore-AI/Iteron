//! Complete FileDiff presentation for standalone viewers and embedded tool results.
//! This owner interprets hunk ranges, syntax hints and code gutters, and produces the
//! final wrapped rows. It has no execution state, transcript identity or tool clock.

use super::{indent_wrap, marker_wrap, primary_marker};
use crate::render::{line_width, wrap_spans};
use crate::theme::Theme;
use iteron_protocol::{DiffTag, FileDiff};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

/// Line number assumed when a hunk header carries no range. The `from_replacement` header
/// (`@@ {path} @@`) has none, and its change is numbered sequentially from the top of the file.
const HUNK_DEFAULT_START_LINE: u32 = 1;

/// The caller selects the real presentation context, not individual rendering flags.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DiffPresentation {
    Standalone,
    ToolResult,
}

/// Standalone viewers include the path/counts and hunk headers. Tool cards have
/// already rendered their result summary, so only the nested code rows are returned.
pub(super) fn render(
    diff: &FileDiff,
    width: u16,
    theme: &Theme,
    presentation: DiffPresentation,
) -> Vec<Line<'static>> {
    match presentation {
        DiffPresentation::Standalone => {
            let mut rows = render_standalone_header(diff, width, theme);
            rows.extend(render_hunks(diff, width, theme, presentation));
            rows
        }
        DiffPresentation::ToolResult => render_hunks(diff, width, theme, presentation),
    }
}

fn render_standalone_header(diff: &FileDiff, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let head = vec![
        Span::styled(
            diff.path.clone(),
            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  +{}", diff.adds),
            Style::default().fg(theme.added),
        ),
        Span::styled(
            format!(" -{}", diff.dels),
            Style::default().fg(theme.removed),
        ),
    ];
    // The diff header earns an ACCENT marker (a diff is a
    // rich viewer, not washed-out chrome). A standalone `/diff` KEEPS the `@@` hunk header (it's a
    // genuine viewer), unlike an inline edit result which suppresses it (findings 2).
    marker_wrap(
        &format!("{} ", primary_marker()),
        Style::default().fg(theme.accent),
        &head,
        width,
    )
}

/// Parse a hunk header's starting line numbers. Unified headers read `@@ -old[,n] +new[,m] @@`; the
/// `from_replacement` header (`@@ {path} @@`) has no ranges, so both default to 1 (sequential
/// numbering from the top of the change). Never panics on a malformed header.
fn hunk_start(header: &str) -> (u32, u32) {
    let mut old = iteron_tunables::param_integer(
        "cli.block.hunk_default_start_line",
        HUNK_DEFAULT_START_LINE,
    );
    let mut new = iteron_tunables::param_integer(
        "cli.block.hunk_default_start_line",
        HUNK_DEFAULT_START_LINE,
    );
    for tok in header.split_whitespace() {
        if let Some(n) = tok.strip_prefix('-') {
            old = n.split(',').next().and_then(|x| x.parse().ok()).unwrap_or(
                iteron_tunables::param_integer(
                    "cli.block.hunk_default_start_line",
                    HUNK_DEFAULT_START_LINE,
                ),
            );
        } else if let Some(n) = tok.strip_prefix('+') {
            new = n.split(',').next().and_then(|x| x.parse().ok()).unwrap_or(
                iteron_tunables::param_integer(
                    "cli.block.hunk_default_start_line",
                    HUNK_DEFAULT_START_LINE,
                ),
            );
        }
    }
    (old, new)
}

/// The lexer language hint for a file path — normally its extension, passed straight to the
/// highlighter (its `spec_for` matches `rs`/`py`/`ts`/… directly). `None` → no highlighting at all,
/// which is the deliberate answer whenever we cannot NAME the language.
///
/// Extensionless build/config files are named, not suffixed, so a basename table is consulted
/// FIRST: `Makefile`, `Dockerfile` and friends otherwise reach the extension split, find nothing,
/// and render plain. Only names the highlighter actually has a `LangSpec` for are mapped; the rest
/// (`Justfile`, `CMakeLists.txt`, the ignore files) map to `None` on purpose — a plain render beats
/// a plausible-looking wrong lexer.
fn lang_for_path(path: &str) -> Option<&str> {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match base {
        "Makefile" | "makefile" | "GNUmakefile" => return Some("make"),
        "Dockerfile" | "Containerfile" => return Some("dockerfile"),
        "Cargo.lock" => return Some("toml"),
        // `just`, `cmake` and the gitignore grammar have no LangSpec — do not guess a near neighbor.
        "Justfile" | "justfile" | "CMakeLists.txt" | ".gitignore" | ".dockerignore" => return None,
        _ => {}
    }
    base.rsplit('.')
        .next()
        .filter(|e| !e.is_empty() && *e != base)
}

/// The diff hunks: a dim `@@` header, then each row = a right-aligned `old│new` line-number gutter
/// (the biggest missing diff cue), a single dim sign cell, and the code text — SYNTAX-HIGHLIGHTED, not
/// flat-colored. Add/del is encoded ONCE by the edge-to-edge background tint + the sign; the code keeps
/// its syntax foreground (like delta/GitHub — TUI v3 §5, review R1/R2). Context rows carry no tint.
/// Rows hang at col 5 (under the connector) so the body reads as nested result.
fn render_hunks(
    diff: &FileDiff,
    width: u16,
    theme: &Theme,
    presentation: DiffPresentation,
) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let indent = "     "; // col 5, under the connector
    let lang = lang_for_path(&diff.path);

    // Pre-pass: the widest line number in the whole diff → the gutter column width.
    let mut max_no = 1u32;
    for h in &diff.hunks {
        let (mut o, mut n) = hunk_start(&h.header);
        for dl in &h.lines {
            match dl.tag {
                DiffTag::Add => {
                    max_no = max_no.max(n);
                    n += 1;
                }
                DiffTag::Del => {
                    max_no = max_no.max(o);
                    o += 1;
                }
                DiffTag::Ctx => {
                    max_no = max_no.max(o.max(n));
                    o += 1;
                    n += 1;
                }
            }
        }
    }
    let gw = max_no.to_string().len();
    let blank = " ".repeat(gw);
    let gutter_style = Style::default().fg(theme.faint);

    // The twin `old│new ` + `sign ` gutter's display width — code hangs under this column (findings 5).
    let gutter_w = 2 * gw + 4; // og(gw) │(1) "ng "(gw+1) "sign "(2)
    let indent_w = indent.chars().count(); // 5, the col-5 connector indent

    for (hi, h) in diff.hunks.iter().enumerate() {
        if presentation == DiffPresentation::Standalone {
            // A standalone `/diff` keeps the `@@ …` hunk header (a genuine viewer — findings 2).
            out.extend(indent_wrap(
                indent,
                &[Span::styled(h.header.clone(), gutter_style)],
                width,
            ));
        } else if hi > 0 {
            // Inline edit result: SUPPRESS the `@@` git tell; a blank row separates successive hunks.
            out.push(Line::from(""));
        }
        let (mut o, mut n) = hunk_start(&h.header);
        let mut st = crate::highlight::LexState::new();
        for dl in &h.lines {
            let (sign, bg, og, ng, changed) = match dl.tag {
                DiffTag::Add => (
                    "+",
                    Some(theme.added_bg),
                    blank.clone(),
                    format!("{n:>gw$}"),
                    theme.added,
                ),
                DiffTag::Del => (
                    "-",
                    Some(theme.removed_bg),
                    format!("{o:>gw$}"),
                    blank.clone(),
                    theme.removed,
                ),
                DiffTag::Ctx => (
                    " ",
                    None,
                    format!("{o:>gw$}"),
                    format!("{n:>gw$}"),
                    theme.faint,
                ),
            };
            match dl.tag {
                DiffTag::Add => n += 1,
                DiffTag::Del => o += 1,
                DiffTag::Ctx => {
                    o += 1;
                    n += 1;
                }
            }
            // add/del is carried PRIMARILY by the sign + the changed-side line number in green/red
            // (delta/Claude Code style), with the row tint as a supporting band. Coloring the sign and
            // number is the load-bearing cue — the dark-theme tint alone (~10/channel off the bg) is too
            // subtle to read, which made the whole card look flat (findings). Context stays faint.
            let sign_style = Style::default().fg(changed);
            let old_style = Style::default().fg(if dl.tag == DiffTag::Del {
                changed
            } else {
                theme.faint
            });
            let new_style = Style::default().fg(if dl.tag == DiffTag::Add {
                changed
            } else {
                theme.faint
            });
            // Expand tabs to spaces BEFORE highlight/wrap: `char_width('\t') == 1` here but the terminal
            // draws a tab as a jump to the next stop, so a tab-indented diff would misalign and its
            // row tint would truncate short of the real right edge (findings 7).
            let expanded = expand_tabs(&dl.text);
            let code_spans = crate::highlight::code_spans(lang, &expanded, &mut st, theme);
            let gutter_spans = || {
                vec![
                    Span::styled(og.clone(), old_style),
                    Span::styled("│".to_string(), gutter_style),
                    Span::styled(format!("{ng} "), new_style),
                    Span::styled(format!("{sign} "), sign_style),
                ]
            };
            let code_col = (indent_w + gutter_w) as u16;
            let mut rows: Vec<Line<'static>> = if code_col < width {
                // HANGING INDENT (findings 5): the gutter (`old│new sign `) prefixes row 0 only; a
                // wrapped continuation gets that gutter width in (faint) spaces so the code stays
                // left-aligned under the code column, never under the line-number gutter. Wrap the CODE
                // at width − code column.
                wrap_spans(&code_spans, width - code_col)
                    .into_iter()
                    .enumerate()
                    .map(|(ri, mut cr)| {
                        let mut spans: Vec<Span<'static>> = vec![Span::raw(indent.to_string())];
                        if ri == 0 {
                            spans.extend(gutter_spans());
                        } else {
                            spans.push(Span::styled(" ".repeat(gutter_w), gutter_style));
                        }
                        spans.append(&mut cr.spans);
                        Line::from(spans)
                    })
                    .collect()
            } else {
                // Pathologically narrow terminal (the gutter alone won't fit a code column): fall back to
                // wrapping gutter+code together so the composed row still respects `<= width` (the
                // pre-wrap→scroll-unit invariant). No hanging indent is possible here anyway.
                let mut spans = gutter_spans();
                spans.extend(code_spans);
                indent_wrap(indent, &spans, width)
            };
            if !theme.mono
                && let Some(bg) = bg
            {
                for row in &mut rows {
                    let w = line_width(row);
                    if w < width {
                        row.spans.push(Span::raw(" ".repeat((width - w) as usize)));
                    }
                    // skip the col-5 connector indent (first span) so the left margin stays neutral;
                    // the tint then runs edge-to-edge from the gutter across the row.
                    for s in row.spans.iter_mut().skip(1) {
                        if s.style.bg.is_none() {
                            s.style = s.style.bg(bg);
                        }
                    }
                }
            }
            out.extend(rows);
        }
    }
    out
}

/// Expand `\t` to spaces on a 4-cell tab grid (the width `char_width` reports for the resulting
/// spaces matches what the terminal draws — a raw `\t` does not). Used before diff highlight/wrap.
fn expand_tabs(s: &str) -> String {
    let mut out = String::new();
    let mut col = 0usize;
    for c in s.chars() {
        if c == '\t' {
            let n = 4 - (col % 4);
            out.push_str(&" ".repeat(n));
            col += n;
        } else {
            out.push(c);
            col += crate::tui::char_width(c) as usize;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::lang_for_path;

    #[test]
    fn lang_for_path_reads_named_files_not_just_extensions() {
        // Extensionless build files are NAMED, so the basename table runs before the extension split.
        assert_eq!(lang_for_path("Makefile"), Some("make"));
        assert_eq!(lang_for_path("sub/dir/GNUmakefile"), Some("make"));
        assert_eq!(lang_for_path("docker/Dockerfile"), Some("dockerfile"));
        assert_eq!(lang_for_path("Containerfile"), Some("dockerfile"));
        assert_eq!(lang_for_path("Cargo.lock"), Some("toml"));
        // Named, but with no LangSpec behind the name: plain, never a near-neighbor guess.
        assert_eq!(lang_for_path("justfile"), None);
        assert_eq!(lang_for_path("CMakeLists.txt"), None);
        assert_eq!(lang_for_path(".gitignore"), None);
        // Extensions still win everywhere else.
        assert_eq!(lang_for_path("crates/cli/src/block.rs"), Some("rs"));
        assert_eq!(lang_for_path("a/b.py"), Some("py"));
        assert_eq!(lang_for_path("README"), None);
        assert_eq!(lang_for_path("dir.d/README"), None);
    }
}
