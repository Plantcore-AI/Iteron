//! A small zero-dependency markdown parser + renderer for assistant output (ADR-015 §Dependencies:
//! model output is ~95% simple markdown; a 250-LOC hand-roll beats pulling a parser crate, and the
//! failure mode is benign — a literal `*` renders as text, never misleading). It parses semantics
//! from the SOURCE TEXT (fixing the old `style==fg(White)` heuristic), covers headings, bold/italic/
//! inline-code/links (R8: inline is P0), bullet/numbered lists, blockquotes, fenced code, and rules,
//! and renders through the semantic `Theme` + the span-aware `wrap_spans` (R3).

use crate::render::{AnnotatedSpan, RenderedLines, line_width, wrap_annotated_spans, wrap_spans};
use crate::theme::Theme;
use crate::tui::hyperlink::Policy as HyperlinkPolicy;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

/// Source indentation is normalized to two cells per level and clamped so hostile/model-generated
/// whitespace cannot create unbounded presentation depth.
const MAX_LIST_NESTING: u8 = 8;
/// A single item cannot absorb an unbounded number of following source lines. Remaining lines are
/// parsed as ordinary blocks instead of being discarded.
const MAX_LIST_CONTINUATION_LINES: usize = 64;

/// An inline run within a paragraph/heading/list item.
#[derive(Debug, Clone, PartialEq)]
pub enum Inline {
    Text(String),
    Bold(String),
    Italic(String),
    Code(String),
    Link { text: String, url: String },
}

/// A block-level markdown element.
#[derive(Debug, Clone, PartialEq)]
pub enum MdBlock {
    Heading(u8, Vec<Inline>),
    Para(Vec<Inline>),
    Bullet {
        depth: u8,
        task: Option<bool>,
        spans: Vec<Inline>,
        continuation: Vec<Vec<Inline>>,
    },
    Numbered {
        depth: u8,
        n: u32,
        task: Option<bool>,
        spans: Vec<Inline>,
        continuation: Vec<Vec<Inline>>,
    },
    Quote(Vec<Inline>),
    Code {
        lang: Option<String>,
        lines: Vec<String>,
    },
    Rule,
    Table {
        headers: Vec<Vec<Inline>>,
        rows: Vec<Vec<Vec<Inline>>>,
    },
}

/// A parsed markdown document.
#[derive(Debug, Clone, PartialEq)]
pub struct MarkdownDoc {
    pub blocks: Vec<MdBlock>,
}

impl MarkdownDoc {
    pub fn parse(text: &str) -> Self {
        MarkdownDoc {
            blocks: parse_blocks(text),
        }
    }

    /// Reconstruct approximate markdown source (for `/export`).
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for b in &self.blocks {
            match b {
                MdBlock::Heading(l, s) => {
                    out.push_str(&format!("{} {}\n", "#".repeat(*l as usize), inline_text(s)))
                }
                MdBlock::Para(s) => out.push_str(&format!("{}\n", inline_text(s))),
                MdBlock::Bullet {
                    depth,
                    task,
                    spans,
                    continuation,
                } => {
                    let indent = "  ".repeat(usize::from(*depth));
                    let task = task.map_or("", |checked| if checked { "[x] " } else { "[ ] " });
                    let prefix = format!("{indent}- {task}");
                    out.push_str(&format!("{prefix}{}\n", inline_text(spans)));
                    for line in continuation {
                        out.push_str(&format!(
                            "{}{}\n",
                            " ".repeat(prefix.chars().count()),
                            inline_text(line)
                        ));
                    }
                }
                MdBlock::Numbered {
                    depth,
                    n,
                    task,
                    spans,
                    continuation,
                } => {
                    let indent = "  ".repeat(usize::from(*depth));
                    let task = task.map_or("", |checked| if checked { "[x] " } else { "[ ] " });
                    let prefix = format!("{indent}{n}. {task}");
                    out.push_str(&format!("{prefix}{}\n", inline_text(spans)));
                    for line in continuation {
                        out.push_str(&format!(
                            "{}{}\n",
                            " ".repeat(prefix.chars().count()),
                            inline_text(line)
                        ));
                    }
                }
                MdBlock::Quote(s) => out.push_str(&format!("> {}\n", inline_text(s))),
                MdBlock::Code { lang, lines } => {
                    out.push_str(&format!("```{}\n", lang.as_deref().unwrap_or("")));
                    for l in lines {
                        out.push_str(l);
                        out.push('\n');
                    }
                    out.push_str("```\n");
                }
                MdBlock::Rule => out.push_str("---\n"),
                MdBlock::Table { headers, rows } => {
                    out.push('|');
                    for c in headers {
                        out.push_str(&format!(" {} |", inline_text(c)));
                    }
                    out.push('\n');
                    out.push('|');
                    for _ in headers {
                        out.push_str(" --- |");
                    }
                    out.push('\n');
                    for r in rows {
                        out.push('|');
                        for c in r {
                            out.push_str(&format!(" {} |", inline_text(c)));
                        }
                        out.push('\n');
                    }
                }
            }
        }
        out
    }
}

/// Reconstruct inline markdown source from parsed runs.
fn inline_text(spans: &[Inline]) -> String {
    let mut s = String::new();
    for i in spans {
        match i {
            Inline::Text(t) => s.push_str(t),
            Inline::Bold(t) => s.push_str(&format!("**{t}**")),
            Inline::Italic(t) => s.push_str(&format!("_{t}_")),
            Inline::Code(t) => s.push_str(&format!("`{t}`")),
            Inline::Link { text, url } => s.push_str(&format!("[{text}]({url})")),
        }
    }
    s
}

/// Parse block structure line-by-line.
fn parse_blocks(text: &str) -> Vec<MdBlock> {
    let mut blocks = Vec::new();
    let mut para: Vec<String> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;

    let flush_para = |blocks: &mut Vec<MdBlock>, para: &mut Vec<String>| {
        if !para.is_empty() {
            let joined = para.join(" ");
            blocks.push(MdBlock::Para(parse_inline(&joined)));
            para.clear();
        }
    };

    while i < lines.len() {
        let line = lines[i];
        let indent = leading_indent_columns(line);
        let trimmed = line.trim_start();
        // fenced code block
        if let Some(rest) = trimmed.strip_prefix("```") {
            flush_para(&mut blocks, &mut para);
            let lang = rest.trim();
            let lang = if lang.is_empty() {
                None
            } else {
                Some(lang.to_string())
            };
            let mut body = Vec::new();
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with("```") {
                body.push(lines[i].to_string());
                i += 1;
            }
            i += 1; // skip closing fence (or run off the end)
            blocks.push(MdBlock::Code { lang, lines: body });
            continue;
        }
        // blank line ends a paragraph
        if trimmed.is_empty() {
            flush_para(&mut blocks, &mut para);
            i += 1;
            continue;
        }
        // horizontal rule
        if trimmed == "---" || trimmed == "***" || trimmed == "___" {
            flush_para(&mut blocks, &mut para);
            blocks.push(MdBlock::Rule);
            i += 1;
            continue;
        }
        // ATX heading
        if let Some(h) = parse_heading(trimmed) {
            flush_para(&mut blocks, &mut para);
            blocks.push(h);
            i += 1;
            continue;
        }
        // blockquote — CONSECUTIVE `>` lines merge into ONE quote block (findings 1: the old
        // one-Quote-per-line emitted a stack of shredded single-line rails instead of a single quote).
        if trimmed.starts_with('>') {
            flush_para(&mut blocks, &mut para);
            let mut quoted = String::new();
            while i < lines.len() {
                let t = lines[i].trim_start();
                let Some(rest) = t.strip_prefix("> ").or_else(|| t.strip_prefix(">")) else {
                    break;
                };
                if !quoted.is_empty() {
                    quoted.push(' ');
                }
                quoted.push_str(rest);
                i += 1;
            }
            blocks.push(MdBlock::Quote(parse_inline(&quoted)));
            continue;
        }
        // bullet list
        if let Some(rest) = bullet_item(trimmed) {
            flush_para(&mut blocks, &mut para);
            let (task, rest) = task_item(rest);
            i += 1;
            let continuation = collect_indented_continuations(&lines, &mut i, indent);
            blocks.push(MdBlock::Bullet {
                depth: list_depth(indent),
                task,
                spans: parse_inline(rest),
                continuation,
            });
            continue;
        }
        // numbered list
        if let Some((n, rest)) = numbered_item(trimmed) {
            flush_para(&mut blocks, &mut para);
            let (task, rest) = task_item(rest);
            i += 1;
            let continuation = collect_indented_continuations(&lines, &mut i, indent);
            blocks.push(MdBlock::Numbered {
                depth: list_depth(indent),
                n,
                task,
                spans: parse_inline(rest),
                continuation,
            });
            continue;
        }
        // table: a pipe row immediately followed by a `|---|---|` separator row.
        if trimmed.contains('|') && i + 1 < lines.len() && is_separator_row(lines[i + 1].trim()) {
            flush_para(&mut blocks, &mut para);
            let headers: Vec<Vec<Inline>> = split_table_row(trimmed)
                .iter()
                .map(|c| parse_inline(c))
                .collect();
            let ncols = headers.len();
            i += 2; // consume the header row and the separator row
            let mut rows = Vec::new();
            while i < lines.len() {
                let t = lines[i].trim();
                if t.is_empty() || !t.contains('|') {
                    break;
                }
                let mut cells: Vec<Vec<Inline>> =
                    split_table_row(t).iter().map(|c| parse_inline(c)).collect();
                cells.resize(ncols, Vec::new()); // normalize to the header column count
                cells.truncate(ncols);
                rows.push(cells);
                i += 1;
            }
            blocks.push(MdBlock::Table { headers, rows });
            continue;
        }
        // otherwise, accumulate into a paragraph
        para.push(trimmed.to_string());
        i += 1;
    }
    flush_para(&mut blocks, &mut para);
    blocks
}

/// Split a markdown table row `| a | b |` into trimmed cell strings (outer pipes optional).
fn split_table_row(line: &str) -> Vec<String> {
    let t = line.trim();
    let t = t.strip_prefix('|').unwrap_or(t);
    let t = t.strip_suffix('|').unwrap_or(t);
    t.split('|').map(|c| c.trim().to_string()).collect()
}

/// Is this the `|---|:--:|---:|` separator row that sits under a table header? Every cell must be
/// non-empty dashes with optional leading/trailing `:` (alignment markers) and contain at least one `-`.
fn is_separator_row(line: &str) -> bool {
    if !line.contains('-') || !line.contains('|') {
        return false;
    }
    let cells = split_table_row(line);
    !cells.is_empty()
        && cells.iter().all(|c| {
            let c = c.trim();
            !c.is_empty() && c.contains('-') && c.chars().all(|ch| ch == '-' || ch == ':')
        })
}

fn parse_heading(s: &str) -> Option<MdBlock> {
    let hashes = s.chars().take_while(|&c| c == '#').count();
    if (1..=6).contains(&hashes) && s.chars().nth(hashes) == Some(' ') {
        let rest = s[hashes + 1..].trim();
        return Some(MdBlock::Heading(hashes as u8, parse_inline(rest)));
    }
    None
}

fn leading_indent_columns(line: &str) -> usize {
    line.chars()
        .take_while(|character| matches!(character, ' ' | '\t'))
        .map(|character| if character == '\t' { 2 } else { 1 })
        .sum()
}

fn list_depth(indent_columns: usize) -> u8 {
    u8::try_from(indent_columns / 2)
        .unwrap_or(u8::MAX)
        .min(MAX_LIST_NESTING)
}

fn bullet_item(s: &str) -> Option<&str> {
    for p in ["- ", "* ", "+ "] {
        if let Some(rest) = s.strip_prefix(p) {
            return Some(rest);
        }
    }
    None
}

fn task_item(item: &str) -> (Option<bool>, &str) {
    for (marker, checked) in [("[ ]", false), ("[x]", true), ("[X]", true)] {
        if item == marker {
            return (Some(checked), "");
        }
        if let Some(rest) = item
            .strip_prefix(marker)
            .and_then(|rest| rest.strip_prefix(' '))
        {
            return (Some(checked), rest);
        }
    }
    (None, item)
}

fn numbered_item(s: &str) -> Option<(u32, &str)> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || digits.len() > 9 {
        return None;
    }
    let after = &s[digits.len()..];
    let rest = after
        .strip_prefix(". ")
        .or_else(|| after.strip_prefix(") "))?;
    Some((digits.parse().ok()?, rest))
}

fn collect_indented_continuations(
    lines: &[&str],
    next: &mut usize,
    item_indent: usize,
) -> Vec<Vec<Inline>> {
    let mut continuation = Vec::new();
    while *next < lines.len() && continuation.len() < MAX_LIST_CONTINUATION_LINES {
        let candidate = lines[*next];
        let trimmed = candidate.trim_start();
        if trimmed.is_empty()
            || leading_indent_columns(candidate) <= item_indent
            || bullet_item(trimmed).is_some()
            || numbered_item(trimmed).is_some()
        {
            break;
        }
        continuation.push(parse_inline(trimmed));
        *next += 1;
    }
    continuation
}

/// Parse inline markdown into styled runs. Handles `` `code` ``, `**bold**`, `*italic*` / `_italic_`,
/// and `[text](url)`. Uses a word-boundary rule for `_` so an intraword underscore (`some_var_name`)
/// is NOT emphasis (CommonMark's intraword rule; snake_case saturates coding-agent prose — R16).
pub fn parse_inline(s: &str) -> Vec<Inline> {
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<Inline> = Vec::new();
    let mut text = String::new();
    let mut i = 0;
    let n = chars.len();

    let flush = |out: &mut Vec<Inline>, text: &mut String| {
        if !text.is_empty() {
            out.push(Inline::Text(std::mem::take(text)));
        }
    };

    while i < n {
        let c = chars[i];
        // inline code — highest precedence, no nested parsing
        if c == '`'
            && let Some(close) = find_char(&chars, i + 1, '`')
        {
            flush(&mut out, &mut text);
            out.push(Inline::Code(chars[i + 1..close].iter().collect()));
            i = close + 1;
            continue;
        }
        // link [text](url)
        if c == '['
            && let Some((txt, url, end)) = parse_link(&chars, i)
        {
            flush(&mut out, &mut text);
            out.push(Inline::Link { text: txt, url });
            i = end;
            continue;
        }
        // bold **...**
        if c == '*'
            && i + 1 < n
            && chars[i + 1] == '*'
            && let Some(close) = find_run(&chars, i + 2, "**")
        {
            flush(&mut out, &mut text);
            out.push(Inline::Bold(chars[i + 2..close].iter().collect()));
            i = close + 2;
            continue;
        }
        // italic *...*  — left/right-flanking: the opening `*` must be followed by a non-space and
        // the closing `*` preceded by a non-space, so ordinary asterisks (`2 * 3`, a glob `*.rs *`)
        // do NOT italicize an unrelated span (review LOW; CommonMark flanking).
        if c == '*'
            && i + 1 < n
            && !chars[i + 1].is_whitespace()
            && let Some(close) = find_closing_star(&chars, i + 1)
        {
            flush(&mut out, &mut text);
            out.push(Inline::Italic(chars[i + 1..close].iter().collect()));
            i = close + 1;
            continue;
        }
        // italic _..._  ONLY at word boundaries (not intraword)
        if c == '_'
            && can_open_underscore(&chars, i)
            && let Some(close) = find_closing_underscore(&chars, i + 1)
        {
            flush(&mut out, &mut text);
            out.push(Inline::Italic(chars[i + 1..close].iter().collect()));
            i = close + 1;
            continue;
        }
        text.push(c);
        i += 1;
    }
    flush(&mut out, &mut text);
    out
}

fn find_char(chars: &[char], from: usize, target: char) -> Option<usize> {
    (from..chars.len()).find(|&j| chars[j] == target)
}

fn find_run(chars: &[char], from: usize, run: &str) -> Option<usize> {
    let r: Vec<char> = run.chars().collect();
    let mut j = from;
    while j + r.len() <= chars.len() {
        if chars[j..j + r.len()] == r[..] {
            return Some(j);
        }
        j += 1;
    }
    None
}

/// Find a closing `*` whose preceding char is non-space (right-flanking), so `a * b` doesn't close.
fn find_closing_star(chars: &[char], from: usize) -> Option<usize> {
    (from..chars.len()).find(|&j| chars[j] == '*' && j > from && !chars[j - 1].is_whitespace())
}

/// An `_` opens emphasis only if it is NOT preceded AND followed by an alphanumeric (word-internal).
fn can_open_underscore(chars: &[char], i: usize) -> bool {
    let prev_alnum = i > 0 && chars[i - 1].is_alphanumeric();
    let next_alnum = i + 1 < chars.len() && chars[i + 1].is_alphanumeric();
    !(prev_alnum && next_alnum)
}

/// Find a closing `_` that is a word boundary (followed by non-alnum or end), so `_x_y` closes at the
/// first `_` but `a_b_c` (intraword) is not treated as emphasis.
fn find_closing_underscore(chars: &[char], from: usize) -> Option<usize> {
    let mut j = from;
    while j < chars.len() {
        if chars[j] == '_' {
            let next_alnum = j + 1 < chars.len() && chars[j + 1].is_alphanumeric();
            let prev_alnum = j > 0 && chars[j - 1].is_alphanumeric();
            if prev_alnum && !next_alnum && j > from {
                return Some(j);
            }
        }
        j += 1;
    }
    None
}

fn parse_link(chars: &[char], start: usize) -> Option<(String, String, usize)> {
    let close_br = find_char(chars, start + 1, ']')?;
    if close_br + 1 >= chars.len() || chars[close_br + 1] != '(' {
        return None;
    }
    let close_paren = find_char(chars, close_br + 2, ')')?;
    let text: String = chars[start + 1..close_br].iter().collect();
    let url: String = chars[close_br + 2..close_paren].iter().collect();
    Some((text, url, close_paren + 1))
}

// ---- rendering ----

/// Escape control characters at this last semantic render seam. Normal assistant ingress is
/// already scrubbed, but keeping Markdown independently safe prevents a future caller or malformed
/// persisted transcript from placing terminal controls in either visible link text or fallback URL.
fn terminal_safe_text(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

/// Convert inline runs to styled spans under a base style. Hyperlink targets remain metadata and
/// never enter Span content; unsupported or unsafe targets retain the existing `text (url)` form.
fn inline_annotated_spans(
    spans: &[Inline],
    theme: &Theme,
    base: Style,
    hyperlinks: &HyperlinkPolicy,
) -> Vec<AnnotatedSpan> {
    let mut out = Vec::new();
    for inl in spans {
        match inl {
            Inline::Text(t) => out.push(AnnotatedSpan {
                span: Span::styled(terminal_safe_text(t), base),
                hyperlink: None,
            }),
            Inline::Bold(t) => out.push(AnnotatedSpan {
                span: Span::styled(terminal_safe_text(t), base.add_modifier(Modifier::BOLD)),
                hyperlink: None,
            }),
            Inline::Italic(t) => out.push(AnnotatedSpan {
                span: Span::styled(terminal_safe_text(t), base.add_modifier(Modifier::ITALIC)),
                hyperlink: None,
            }),
            Inline::Code(t) => {
                // Inline code in prose = `fg` on `code_bg`, NEVER green (green was overloaded 3 ways —
                // TUI v3 §3). The tint alone distinguishes it from prose — so NO padding spaces (the old
                // " {t} " padding read as "the  foo  function", double gaps around every span; findings
                // 1). But the bg tint FAILS silently when `code_bg` equals/near the terminal bg — the
                // Tokyo-Night family runs the dark theme (code_bg 0x1a1b26) on a Tokyo-Night terminal
                // (bg 0x1a1b26), so inline code becomes indistinguishable from prose. Add a subtle ITALIC
                // (and DIM under mono, where there is no tint at all) so the distinction ALWAYS survives
                // regardless of the terminal background (findings 6).
                let mut s = Style::default().fg(theme.fg).add_modifier(Modifier::ITALIC);
                if theme.mono {
                    s = s.add_modifier(Modifier::DIM);
                } else {
                    s = s.bg(theme.code_bg);
                }
                out.push(AnnotatedSpan {
                    span: Span::styled(terminal_safe_text(t), s),
                    hyperlink: None,
                });
            }
            Inline::Link { text, url } => {
                let text = terminal_safe_text(text);
                let url_fallback = terminal_safe_text(url);
                let has_visible_label = text
                    .chars()
                    .any(|character| crate::tui::char_width(character) > 0);
                let target = has_visible_label
                    .then(|| hyperlinks.admit_target(url))
                    .flatten();
                out.push(AnnotatedSpan {
                    span: Span::styled(
                        text.clone(),
                        base.fg(theme.accent).add_modifier(Modifier::UNDERLINED),
                    ),
                    hyperlink: target,
                });
                if out.last().is_some_and(|span| span.hyperlink.is_none())
                    && !url_fallback.is_empty()
                    && url_fallback != text
                {
                    out.push(AnnotatedSpan {
                        span: Span::styled(
                            format!(" ({url_fallback})"),
                            Style::default().fg(theme.muted),
                        ),
                        hyperlink: None,
                    });
                }
            }
        }
    }
    if out.is_empty() {
        out.push(AnnotatedSpan {
            span: Span::styled(String::new(), base),
            hyperlink: None,
        });
    }
    out
}

#[cfg(test)]
fn inline_spans(spans: &[Inline], theme: &Theme, base: Style) -> Vec<Span<'static>> {
    inline_annotated_spans(spans, theme, base, &HyperlinkPolicy::disabled())
        .into_iter()
        .map(|span| span.span)
        .collect()
}

/// Render the document to wrapped display rows at `width`, through the theme. Fenced code is
/// syntax-highlighted via the stateful lexer (R6), with a fresh `LexState` per fence.
pub fn render_doc(doc: &MarkdownDoc, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    render_doc_with_hyperlinks(doc, width, theme, &HyperlinkPolicy::disabled()).lines
}

pub(crate) fn render_doc_with_hyperlinks(
    doc: &MarkdownDoc,
    width: u16,
    theme: &Theme,
    hyperlinks: &HyperlinkPolicy,
) -> RenderedLines {
    let mut out = RenderedLines::default();
    let mut prev_marked = false; // suppress the blank between adjacent list items (critique P1)
    for (bi, b) in doc.blocks.iter().enumerate() {
        let is_marked = matches!(b, MdBlock::Bullet { .. } | MdBlock::Numbered { .. });
        if bi > 0 && !(prev_marked && is_marked) {
            out.push_plain(Line::from("")); // blank spacer between blocks (not between consecutive list items)
        }
        prev_marked = is_marked;
        match b {
            MdBlock::Heading(level, spans) => {
                // Typography, not hue (TUI v3 §6): NO literal '###', NO underline, NO accent color —
                // H1/H2 bold fg, H3+ bold-dim, stepping down by value only.
                let base = match level {
                    1 | 2 => Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
                    _ => Style::default()
                        .fg(theme.muted)
                        .add_modifier(Modifier::BOLD),
                };
                out.append(wrap_annotated_spans(
                    &inline_annotated_spans(spans, theme, base, hyperlinks),
                    width,
                ));
            }
            MdBlock::Para(spans) => {
                let spans =
                    inline_annotated_spans(spans, theme, Style::default().fg(theme.fg), hyperlinks);
                out.append(wrap_annotated_spans(&spans, width));
            }
            MdBlock::Bullet {
                depth,
                task,
                spans,
                continuation,
            } => {
                // ONE bullet column (findings 4): the marker glyph sits at the open-voice left edge
                // (col 0), the same edge as prose/headings — not indented 2 cells into its own column
                // that made lists float away from the rest of the assistant document.
                let marker = task.map_or("• ", |checked| if checked { "☑ " } else { "☐ " });
                out.append(render_marked(
                    *depth,
                    marker,
                    spans,
                    continuation,
                    width,
                    theme,
                    hyperlinks,
                ));
            }
            MdBlock::Numbered {
                depth,
                n,
                task,
                spans,
                continuation,
            } => {
                let task_marker = task.map_or("", |checked| if checked { "☑ " } else { "☐ " });
                out.append(render_marked(
                    *depth,
                    &format!("{n}. {task_marker}"),
                    spans,
                    continuation,
                    width,
                    theme,
                    hyperlinks,
                ));
            }
            MdBlock::Quote(spans) => {
                let base = Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC);
                let inner = inline_annotated_spans(spans, theme, base, hyperlinks);
                let gutter = (width >= 3).then_some("▎ ");
                let gutter_w = gutter.map_or(0, |_| 2u16);
                let mut wrapped =
                    wrap_annotated_spans(&inner, width.saturating_sub(gutter_w).max(1));
                wrapped.shift_columns(gutter_w);
                for row in &mut wrapped.lines {
                    let mut sp = gutter
                        .map(|text| vec![Span::styled(text, Style::default().fg(theme.muted))])
                        .unwrap_or_default();
                    sp.append(&mut row.spans);
                    *row = Line::from(sp);
                }
                out.append(wrapped);
            }
            MdBlock::Code { lang, lines } => {
                // A framed fence (TUI v3 §6): a persistent faint `│ ` gutter frames the block even when
                // code_bg = Reset; every row is right-padded to FULL width so the tint is a clean
                // rectangle (no ragged-right stair-step); the language is a dim right-aligned tag on the
                // first row.
                let mut st = crate::highlight::LexState::new();
                let gutter = (width >= 3).then_some("│ ");
                let gutter_w = gutter.map_or(0, |_| 2);
                let inner_w = width.saturating_sub(gutter_w).max(1);
                let tag = lang.as_deref().filter(|s| !s.is_empty());
                let mut first = true;
                for l in lines {
                    let spans = crate::highlight::code_spans(lang.as_deref(), l, &mut st, theme);
                    let mut wrapped = wrap_spans(&spans, inner_w);
                    if wrapped.is_empty() {
                        wrapped.push(Line::from(Span::raw(String::new())));
                    }
                    for mut row in wrapped {
                        // frame gutter
                        let mut sp = gutter
                            .map(|text| {
                                vec![Span::styled(
                                    text.to_string(),
                                    Style::default().fg(theme.faint),
                                )]
                            })
                            .unwrap_or_default();
                        sp.append(&mut row.spans);
                        let mut line = Line::from(sp);
                        // right-pad to full width; drop the dim language tag into the first row's padding
                        let w = line_width(&line);
                        if w < width {
                            let pad = (width - w) as usize;
                            let tag_str = if first { tag } else { None };
                            match tag_str {
                                Some(lg)
                                    if pad
                                        > usize::from(line_width(&Line::from(lg.to_string())))
                                            + 1 =>
                                {
                                    let tag_width =
                                        usize::from(line_width(&Line::from(lg.to_string())));
                                    line.spans.push(Span::raw(" ".repeat(pad - tag_width)));
                                    line.spans.push(Span::styled(
                                        lg.to_string(),
                                        Style::default()
                                            .fg(theme.muted)
                                            .add_modifier(Modifier::DIM),
                                    ));
                                }
                                _ => line.spans.push(Span::raw(" ".repeat(pad))),
                            }
                        }
                        if !theme.mono {
                            line.spans.iter_mut().for_each(|s| {
                                if s.style.bg.is_none() {
                                    s.style = s.style.bg(theme.code_bg);
                                }
                            });
                        }
                        out.push_plain(line);
                        first = false;
                    }
                }
            }
            MdBlock::Rule => {
                // The ONE rule primitive — full-width, faint, and already width-bounded.
                for line in crate::block::rule_line(width, theme) {
                    out.push_plain(line);
                }
            }
            MdBlock::Table { headers, rows } => {
                out.append(render_table(headers, rows, width, theme, hyperlinks));
            }
        }
    }
    if out.lines.is_empty() {
        out.push_plain(Line::from(""));
    }
    out
}

/// Render a markdown table as a box-drawn grid, CJK-aware and bounded to `width`. Column widths are
/// the natural cell widths, shrunk proportionally if the whole table would exceed `width`; each cell
/// is fit (truncated + padded) to its column. Header cells are bold; borders are faint. Inline cell
/// styling (code/bold/links) is preserved within the fit.
fn render_table(
    headers: &[Vec<Inline>],
    rows: &[Vec<Vec<Inline>>],
    width: u16,
    theme: &Theme,
    hyperlinks: &HyperlinkPolicy,
) -> RenderedLines {
    use crate::tui::char_width;
    let mut out = RenderedLines::default();
    let ncols = headers.len();
    if ncols == 0 || width == 0 {
        return out;
    }
    // A box needs one cell per column plus `│ ` / ` │` framing. Below that physical minimum,
    // retaining a malformed or over-wide grid is worse than losing the box. Render each logical row
    // as a wrapped, styled sequence instead; content and hyperlink metadata remain intact.
    let minimum_box_width = 4usize.saturating_mul(ncols).saturating_add(1);
    if usize::from(width) < minimum_box_width {
        let compact_row = |cells: &[Vec<Inline>], header: bool| {
            let base = if header {
                Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.fg)
            };
            let mut spans = Vec::new();
            for (column, cell) in cells.iter().enumerate().take(ncols) {
                if column > 0 {
                    spans.push(AnnotatedSpan {
                        span: Span::styled(" · ", Style::default().fg(theme.faint)),
                        hyperlink: None,
                    });
                }
                spans.extend(inline_annotated_spans(cell, theme, base, hyperlinks));
            }
            wrap_annotated_spans(&spans, width)
        };
        out.append(compact_row(headers, true));
        for row in rows {
            out.append(compact_row(row, false));
        }
        return out;
    }
    let cell_w = |cell: &[Inline]| -> usize {
        inline_annotated_spans(cell, theme, Style::default(), hyperlinks)
            .iter()
            .flat_map(|span| span.span.content.chars())
            .map(|character| char_width(character) as usize)
            .sum()
    };
    // Natural column widths (max of header + body cell widths, at least 1).
    let mut col: Vec<usize> = (0..ncols)
        .map(|c| {
            let h = cell_w(&headers[c]);
            let b = rows
                .iter()
                .map(|r| r.get(c).map(|x| cell_w(x)).unwrap_or(0))
                .max()
                .unwrap_or(0);
            h.max(b).max(1)
        })
        .collect();
    // Fit to width. Border overhead = `│ ` + `… │ …` + ` │` = 3*ncols + 1 fixed cells.
    let overhead = 3 * ncols + 1;
    let avail = (width as usize).saturating_sub(overhead).max(ncols);
    let total: usize = col.iter().sum();
    if total > avail {
        for w in col.iter_mut() {
            *w = ((*w * avail) / total).max(1);
        }
        let mut over = col.iter().sum::<usize>().saturating_sub(avail);
        while over > 0 {
            match col.iter_mut().filter(|w| **w > 1).max_by_key(|w| **w) {
                Some(m) => {
                    *m -= 1;
                    over -= 1;
                }
                None => break,
            }
        }
    }
    let faint = Style::default().fg(theme.faint);
    let border = |left: char, mid: char, right: char| -> Line<'static> {
        let mut s = String::new();
        s.push(left);
        for (i, w) in col.iter().enumerate() {
            if i > 0 {
                s.push(mid);
            }
            for _ in 0..(w + 2) {
                s.push('─');
            }
        }
        s.push(right);
        Line::from(Span::styled(s, faint))
    };
    let data_row = |cells: &[Vec<Inline>], header: bool| -> RenderedLines {
        let base = if header {
            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.fg)
        };
        let mut sp: Vec<Span<'static>> = Vec::new();
        let mut regions = Vec::new();
        let mut column = 0u16;
        for (c, &w) in col.iter().enumerate() {
            let prefix = if c == 0 { "│ " } else { " " };
            sp.push(Span::styled(prefix.to_string(), faint));
            column = column.saturating_add(
                prefix
                    .chars()
                    .map(char_width)
                    .fold(0u16, u16::saturating_add),
            );
            let empty: Vec<Inline> = Vec::new();
            let cell = cells.get(c).unwrap_or(&empty);
            let mut fitted = fit_annotated_spans(
                inline_annotated_spans(cell, theme, base, hyperlinks),
                w,
                base,
            );
            for region in &mut fitted.hyperlinks {
                region.col = region.col.saturating_add(column);
            }
            regions.append(&mut fitted.hyperlinks);
            if let Some(line) = fitted.lines.pop() {
                sp.extend(line.spans);
            }
            column = column.saturating_add(u16::try_from(w).unwrap_or(u16::MAX));
            sp.push(Span::styled(" │".to_string(), faint));
            column = column.saturating_add(2);
        }
        RenderedLines {
            lines: vec![Line::from(sp)],
            hyperlinks: regions,
        }
    };
    out.push_plain(border('┌', '┬', '┐'));
    out.append(data_row(headers, true));
    out.push_plain(border('├', '┼', '┤'));
    for r in rows {
        out.append(data_row(r, false));
    }
    out.push_plain(border('└', '┴', '┘'));
    out
}

/// Truncate annotated spans to exactly `w` display cells (CJK-aware), padding the tail with spaces.
/// A wide char that would overflow the last cell is dropped rather than split. Passing the fitted
/// runs through the shared annotated wrapper produces the same hyperlink geometry as prose without
/// putting OSC bytes into printable content.
fn fit_annotated_spans(spans: Vec<AnnotatedSpan>, w: usize, pad_style: Style) -> RenderedLines {
    use crate::tui::char_width;
    let mut fitted = Vec::new();
    let mut used = 0usize;
    'outer: for sp in spans {
        if used >= w {
            break;
        }
        let mut taken = String::new();
        for ch in sp.span.content.chars() {
            let cw = char_width(ch) as usize;
            if used + cw > w {
                if !taken.is_empty() {
                    fitted.push(AnnotatedSpan {
                        span: Span::styled(std::mem::take(&mut taken), sp.span.style),
                        hyperlink: sp.hyperlink.clone(),
                    });
                }
                break 'outer;
            }
            taken.push(ch);
            used += cw;
        }
        if !taken.is_empty() {
            fitted.push(AnnotatedSpan {
                span: Span::styled(taken, sp.span.style),
                hyperlink: sp.hyperlink,
            });
        }
    }
    if used < w {
        fitted.push(AnnotatedSpan {
            span: Span::styled(" ".repeat(w - used), pad_style),
            hyperlink: None,
        });
    }
    wrap_annotated_spans(&fitted, u16::try_from(w).unwrap_or(u16::MAX))
}

/// Render a list item with a hanging indent: the marker on the first row, aligned spaces on
/// continuation rows.
fn render_marked(
    depth: u8,
    marker: &str,
    spans: &[Inline],
    continuation: &[Vec<Inline>],
    width: u16,
    theme: &Theme,
    hyperlinks: &HyperlinkPolicy,
) -> RenderedLines {
    let marker_width = marker
        .chars()
        .map(crate::tui::char_width)
        .fold(0u16, u16::saturating_add);
    let marker_fits = marker_width < width;
    let requested_indent = u16::from(depth).saturating_mul(2);
    let indent_width = if marker_fits {
        requested_indent.min(width.saturating_sub(marker_width).saturating_sub(1))
    } else {
        0
    };
    let prefix = if marker_fits {
        format!("{}{}", " ".repeat(usize::from(indent_width)), marker)
    } else {
        String::new()
    };
    let prefix_width = if marker_fits {
        indent_width.saturating_add(marker_width)
    } else {
        0
    };
    let inner_width = width.saturating_sub(prefix_width).max(1);
    let mut out = RenderedLines::default();

    let mut append_source_line = |source: &[Inline], first: bool| {
        let inner =
            inline_annotated_spans(source, theme, Style::default().fg(theme.fg), hyperlinks);
        let mut wrapped = wrap_annotated_spans(&inner, inner_width);
        wrapped.shift_columns(prefix_width);
        for (row_index, row) in wrapped.lines.iter_mut().enumerate() {
            let lead = if first && row_index == 0 {
                Span::styled(prefix.clone(), Style::default().fg(theme.muted))
            } else {
                Span::raw(" ".repeat(usize::from(prefix_width)))
            };
            let mut composed = vec![lead];
            composed.append(&mut row.spans);
            *row = Line::from(composed);
        }
        out.append(wrapped);
    };
    append_source_line(spans, true);
    for line in continuation {
        append_source_line(line, false);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn repaint_vt100(parser: &mut vt100::Parser, lines: &[Line<'static>]) {
        let (height, _) = parser.screen().size();
        parser.process(b"\x1b[2J");
        for (row, line) in lines.iter().enumerate().take(usize::from(height)) {
            parser.process(format!("\x1b[{};1H", row + 1).as_bytes());
            let visible = line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>();
            parser.process(visible.as_bytes());
        }
    }

    fn repaint_retained_vt100(parser: &mut vt100::Parser, lines: &[Line<'static>]) {
        let (height, _) = parser.screen().size();
        for row in 0..height {
            parser.process(format!("\x1b[{};1H", row + 1).as_bytes());
            if let Some(line) = lines.get(usize::from(row)) {
                let visible = line
                    .spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>();
                parser.process(visible.as_bytes());
            }
            parser.process(b"\x1b[K");
        }
    }

    fn paint_vt100(lines: &[Line<'static>], width: u16, height: u16) -> vt100::Parser {
        let mut parser = vt100::Parser::new(height, width, 0);
        repaint_vt100(&mut parser, lines);
        parser
    }

    /// Serialize exact terminal cells. `·` is an empty cell and `»` is the second physical cell of a
    /// wide glyph, so the golden catches both padding and CJK column drift.
    fn vt100_screen_cell_grid(screen: &vt100::Screen, width: u16, height: u16) -> String {
        (0..height)
            .map(|row| {
                (0..width)
                    .map(|column| {
                        let cell = screen.cell(row, column).expect("cell inside vt100 grid");
                        if cell.is_wide_continuation() {
                            "»".to_string()
                        } else if cell.has_contents() {
                            cell.contents()
                        } else {
                            "·".to_string()
                        }
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn vt100_cell_grid(lines: &[Line<'static>], width: u16) -> String {
        let height = u16::try_from(lines.len()).unwrap_or(u16::MAX).max(1);
        let parser = paint_vt100(lines, width, height);
        assert_eq!(parser.screen().errors(), 0, "vt100 accepted the render");
        vt100_screen_cell_grid(parser.screen(), width, height)
    }

    #[test]
    fn nested_task_lists_and_ordered_continuations_are_bounded_and_round_trip() {
        let source = concat!(
            "- [x] shipped\n",
            "  - [ ] nested todo\n",
            "    12. ordered item\n",
            "        continuation one\n",
            "        continuation two\n",
            "                                        - depth is bounded\n",
        );
        let doc = MarkdownDoc::parse(source);
        assert_eq!(doc.blocks.len(), 4);
        assert!(matches!(
            &doc.blocks[0],
            MdBlock::Bullet {
                depth: 0,
                task: Some(true),
                ..
            }
        ));
        assert!(matches!(
            &doc.blocks[1],
            MdBlock::Bullet {
                depth: 1,
                task: Some(false),
                ..
            }
        ));
        match &doc.blocks[2] {
            MdBlock::Numbered {
                depth,
                n,
                task,
                spans,
                continuation,
            } => {
                assert_eq!((*depth, *n, *task), (2, 12, None));
                assert_eq!(inline_text(spans), "ordered item");
                assert_eq!(continuation.len(), 2);
                assert_eq!(inline_text(&continuation[0]), "continuation one");
                assert_eq!(inline_text(&continuation[1]), "continuation two");
            }
            other => panic!("expected ordered list item, got {other:?}"),
        }
        assert!(matches!(
            &doc.blocks[3],
            MdBlock::Bullet {
                depth: MAX_LIST_NESTING,
                ..
            }
        ));

        let reparsed = MarkdownDoc::parse(&doc.to_text());
        assert_eq!(reparsed, doc, "export preserves list semantics");

        let rendered = render_doc(&doc, 24, &Theme::dark());
        let continuation_rows: Vec<String> = rendered
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect()
            })
            .filter(|line: &String| line.contains("continuation"))
            .collect();
        assert_eq!(continuation_rows.len(), 2);
        assert!(
            continuation_rows
                .iter()
                .all(|line| line.starts_with("        ")),
            "ordered continuations hang below the item content: {continuation_rows:?}"
        );
        assert!(
            rendered.iter().all(|line| line_width(line) <= 24),
            "bounded depth must remain inside the render width"
        );
    }

    #[test]
    fn parses_and_renders_a_table() {
        let md = "before\n\n| Name | Role |\n|---|:--:|\n| Exa | search |\n| 蔡治郅 | 杭州工核智能负责人 |\n\nafter";
        let doc = MarkdownDoc::parse(md);
        let (headers, rows) = doc
            .blocks
            .iter()
            .find_map(|b| match b {
                MdBlock::Table { headers, rows } => Some((headers, rows)),
                _ => None,
            })
            .expect("a table block was parsed");
        assert_eq!(headers.len(), 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(inline_text(&headers[0]), "Name");
        assert_eq!(inline_text(&rows[1][0]), "蔡治郅");
        // surrounding paragraphs are still their own blocks (para + table + para)
        assert_eq!(doc.blocks.len(), 3);

        let theme = Theme::dark();
        let lines = render_doc(&doc, 40, &theme);
        let text = plain(&lines);
        eprintln!("\n{text}\n"); // eyeball with --nocapture
        assert!(text.contains('┌') && text.contains('┼') && text.contains('┴'));
        assert!(text.contains('│'));
        // every rendered row fits the width (no horizontal overflow)
        assert!(
            lines.iter().all(|l| crate::render::line_width(l) <= 40),
            "a table row exceeded the width bound"
        );
        // a not-a-table pipe line stays a paragraph (needs the separator row)
        let p = MarkdownDoc::parse("a | b | c");
        assert!(p.blocks.iter().all(|b| !matches!(b, MdBlock::Table { .. })));
    }

    #[test]
    fn table_cells_preserve_osc8_metadata_without_printing_escape_bytes() {
        let theme = Theme::dark();
        let policy = HyperlinkPolicy::new(
            crate::tui::hyperlink::Capability::Osc8,
            &std::env::current_dir().unwrap(),
        );
        let doc = MarkdownDoc::parse(
            "| Name | Resource |\n|---|---|\n| 核心 | [guide](https://example.com/guide) |",
        );
        let rendered = render_doc_with_hyperlinks(&doc, 40, &theme, &policy);
        let visible = plain(&rendered.lines);
        assert!(!visible.contains('\u{1b}'));
        assert!(visible.contains("核心"));
        assert!(visible.contains("guide"));
        assert!(!visible.contains("https://"));
        assert_eq!(rendered.hyperlinks.len(), 1);
        let region = &rendered.hyperlinks[0];
        assert_eq!(region.target, "https://example.com/guide");
        assert_eq!(region.width, 5);
        assert_eq!(region.row, 3);
        assert!(region.col.saturating_add(region.width) <= 40);

        let fallback = render_doc_with_hyperlinks(&doc, 80, &theme, &HyperlinkPolicy::disabled());
        assert!(fallback.hyperlinks.is_empty());
        let fallback_visible = plain(&fallback.lines);
        assert!(fallback_visible.contains("guide (https://example.com/guide)"));
        assert!(!fallback_visible.contains('\u{1b}'));
    }

    #[test]
    fn table_degrades_to_bounded_wrapped_rows_below_the_box_minimum() {
        let doc = MarkdownDoc::parse("| A | B |\n|---|---|\n| [x](https://example.com/x) | 界 |");
        let policy = HyperlinkPolicy::new(
            crate::tui::hyperlink::Capability::Osc8,
            &std::env::current_dir().unwrap(),
        );
        for width in 1..9 {
            let rendered = render_doc_with_hyperlinks(&doc, width, &Theme::dark(), &policy);
            assert!(
                rendered.lines.iter().all(|line| line_width(line) <= width),
                "compact table overflowed width {width}"
            );
            assert!(
                rendered.hyperlinks.iter().all(|region| {
                    region.col.saturating_add(region.width) <= width
                        && region.row < rendered.lines.len()
                }),
                "compact table link geometry escaped width {width}"
            );
        }
    }

    #[test]
    fn vt100_cell_grid_golden_covers_rich_markdown_geometry() {
        let source = concat!(
            "| 名称 | 状态 |\n",
            "|---|---|\n",
            "| 核心 | 就绪 |\n",
            "\n",
            "- [x] shipped\n",
            "  - [ ] nested\n",
            "    7. ordered item\n",
            "       continuation\n",
            "\n",
            "```rust\n",
            "let 名称 = 1;\n",
            "```\n",
        );
        let lines = render_doc(&MarkdownDoc::parse(source), 24, &Theme::dark());
        let grid = vt100_cell_grid(&lines, 24);
        assert_eq!(
            grid,
            concat!(
                "┌──────┬──────┐·········\n",
                "│ 名»称» │ 状»态» │·········\n",
                "├──────┼──────┤·········\n",
                "│ 核»心» │ 就»绪» │·········\n",
                "└──────┴──────┘·········\n",
                "························\n",
                "☑ shipped···············\n",
                "  ☐ nested··············\n",
                "    7. ordered item·····\n",
                "       continuation·····\n",
                "························\n",
                "│ let 名»称» = 1;     rust",
            )
        );
    }

    #[test]
    fn delimiter_split_stream_and_width_resize_converge_to_single_shot_grid() {
        let chunks = [
            "| 名",
            "称 | [文",
            "档](https://example.com) |\n|--",
            "-|---|\n| 核心 | ready |\n\n- [",
            "x] **do",
            "ne**\n  2. nested item\n     continued\n\n```ru",
            "st\nlet x = 1;\n``",
            "`\n",
        ];
        let widths = [36u16, 18, 27, 15, 31, 20, 24, 18];
        let mut streamed = String::new();
        let terminal_height = 64;
        let mut terminal = vt100::Parser::new(terminal_height, widths[0], 0);
        for (chunk, width) in chunks.iter().zip(widths) {
            streamed.push_str(chunk);
            let rows = render_doc(&MarkdownDoc::parse(&streamed), width, &Theme::dark());
            assert!(
                rows.iter().all(|line| line_width(line) <= width),
                "partial delimiter render overflowed at width {width}"
            );
            terminal.set_size(terminal_height, width);
            repaint_retained_vt100(&mut terminal, &rows);
            assert_eq!(
                terminal.screen().errors(),
                0,
                "resized vt100 accepted the partial render"
            );
        }

        let final_width = 18;
        let streamed_rows = render_doc(&MarkdownDoc::parse(&streamed), final_width, &Theme::dark());
        let complete = chunks.concat();
        let single_shot_rows =
            render_doc(&MarkdownDoc::parse(&complete), final_width, &Theme::dark());
        assert_eq!(
            vt100_cell_grid(&streamed_rows, final_width),
            vt100_cell_grid(&single_shot_rows, final_width),
            "delimiter splits and intervening resizes cannot alter the final cell grid"
        );
        terminal.set_size(terminal_height, final_width);
        repaint_retained_vt100(&mut terminal, &streamed_rows);
        let final_height = u16::try_from(streamed_rows.len()).unwrap_or(u16::MAX);
        assert_eq!(
            vt100_screen_cell_grid(terminal.screen(), final_width, final_height),
            vt100_cell_grid(&single_shot_rows, final_width),
            "the same resized terminal converges to the fresh single-shot grid"
        );

        let wide_rows = render_doc(&MarkdownDoc::parse(&complete), 36, &Theme::dark());
        let resized_back = render_doc(&MarkdownDoc::parse(&complete), 18, &Theme::dark());
        assert!(!vt100_cell_grid(&wide_rows, 36).is_empty());
        assert_eq!(
            vt100_cell_grid(&resized_back, 18),
            vt100_cell_grid(&single_shot_rows, 18),
            "reflowing wide then narrow returns to the canonical narrow grid"
        );
    }

    #[test]
    fn intraword_underscore_is_not_italic() {
        let spans = parse_inline("call some_var_name here");
        // must be a single Text run — no Italic
        assert!(
            spans.iter().all(|s| !matches!(s, Inline::Italic(_))),
            "snake_case must not italicize: {spans:?}"
        );
    }

    #[test]
    fn spaced_asterisks_do_not_italicize() {
        // `2 * 3 * 4` (multiplication) and a glob must NOT become italic (flanking rule, review LOW).
        for src in ["2 * 3 * 4", "run *.rs * files", "a * b"] {
            let spans = parse_inline(src);
            assert!(
                spans.iter().all(|s| !matches!(s, Inline::Italic(_))),
                "{src:?} must not italicize: {spans:?}"
            );
        }
        // real emphasis still works
        assert_eq!(parse_inline("*yes*"), vec![Inline::Italic("yes".into())]);
    }

    #[test]
    fn narrow_width_list_stays_bounded() {
        // Before the .max(1) fix, wrapping at width 0 returned the content UNWRAPPED — a ~50-cell row
        // on a 1-cell terminal. After: each row is bounded to ~marker + a few cells (Paragraph clips
        // the 4-cell marker itself on a <4 terminal, which is fine). Assert boundedness, not <= width.
        use crate::render::line_width;
        let theme = Theme::dark();
        let doc = MarkdownDoc::parse("- an item that is longer than a tiny terminal is wide");
        for width in [1u16, 2, 3, 4, 5] {
            for row in render_doc(&doc, width, &theme) {
                assert!(
                    line_width(&row) <= 8,
                    "narrow list row not bounded at width {width}: {} cells",
                    line_width(&row)
                );
            }
        }
    }

    #[test]
    fn bold_italic_code_link_parse() {
        assert_eq!(parse_inline("**b**"), vec![Inline::Bold("b".into())]);
        assert_eq!(parse_inline("_i_"), vec![Inline::Italic("i".into())]);
        assert_eq!(parse_inline("`c`"), vec![Inline::Code("c".into())]);
        assert_eq!(
            parse_inline("[t](u)"),
            vec![Inline::Link {
                text: "t".into(),
                url: "u".into()
            }]
        );
        // mixed
        let m = parse_inline("use **cargo** and `foo()` now");
        assert!(m.contains(&Inline::Bold("cargo".into())));
        assert!(m.contains(&Inline::Code("foo()".into())));
    }

    #[test]
    fn blocks_parse() {
        let doc = MarkdownDoc::parse(
            "# Title\n\nsome *text*\n\n- one\n- two\n\n```rust\nlet x = 1;\n```\n",
        );
        assert!(matches!(doc.blocks[0], MdBlock::Heading(1, _)));
        assert!(
            doc.blocks
                .iter()
                .any(|b| matches!(b, MdBlock::Bullet { .. }))
        );
        assert!(
            doc.blocks
                .iter()
                .any(|b| matches!(b, MdBlock::Code { lang: Some(l), .. } if l == "rust"))
        );
    }

    #[test]
    fn consecutive_quote_lines_merge_into_one_block() {
        // findings 1: a multi-line blockquote must be ONE Quote block, not one-per-line shreds.
        let doc = MarkdownDoc::parse("> line one\n> line two\n> line three\n\nafter");
        let quotes: Vec<_> = doc
            .blocks
            .iter()
            .filter(|b| matches!(b, MdBlock::Quote(_)))
            .collect();
        assert_eq!(
            quotes.len(),
            1,
            "consecutive `>` lines are one quote block: {:?}",
            doc.blocks
        );
        if let MdBlock::Quote(spans) = quotes[0] {
            let text = inline_text(spans);
            assert!(
                text.contains("line one") && text.contains("line three"),
                "all lines merged: {text:?}"
            );
        }
    }

    #[test]
    fn inline_code_has_no_padding_spaces() {
        // findings 1: inline code must not inject " {t} " padding ("the  foo  function").
        let theme = Theme::dark();
        let spans = inline_spans(
            &[Inline::Code("foo".into())],
            &theme,
            Style::default().fg(theme.fg),
        );
        assert_eq!(
            spans[0].content.as_ref(),
            "foo",
            "no surrounding padding spaces"
        );
    }

    #[test]
    fn render_stays_within_width() {
        use crate::render::line_width;
        let theme = Theme::dark();
        let doc = MarkdownDoc::parse(
            "# A longish heading that should wrap across the narrow width\n\n- a bullet item that is also quite long and wraps\n\n> a quoted line that wraps too\n\n```语言😀\nsome code line that is long enough to wrap around\n```",
        );
        for width in [1u16, 2, 3, 10, 20, 40] {
            for row in render_doc(&doc, width, &theme) {
                assert!(
                    line_width(&row) <= width,
                    "md row over width {width}: {row:?}"
                );
            }
        }
    }

    #[test]
    fn osc8_capability_keeps_link_text_and_records_clickable_regions() {
        let theme = Theme::dark();
        let doc = MarkdownDoc::parse("Read [the guide](https://example.com/guide) now.");
        let policy = HyperlinkPolicy::new(
            crate::tui::hyperlink::Capability::Osc8,
            &std::env::current_dir().unwrap(),
        );
        let rendered = render_doc_with_hyperlinks(&doc, 80, &theme, &policy);
        let visible: String = rendered
            .lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        assert_eq!(visible, "Read the guide now.");
        assert_eq!(rendered.hyperlinks.len(), 1);
        assert_eq!(rendered.hyperlinks[0].col, 5);
        assert_eq!(rendered.hyperlinks[0].width, 9);
        assert_eq!(rendered.hyperlinks[0].target, "https://example.com/guide");
    }

    #[test]
    fn non_capable_terminal_has_exact_plain_link_fallback() {
        let theme = Theme::dark();
        let doc = MarkdownDoc::parse("Read [the guide](https://example.com/guide) now.");
        let rows = render_doc(&doc, 80, &theme);
        let visible: String = rows
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        assert_eq!(visible, "Read the guide (https://example.com/guide) now.");
        assert!(!visible.contains('\u{1b}'));
    }

    #[test]
    fn hyperlinked_spans_keep_wrap_invariant_and_hostile_targets_stay_plain() {
        let theme = Theme::dark();
        let policy = HyperlinkPolicy::new(
            crate::tui::hyperlink::Capability::Osc8,
            &std::env::current_dir().unwrap(),
        );
        let doc = MarkdownDoc::parse(
            "prefix [a clickable link with wide 文本](https://example.com/docs) suffix",
        );
        for width in [8u16, 12, 20, 40] {
            let rendered = render_doc_with_hyperlinks(&doc, width, &theme, &policy);
            assert!(rendered.lines.iter().all(|line| line_width(line) <= width));
            assert!(rendered.hyperlinks.iter().all(|link| {
                link.col.saturating_add(link.width) <= width && link.row < rendered.lines.len()
            }));
        }

        let hostile = MarkdownDoc::parse("[safe label](https://example.com/\u{1b}]8;;injected)");
        let rendered = render_doc_with_hyperlinks(&hostile, 80, &theme, &policy);
        assert!(rendered.hyperlinks.is_empty());
        let visible: String = rendered
            .lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        assert!(!visible.contains('\u{1b}'));
        assert!(visible.contains("\\u{1b}"));
    }

    #[test]
    fn inline_code_is_fg_not_green_and_fence_is_framed() {
        // TUI v3 §3: inline code = fg on code_bg, never green (green was overloaded 3 ways).
        let theme = Theme::dark();
        let code = inline_spans(
            &[Inline::Code("x".into())],
            &theme,
            Style::default().fg(theme.fg),
        );
        assert_eq!(
            code[0].style.fg,
            Some(theme.fg),
            "inline code fg is body fg"
        );
        assert_ne!(
            code[0].style.fg,
            Some(theme.syn_string),
            "inline code is NOT green"
        );
        // TUI v3 §6: the fenced block is framed by a persistent `│ ` faint gutter, padded to width.
        use crate::render::line_width;
        let doc = MarkdownDoc::parse("```rust\nlet x = 1;\n```");
        let rows = render_doc(&doc, 40, &theme);
        assert!(
            rows.iter()
                .any(|l| l.spans.first().is_some_and(|s| s.content.starts_with('│'))),
            "code rows carry a │ frame gutter"
        );
        let code_row = rows
            .iter()
            .find(|l| l.spans.iter().any(|s| s.content.contains("let")))
            .expect("a code row");
        assert_eq!(
            line_width(code_row),
            40,
            "code row padded to full width (no ragged-right stair-step)"
        );
    }

    #[test]
    fn inline_code_carries_a_distinguishing_modifier() {
        // findings 6: on a terminal whose bg equals code_bg (Tokyo-Night family) the bg tint fails
        // silently, so inline code must ALSO carry a subtle ITALIC (and DIM under mono) — the
        // distinction from prose survives regardless of the terminal background.
        let dark = Theme::dark();
        let c = inline_spans(
            &[Inline::Code("x".into())],
            &dark,
            Style::default().fg(dark.fg),
        );
        assert!(
            c[0].style.add_modifier.contains(Modifier::ITALIC),
            "inline code is italic so it survives a matching bg"
        );
        assert_eq!(
            c[0].style.fg,
            Some(dark.fg),
            "still fg on code_bg (not recolored)"
        );
        let mono = Theme::mono();
        let m = inline_spans(
            &[Inline::Code("x".into())],
            &mono,
            Style::default().fg(mono.fg),
        );
        assert!(
            m[0].style.add_modifier.contains(Modifier::DIM),
            "under mono (no bg) inline code dims to stay distinct"
        );
    }

    #[test]
    fn list_markers_sit_at_the_open_voice_left_edge() {
        // findings 4: bullet/numbered markers align at the document left edge (col 0), one column — not
        // an arbitrary 2-cell indent that floated lists away from prose.
        let theme = Theme::dark();
        let doc = MarkdownDoc::parse("- one\n\n1. two");
        let rows = render_doc(&doc, 40, &theme);
        let bullet = rows
            .iter()
            .find(|l| l.spans.iter().any(|s| s.content.contains("one")))
            .unwrap();
        let numbered = rows
            .iter()
            .find(|l| l.spans.iter().any(|s| s.content.contains("two")))
            .unwrap();
        assert!(
            bullet.spans[0].content.starts_with("• "),
            "bullet glyph at col 0: {:?}",
            bullet.spans[0].content
        );
        assert!(
            numbered.spans[0].content.starts_with("1. "),
            "number at col 0: {:?}",
            numbered.spans[0].content
        );
    }

    #[test]
    fn unclosed_markers_render_as_text() {
        // streaming: a partial `**bold` with no close must not panic and must keep the text
        let spans = parse_inline("this is **unclosed and `also open");
        let joined: String = spans
            .iter()
            .map(|s| match s {
                Inline::Text(t) => t.clone(),
                _ => String::new(),
            })
            .collect();
        assert!(joined.contains("unclosed"));
    }
}
