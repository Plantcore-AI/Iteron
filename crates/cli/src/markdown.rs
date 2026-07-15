//! A small zero-dependency markdown parser + renderer for assistant output (ADR-015 §Dependencies:
//! model output is ~95% simple markdown; a 250-LOC hand-roll beats pulling a parser crate, and the
//! failure mode is benign — a literal `*` renders as text, never misleading). It parses semantics
//! from the SOURCE TEXT (fixing the old `style==fg(White)` heuristic), covers headings, bold/italic/
//! inline-code/links (R8: inline is P0), bullet/numbered lists, blockquotes, fenced code, and rules,
//! and renders through the semantic `Theme` + the span-aware `wrap_spans` (R3).

use crate::render::{line_width, wrap_spans};
use crate::theme::Theme;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

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
        spans: Vec<Inline>,
    },
    Numbered {
        n: u32,
        spans: Vec<Inline>,
    },
    Quote(Vec<Inline>),
    Code {
        lang: Option<String>,
        lines: Vec<String>,
    },
    Rule,
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
                MdBlock::Bullet { spans } => out.push_str(&format!("- {}\n", inline_text(spans))),
                MdBlock::Numbered { n, spans } => {
                    out.push_str(&format!("{n}. {}\n", inline_text(spans)))
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
            blocks.push(MdBlock::Bullet {
                spans: parse_inline(rest),
            });
            i += 1;
            continue;
        }
        // numbered list
        if let Some((n, rest)) = numbered_item(trimmed) {
            flush_para(&mut blocks, &mut para);
            blocks.push(MdBlock::Numbered {
                n,
                spans: parse_inline(rest),
            });
            i += 1;
            continue;
        }
        // otherwise, accumulate into a paragraph
        para.push(trimmed.to_string());
        i += 1;
    }
    flush_para(&mut blocks, &mut para);
    blocks
}

fn parse_heading(s: &str) -> Option<MdBlock> {
    let hashes = s.chars().take_while(|&c| c == '#').count();
    if (1..=6).contains(&hashes) && s.chars().nth(hashes) == Some(' ') {
        let rest = s[hashes + 1..].trim();
        return Some(MdBlock::Heading(hashes as u8, parse_inline(rest)));
    }
    None
}

fn bullet_item(s: &str) -> Option<&str> {
    for p in ["- ", "* ", "+ "] {
        if let Some(rest) = s.strip_prefix(p) {
            return Some(rest);
        }
    }
    None
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

/// Convert inline runs to styled spans under a base style.
fn inline_spans(spans: &[Inline], theme: &Theme, base: Style) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    for inl in spans {
        match inl {
            Inline::Text(t) => out.push(Span::styled(t.clone(), base)),
            Inline::Bold(t) => out.push(Span::styled(t.clone(), base.add_modifier(Modifier::BOLD))),
            Inline::Italic(t) => {
                out.push(Span::styled(t.clone(), base.add_modifier(Modifier::ITALIC)))
            }
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
                out.push(Span::styled(t.clone(), s));
            }
            Inline::Link { text, url } => {
                out.push(Span::styled(
                    text.clone(),
                    base.fg(theme.accent).add_modifier(Modifier::UNDERLINED),
                ));
                if !url.is_empty() && url != text {
                    out.push(Span::styled(
                        format!(" ({url})"),
                        Style::default().fg(theme.muted),
                    ));
                }
            }
        }
    }
    if out.is_empty() {
        out.push(Span::styled(String::new(), base));
    }
    out
}

/// Render the document to wrapped display rows at `width`, through the theme. Fenced code is
/// syntax-highlighted via the stateful lexer (R6), with a fresh `LexState` per fence.
pub fn render_doc(doc: &MarkdownDoc, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();
    let mut prev_marked = false; // suppress the blank between adjacent list items (critique P1)
    for (bi, b) in doc.blocks.iter().enumerate() {
        let is_marked = matches!(b, MdBlock::Bullet { .. } | MdBlock::Numbered { .. });
        if bi > 0 && !(prev_marked && is_marked) {
            out.push(Line::from("")); // blank spacer between blocks (not between consecutive list items)
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
                out.extend(wrap_spans(&inline_spans(spans, theme, base), width));
            }
            MdBlock::Para(spans) => {
                let s = inline_spans(spans, theme, Style::default().fg(theme.fg));
                out.extend(wrap_spans(&s, width));
            }
            MdBlock::Bullet { spans } => {
                // ONE bullet column (findings 4): the marker glyph sits at the open-voice left edge
                // (col 0), the same edge as prose/headings — not indented 2 cells into its own column
                // that made lists float away from the rest of the assistant document.
                out.extend(render_marked("• ", spans, width, theme));
            }
            MdBlock::Numbered { n, spans } => {
                out.extend(render_marked(&format!("{n}. "), spans, width, theme));
            }
            MdBlock::Quote(spans) => {
                let base = Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC);
                let inner = inline_spans(spans, theme, base);
                let gutter_w = 2u16;
                let wrapped = wrap_spans(&inner, width.saturating_sub(gutter_w).max(1));
                for row in wrapped {
                    let mut sp = vec![Span::styled("▎ ", Style::default().fg(theme.muted))]; // unified rail glyph
                    sp.extend(row.spans);
                    out.push(Line::from(sp));
                }
            }
            MdBlock::Code { lang, lines } => {
                // A framed fence (TUI v3 §6): a persistent faint `│ ` gutter frames the block even when
                // code_bg = Reset; every row is right-padded to FULL width so the tint is a clean
                // rectangle (no ragged-right stair-step); the language is a dim right-aligned tag on the
                // first row.
                let mut st = crate::highlight::LexState::new();
                let inner_w = width.saturating_sub(2).max(1); // room for the "│ " gutter
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
                        let mut sp = vec![Span::styled(
                            "│ ".to_string(),
                            Style::default().fg(theme.faint),
                        )];
                        sp.append(&mut row.spans);
                        let mut line = Line::from(sp);
                        // right-pad to full width; drop the dim language tag into the first row's padding
                        let w = line_width(&line);
                        if w < width {
                            let pad = (width - w) as usize;
                            let tag_str = if first { tag } else { None };
                            match tag_str {
                                Some(lg) if pad > lg.chars().count() + 1 => {
                                    line.spans
                                        .push(Span::raw(" ".repeat(pad - lg.chars().count())));
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
                        out.push(line);
                        first = false;
                    }
                }
            }
            MdBlock::Rule => {
                // The ONE rule primitive — full-width, faint, and already width-bounded.
                out.extend(crate::block::rule_line(width, theme));
            }
        }
    }
    if out.is_empty() {
        out.push(Line::from(""));
    }
    out
}

/// Render a list item with a hanging indent: the marker on the first row, aligned spaces on
/// continuation rows.
fn render_marked(marker: &str, spans: &[Inline], width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let marker_w = marker.chars().map(crate::tui::char_width).sum::<u16>();
    let inner = inline_spans(spans, theme, Style::default().fg(theme.fg));
    // .max(1): wrap_spans at width 0 returns UNWRAPPED content, which would overflow the row on a
    // terminal narrower than the marker (review LOW). At least 1 keeps it wrapping.
    let wrapped = wrap_spans(&inner, width.saturating_sub(marker_w).max(1));
    let mut out = Vec::new();
    for (ri, row) in wrapped.into_iter().enumerate() {
        let lead = if ri == 0 {
            Span::styled(marker.to_string(), Style::default().fg(theme.muted))
        } else {
            Span::raw(" ".repeat(marker_w as usize))
        };
        let mut sp = vec![lead];
        sp.extend(row.spans);
        out.push(Line::from(sp));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "# A longish heading that should wrap across the narrow width\n\n- a bullet item that is also quite long and wraps\n\n> a quoted line that wraps too\n\n```\nsome code line that is long enough to wrap around\n```",
        );
        for width in [10u16, 20, 40] {
            for row in render_doc(&doc, width, &theme) {
                assert!(
                    line_width(&row) <= width,
                    "md row over width {width}: {row:?}"
                );
            }
        }
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
