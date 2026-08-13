//! Shared render primitives for the structured transcript (ADR-015 R3).
//!
//! `wrap_spans` is the load-bearing one: unlike `wrap_display` (one style per row), it wraps a
//! *multi-span* line — syntax-highlighted code, `**bold** and `code`` markdown — into display rows
//! each at most `width` cells wide, PRESERVING per-token styles and sharing the exact CJK-correct
//! `char_width` table. The transcript `Paragraph` has no `.wrap()` (so rendered rows == scroll units,
//! the load-bearing R6 invariant), and it TRUNCATES over-wide rows — so every block wraps its content
//! at `width - gutter` and prepends the gutter itself, keeping each composed row exactly `width`.

use crate::tui::char_width;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

/// Whether an exhausted row still has a trailing space to strip. False, so the trim loop stops
/// at an empty row instead of popping past its start.
const EMPTY_ROW_HAS_TRAILING_SPACE: bool = false;

/// One OSC-8-capable region in an already-wrapped row. Coordinates are display cells, never byte
/// offsets, so CJK and combining text keep the same geometry as the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HyperlinkRegion {
    pub row: usize,
    pub col: u16,
    pub width: u16,
    pub target: String,
}

/// Wrapped rows plus optional terminal-hyperlink metadata. Escape bytes are deliberately absent
/// from `lines`; the TUI applies regions to the final Ratatui buffer only after layout and scroll.
#[derive(Debug, Clone, Default)]
pub(crate) struct RenderedLines {
    pub lines: Vec<Line<'static>>,
    pub hyperlinks: Vec<HyperlinkRegion>,
}

impl RenderedLines {
    pub fn plain(lines: Vec<Line<'static>>) -> Self {
        Self {
            lines,
            hyperlinks: Vec::new(),
        }
    }

    pub fn push_plain(&mut self, line: Line<'static>) {
        self.lines.push(line);
    }

    pub fn append(&mut self, mut other: Self) {
        let row_offset = self.lines.len();
        for hyperlink in &mut other.hyperlinks {
            hyperlink.row = hyperlink.row.saturating_add(row_offset);
        }
        self.lines.append(&mut other.lines);
        self.hyperlinks.append(&mut other.hyperlinks);
    }

    pub fn shift_columns(&mut self, columns: u16) {
        for hyperlink in &mut self.hyperlinks {
            hyperlink.col = hyperlink.col.saturating_add(columns);
        }
    }
}

/// A styled span optionally associated with a previously validated terminal target.
pub(crate) struct AnnotatedSpan {
    pub span: Span<'static>,
    pub hyperlink: Option<String>,
}

/// The display width of a run of styled chars.
fn run_width(chars: &[(char, Style)]) -> u16 {
    chars
        .iter()
        .map(|(c, _)| char_width(*c))
        .fold(0u16, |a, w| a.saturating_add(w))
}

/// Group a run of `(char, style)` into a `Line`, coalescing consecutive same-style chars into one
/// `Span` (so we don't emit one span per char).
fn to_line(chars: &[(char, Style)]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut buf = String::new();
    let mut cur_style: Option<Style> = None;
    for (c, st) in chars {
        if cur_style != Some(*st) {
            if !buf.is_empty() {
                spans.push(Span::styled(
                    std::mem::take(&mut buf),
                    cur_style.unwrap_or_default(),
                ));
            }
            cur_style = Some(*st);
        }
        buf.push(*c);
    }
    if !buf.is_empty() {
        spans.push(Span::styled(buf, cur_style.unwrap_or_default()));
    }
    Line::from(spans)
}

/// Wrap styled `spans` into display rows at most `width` cells wide, preferring to break at the last
/// space, preserving each char's style. Every returned row's display width is `<= width` (unit-tested
/// — the invariant that keeps a prepended gutter from clipping content off the right edge, R3/R11).
pub fn wrap_spans(spans: &[Span], width: u16) -> Vec<Line<'static>> {
    // Flatten to (char, style) so wrapping is a single pass regardless of span boundaries.
    let mut chars: Vec<(char, Style)> = Vec::new();
    for s in spans {
        for c in s.content.chars() {
            chars.push((c, s.style));
        }
    }
    if width == 0 || chars.is_empty() {
        return vec![to_line(&chars)];
    }
    let mut rows: Vec<Line<'static>> = Vec::new();
    let mut cur: Vec<(char, Style)> = Vec::new();
    let mut cur_w = 0u16;
    let mut last_space: Option<usize> = None; // index in `cur` just after a space
    for (c, st) in chars {
        // A double-width glyph cannot physically fit in a one-cell terminal row. Keep the
        // renderer's hard width contract by using a visible, single-cell replacement at that
        // degenerate width instead of handing Ratatui an overflowing glyph.
        let c = if char_width(c) > width { '?' } else { c };
        let cw = char_width(c);
        if cur_w.saturating_add(cw) > width && !cur.is_empty() {
            if let Some(sp) = last_space.filter(|&sp| sp > 0 && sp < cur.len()) {
                let tail = cur.split_off(sp);
                while cur
                    .last()
                    .map(|(c, _)| *c == ' ')
                    .unwrap_or(EMPTY_ROW_HAS_TRAILING_SPACE)
                {
                    cur.pop();
                }
                rows.push(to_line(&cur));
                cur = tail;
            } else {
                rows.push(to_line(&cur));
                cur = Vec::new();
            }
            cur_w = run_width(&cur);
            last_space = None;
        }
        cur.push((c, st));
        cur_w = cur_w.saturating_add(cw);
        if c == ' ' {
            last_space = Some(cur.len());
        }
    }
    if !cur.is_empty() || rows.is_empty() {
        rows.push(to_line(&cur));
    }
    rows
}

/// Wrap styled spans while retaining hyperlink ranges outside the printable content. This mirrors
/// `wrap_spans` exactly: links therefore cannot change row count, display width, or break points.
pub(crate) fn wrap_annotated_spans(spans: &[AnnotatedSpan], width: u16) -> RenderedLines {
    let targets: Vec<&str> = spans
        .iter()
        .filter_map(|span| span.hyperlink.as_deref())
        .collect();
    let mut next_target = 0usize;
    let mut chars: Vec<(char, Style, Option<usize>)> = Vec::new();
    for span in spans {
        let target = span.hyperlink.as_ref().map(|_| {
            let id = next_target;
            next_target = next_target.saturating_add(1);
            id
        });
        for c in span.span.content.chars() {
            chars.push((c, span.span.style, target));
        }
    }
    if width == 0 || chars.is_empty() {
        let (line, hyperlinks) = annotated_line(&chars, &targets, 0);
        return RenderedLines {
            lines: vec![line],
            hyperlinks,
        };
    }

    let mut rendered = RenderedLines::default();
    let mut current: Vec<(char, Style, Option<usize>)> = Vec::new();
    let mut current_width = 0u16;
    let mut last_space: Option<usize> = None;
    for (character, style, target) in chars {
        // Match `wrap_spans`: at a one-cell viewport an over-wide glyph has no valid placement.
        // Retain its style and hyperlink identity on a visible one-cell replacement.
        let character = if char_width(character) > width {
            '?'
        } else {
            character
        };
        let entry = (character, style, target);
        let character_width = char_width(character);
        if current_width.saturating_add(character_width) > width && !current.is_empty() {
            if let Some(space) = last_space.filter(|&space| space > 0 && space < current.len()) {
                let tail = current.split_off(space);
                while current
                    .last()
                    .is_some_and(|(character, _, _)| *character == ' ')
                {
                    current.pop();
                }
                push_annotated_line(&mut rendered, &current, &targets);
                current = tail;
            } else {
                push_annotated_line(&mut rendered, &current, &targets);
                current = Vec::new();
            }
            current_width = current
                .iter()
                .map(|(character, _, _)| char_width(*character))
                .fold(0u16, u16::saturating_add);
            last_space = None;
        }
        current.push(entry);
        current_width = current_width.saturating_add(character_width);
        if character == ' ' {
            last_space = Some(current.len());
        }
    }
    if !current.is_empty() || rendered.lines.is_empty() {
        push_annotated_line(&mut rendered, &current, &targets);
    }
    rendered
}

fn push_annotated_line(
    rendered: &mut RenderedLines,
    chars: &[(char, Style, Option<usize>)],
    targets: &[&str],
) {
    let row = rendered.lines.len();
    let (line, mut hyperlinks) = annotated_line(chars, targets, row);
    rendered.lines.push(line);
    rendered.hyperlinks.append(&mut hyperlinks);
}

fn annotated_line(
    chars: &[(char, Style, Option<usize>)],
    targets: &[&str],
    row: usize,
) -> (Line<'static>, Vec<HyperlinkRegion>) {
    let printable: Vec<(char, Style)> = chars
        .iter()
        .map(|(character, style, _)| (*character, *style))
        .collect();
    let mut hyperlinks = Vec::new();
    let mut column = 0u16;
    let mut current_target: Option<usize> = None;
    let mut region_start = 0u16;
    for (character, _, target) in chars {
        if *target != current_target {
            finish_region(
                &mut hyperlinks,
                current_target,
                targets,
                row,
                region_start,
                column,
            );
            current_target = *target;
            region_start = column;
        }
        column = column.saturating_add(char_width(*character));
    }
    finish_region(
        &mut hyperlinks,
        current_target,
        targets,
        row,
        region_start,
        column,
    );
    (to_line(&printable), hyperlinks)
}

fn finish_region(
    hyperlinks: &mut Vec<HyperlinkRegion>,
    target: Option<usize>,
    targets: &[&str],
    row: usize,
    start: u16,
    end: u16,
) {
    let Some(target) = target.and_then(|target| targets.get(target)) else {
        return;
    };
    let width = end.saturating_sub(start);
    if width > 0 {
        hyperlinks.push(HyperlinkRegion {
            row,
            col: start,
            width,
            target: (*target).to_string(),
        });
    }
}

/// The display width of a whole `Line` (sum over its spans). Used by tests to assert the wrap
/// invariant and by callers that need to know a rendered row's width.
pub fn line_width(l: &Line) -> u16 {
    l.spans
        .iter()
        .flat_map(|s| s.content.chars())
        .map(char_width)
        .fold(0u16, |a, w| a.saturating_add(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::{Color, Modifier};

    fn styled(text: &str, color: Color) -> Span<'static> {
        Span::styled(text.to_string(), Style::default().fg(color))
    }

    #[test]
    fn every_wrapped_row_is_within_width() {
        let spans = vec![
            styled("the quick brown fox ", Color::White),
            styled("jumps_over_the_lazy_dog", Color::Green),
            styled(" and runs far away today", Color::Blue),
        ];
        for width in [4u16, 7, 10, 20, 40, 80] {
            for row in wrap_spans(&spans, width) {
                assert!(
                    line_width(&row) <= width,
                    "row exceeds width {width}: {:?}",
                    row
                );
            }
        }
    }

    #[test]
    fn preserves_per_span_styles_across_a_wrap() {
        let spans = vec![
            Span::styled(
                "keyword",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" plain ", Style::default().fg(Color::White)),
            Span::styled(
                "\"string here that is quite long\"",
                Style::default().fg(Color::Green),
            ),
        ];
        let rows = wrap_spans(&spans, 12);
        // the bold magenta keyword must keep its style wherever it lands
        let has_bold_magenta = rows.iter().flat_map(|l| l.spans.iter()).any(|s| {
            s.content.contains("keyword")
                && s.style.fg == Some(Color::Magenta)
                && s.style.add_modifier.contains(Modifier::BOLD)
        });
        assert!(has_bold_magenta, "per-span style lost across wrap");
        for row in &rows {
            assert!(line_width(row) <= 12);
        }
    }

    #[test]
    fn cjk_rows_respect_width_and_gutter_keeps_it() {
        let spans = vec![styled("写代码测试写代码测试写代码", Color::White)];
        let rows = wrap_spans(&spans, 8);
        for row in &rows {
            assert!(line_width(row) <= 8, "CJK row over width");
        }
        // with a 2-cell gutter prepended, wrapping at width-2 keeps the composed row within width
        for mut row in wrap_spans(&[styled("写代码测试写代码测试", Color::White)], 8 - 2)
        {
            let mut sp = vec![Span::raw("│ ")];
            sp.append(&mut row.spans);
            assert!(
                line_width(&Line::from(sp)) <= 8,
                "gutter pushed the row over width"
            );
        }
    }

    #[test]
    fn one_cell_rows_replace_physically_unrenderable_wide_glyphs() {
        let spans = vec![styled("界a", Color::White)];
        let rows = wrap_spans(&spans, 1);
        assert!(rows.iter().all(|row| line_width(row) <= 1));
        assert_eq!(
            rows.iter()
                .flat_map(|row| row.spans.iter())
                .map(|span| span.content.as_ref())
                .collect::<String>(),
            "?a"
        );

        let annotated = wrap_annotated_spans(
            &[AnnotatedSpan {
                span: styled("界", Color::Blue),
                hyperlink: Some("https://example.com/wide".into()),
            }],
            1,
        );
        assert!(annotated.lines.iter().all(|row| line_width(row) <= 1));
        assert_eq!(annotated.hyperlinks.len(), 1);
        assert_eq!(annotated.hyperlinks[0].width, 1);
    }

    #[test]
    fn empty_input_yields_one_empty_row() {
        assert_eq!(wrap_spans(&[], 10).len(), 1);
    }

    #[test]
    fn annotated_links_wrap_without_changing_visible_width() {
        let spans = vec![
            AnnotatedSpan {
                span: styled("before ", Color::White),
                hyperlink: None,
            },
            AnnotatedSpan {
                span: styled("clickable words", Color::Blue),
                hyperlink: Some("https://example.com/docs".into()),
            },
            AnnotatedSpan {
                span: styled(" after", Color::White),
                hyperlink: None,
            },
        ];
        let rendered = wrap_annotated_spans(&spans, 10);
        assert!(rendered.lines.iter().all(|line| line_width(line) <= 10));
        let expected = wrap_spans(
            &[
                styled("before ", Color::White),
                styled("clickable words", Color::Blue),
                styled(" after", Color::White),
            ],
            10,
        );
        assert_eq!(
            rendered
                .lines
                .iter()
                .map(|line| {
                    line.spans
                        .iter()
                        .map(|span| span.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|line| {
                    line.spans
                        .iter()
                        .map(|span| span.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(rendered.hyperlinks.len(), 2);
        assert!(
            rendered
                .hyperlinks
                .iter()
                .all(|link| link.target == "https://example.com/docs")
        );
    }
}
