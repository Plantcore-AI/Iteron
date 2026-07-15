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
        let cw = char_width(c);
        if cur_w.saturating_add(cw) > width && !cur.is_empty() {
            if let Some(sp) = last_space.filter(|&sp| sp > 0 && sp < cur.len()) {
                let tail = cur.split_off(sp);
                while cur.last().map(|(c, _)| *c == ' ').unwrap_or(false) {
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
    fn empty_input_yields_one_empty_row() {
        assert_eq!(wrap_spans(&[], 10).len(), 1);
    }
}
