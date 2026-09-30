//! Bounded popup rows, retained layout and terminal-safe preview rendering.

use super::*;

/// Pad a run of spans with a trailing filler so the row fills `width` cells; when `bg` is Some the
/// filler carries that background, extending a selection bar edge-to-edge (TUI v3 §9 — the selection
/// is ONE full-width inverted bar).
pub(super) fn pad_line_to(spans: &mut Vec<Span<'static>>, width: u16, fill: Style) {
    let w: u16 = spans
        .iter()
        .map(|span| text_width(span.content.as_ref()))
        .fold(0u16, |a, x| a.saturating_add(x));
    if w < width {
        spans.push(Span::styled(" ".repeat((width - w) as usize), fill));
    }
}

/// One row of a list popup: a `lead` label (accent when `lead_accent`, else fg) and a dim `aux` tail
/// (description / hint / "(current)"). The completion menu and the selection picker are both built from
/// these — ONE component (TUI v3 §9), so width, height, border, nav and the selection bar can't drift.
pub(super) struct PopupRow {
    pub(super) lead: String,
    pub(super) lead_accent: bool,
    pub(super) aux: String,
    pub(super) enabled: bool,
}

/// A modal must never own the keyboard while being completely invisible. When a terminal cannot
/// spare the three rows or columns required for a bordered menu, render a one/two-line selection
/// strip over the available frame. Detail yields, but focus and the escape route remain visible.
pub(super) fn render_compact_popup(
    f: &mut Frame,
    anchor: Rect,
    title: &str,
    rows: &[PopupRow],
    sel: usize,
    theme: &theme::Theme,
    width: u16,
) {
    let frame = f.area();
    let height = frame.height.min(2);
    if width == 0 || height == 0 {
        return;
    }
    let x = anchor
        .x
        .min(frame.right().saturating_sub(width))
        .max(frame.x);
    let max_y = frame.bottom().saturating_sub(height);
    let y = anchor.y.saturating_sub(height).clamp(frame.y, max_y);
    let area = Rect::new(x, y, width, height).intersection(frame);
    if area.width == 0 || area.height == 0 {
        return;
    }

    let mut lines = Vec::new();
    if area.height == 2 {
        lines.push(Line::from(Span::styled(
            clip_text(&format!("{title} · enter/esc"), area.width),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
    }
    let row = rows.get(sel);
    let enabled = row.is_some_and(|row| row.enabled);
    let selection = if theme.mono || !enabled {
        Style::default()
            .fg(if enabled { theme.fg } else { theme.muted })
            .add_modifier(Modifier::REVERSED)
    } else {
        Style::default().fg(theme.on_accent).bg(theme.accent)
    };
    let label = row
        .map(|row| format!("› {}", row.lead))
        .unwrap_or_else(|| "no matches · esc".into());
    let mut spans = vec![Span::styled(clip_text(&label, area.width), selection)];
    pad_line_to(&mut spans, area.width, selection);
    lines.push(Line::from(spans));

    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(Paragraph::new(lines), area);
}

/// The ONE list-popup renderer (TUI v3 §9): the completion menu AND the picker both call this, so they
/// share a plain terminal border, responsive width, visible-height budget, windowing, title
/// grammar, and — critically — the selection bar. Selection = a SINGLE full-width inverted bar:
/// `fg(on_accent).bg(accent)` in color, `REVERSED` under mono (so NO_COLOR, where accent==Reset, still
/// shows the bar; and no raw `Color::Black` — review R3/R4). Left-aligned above `anchor`, always
/// clamped to the frame so a short terminal can't panic ratatui's `Clear` (round-3 review).
pub(super) fn render_list_popup(
    f: &mut Frame,
    anchor: Rect,
    title: &str,
    rows: &[PopupRow],
    sel: usize,
    query: Option<&str>,
    theme: &theme::Theme,
) {
    let frame = f.area();
    let total = rows.len();
    let w = match surface::Density::for_width(anchor.width) {
        surface::Density::Compact => anchor.width,
        surface::Density::Standard => anchor.width.min(72),
        surface::Density::Wide => anchor.width.min(88),
    }
    .min(frame.width);
    if w == 0 {
        return;
    }
    let bar_w = w.saturating_sub(2); // inside the border
    let max_h = anchor.y.saturating_sub(frame.y).min(frame.height).min(14);
    if w < 3 || max_h < 3 {
        render_compact_popup(f, anchor, title, rows, sel, theme, w);
        return;
    }
    let selected_detail = rows.get(sel).map(|row| row.aux.trim()).unwrap_or("");
    let inner_h = max_h.saturating_sub(2);
    let query_h = u16::from(query.is_some() && inner_h >= 3);
    // The footer owns the interaction legend; the border title carries identity only. Reserve one
    // navigable row before selected detail so a short popup remains an actionable control.
    let footer_h = u16::from(inner_h.saturating_sub(query_h) >= 2);
    let min_list_h = u16::try_from(total.clamp(1, 2))
        .unwrap_or(iteron_tunables::param_integer(
            "cli.tui.min_list_rows_on_overflow",
            MIN_LIST_ROWS_ON_OVERFLOW,
        ))
        .min(inner_h.saturating_sub(query_h).saturating_sub(footer_h));
    let detail_budget = if max_h >= 6 {
        inner_h
            .saturating_sub(query_h)
            .saturating_sub(footer_h)
            .saturating_sub(min_list_h)
            .min(3)
    } else {
        0
    };
    let detail_lines = popup_detail_lines(
        selected_detail,
        bar_w,
        detail_budget as usize,
        Style::default().fg(theme.muted),
    );
    let detail_h = u16::try_from(detail_lines.len()).unwrap_or(detail_budget);
    let vis = (inner_h
        .saturating_sub(query_h)
        .saturating_sub(footer_h)
        .saturating_sub(detail_h) as usize)
        .clamp(1, 10);
    let start = if total == 0 {
        0
    } else {
        sel.saturating_sub(vis.saturating_sub(1))
            .min(total.saturating_sub(vis))
    };
    // The selection bar style (mono-safe): one signal, edge-to-edge.
    let sel_style = if theme.mono {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default().fg(theme.on_accent).bg(theme.accent)
    };
    // Disabled rows remain focusable so the operator can read why a model is unavailable. Keep
    // their text muted even while focused, with reversal as the independent selection signal.
    let disabled_sel_style = Style::default()
        .fg(theme.muted)
        .add_modifier(Modifier::REVERSED);
    let mut visible: Vec<Line> = Vec::new();
    if query_h > 0 {
        let query = query.unwrap_or_default();
        let value = if query.is_empty() {
            "type to filter".to_string()
        } else {
            query.to_string()
        };
        visible.push(Line::from(vec![
            Span::styled(" search  ", Style::default().fg(theme.muted)),
            Span::styled(
                clip_text(&value, bar_w.saturating_sub(9)),
                Style::default().fg(theme.fg),
            ),
        ]));
    }
    if total == 0 {
        let message = query
            .filter(|query| !query.is_empty())
            .map(|query| {
                format!(
                    "No matches for “{}”",
                    clip_text(query, bar_w.saturating_sub(18))
                )
            })
            .unwrap_or_else(|| "No selectable items".into());
        visible.push(Line::from(Span::styled(
            clip_text(&message, bar_w),
            Style::default().fg(theme.muted),
        )));
    }
    visible.extend(rows.iter().enumerate().skip(start).take(vis).map(|(i, r)| {
        let selected = i == sel;
        let (lead_style, aux_style) = if selected {
            let selected_style = if r.enabled {
                sel_style
            } else {
                disabled_sel_style
            };
            (selected_style, selected_style)
        } else if !r.enabled {
            (
                Style::default().fg(theme.muted),
                Style::default().fg(theme.faint),
            )
        } else {
            let lead = if r.lead_accent {
                theme.accent
            } else {
                theme.fg
            };
            (Style::default().fg(lead), Style::default().fg(theme.muted))
        };
        let aux_gap = u16::from(!r.aux.is_empty()) * 2;
        let lead_budget = if r.aux.is_empty() {
            bar_w
        } else {
            bar_w.saturating_mul(3) / 5
        };
        let lead = clip_text(&r.lead, lead_budget);
        let mut sp = vec![Span::styled(lead.clone(), lead_style)];
        if !r.aux.is_empty() && text_width(&lead).saturating_add(aux_gap) < bar_w {
            let aux_w = bar_w
                .saturating_sub(text_width(&lead))
                .saturating_sub(aux_gap);
            sp.push(Span::styled(
                format!("  {}", clip_text(&r.aux, aux_w)),
                aux_style,
            ));
        }
        pad_line_to(
            &mut sp,
            bar_w,
            if selected {
                if r.enabled {
                    sel_style
                } else {
                    disabled_sel_style
                }
            } else {
                Style::default()
            },
        );
        Line::from(sp)
    }));
    visible.extend(detail_lines);
    if footer_h > 0 {
        let footer_text = if total == 0 {
            " no matches · type to search · backspace edit · esc clear".to_string()
        } else if query.is_some() {
            format!(
                " {}/{}  type filter · ↑↓ navigate · enter select · esc clear/close",
                sel + 1,
                total
            )
        } else {
            format!(
                " {}/{}  ↑↓ navigate · enter select · esc close",
                sel + 1,
                total
            )
        };
        let footer = clip_text(&footer_text, bar_w);
        visible.push(Line::from(Span::styled(
            footer,
            Style::default().fg(theme.muted),
        )));
    }
    let n = visible.len() as u16;
    let h = (n + 2).min(max_h);
    let y = anchor.y.saturating_sub(h);
    let area = Rect {
        x: anchor.x.min(frame.right().saturating_sub(w)),
        y,
        width: w,
        height: h,
    }
    .intersection(frame);
    if area.height < 3 || area.width < 3 {
        return;
    }
    let full = clip_text(&format!(" {title} "), w.saturating_sub(4));
    let popup = Paragraph::new(visible).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme.accent))
            .title(full),
    );
    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(popup, area);
}

/// Wrap a selected row's full auxiliary detail by terminal cells. `max_rows` is a layout budget,
/// not a fixed one-line clip; if the detail still exceeds that budget, the final visible row gets a
/// truthful ellipsis. The popup retains at least one (normally two) navigable list rows above it.
pub(super) fn popup_detail_lines(
    detail: &str,
    width: u16,
    max_rows: usize,
    style: Style,
) -> Vec<Line<'static>> {
    if detail.is_empty() || width == 0 || max_rows == 0 {
        return Vec::new();
    }
    let mut rows = crate::render::wrap_spans(&[Span::styled(detail.to_string(), style)], width);
    if rows.len() <= max_rows {
        return rows;
    }
    rows.truncate(max_rows);
    if let Some(last) = rows.last_mut() {
        let text = last
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        let visible = clip_text(&text, width.saturating_sub(1));
        *last = Line::from(Span::styled(format!("{visible}…"), style));
    }
    rows
}

pub(super) fn spans_width(spans: &[Span<'_>]) -> u16 {
    spans
        .iter()
        .map(|span| text_width(span.content.as_ref()))
        .fold(0u16, u16::saturating_add)
}

pub(super) fn clip_spans(spans: Vec<Span<'static>>, width: u16) -> Vec<Span<'static>> {
    let mut remaining = width;
    let mut clipped = Vec::new();
    for span in spans {
        if remaining == 0 {
            break;
        }
        let span_width = text_width(span.content.as_ref());
        if span_width <= remaining {
            remaining = remaining.saturating_sub(span_width);
            clipped.push(span);
            continue;
        }
        clipped.push(Span::styled(
            clip_text(span.content.as_ref(), remaining),
            span.style,
        ));
        break;
    }
    clipped
}

pub(crate) fn clip_text(text: &str, width: u16) -> String {
    if text_width(text) <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return "…".into();
    }
    let budget = width - 1;
    let mut used = 0u16;
    let mut out = String::new();
    for grapheme in unicode_segmentation::UnicodeSegmentation::graphemes(text, true) {
        let cw = grapheme_width(grapheme);
        if used.saturating_add(cw) > budget {
            break;
        }
        out.push_str(grapheme);
        used = used.saturating_add(cw);
    }
    out.push('…');
    out
}

pub(super) fn one_line_preview(text: &str, width: u16) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    clip_text(&collapsed, width)
}
