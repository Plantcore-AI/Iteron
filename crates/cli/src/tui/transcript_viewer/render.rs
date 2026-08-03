//! Viewport-only rendering for the fullscreen transcript viewer.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block as WidgetBlock, Borders, Paragraph};
use unicode_segmentation::UnicodeSegmentation as _;
use unicode_width::UnicodeWidthStr as _;

use crate::theme;

use super::{Detail, MAX_DETAIL_ROWS, Viewer};

pub(crate) fn render(frame: &mut Frame, viewer: &mut Viewer, theme: &theme::Theme) {
    let area = frame.area();
    frame.render_widget(ratatui::widgets::Clear, area);
    if area.width == 0 || area.height == 0 {
        return;
    }
    let header = Rect::new(area.x, area.y, area.width, 1);
    let footer_height = area.height.saturating_sub(1).min(2);
    let footer = Rect::new(
        area.x,
        area.y + area.height.saturating_sub(footer_height),
        area.width,
        footer_height,
    );
    let body = Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width,
        area.height.saturating_sub(1 + footer_height),
    );

    let selected_position = viewer
        .selected_id
        .and_then(|id| viewer.entry_positions.get(&id).copied());
    let selected = selected_position.and_then(|position| viewer.entries.get(position));
    let selected_position = selected_position.map_or(0, |position| position + 1);
    let result_status = if viewer.query.is_empty() {
        String::new()
    } else if viewer.results.is_empty() {
        " · no matches".into()
    } else {
        format!(
            " · match {}/{}{}",
            viewer.result_position + 1,
            viewer.results.len(),
            if viewer.results_truncated { "+" } else { "" }
        )
    };
    let index_status = if viewer.incomplete_entries == 0 {
        String::new()
    } else {
        format!(" · search incomplete {} blocks", viewer.incomplete_entries)
    };
    let work_status = viewer
        .work_progress()
        .map_or_else(String::new, |(phase, done, total)| {
            format!(" · {phase} {done}/{total}")
        });
    let effect_status = viewer
        .pending_effect
        .map_or_else(String::new, |label| format!(" · {label} pending"));
    let header_text = format!(
        " Transcript · block {selected_position}/{} · {}{}{}{}{} ",
        viewer.entries.len(),
        if viewer.raw { "raw" } else { "pretty" },
        result_status,
        index_status,
        work_status,
        effect_status,
    );
    let header_style = if theme.mono {
        Style::default()
            .add_modifier(Modifier::REVERSED)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(theme.on_accent)
            .bg(theme.accent)
            .add_modifier(Modifier::BOLD)
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(header_text, header_style))),
        header,
    );

    let inner_width = body.width.saturating_sub(2);
    let inner_height = body.height.saturating_sub(2);
    let lines = if let Some(detail) = viewer.detail.as_mut() {
        ensure_layout(detail, inner_width);
        viewer.scroll = viewer.scroll.min(
            detail
                .row_ranges
                .len()
                .saturating_sub(usize::from(inner_height)),
        );
        visible_rows(
            &detail.text,
            &detail.row_ranges,
            inner_width,
            viewer.scroll,
            usize::from(inner_height),
        )
    } else {
        Vec::new()
    };
    let title = selected.map_or_else(
        || " no selected block ".to_string(),
        |entry| {
            format!(
                " {} #{}{}{} ",
                entry.label,
                entry.id,
                if entry.complete {
                    ""
                } else {
                    " · search-unindexed"
                },
                if viewer
                    .detail
                    .as_ref()
                    .is_some_and(|detail| detail.truncated)
                {
                    " · detail-truncated"
                } else {
                    ""
                }
            )
        },
    );
    frame.render_widget(
        Paragraph::new(lines).block(
            WidgetBlock::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(theme.faint)),
        ),
        body,
    );

    let prompt = if viewer.editing_query {
        "search> "
    } else {
        "filter: "
    };
    let query = if viewer.query.is_empty() {
        "(all)"
    } else {
        &viewer.query
    };
    let first = Line::from(vec![
        Span::styled(prompt, Style::default().fg(theme.accent)),
        Span::styled(query.to_string(), Style::default().fg(theme.fg)),
        Span::styled(
            if viewer.editing_query {
                "  enter accept · esc finish"
            } else {
                "  / search · j/k blocks · n/N matches · r raw"
            },
            Style::default().fg(theme.muted),
        ),
    ]);
    let second = if viewer.notice.is_empty() && viewer.work_progress().is_some() {
        "index update pending · input and redraw remain active · snapshot effects wait".to_string()
    } else if viewer.notice.is_empty() {
        "y copy block · Y copy match · e export filtered · E export all · esc close".to_string()
    } else {
        viewer.notice.clone()
    };
    frame.render_widget(
        Paragraph::new(vec![
            first,
            Line::from(Span::styled(second, Style::default().fg(theme.muted))),
        ]),
        footer,
    );
    // The ordinary composer set the prior frame's cursor. A resize while fullscreen must not leave
    // that stale coordinate outside the new terminal; keep it on this viewer's bounded filter row.
    let cursor_y = if footer.height > 0 { footer.y } else { area.y };
    let query_width = u16::try_from(query.width()).unwrap_or(u16::MAX);
    let desired_x = area.x.saturating_add(8).saturating_add(query_width);
    let cursor_x = desired_x.min(area.x.saturating_add(area.width.saturating_sub(1)));
    frame.set_cursor_position((cursor_x, cursor_y));
}

fn ensure_layout(detail: &mut Detail, width: u16) {
    if detail.layout_width == width {
        return;
    }
    detail.layout_width = width;
    detail.row_ranges = layout_rows(&detail.text, width);
}

/// Cache byte ranges once per detail/width. Steady frames then touch and allocate only the visible
/// slice. Detail bytes and ranges are independently capped, including on adversarial newlines.
pub(super) fn layout_rows(text: &str, width: u16) -> Vec<(usize, usize)> {
    if width == 0 {
        return Vec::new();
    }
    let mut rows = Vec::new();
    let mut start = 0usize;
    let mut row_width = 0u16;
    for (offset, grapheme) in text.grapheme_indices(true) {
        if rows.len() == MAX_DETAIL_ROWS {
            break;
        }
        if grapheme == "\n" {
            rows.push((start, offset));
            start = offset + grapheme.len();
            row_width = 0;
            continue;
        }
        let measured = u16::try_from(grapheme.width()).unwrap_or(u16::MAX);
        let character_width = if measured > width { 1 } else { measured };
        if row_width.saturating_add(character_width) > width && offset > start {
            rows.push((start, offset));
            start = offset;
            row_width = 0;
            if rows.len() == MAX_DETAIL_ROWS {
                break;
            }
        }
        row_width = row_width.saturating_add(character_width);
    }
    if rows.len() < MAX_DETAIL_ROWS && (start < text.len() || rows.is_empty()) {
        rows.push((start, text.len()));
    }
    rows
}

/// Materialize exactly the cached row ranges visible in this frame.
pub(super) fn visible_rows(
    text: &str,
    rows: &[(usize, usize)],
    width: u16,
    scroll: usize,
    height: usize,
) -> Vec<Line<'static>> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    rows.iter()
        .skip(scroll)
        .take(height)
        .map(|(start, end)| {
            let row = text[*start..*end]
                .graphemes(true)
                .map(|grapheme| {
                    if grapheme.width() > usize::from(width) {
                        "?"
                    } else {
                        grapheme
                    }
                })
                .collect::<String>();
            Line::from(row)
        })
        .collect()
}
