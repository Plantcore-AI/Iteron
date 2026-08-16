//! Theme-aware footer segments.
//!
//! The footer is a compact semantic projection, not a table. Segments carry a presentation role,
//! separators are quiet punctuation, and callers retain whole groups while negotiating width so
//! route/effort identity can never split into contradictory fragments.

use crate::theme::Theme;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use unicode_width::UnicodeWidthStr as _;

/// Codex's status-line cadence: a centered dot with breathing room, dimmed independently from the
/// data on either side. Keeping one constant prevents nested route/effort metadata from drifting
/// back to table-like vertical rules.
pub(super) const SEPARATOR: &str = " · ";

fn separator() -> &'static str {
    iteron_tunables::param_str("cli.tui.status_line.separator", SEPARATOR)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Accent {
    Model,
    Usage,
    Metadata,
    Mode,
    Progress,
    Warning,
}

impl Accent {
    fn style(self, theme: &Theme) -> Style {
        if theme.mono {
            return Style::default().add_modifier(Modifier::DIM);
        }
        let color = match self {
            Self::Model => theme.accent,
            Self::Usage | Self::Progress => theme.success,
            Self::Metadata => theme.muted,
            Self::Mode | Self::Warning => theme.warn,
        };
        Style::default().fg(color)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Segment {
    text: String,
    accent: Accent,
}

impl Segment {
    fn new(text: impl Into<String>, accent: Accent) -> Self {
        Self {
            text: text.into(),
            accent,
        }
    }
}

/// One width-negotiation unit. A group may contain several independently styled visible segments;
/// the renderer drops the group as one unit when the footer narrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Group {
    segments: Vec<Segment>,
}

impl Group {
    pub(super) fn single(text: impl Into<String>, accent: Accent) -> Self {
        Self {
            segments: vec![Segment::new(text, accent)],
        }
    }

    #[cfg(test)]
    pub(super) fn pair(
        first: impl Into<String>,
        first_accent: Accent,
        second: impl Into<String>,
        second_accent: Accent,
    ) -> Self {
        Self {
            segments: vec![
                Segment::new(first, first_accent),
                Segment::new(second, second_accent),
            ],
        }
    }

    #[cfg(test)]
    pub(super) fn text(&self) -> String {
        self.segments
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>()
            .join(separator())
    }
}

pub(super) fn width(groups: &[Group]) -> u16 {
    let text_width = groups
        .iter()
        .flat_map(|group| group.segments.iter())
        .map(|segment| segment.text.width())
        .sum::<usize>();
    let segment_count = groups
        .iter()
        .map(|group| group.segments.len())
        .sum::<usize>();
    let separators = segment_count.saturating_sub(1) * separator().width();
    u16::try_from(text_width.saturating_add(separators)).unwrap_or(u16::MAX)
}

pub(super) fn spans(groups: &[Group], theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for segment in groups.iter().flat_map(|group| group.segments.iter()) {
        if !spans.is_empty() {
            spans.push(Span::styled(
                separator(),
                Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
            ));
        }
        spans.push(Span::styled(
            segment.text.clone(),
            segment.accent.style(theme),
        ));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    fn text(spans: &[Span<'_>]) -> String {
        spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    #[test]
    fn status_segments_use_dot_cadence_and_semantic_theme_accents() {
        let theme = Theme::dark();
        let groups = vec![
            Group::single("deepseek/v4", Accent::Model),
            Group::single("ctx 83% left", Accent::Usage),
            Group::single("bypass", Accent::Mode),
        ];
        let rendered = spans(&groups, &theme);

        assert_eq!(text(&rendered), "deepseek/v4 · ctx 83% left · bypass");
        assert_eq!(width(&groups), 35);
        assert_eq!(rendered[0].style.fg, Some(theme.accent));
        assert_eq!(rendered[1].style.fg, Some(theme.faint));
        assert!(rendered[1].style.add_modifier.contains(Modifier::DIM));
        assert_eq!(rendered[2].style.fg, Some(theme.success));
        assert_eq!(rendered[4].style.fg, Some(theme.warn));
    }

    #[test]
    fn mono_keeps_the_same_text_and_dims_every_semantic_item() {
        let theme = Theme::mono();
        let groups = vec![Group::pair(
            "provider/model",
            Accent::Model,
            "● high",
            Accent::Warning,
        )];
        let rendered = spans(&groups, &theme);

        assert_eq!(text(&rendered), "provider/model · ● high");
        assert!(rendered.iter().all(|span| {
            span.style.fg == Some(Color::Reset) || span.style.add_modifier.contains(Modifier::DIM)
        }));
    }
}
