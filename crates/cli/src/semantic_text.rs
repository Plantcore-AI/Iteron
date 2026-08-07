//! Shared semantic highlighting for short machine-authored text.
//!
//! Markdown owns prose and fenced-code parsing; `highlight` owns lexical source-code classes; the
//! diff renderer owns add/delete rows. This module covers the remaining compact surfaces — notices,
//! tool summaries, panel values, paths, commands, counters and state words — so those surfaces do
//! not each invent a local color grammar. Classification is deliberately conservative: unknown
//! words retain the caller's base tone, and color never replaces the visible token itself.

use crate::theme::{SynClass, Theme};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    Body,
    Muted,
    Error,
}

impl Tone {
    fn style(self, theme: &Theme) -> Style {
        match self {
            Self::Body => Style::default().fg(theme.fg),
            Self::Muted => Style::default().fg(theme.muted),
            Self::Error => Style::default().fg(theme.error),
        }
    }
}

/// Highlight compact, already-safe display text without changing a single visible character.
pub(crate) fn spans(text: &str, tone: Tone, theme: &Theme) -> Vec<Span<'static>> {
    if text.is_empty() {
        return vec![Span::styled(String::new(), tone.style(theme))];
    }

    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        push_plain(&rest[..open], tone, theme, &mut out);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('`') else {
            push_plain(&rest[open..], tone, theme, &mut out);
            rest = "";
            break;
        };
        out.push(Span::styled(
            "`".to_owned(),
            Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
        ));
        out.push(Span::styled(
            after_open[..close].to_owned(),
            theme
                .syn_style(SynClass::Func)
                .bg(theme.code_bg)
                .add_modifier(Modifier::BOLD),
        ));
        out.push(Span::styled(
            "`".to_owned(),
            Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
        ));
        rest = &after_open[close + 1..];
    }
    push_plain(rest, tone, theme, &mut out);
    out
}

fn push_plain(text: &str, tone: Tone, theme: &Theme, out: &mut Vec<Span<'static>>) {
    let mut start = 0;
    let mut whitespace = text
        .char_indices()
        .next()
        .is_some_and(|(_, ch)| ch.is_whitespace());
    for (index, ch) in text.char_indices() {
        if ch.is_whitespace() != whitespace {
            push_token(&text[start..index], whitespace, tone, theme, out);
            start = index;
            whitespace = !whitespace;
        }
    }
    push_token(&text[start..], whitespace, tone, theme, out);
}

fn push_token(
    token: &str,
    whitespace: bool,
    tone: Tone,
    theme: &Theme,
    out: &mut Vec<Span<'static>>,
) {
    if token.is_empty() {
        return;
    }
    let style = if whitespace {
        tone.style(theme)
    } else {
        token_style(token, tone, theme)
    };
    out.push(Span::styled(token.to_owned(), style));
}

fn token_style(token: &str, tone: Tone, theme: &Theme) -> Style {
    let core = token.trim_matches(|ch: char| {
        matches!(
            ch,
            '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | ':' | '"' | '\''
        )
    });
    let lower = core.to_ascii_lowercase();

    if matches!(core, "·" | "│" | "|" | "→" | "←" | "↳" | "⎿") {
        return Style::default().fg(theme.faint).add_modifier(Modifier::DIM);
    }
    if matches!(core, "▧" | "▤" | "◆" | "●" | "○" | "◐" | "◉" | "⦿") {
        return Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD);
    }
    if signed_number(core, '+') {
        return Style::default()
            .fg(theme.added)
            .add_modifier(Modifier::BOLD);
    }
    if signed_number(core, '-') {
        return Style::default()
            .fg(theme.removed)
            .add_modifier(Modifier::BOLD);
    }
    if is_command(core) {
        return Style::default()
            .fg(if core.starts_with('!') {
                theme.warn
            } else {
                theme.accent
            })
            .add_modifier(Modifier::BOLD);
    }
    if is_path(core) {
        return theme.syn_style(SynClass::Type);
    }
    if is_number(core) {
        return theme.syn_style(SynClass::Number);
    }
    if matches!(
        lower.as_str(),
        "done"
            | "passed"
            | "success"
            | "succeeded"
            | "added"
            | "created"
            | "updated"
            | "ready"
            | "resumed"
    ) {
        return Style::default()
            .fg(theme.success)
            .add_modifier(Modifier::BOLD);
    }
    if matches!(
        lower.as_str(),
        "failed" | "failure" | "error" | "errored" | "denied" | "deleted" | "removed" | "killed"
    ) {
        return Style::default()
            .fg(theme.error)
            .add_modifier(Modifier::BOLD);
    }
    if matches!(
        lower.as_str(),
        "warning"
            | "warn"
            | "partial"
            | "stopped"
            | "interrupted"
            | "skipped"
            | "queued"
            | "pending"
    ) {
        return Style::default().fg(theme.warn);
    }
    tone.style(theme)
}

fn signed_number(token: &str, sign: char) -> bool {
    token
        .strip_prefix(sign)
        .is_some_and(|rest| !rest.is_empty() && is_number(rest))
}

fn is_number(token: &str) -> bool {
    let token = token
        .trim_start_matches('#')
        .trim_end_matches([',', '.', ')', ']']);
    let numeric = token
        .trim_end_matches(|ch: char| ch.is_ascii_alphabetic() || matches!(ch, '%' | 'µ' | '$'));
    !numeric.is_empty()
        && numeric.chars().any(|ch| ch.is_ascii_digit())
        && numeric
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | ',' | '_' | ':' | '/'))
}

fn is_command(token: &str) -> bool {
    if let Some(command) = token.strip_prefix('/') {
        return !command.is_empty()
            && !command.contains('/')
            && command
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'));
    }
    token
        .strip_prefix('!')
        .is_some_and(|command| !command.is_empty() && !command.contains('/'))
}

fn is_path(token: &str) -> bool {
    if token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with("~/")
        || token.contains('\\')
        || token.matches('/').count() >= 2
    {
        return true;
    }
    if token.contains('/') && !token.starts_with("http://") && !token.starts_with("https://") {
        return true;
    }
    let Some(extension) = token.rsplit('.').next() else {
        return false;
    };
    token.len() > extension.len().saturating_add(1)
        && matches!(
            extension.trim_end_matches([',', ':', ';', ')']),
            "rs" | "toml"
                | "md"
                | "json"
                | "yaml"
                | "yml"
                | "ts"
                | "tsx"
                | "js"
                | "jsx"
                | "py"
                | "go"
                | "java"
                | "kt"
                | "c"
                | "cc"
                | "cpp"
                | "h"
                | "hpp"
                | "sh"
                | "zsh"
                | "fish"
                | "html"
                | "css"
                | "sql"
                | "xml"
                | "txt"
                | "log"
                | "lock"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    #[test]
    fn machine_text_uses_stable_roles_without_changing_visible_text() {
        let theme = Theme::dark();
        let rendered = spans(
            "updated crates/cli/src/tui.rs via /diff in 42ms · done",
            Tone::Muted,
            &theme,
        );
        assert_eq!(
            rendered
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>(),
            "updated crates/cli/src/tui.rs via /diff in 42ms · done"
        );
        assert!(rendered.iter().any(|span| {
            span.content == "crates/cli/src/tui.rs" && span.style.fg == Some(theme.syn_type)
        }));
        assert!(
            rendered
                .iter()
                .any(|span| span.content == "/diff" && span.style.fg == Some(theme.accent))
        );
        assert!(
            rendered
                .iter()
                .any(|span| span.content == "42ms" && span.style.fg == Some(theme.syn_number))
        );
        assert!(
            rendered
                .iter()
                .any(|span| span.content == "done" && span.style.fg == Some(theme.success))
        );
    }

    #[test]
    fn signed_counts_and_failure_words_keep_diff_and_state_colors() {
        let theme = Theme::dark();
        let rendered = spans("+12 -3 failed", Tone::Body, &theme);
        assert_eq!(rendered[0].style.fg, Some(theme.added));
        assert_eq!(rendered[2].style.fg, Some(theme.removed));
        assert_eq!(rendered[4].style.fg, Some(theme.error));
    }

    #[test]
    fn inline_code_uses_the_syntax_palette_and_mono_keeps_visible_truth() {
        let dark = Theme::dark();
        let rendered = spans("run `cargo test` now", Tone::Body, &dark);
        assert!(rendered.iter().any(|span| {
            span.content == "cargo test"
                && span.style.fg == Some(dark.syn_func)
                && span.style.bg == Some(dark.code_bg)
        }));

        let mono = Theme::mono();
        let rendered = spans("+2 -1 failed /diff", Tone::Muted, &mono);
        assert_eq!(
            rendered
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>(),
            "+2 -1 failed /diff"
        );
        assert!(
            rendered
                .iter()
                .all(|span| span.style.fg == Some(Color::Reset))
        );
    }
}
