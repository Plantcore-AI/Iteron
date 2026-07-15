//! The semantic color theme (ADR-015 §4). Every render site references a *semantic token* (role,
//! tool, success, a syntax class) — never a raw `Color` literal — so the palette is swappable and
//! degrades cleanly: `NO_COLOR` → monochrome, a non-truecolor terminal keeps the same tokens (ratatui
//! maps `Rgb` down to the nearest 256/16 on output). One tuned dark theme ships first; a light theme
//! and a runtime `/theme` swap are P2.

use ratatui::style::{Color, Modifier, Style};

/// A lexical token class the highlighter emits; the theme maps it to a color (ADR-015 R6 — the
/// backend returns SEMANTIC classes, not tmTheme RGB, so the app theme stays authoritative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynClass {
    Keyword,
    Str,
    Comment,
    Number,
    Type,
    Func,
    Punct,
    Text,
}

/// The full palette. All fields are semantic; the render code never names a `Color` directly.
#[derive(Debug, Clone)]
pub struct Theme {
    pub fg: Color,
    pub muted: Color,
    pub accent: Color,
    /// Passive structural edge. Focused edges continue to use `accent`/state colors.
    pub border: Color,
    /// Subtle full-row surface for submitted operator messages. The live composer uses one terminal
    /// frame; settled prompts use the same compact `›` marker without a permanent role label.
    pub user_bg: Color,
    /// Foreground paired with `user_bg`. Terminal-inherit uses an explicit ANSI pair because an
    /// unknown physical background cannot produce a reliable low-alpha blend.
    pub user_fg: Color,
    /// A legible foreground to paint ON the `accent` background — the text color of a selection bar /
    /// inverted menu row. Replaces raw `Color::Black` at render sites (theme rule §3). Under mono the
    /// selection uses `REVERSED` instead, so this is unused there.
    pub on_accent: Color,
    pub role_user: Color,
    pub role_assistant: Color,
    /// Pure decoration (TUI v3 §3): the marker/connector color of a settled/ok machine block and any
    /// hairline. Dimmer than `muted` (which must stay legible). Replaces the deleted `tool` token —
    /// machine blocks are colored by role/status, never by a `tool` hue.
    pub faint: Color,
    pub success: Color,
    pub warn: Color,
    pub error: Color,
    pub code_bg: Color,
    pub added: Color,
    pub removed: Color,
    /// Full-row background tints for diff +/- lines (edge-to-edge, delta-style — the strongest
    /// "not a toy" diff cue). `Reset` under mono.
    pub added_bg: Color,
    pub removed_bg: Color,
    // syntax sub-palette
    pub syn_keyword: Color,
    pub syn_string: Color,
    pub syn_comment: Color,
    pub syn_number: Color,
    pub syn_type: Color,
    pub syn_func: Color,
    pub syn_punct: Color,
    /// true when colors are disabled (NO_COLOR) — render code can branch to skip backgrounds.
    pub mono: bool,
}

impl Theme {
    /// Pick a theme from the environment. An explicit override always wins. Without one, a reliable
    /// `COLORFGBG` background hint selects the tuned light/dark palette; absent or malformed evidence
    /// falls back to terminal-inherit so open terminal-native surfaces remain legible on either
    /// background. `NO_COLOR` → mono; `/theme` swaps at runtime.
    pub fn detect() -> Self {
        if std::env::var_os("NO_COLOR").is_some() {
            return Self::mono();
        }
        match std::env::var("CORE_THEME").ok().as_deref() {
            Some("light") => Self::light(),
            Some("terminal") => Self::terminal(),
            Some("high-contrast") | Some("hc") => Self::high_contrast(),
            Some("mono") => Self::mono(),
            Some("dark") => Self::dark(),
            // No explicit override: use fixed RGB only when the terminal supplies background evidence.
            _ => Self::detect_by_background(),
        }
    }

    /// Probe `COLORFGBG` (set by many terminals as `"fg;bg"`, e.g. `"15;0"` dark, `"0;15"` light) to
    /// pick light vs dark. Only the trailing background field decides. Anything missing, malformed or
    /// outside the ANSI 0–15 range inherits the terminal palette instead of guessing a contrast.
    fn detect_by_background() -> Self {
        Self::for_colorfgbg(std::env::var("COLORFGBG").ok().as_deref())
    }

    fn for_colorfgbg(value: Option<&str>) -> Self {
        match value
            .and_then(|value| value.rsplit(';').next())
            .and_then(|value| value.trim().parse::<u8>().ok())
        {
            Some(7 | 10..=15) => Self::light(),
            Some(0..=6 | 8 | 9) => Self::dark(),
            _ => Self::terminal(),
        }
    }

    /// The default: INHERIT the terminal's own palette via NAMED ANSI colors + dim, with ONE accent
    /// (cyan) for anything interactive/live and a state-only semantic triad (green/red/yellow). No
    /// imposed hex; hierarchy comes from value (dim→normal→bold), not a rainbow of hues.
    pub fn terminal() -> Self {
        Theme {
            fg: Color::Reset,
            // muted must stay LEGIBLE (TUI v3 §3): a real gray, not the near-invisible DarkGray.
            muted: Color::Gray,
            accent: Color::Cyan,
            border: Color::DarkGray,
            // Codex blends a quiet user surface from the detected terminal background. When that
            // background is unavailable, use a portable ANSI gray/white pair instead of silently
            // dropping the surface: submitted prompts must remain visibly distinct from answers.
            user_bg: Color::DarkGray,
            user_fg: Color::White,
            on_accent: Color::Black,
            role_user: Color::Cyan,
            role_assistant: Color::Reset,
            faint: Color::DarkGray,
            success: Color::Green,
            warn: Color::Yellow,
            error: Color::Red,
            code_bg: Color::Reset,
            added: Color::Green,
            removed: Color::Red,
            added_bg: Color::Reset,
            removed_bg: Color::Reset,
            syn_keyword: Color::Magenta,
            syn_string: Color::Green,
            syn_comment: Color::DarkGray,
            syn_number: Color::Yellow,
            // syn_type must DIFFER from accent (Cyan) so code type names don't light up in the
            // prompt/user cyan (TUI v3 §3, findings 5) — a teal, distinct from the accent hue.
            syn_type: Color::Rgb(0x73, 0xda, 0xca),
            // syn_func must also DIFFER from accent — Blue vs Cyan accent here.
            syn_func: Color::Blue,
            syn_punct: Color::Reset,
            mono: false,
        }
    }

    /// A tuned dark palette (Tokyo-Night-family — restrained, high legibility, not neon).
    pub fn dark() -> Self {
        let rgb = Color::Rgb;
        Theme {
            fg: rgb(0xdc, 0xe3, 0xf0),
            muted: rgb(0x9a, 0xa7, 0xba),
            accent: rgb(0x7a, 0xa2, 0xf7),
            border: rgb(0x3a, 0x43, 0x5f),
            // Approximately a 12% white lift over the dark canvas, matching the low-contrast
            // submitted-message treatment used by Codex without retaining the old blue card tint.
            user_bg: rgb(0x2e, 0x30, 0x34),
            user_fg: rgb(0xdc, 0xe3, 0xf0),
            on_accent: rgb(0x0b, 0x0f, 0x17),
            // The `>` user marker is `accent` (TUI v3 §3), NOT the success/added green — dark
            // `role_user` was `0x9ece6a`, identical to success/added/syn_string (findings 10). Give it
            // the accent hue so "you" reads as interactive, distinct from a green state change.
            role_user: rgb(0x7a, 0xa2, 0xf7),
            role_assistant: rgb(0x7a, 0xa2, 0xf7),
            faint: rgb(0x66, 0x70, 0x85),
            success: rgb(0x8b, 0xd4, 0x9c),
            warn: rgb(0xe6, 0xb8, 0x6a),
            error: rgb(0xf0, 0x71, 0x78),
            code_bg: rgb(0x0f, 0x14, 0x1d),
            added: rgb(0x8b, 0xd4, 0x9c),
            removed: rgb(0xf0, 0x71, 0x78),
            added_bg: rgb(0x14, 0x26, 0x1b),
            removed_bg: rgb(0x2a, 0x17, 0x1d),
            syn_keyword: rgb(0xbb, 0x9a, 0xf7),
            syn_string: rgb(0xb8, 0xd4, 0x7a),
            syn_comment: rgb(0x56, 0x5f, 0x89),
            syn_number: rgb(0xff, 0x9e, 0x64),
            syn_type: rgb(0x2a, 0xc3, 0xde),
            // distinct from accent (0x7aa2f7) so code function names don't light up like UI chrome.
            syn_func: rgb(0x73, 0xda, 0xca),
            syn_punct: rgb(0x89, 0xdd, 0xff),
            mono: false,
        }
    }

    /// A light palette for light terminals (Tokyo-Night-light-family).
    pub fn light() -> Self {
        let rgb = Color::Rgb;
        Theme {
            fg: rgb(0x18, 0x20, 0x33),
            muted: rgb(0x53, 0x60, 0x78),
            accent: rgb(0x34, 0x5b, 0xd1),
            border: rgb(0xd6, 0xdc, 0xe8),
            // Approximately a 4% black veil over a light canvas.
            user_bg: rgb(0xf1, 0xf2, 0xf3),
            user_fg: rgb(0x18, 0x20, 0x33),
            on_accent: rgb(0xff, 0xff, 0xff),
            // accent, not the success/added green (findings 10).
            role_user: rgb(0x34, 0x55, 0xb5),
            role_assistant: rgb(0x34, 0x55, 0xb5),
            faint: rgb(0x7e, 0x89, 0x9d),
            success: rgb(0x38, 0x7d, 0x2c),
            warn: rgb(0x8f, 0x5e, 0x15),
            error: rgb(0xc6, 0x4b, 0x5a),
            code_bg: rgb(0xe9, 0xed, 0xf5),
            added: rgb(0x38, 0x7d, 0x2c),
            removed: rgb(0xc6, 0x4b, 0x5a),
            added_bg: rgb(0xdf, 0xf2, 0xe0),
            removed_bg: rgb(0xfa, 0xe2, 0xe6),
            syn_keyword: rgb(0x7b, 0x43, 0xba),
            syn_string: rgb(0x38, 0x7d, 0x2c),
            syn_comment: rgb(0x9a, 0xa0, 0xb0),
            syn_number: rgb(0xb1, 0x5c, 0x00),
            syn_type: rgb(0x0f, 0x86, 0x9e),
            // distinct from accent (0x3455b5) — a teal, not the accent blue.
            syn_func: rgb(0x11, 0x8b, 0x8b),
            syn_punct: rgb(0x0f, 0x6a, 0x8e),
            mono: false,
        }
    }

    /// A high-contrast dark palette (accessibility).
    pub fn high_contrast() -> Self {
        let rgb = Color::Rgb;
        Theme {
            fg: rgb(0xff, 0xff, 0xff),
            muted: rgb(0xb0, 0xb0, 0xb0),
            accent: rgb(0x6c, 0xb6, 0xff),
            border: rgb(0xb0, 0xb0, 0xb0),
            user_bg: rgb(0x24, 0x24, 0x24),
            user_fg: rgb(0xff, 0xff, 0xff),
            on_accent: rgb(0x00, 0x00, 0x00),
            // accent, not the success/added green (findings 10).
            role_user: rgb(0x6c, 0xb6, 0xff),
            role_assistant: rgb(0x6c, 0xb6, 0xff),
            faint: rgb(0x70, 0x70, 0x70),
            success: rgb(0x5d, 0xff, 0x5d),
            warn: rgb(0xff, 0xd0, 0x50),
            error: rgb(0xff, 0x6b, 0x6b),
            code_bg: rgb(0x00, 0x00, 0x00),
            added: rgb(0x5d, 0xff, 0x5d),
            removed: rgb(0xff, 0x6b, 0x6b),
            added_bg: rgb(0x00, 0x2a, 0x00),
            removed_bg: rgb(0x2a, 0x00, 0x00),
            syn_keyword: rgb(0xff, 0x9c, 0xf0),
            syn_string: rgb(0x9d, 0xff, 0x9d),
            syn_comment: rgb(0xb0, 0xb0, 0xb0),
            syn_number: rgb(0xff, 0xc0, 0x70),
            syn_type: rgb(0x6c, 0xe6, 0xff),
            syn_func: rgb(0x8c, 0xc6, 0xff),
            syn_punct: rgb(0xc0, 0xf0, 0xff),
            mono: false,
        }
    }

    /// Named theme presets for the `/theme` picker.
    pub fn presets() -> Vec<(&'static str, Theme)> {
        vec![
            ("terminal (inherit)", Theme::terminal()),
            ("dark", Theme::dark()),
            ("light", Theme::light()),
            ("high-contrast", Theme::high_contrast()),
            ("mono (no color)", Theme::mono()),
        ]
    }

    /// Monochrome (NO_COLOR): every token is the default foreground; structure comes from glyphs,
    /// gutters, spacing, and modifiers (bold/dim/italic), not color.
    pub fn mono() -> Self {
        let d = Color::Reset;
        Theme {
            fg: d,
            muted: d,
            accent: d,
            border: d,
            user_bg: Color::Reset,
            user_fg: d,
            on_accent: d,
            role_user: d,
            role_assistant: d,
            faint: d,
            success: d,
            warn: d,
            error: d,
            code_bg: Color::Reset,
            added: d,
            removed: d,
            added_bg: Color::Reset,
            removed_bg: Color::Reset,
            syn_keyword: d,
            syn_string: d,
            syn_comment: d,
            syn_number: d,
            syn_type: d,
            syn_func: d,
            syn_punct: d,
            mono: true,
        }
    }

    /// The color for a syntax class.
    pub fn syn(&self, c: SynClass) -> Color {
        match c {
            SynClass::Keyword => self.syn_keyword,
            SynClass::Str => self.syn_string,
            SynClass::Comment => self.syn_comment,
            SynClass::Number => self.syn_number,
            SynClass::Type => self.syn_type,
            SynClass::Func => self.syn_func,
            SynClass::Punct => self.syn_punct,
            SynClass::Text => self.fg,
        }
    }

    /// Style for a syntax class (comments italic, keywords bold — a subtle SOTA touch).
    pub fn syn_style(&self, c: SynClass) -> Style {
        let s = Style::default().fg(self.syn(c));
        match c {
            SynClass::Comment => s.add_modifier(Modifier::ITALIC),
            SynClass::Keyword => s.add_modifier(Modifier::BOLD),
            _ => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_detection_uses_a_portable_ansi_user_surface_without_rgb_evidence() {
        for value in [None, Some(""), Some("unknown"), Some("15;99")] {
            let theme = Theme::for_colorfgbg(value);
            assert_eq!(theme.fg, Color::Reset);
            assert_eq!(theme.user_bg, Color::DarkGray);
            assert_eq!(theme.user_fg, Color::White);
        }
        assert_eq!(Theme::for_colorfgbg(Some("15;0")).fg, Theme::dark().fg);
        assert_eq!(Theme::for_colorfgbg(Some("0;15")).fg, Theme::light().fg);
    }

    #[test]
    fn submitted_prompt_surfaces_are_neutral_and_distinct_from_code_and_diffs() {
        for theme in [Theme::dark(), Theme::light(), Theme::high_contrast()] {
            let Color::Rgb(r, g, b) = theme.user_bg else {
                panic!("fixed visual presets need a measurable submitted-prompt gray")
            };
            let low = r.min(g).min(b);
            let high = r.max(g).max(b);
            assert!(
                high - low <= 6,
                "submitted-prompt background must remain neutral: {:?}",
                theme.user_bg
            );
            assert_ne!(theme.user_bg, theme.code_bg);
            assert_ne!(theme.user_bg, theme.added_bg);
            assert_ne!(theme.user_bg, theme.removed_bg);
        }
        assert_eq!(Theme::mono().user_bg, Color::Reset);
        assert_eq!(Theme::mono().user_fg, Color::Reset);
    }
}
