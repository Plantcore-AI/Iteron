//! Bounded terminal capability detection for theme selection.
//!
//! Environment hints are captured once per session. The TUI input adapter owns OSC 11 transport and
//! passes only a parsed light/dark classification into this module.

use super::Theme;
use ratatui::style::Color;

const MAX_ENV_VALUE_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackgroundTone {
    Dark,
    Light,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColorDepth {
    Ansi16,
    Ansi256,
    TrueColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Preset {
    Terminal,
    Dark,
    Light,
    HighContrast,
    Mono,
}

/// Session-stable environment evidence used by both initial detection and runtime theme changes.
#[derive(Debug, Clone)]
pub(crate) struct Environment {
    pub(crate) no_color: bool,
    pub(crate) preset: Option<Preset>,
    pub(crate) colorfgbg: Option<String>,
    pub(crate) color_depth: ColorDepth,
    pub(crate) interactive_query_supported: bool,
}

impl Environment {
    pub(crate) fn capture() -> Self {
        let term = bounded_env("TERM");
        let colorterm = bounded_env("COLORTERM");
        let interactive_query_supported = term.as_deref() != Some("dumb")
            && std::env::var_os("TMUX").is_none()
            && std::env::var_os("STY").is_none();
        Self {
            // NO_COLOR is active when present and non-empty. `NO_COLOR=` is the convention's
            // explicit inactive shape and must not silently flatten a configured theme.
            no_color: std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            preset: bounded_env("CORE_THEME").as_deref().and_then(parse_preset),
            colorfgbg: bounded_env("COLORFGBG"),
            color_depth: ColorDepth::from_hints(term.as_deref(), colorterm.as_deref()),
            interactive_query_supported,
        }
    }

    pub(crate) fn wants_background_query(&self) -> bool {
        !self.no_color && self.preset.is_none() && self.interactive_query_supported
    }
}

fn bounded_env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    (value.len() <= MAX_ENV_VALUE_BYTES).then_some(value)
}

fn parse_preset(value: &str) -> Option<Preset> {
    match value {
        "terminal" => Some(Preset::Terminal),
        "dark" => Some(Preset::Dark),
        "light" => Some(Preset::Light),
        "high-contrast" | "hc" => Some(Preset::HighContrast),
        "mono" => Some(Preset::Mono),
        _ => None,
    }
}

impl ColorDepth {
    pub(crate) fn from_hints(term: Option<&str>, colorterm: Option<&str>) -> Self {
        let colorterm = colorterm.unwrap_or_default().to_ascii_lowercase();
        if matches!(colorterm.as_str(), "truecolor" | "24bit") {
            Self::TrueColor
        } else if term
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("256color")
        {
            Self::Ansi256
        } else {
            Self::Ansi16
        }
    }

    pub(crate) fn project_theme(self, mut theme: Theme) -> Theme {
        let colors = [
            &mut theme.fg,
            &mut theme.muted,
            &mut theme.accent,
            &mut theme.brand_back,
            &mut theme.brand_mid,
            &mut theme.brand_front,
            &mut theme.border,
            &mut theme.user_bg,
            &mut theme.user_fg,
            &mut theme.on_accent,
            &mut theme.role_user,
            &mut theme.role_assistant,
            &mut theme.faint,
            &mut theme.success,
            &mut theme.warn,
            &mut theme.error,
            &mut theme.code_bg,
            &mut theme.added,
            &mut theme.removed,
            &mut theme.added_bg,
            &mut theme.removed_bg,
            &mut theme.syn_keyword,
            &mut theme.syn_string,
            &mut theme.syn_comment,
            &mut theme.syn_number,
            &mut theme.syn_type,
            &mut theme.syn_func,
            &mut theme.syn_punct,
        ];
        for color in colors {
            *color = self.project_color(*color);
        }
        theme
    }

    pub(crate) fn project_color(self, color: Color) -> Color {
        match (self, color) {
            (Self::TrueColor, _) => color,
            (Self::Ansi256, Color::Rgb(r, g, b)) => Color::Indexed(nearest_ansi256(r, g, b)),
            (Self::Ansi16, Color::Rgb(r, g, b)) => ANSI16[nearest_ansi16(r, g, b) as usize].0,
            (Self::Ansi16, Color::Indexed(index)) => {
                let (r, g, b) = ansi256_rgb(index);
                ANSI16[nearest_ansi16(r, g, b) as usize].0
            }
            _ => color,
        }
    }
}

const ANSI16: [(Color, (u8, u8, u8)); 16] = [
    (Color::Black, (0, 0, 0)),
    (Color::Red, (128, 0, 0)),
    (Color::Green, (0, 128, 0)),
    (Color::Yellow, (128, 128, 0)),
    (Color::Blue, (0, 0, 128)),
    (Color::Magenta, (128, 0, 128)),
    (Color::Cyan, (0, 128, 128)),
    (Color::Gray, (192, 192, 192)),
    (Color::DarkGray, (128, 128, 128)),
    (Color::LightRed, (255, 0, 0)),
    (Color::LightGreen, (0, 255, 0)),
    (Color::LightYellow, (255, 255, 0)),
    (Color::LightBlue, (0, 0, 255)),
    (Color::LightMagenta, (255, 0, 255)),
    (Color::LightCyan, (0, 255, 255)),
    (Color::White, (255, 255, 255)),
];

fn nearest_ansi16(r: u8, g: u8, b: u8) -> u8 {
    ANSI16
        .iter()
        .enumerate()
        .map(|(index, (_, candidate))| (rgb_distance((r, g, b), *candidate), index as u8))
        .min()
        .map_or(0, |(_, index)| index)
}

fn nearest_ansi256(r: u8, g: u8, b: u8) -> u8 {
    (0_u8..=u8::MAX)
        .map(|index| (rgb_distance((r, g, b), ansi256_rgb(index)), index))
        .min()
        .map_or(0, |(_, index)| index)
}

fn ansi256_rgb(index: u8) -> (u8, u8, u8) {
    match index {
        0..=15 => ANSI16[index as usize].1,
        16..=231 => {
            const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
            let offset = index - 16;
            (
                LEVELS[(offset / 36) as usize],
                LEVELS[((offset % 36) / 6) as usize],
                LEVELS[(offset % 6) as usize],
            )
        }
        232..=255 => {
            let gray = 8 + (index - 232) * 10;
            (gray, gray, gray)
        }
    }
}

fn rgb_distance(left: (u8, u8, u8), right: (u8, u8, u8)) -> u32 {
    let dr = i32::from(left.0) - i32::from(right.0);
    let dg = i32::from(left.1) - i32::from(right.1);
    let db = i32::from(left.2) - i32::from(right.2);
    (dr * dr + dg * dg + db * db) as u32
}

/// Parse the bounded body reconstructed by the TUI's OSC 11 input demultiplexer.
pub(crate) fn tone_from_osc11_body(body: &str) -> Option<BackgroundTone> {
    let (r, g, b) = parse_rgb(body)?;
    let brightness = u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114;
    Some(if brightness >= 150_000 {
        BackgroundTone::Light
    } else {
        BackgroundTone::Dark
    })
}

fn parse_rgb(body: &str) -> Option<(u8, u8, u8)> {
    if let Some(hex) = body.strip_prefix('#') {
        if hex.len() != 6 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        return Some((
            u8::from_str_radix(&hex[0..2], 16).ok()?,
            u8::from_str_radix(&hex[2..4], 16).ok()?,
            u8::from_str_radix(&hex[4..6], 16).ok()?,
        ));
    }
    let mut components = body.strip_prefix("rgb:")?.split('/');
    let rgb = (
        scale_hex_component(components.next()?)?,
        scale_hex_component(components.next()?)?,
        scale_hex_component(components.next()?)?,
    );
    components.next().is_none().then_some(rgb)
}

fn scale_hex_component(component: &str) -> Option<u8> {
    if component.is_empty()
        || component.len() > 4
        || !component.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let value = u32::from_str_radix(component, 16).ok()?;
    let max = (1_u32 << (component.len() * 4)) - 1;
    Some(((value * 255 + max / 2) / max) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_projection_is_deterministic_and_never_leaves_rgb_on_ansi16() {
        assert_eq!(
            ColorDepth::from_hints(Some("xterm-direct"), Some("TRUECOLOR")),
            ColorDepth::TrueColor
        );
        assert_eq!(
            ColorDepth::from_hints(Some("xterm-256color"), None),
            ColorDepth::Ansi256
        );
        assert_eq!(
            ColorDepth::from_hints(Some("xterm"), None),
            ColorDepth::Ansi16
        );

        let theme = ColorDepth::Ansi16.project_theme(Theme::dark());
        let snapshot = [
            theme.fg,
            theme.muted,
            theme.accent,
            theme.border,
            theme.user_bg,
            theme.success,
            theme.warn,
            theme.error,
            theme.syn_keyword,
            theme.syn_string,
            theme.syn_number,
            theme.syn_type,
            theme.syn_func,
        ];
        assert!(
            snapshot
                .iter()
                .all(|color| !matches!(color, Color::Rgb(..) | Color::Indexed(_)))
        );
        assert!(
            [theme.brand_back, theme.brand_mid, theme.brand_front]
                .iter()
                .all(|color| !matches!(color, Color::Rgb(..) | Color::Indexed(_))),
            "Plantcore brand planes are projected with the rest of the semantic palette"
        );
        assert_eq!(
            format!("{snapshot:?}"),
            "[White, Gray, Gray, Cyan, Black, Gray, Gray, DarkGray, Gray, Gray, Gray, LightCyan, Gray]"
        );
    }

    #[test]
    fn osc11_body_parser_rejects_oversized_components_and_classifies_bounded_rgb() {
        assert_eq!(tone_from_osc11_body("rgb:fffff/0/0"), None);
        assert_eq!(
            tone_from_osc11_body("rgb:ffff/ffff/ffff"),
            Some(BackgroundTone::Light)
        );
        assert_eq!(tone_from_osc11_body("#000000"), Some(BackgroundTone::Dark));
    }
}
