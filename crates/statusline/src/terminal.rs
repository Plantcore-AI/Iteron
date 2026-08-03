//! What the terminal on the other end can actually do, and what that obliges us to.
//!
//! Capability is detected from the environment rather than probed, because probing means writing a
//! query and waiting for a reply, and a terminal that does not implement the query simply never
//! answers -- so the fallback path is a timeout on every start-up in exactly the terminals that
//! need the fallback.
//!
//! Two of these are not preferences and are treated as obligations. `NO_COLOR` is a published
//! convention with a precise rule, and a screen-reader session needs semantic text rather than
//! alignment achieved with padding. Getting either wrong makes the tool unusable rather than ugly,
//! which is why they are typed states here instead of hints a renderer may consult.

/// How much colour may be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Color {
    /// No escape sequences for colour at all.
    None,
    /// The original 16.
    Ansi16,
    Ansi256,
    TrueColor,
}

/// How output should be shaped for the reader, as opposed to how it should be painted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presentation {
    /// Box drawing, alignment padding and colour are meaningful.
    Visual,
    /// A screen reader announces characters it cannot interpret and reads padding as content, so
    /// output must be semantic: no alignment spaces, no box drawing, no colour-only distinctions.
    Semantic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub color: Color,
    pub presentation: Presentation,
    /// Inside a multiplexer. Passthrough of exotic sequences is unreliable, so features like the
    /// title stack are best treated as advisory here.
    pub multiplexed: bool,
    /// Reached over SSH. Latency makes high-frequency repaint a bad default.
    pub remote: bool,
}

impl Capabilities {
    /// Detect from environment variables via a supplied lookup, so this is testable and free of
    /// ambient state.
    ///
    /// Precedence is deliberate: an explicit accessibility or `NO_COLOR` request outranks anything
    /// inferred from `TERM`. A user who set `NO_COLOR` on a 24-bit terminal meant it.
    pub fn detect(get: impl Fn(&str) -> Option<String>) -> Self {
        let term = get("TERM").unwrap_or_default();
        let dumb = term.is_empty() || term == "dumb";

        // NO_COLOR (no-color.org): honoured when *present and non-empty*, whatever the value.
        // Testing for "1" or "true" is the common bug -- `NO_COLOR=0` still means no colour.
        let no_color = get("NO_COLOR").is_some_and(|v| !v.is_empty());

        let color = if no_color || dumb {
            Color::None
        } else if get("COLORTERM").is_some_and(|v| v == "truecolor" || v == "24bit") {
            Color::TrueColor
        } else if term.contains("256color") {
            Color::Ansi256
        } else {
            Color::Ansi16
        };

        let screen_reader = get("CORE_SCREEN_READER").is_some_and(|v| !v.is_empty());
        let presentation = if screen_reader || dumb {
            Presentation::Semantic
        } else {
            Presentation::Visual
        };

        Capabilities {
            color,
            presentation,
            multiplexed: get("TMUX").is_some() || term.starts_with("screen"),
            remote: get("SSH_TTY").is_some() || get("SSH_CONNECTION").is_some(),
        }
    }

    /// Whether a renderer may emit colour escapes at all.
    pub fn may_use_color(&self) -> bool {
        self.color != Color::None
    }

    /// Whether alignment padding and box drawing are meaningful.
    pub fn may_use_layout(&self) -> bool {
        self.presentation == Presentation::Visual
    }
}

/// sRGB colour, for contrast checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

/// WCAG relative luminance.
fn relative_luminance(c: Rgb) -> f64 {
    fn channel(v: u8) -> f64 {
        let s = f64::from(v) / 255.0;
        if s <= 0.039_28 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * channel(c.0) + 0.7152 * channel(c.1) + 0.0722 * channel(c.2)
}

/// WCAG contrast ratio, from 1.0 (identical) to 21.0 (black on white).
pub fn contrast_ratio(a: Rgb, b: Rgb) -> f64 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// WCAG AA for normal-size text.
pub const MIN_CONTRAST_AA: f64 = 4.5;

/// Whether a foreground/background pair is legible at normal size.
///
/// This is checked rather than assumed because a theme is chosen once by whoever wrote it and then
/// read by everyone, including people the author cannot see.
pub fn meets_aa(fg: Rgb, bg: Rgb) -> bool {
    contrast_ratio(fg, bg) >= MIN_CONTRAST_AA
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn no_color_is_honoured_by_presence_not_by_value() {
        // The standard says any non-empty value disables colour. Testing for "1"/"true" is the
        // common bug: `NO_COLOR=0` reads as "no colour", not as "colour please".
        for value in ["1", "0", "false", "no", "anything"] {
            let caps =
                Capabilities::detect(env(&[("TERM", "xterm-256color"), ("NO_COLOR", value)]));
            assert_eq!(
                caps.color,
                Color::None,
                "NO_COLOR={value} must disable colour"
            );
            assert!(!caps.may_use_color());
        }
    }

    #[test]
    fn an_empty_no_color_does_not_disable_colour() {
        // Also from the standard: empty means unset.
        let caps = Capabilities::detect(env(&[("TERM", "xterm-256color"), ("NO_COLOR", "")]));
        assert_eq!(caps.color, Color::Ansi256);
    }

    #[test]
    fn no_color_outranks_a_capable_terminal() {
        let caps = Capabilities::detect(env(&[
            ("TERM", "xterm-256color"),
            ("COLORTERM", "truecolor"),
            ("NO_COLOR", "1"),
        ]));
        assert_eq!(caps.color, Color::None);
    }

    #[test]
    fn colour_depth_is_read_from_colorterm_then_term() {
        assert_eq!(
            Capabilities::detect(env(&[("TERM", "xterm"), ("COLORTERM", "truecolor")])).color,
            Color::TrueColor
        );
        assert_eq!(
            Capabilities::detect(env(&[("TERM", "xterm-256color")])).color,
            Color::Ansi256
        );
        assert_eq!(
            Capabilities::detect(env(&[("TERM", "xterm")])).color,
            Color::Ansi16
        );
    }

    #[test]
    fn a_dumb_or_absent_term_gets_neither_colour_nor_layout() {
        for pairs in [vec![("TERM", "dumb")], vec![]] {
            let caps = Capabilities::detect(env(&pairs));
            assert_eq!(caps.color, Color::None);
            assert_eq!(caps.presentation, Presentation::Semantic);
            assert!(!caps.may_use_layout());
        }
    }

    #[test]
    fn a_screen_reader_session_disables_layout_but_not_necessarily_colour() {
        // Padding and box drawing are read aloud as content; colour is not, so it survives.
        let caps = Capabilities::detect(env(&[
            ("TERM", "xterm-256color"),
            ("CORE_SCREEN_READER", "1"),
        ]));
        assert_eq!(caps.presentation, Presentation::Semantic);
        assert!(!caps.may_use_layout());
        assert!(caps.may_use_color());
    }

    #[test]
    fn multiplexer_and_ssh_are_detected() {
        let tmux = Capabilities::detect(env(&[("TERM", "xterm"), ("TMUX", "/tmp/tmux-0/default")]));
        assert!(tmux.multiplexed);
        let screen = Capabilities::detect(env(&[("TERM", "screen.xterm-256color")]));
        assert!(screen.multiplexed);
        let ssh = Capabilities::detect(env(&[("TERM", "xterm"), ("SSH_TTY", "/dev/pts/0")]));
        assert!(ssh.remote);
        assert!(!tmux.remote);
    }

    #[test]
    fn contrast_ratio_matches_the_wcag_reference_points() {
        // Black on white is the defined maximum, and identical colours the defined minimum.
        let black = Rgb(0, 0, 0);
        let white = Rgb(255, 255, 255);
        assert!((contrast_ratio(black, white) - 21.0).abs() < 0.01);
        assert!((contrast_ratio(white, white) - 1.0).abs() < 0.001);
        // Symmetric: order of arguments must not change the verdict.
        assert!((contrast_ratio(black, white) - contrast_ratio(white, black)).abs() < 1e-9);
    }

    #[test]
    fn mid_grey_on_white_fails_aa_and_dark_grey_passes() {
        let white = Rgb(255, 255, 255);
        // #999 is the classic "looks fine to the author" placeholder that fails at normal size.
        assert!(!meets_aa(Rgb(0x99, 0x99, 0x99), white));
        assert!(meets_aa(Rgb(0x59, 0x59, 0x59), white));
    }

    #[test]
    fn a_theme_pair_can_be_checked_before_it_ships() {
        // The point of exposing this: a theme is written once and read by people its author
        // cannot see, so the check belongs in the test suite rather than in a reviewer's eye.
        let bg = Rgb(0x1e, 0x1e, 0x1e);
        for fg in [Rgb(0xd4, 0xd4, 0xd4), Rgb(0xff, 0xff, 0xff)] {
            assert!(meets_aa(fg, bg), "{fg:?} on {bg:?} must meet AA");
        }
    }
}
