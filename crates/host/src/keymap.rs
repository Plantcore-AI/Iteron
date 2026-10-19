//! Portable keymap configuration and conflict validation. Terminal adapters translate events.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    Enter,
    Esc,
    Tab,
    BackTab,
    Backspace,
    Delete,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Char(char),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyModifiers(u8);
impl KeyModifiers {
    pub const NONE: Self = Self(0);
    pub const SHIFT: Self = Self(1);
    pub const CONTROL: Self = Self(2);
    pub const ALT: Self = Self(4);
    pub const SUPER: Self = Self(8);
    pub const HYPER: Self = Self(16);
    pub const META: Self = Self(32);
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}
impl std::ops::BitOr for KeyModifiers {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl std::ops::BitAnd for KeyModifiers {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::Not for KeyModifiers {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Standard,
    Vim,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    /// Closed action name -> one chord such as `ctrl+g` or `alt+enter`.
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    ExternalEditor,
    ReverseSearch,
    RestoreDraft,
    ToggleFold,
    TranscriptViewer,
}

impl Action {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "external_editor" => Some(Self::ExternalEditor),
            "reverse_search" => Some(Self::ReverseSearch),
            "restore_draft" => Some(Self::RestoreDraft),
            "toggle_fold" => Some(Self::ToggleFold),
            "transcript_viewer" => Some(Self::TranscriptViewer),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::ExternalEditor => "external_editor",
            Self::ReverseSearch => "reverse_search",
            Self::RestoreDraft => "restore_draft",
            Self::ToggleFold => "toggle_fold",
            Self::TranscriptViewer => "transcript_viewer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Chord {
    code: KeyCode,
    modifiers: KeyModifiers,
}

impl Chord {
    fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() || value.len() > 64 {
            return Err("a key chord must be 1..=64 ASCII bytes".into());
        }
        let mut parts = value.split('+').collect::<Vec<_>>();
        let key = parts
            .pop()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| format!("invalid key chord `{value}`"))?;
        let mut modifiers = KeyModifiers::NONE;
        for modifier in parts {
            let flag = match modifier {
                "ctrl" | "control" => KeyModifiers::CONTROL,
                "alt" | "option" => KeyModifiers::ALT,
                "shift" => KeyModifiers::SHIFT,
                "super" | "cmd" | "command" => KeyModifiers::SUPER,
                "hyper" => KeyModifiers::HYPER,
                "meta" => KeyModifiers::META,
                _ => return Err(format!("unknown modifier `{modifier}` in `{value}`")),
            };
            if modifiers.contains(flag) {
                return Err(format!("duplicate modifier `{modifier}` in `{value}`"));
            }
            modifiers.insert(flag);
        }
        let code = match key {
            "enter" => KeyCode::Enter,
            "esc" | "escape" => KeyCode::Esc,
            "tab" => KeyCode::Tab,
            "backtab" => {
                modifiers.insert(KeyModifiers::SHIFT);
                KeyCode::BackTab
            }
            "backspace" => KeyCode::Backspace,
            "delete" => KeyCode::Delete,
            "up" => KeyCode::Up,
            "down" => KeyCode::Down,
            "left" => KeyCode::Left,
            "right" => KeyCode::Right,
            "home" => KeyCode::Home,
            "end" => KeyCode::End,
            "pageup" => KeyCode::PageUp,
            "pagedown" => KeyCode::PageDown,
            _ if key.chars().count() == 1 => KeyCode::Char(key.chars().next().unwrap()),
            _ => return Err(format!("unknown key `{key}` in `{value}`")),
        };
        Ok(Self { code, modifiers })
    }

    fn from_event(code: KeyCode, modifiers: KeyModifiers) -> Self {
        let code = match code {
            KeyCode::Char(character) => KeyCode::Char(character.to_ascii_lowercase()),
            other => other,
        };
        let modifiers = modifiers
            & (KeyModifiers::CONTROL
                | KeyModifiers::ALT
                | KeyModifiers::SHIFT
                | KeyModifiers::SUPER
                | KeyModifiers::HYPER
                | KeyModifiers::META);
        Self { code, modifiers }
    }
}

#[derive(Debug, Clone)]
pub struct Keymap {
    mode: Mode,
    custom: bool,
    chords: BTreeMap<Action, Chord>,
}

impl Default for Keymap {
    fn default() -> Self {
        Self::from_config(None).expect("built-in keymap is valid")
    }
}

impl Keymap {
    pub fn from_config(config: Option<&Config>) -> Result<Self, String> {
        let config = config.cloned().unwrap_or_default();
        let custom = !config.bindings.is_empty();
        let mut chords = BTreeMap::from([
            (Action::ExternalEditor, Chord::parse("ctrl+g")?),
            (Action::ReverseSearch, Chord::parse("ctrl+r")?),
            (Action::RestoreDraft, Chord::parse("ctrl+z")?),
            (Action::ToggleFold, Chord::parse("ctrl+o")?),
            (Action::TranscriptViewer, Chord::parse("ctrl+f")?),
        ]);
        for (name, value) in &config.bindings {
            let action = Action::parse(name).ok_or_else(|| {
                format!(
                    "unknown keymap action `{name}`; expected external_editor, reverse_search, restore_draft, toggle_fold, or transcript_viewer"
                )
            })?;
            let chord = Chord::parse(value)?;
            if reserved(&chord) {
                return Err(format!(
                    "keymap action `{}` cannot use reserved lifecycle chord `{value}`",
                    action.name()
                ));
            }
            chords.insert(action, chord);
        }
        let mut unique = Vec::with_capacity(chords.len());
        for (action, chord) in &chords {
            if unique.contains(chord) {
                return Err(format!(
                    "keymap chord for `{}` conflicts with another action",
                    action.name()
                ));
            }
            unique.push(chord.clone());
        }
        Ok(Self {
            mode: config.mode,
            custom,
            chords,
        })
    }

    pub fn action_for(&self, code: KeyCode, modifiers: KeyModifiers) -> Option<Action> {
        let chord = Chord::from_event(code, modifiers);
        let exact = self
            .chords
            .iter()
            .find_map(|(action, registered)| (*registered == chord).then_some(*action));
        if exact.is_some() || !modifiers.contains(KeyModifiers::SHIFT) {
            return exact;
        }
        // Shift is the explicit "search even from an empty retry composer" modifier. Preserve it
        // for the caller's retry-vs-search decision while matching the configured base chord.
        let unshifted = Chord::from_event(code, modifiers & !KeyModifiers::SHIFT);
        self.chords
            .get(&Action::ReverseSearch)
            .filter(|registered| **registered == unshifted)
            .map(|_| Action::ReverseSearch)
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn is_custom(&self) -> bool {
        self.custom
    }
}

fn reserved(chord: &Chord) -> bool {
    [
        "ctrl+c",
        "ctrl+d",
        "ctrl+j",
        "ctrl+t",
        "ctrl+v",
        "enter",
        "esc",
        "tab",
        "shift+tab",
        "backtab",
    ]
    .iter()
    .filter_map(|value| Chord::parse(value).ok())
    .any(|reserved| reserved == *chord)
}
