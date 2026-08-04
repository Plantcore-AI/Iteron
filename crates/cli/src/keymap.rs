//! Typed, conflict-checked TUI keymaps and a small deterministic Vim input state machine.
//!
//! Configuration carries printable chord strings, but the live loop sees only parsed `Chord`
//! values and a closed `Action` vocabulary. Safety/lifecycle keys are reserved and cannot be
//! rebound; duplicate chords are rejected instead of making match order the hidden authority.

use crossterm::event::{KeyCode, KeyModifiers};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    #[default]
    Standard,
    Vim,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    #[serde(default)]
    pub(crate) mode: Mode,
    /// Closed action name -> one chord such as `ctrl+g` or `alt+enter`.
    #[serde(default)]
    pub(crate) bindings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Action {
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
pub(crate) struct Keymap {
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
    pub(crate) fn from_config(config: Option<&Config>) -> Result<Self, String> {
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

    pub(crate) fn action_for(&self, code: KeyCode, modifiers: KeyModifiers) -> Option<Action> {
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

    pub(crate) fn mode(&self) -> Mode {
        self.mode
    }

    pub(crate) fn is_custom(&self) -> bool {
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum VimState {
    #[default]
    Insert,
    Normal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VimAction {
    EnterInsert,
    EnterNormal,
    AppendInsert,
    AppendEndInsert,
    InsertStart,
    Left,
    Right,
    Home,
    End,
    WordLeft,
    WordRight,
    Delete,
    Clear,
    HistoryPrevious,
    HistoryNext,
    Consumed,
}

#[derive(Debug, Default)]
pub(crate) struct Vim {
    state: VimState,
    pending_delete: bool,
}

impl Vim {
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn state(&self) -> VimState {
        self.state
    }

    /// Return `None` when ordinary insert-mode routing should handle the key.
    pub(crate) fn route(
        &mut self,
        enabled: bool,
        code: KeyCode,
        modifiers: KeyModifiers,
    ) -> Option<VimAction> {
        if !enabled {
            self.reset();
            return None;
        }
        if self.state == VimState::Insert {
            // Without progressive keyboard disambiguation, terminals encode a fast `Esc` followed
            // by a printable normal-mode command as one Alt+char event. Registered Alt bindings
            // are consumed before this state machine; every other Alt+char is therefore the
            // portable Esc-prefix form and must not leak the command into insert mode.
            if modifiers == KeyModifiers::ALT && matches!(code, KeyCode::Char(_)) {
                self.state = VimState::Normal;
                self.pending_delete = false;
                return Some(
                    self.route(true, code, KeyModifiers::NONE)
                        .unwrap_or(VimAction::Consumed),
                );
            }
            if code == KeyCode::Esc && modifiers.is_empty() {
                self.state = VimState::Normal;
                self.pending_delete = false;
                return Some(VimAction::EnterNormal);
            }
            return None;
        }
        // Crossterm reports `A`/`I` either as an uppercase character alone or as that character
        // plus SHIFT depending on the terminal protocol. Both are the same Vim command; no other
        // modified normal-mode key is allowed to leak into the state machine.
        let shifted_uppercase =
            modifiers == KeyModifiers::SHIFT && matches!(code, KeyCode::Char('A' | 'I'));
        if !modifiers.is_empty() && !shifted_uppercase {
            self.pending_delete = false;
            return None;
        }
        let action = match code {
            KeyCode::Esc => VimAction::Consumed,
            KeyCode::Char('i') => VimAction::EnterInsert,
            KeyCode::Char('a') => VimAction::AppendInsert,
            KeyCode::Char('A') => VimAction::AppendEndInsert,
            KeyCode::Char('I') => VimAction::InsertStart,
            KeyCode::Char('h') => VimAction::Left,
            KeyCode::Char('l') => VimAction::Right,
            KeyCode::Char('0') => VimAction::Home,
            KeyCode::Char('$') => VimAction::End,
            KeyCode::Char('b') => VimAction::WordLeft,
            KeyCode::Char('w') => VimAction::WordRight,
            KeyCode::Char('x') => VimAction::Delete,
            KeyCode::Char('k') => VimAction::HistoryPrevious,
            KeyCode::Char('j') => VimAction::HistoryNext,
            KeyCode::Char('d') if self.pending_delete => VimAction::Clear,
            KeyCode::Char('d') => {
                self.pending_delete = true;
                return Some(VimAction::Consumed);
            }
            KeyCode::Char(_) | KeyCode::Backspace | KeyCode::Delete => VimAction::Consumed,
            _ => {
                self.pending_delete = false;
                return None;
            }
        };
        self.pending_delete = false;
        if matches!(
            action,
            VimAction::EnterInsert
                | VimAction::AppendInsert
                | VimAction::AppendEndInsert
                | VimAction::InsertStart
        ) {
            self.state = VimState::Insert;
        }
        Some(action)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FileStamp {
    Missing,
    Present {
        modified: Option<std::time::SystemTime>,
        len: u64,
        #[cfg(unix)]
        device: u64,
        #[cfg(unix)]
        inode: u64,
    },
}

/// Cheap config watcher polled immediately before each key is routed. This preserves the TUI's
/// zero-idle-poll contract while ensuring the first key after an atomic config rewrite sees the
/// new map (or the safe built-in fallback).
pub(crate) struct Watcher {
    path: Option<PathBuf>,
    stamp: FileStamp,
}

impl Watcher {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        let stamp = stamp(path.as_deref());
        Self { path, stamp }
    }

    pub(crate) fn changed(&mut self) -> bool {
        let next = stamp(self.path.as_deref());
        if next == self.stamp {
            return false;
        }
        self.stamp = next;
        true
    }
}

fn stamp(path: Option<&Path>) -> FileStamp {
    let Some(path) = path else {
        return FileStamp::Missing;
    };
    std::fs::metadata(path)
        .map(|metadata| {
            #[cfg(unix)]
            use std::os::unix::fs::MetadataExt as _;
            FileStamp::Present {
                modified: metadata.modified().ok(),
                len: metadata.len(),
                #[cfg(unix)]
                device: metadata.dev(),
                #[cfg(unix)]
                inode: metadata.ino(),
            }
        })
        .unwrap_or(FileStamp::Missing)
}

#[cfg(test)]
#[path = "keymap_tests.rs"]
mod tests;
