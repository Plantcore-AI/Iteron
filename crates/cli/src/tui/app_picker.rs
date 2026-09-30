use super::{App, ApprovalInput, PickerEvent};
use crossterm::event::{KeyCode, KeyModifiers};
use std::path::Path;

impl App {
    /// Route a keypress to the open picker. Returns None if no picker is open (fall through to normal
    /// key handling). The picker OWNS the keyboard while open — no fall-through to editor/history/
    /// Shift+Tab (C6). Take-then-apply on accept (C5); theme live-preview on nav + Esc-restore (C1).
    #[cfg(test)]
    pub(super) fn picker_key(&mut self, code: KeyCode) -> Option<PickerEvent> {
        self.picker_key_with_modifiers(code, KeyModifiers::NONE)
    }

    pub(super) fn picker_key_with_modifiers(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
    ) -> Option<PickerEvent> {
        let update = self.pickers.key(code, modifiers)?;
        if let Some(theme) = update.theme {
            self.set_theme(theme);
        }
        Some(update.event)
    }
    pub(super) fn picker_paste(&mut self, pasted: &str) -> bool {
        self.pickers.paste(pasted)
    }
    pub(super) fn close_picker_restore_theme(&mut self) {
        if let Some(theme) = self.pickers.close() {
            self.set_theme(theme);
        }
    }

    pub(super) fn approval_key(&mut self, code: KeyCode) -> ApprovalInput {
        self.permission_prompt.key(code)
    }

    /// Legacy terminals encode Alt+key as `ESC` followed by the key bytes. When an automation (or
    /// a fast typist) starts the next command immediately after dismissing a picker, crossterm can
    /// therefore surface `Esc` + `/` as one `Alt+/` event. A picker otherwise consumes every
    /// printable key, so the slash and the rest of the command would disappear into the modal.
    ///
    /// Printable Alt keys have no picker binding, so while a picker owns the keyboard we can safely
    /// recover this ambiguous sequence as "cancel, then type". Terminals with disambiguated key
    /// reporting continue to send an ordinary `Esc` and never enter this compatibility path.
    pub(super) fn recover_picker_escape_prefixed_char(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        _repo: &Path,
    ) -> bool {
        if !self.pickers.is_open()
            || !modifiers.contains(KeyModifiers::ALT)
            || modifiers.contains(KeyModifiers::CONTROL)
        {
            return false;
        }
        let KeyCode::Char(ch) = code else {
            return false;
        };
        if ch.is_control() {
            return false;
        }

        // Route the synthetic cancellation through picker_key so theme live-preview restoration
        // remains identical to a separately reported Esc.
        self.close_picker_restore_theme();
        self.editor.insert(ch);
        self.schedule_completion();
        true
    }

    /// Recover legacy `Esc` + printable input while a standard-mode run is active.
    ///
    /// Without keyboard disambiguation those two physical keys arrive as one Alt+char event, so
    /// waiting for an `Esc` event first can never work. Unbound Alt+char has no meaning in the
    /// standard composer; in this live-run context it therefore means "interrupt, then type".
    /// Registered operator bindings and Alt-B/Alt-F word movement keep their normal meaning.
    pub(super) fn recover_running_escape_prefixed_char(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        _repo: &Path,
        standard_mode: bool,
        unbound: bool,
    ) -> bool {
        if !standard_mode
            || !unbound
            || !self.running
            || self.interrupting
            || self.permission_prompt.read().is_some()
            || self.pickers.is_open()
            || !modifiers.contains(KeyModifiers::ALT)
            || modifiers.contains(KeyModifiers::CONTROL)
        {
            return false;
        }
        let KeyCode::Char(ch) = code else {
            return false;
        };
        if ch.is_control() {
            return false;
        }
        if matches!(ch.to_ascii_lowercase(), 'b' | 'f') {
            return false;
        }
        self.interrupting = true;
        self.editor.insert(ch);
        self.schedule_completion();
        true
    }
}
