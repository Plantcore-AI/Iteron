use super::*;

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
        self.picker.as_ref()?;
        // Esc first clears an active filter. A second Esc closes and restores a live-preview theme.
        if code == KeyCode::Esc {
            if self.picker.as_ref().is_some_and(Picker::has_query) {
                let pk = self.picker.as_mut()?;
                pk.query.clear();
                let visible = pk.visible_indices();
                pk.normalize_selection(&visible);
            } else {
                self.close_picker_restore_theme();
                return Some(PickerEvent::Cancel);
            }
        } else if code == KeyCode::Backspace {
            let pk = self.picker.as_mut()?;
            pk.query.pop();
            let visible = pk.visible_indices();
            pk.normalize_selection(&visible);
        } else if let KeyCode::Char(ch) = code
            && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && !is_unsafe_display_char(ch)
        {
            let pk = self.picker.as_mut()?;
            let mut encoded = [0; 4];
            pk.append_query_text(ch.encode_utf8(&mut encoded));
            let visible = pk.visible_indices();
            pk.normalize_selection(&visible);
        }

        let visible = self.picker.as_ref()?.visible_indices();
        if visible.is_empty() {
            return Some(PickerEvent::Consumed);
        }

        // A catalog refresh or ancestor collapse may invalidate the old selection. Normalize before
        // handling Enter so a hidden child can never be accepted accidentally.
        self.picker.as_mut()?.normalize_selection(&visible);

        let pos = self.picker.as_ref()?.visible_selection(&visible);
        match code {
            KeyCode::Up => {
                let next = (pos + visible.len() - 1) % visible.len();
                self.picker.as_mut()?.sel = visible[next];
            }
            KeyCode::Down => {
                let next = (pos + 1) % visible.len();
                self.picker.as_mut()?.sel = visible[next];
            }
            KeyCode::PageUp => {
                self.picker.as_mut()?.sel = visible[pos.saturating_sub(8)];
            }
            KeyCode::PageDown => {
                self.picker.as_mut()?.sel = visible[(pos + 8).min(visible.len() - 1)];
            }
            KeyCode::Home => self.picker.as_mut()?.sel = visible[0],
            KeyCode::End => self.picker.as_mut()?.sel = *visible.last()?,
            KeyCode::Right => {
                let pk = self.picker.as_mut()?;
                if let Some(item) = pk.items.get_mut(pk.sel)
                    && item.expandable
                {
                    item.expanded = true;
                }
            }
            KeyCode::Left => {
                let pk = self.picker.as_mut()?;
                let Some(item) = pk.items.get(pk.sel) else {
                    return Some(PickerEvent::Consumed);
                };
                let (expandable, expanded, parent) = (item.expandable, item.expanded, item.parent);
                if expandable && expanded {
                    if let Some(item) = pk.items.get_mut(pk.sel) {
                        item.expanded = false;
                    }
                } else if let Some(parent) = parent
                    && visible.contains(&parent)
                {
                    pk.sel = parent;
                }
            }
            KeyCode::Enter | KeyCode::Tab => {
                let pk = self.picker.as_mut()?;
                let Some(item) = pk.items.get_mut(pk.sel) else {
                    return Some(PickerEvent::Consumed);
                };
                if item.expandable {
                    item.expanded = true;
                    return Some(PickerEvent::Consumed);
                }
                if !item.enabled {
                    return Some(PickerEvent::Consumed);
                }
                let action = item.action.clone();
                self.picker = None; // borrow dropped before apply (C5)
                return Some(PickerEvent::Accept(action));
            }
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Char(_) => {}
            _ => return Some(PickerEvent::Consumed),
        }
        // theme live-preview: apply the newly-selected theme (extract, then assign — no borrow clash)
        let preview = self.picker.as_ref().and_then(|pk| {
            if pk.saved_theme.is_some() {
                match pk.items.get(pk.sel).map(|i| &i.action) {
                    Some(PickAction::SetTheme(t)) => Some(t.clone()),
                    _ => None,
                }
            } else {
                None
            }
        });
        if let Some(t) = preview {
            self.set_theme(t);
        }
        Some(PickerEvent::Consumed)
    }

    /// Bracketed paste belongs to an open picker just like keypresses do. Returning `false` means
    /// no picker was open; returning `true` means the event was fully consumed and must never reach
    /// the composer or image-attachment parser.
    pub(super) fn picker_paste(&mut self, pasted: &str) -> bool {
        let Some(picker) = self.picker.as_mut() else {
            return false;
        };
        picker.append_query_text(pasted);
        let visible = picker.visible_indices();
        picker.normalize_selection(&visible);
        true
    }

    pub(super) fn close_picker_restore_theme(&mut self) {
        if let Some(pk) = self.picker.take()
            && let Some(theme) = pk.saved_theme
        {
            self.set_theme(theme);
        }
    }

    /// Route one physical key through the blocking permission control. Navigation only changes
    /// focus; Enter emits exactly one answer for that focus. Direct y/a/n shortcuts remain
    /// available, but an impossible session-wide grant is never constructed.
    pub(super) fn approval_key(&mut self, code: KeyCode) -> ApprovalInput {
        let Some(pending) = self.pending.as_ref() else {
            return ApprovalInput::Consumed;
        };
        let choices: &[ApprovalChoice] = if capability_can_be_remembered(pending.cap) {
            &[
                ApprovalChoice::Once,
                ApprovalChoice::Session,
                ApprovalChoice::Deny,
            ]
        } else {
            &[ApprovalChoice::Once, ApprovalChoice::Deny]
        };
        if !choices.contains(&self.approval_choice) {
            self.approval_choice = ApprovalChoice::Deny;
        }
        let position = choices
            .iter()
            .position(|choice| *choice == self.approval_choice)
            .unwrap_or(choices.len() - 1);
        match code {
            KeyCode::Left | KeyCode::Up | KeyCode::BackTab => {
                self.approval_choice = choices[(position + choices.len() - 1) % choices.len()];
                ApprovalInput::Consumed
            }
            KeyCode::Right | KeyCode::Down | KeyCode::Tab => {
                self.approval_choice = choices[(position + 1) % choices.len()];
                ApprovalInput::Consumed
            }
            KeyCode::Enter => match self.approval_choice {
                ApprovalChoice::Once => ApprovalInput::Answer {
                    approved: true,
                    remember: false,
                },
                ApprovalChoice::Session if capability_can_be_remembered(pending.cap) => {
                    ApprovalInput::Answer {
                        approved: true,
                        remember: true,
                    }
                }
                ApprovalChoice::Session | ApprovalChoice::Deny => ApprovalInput::Answer {
                    approved: false,
                    remember: false,
                },
            },
            KeyCode::Char('y') | KeyCode::Char('Y') => ApprovalInput::Answer {
                approved: true,
                remember: false,
            },
            KeyCode::Char('a') | KeyCode::Char('A')
                if capability_can_be_remembered(pending.cap) =>
            {
                ApprovalInput::Answer {
                    approved: true,
                    remember: true,
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ApprovalInput::Answer {
                approved: false,
                remember: false,
            },
            _ => ApprovalInput::Consumed,
        }
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
        repo: &Path,
    ) -> bool {
        if self.picker.is_none()
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
        self.refresh_completion(repo);
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
        repo: &Path,
        standard_mode: bool,
        unbound: bool,
    ) -> bool {
        if !standard_mode
            || !unbound
            || !self.running
            || self.interrupting
            || self.pending.is_some()
            || self.picker.is_some()
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
        self.refresh_completion(repo);
        true
    }
}
