use super::*;

#[test]
fn custom_bindings_are_typed_unique_and_cannot_steal_lifecycle_keys() {
    let mut config = Config::default();
    config
        .bindings
        .insert("external_editor".into(), "alt+e".into());
    let map = Keymap::from_config(Some(&config)).unwrap();
    assert_eq!(
        map.action_for(KeyCode::Char('e'), KeyModifiers::ALT),
        Some(Action::ExternalEditor)
    );
    assert!(map.is_custom());
    assert_eq!(
        Keymap::default().action_for(
            KeyCode::Char('R'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT
        ),
        Some(Action::ReverseSearch),
        "Ctrl-Shift-R keeps the explicit empty-query search route"
    );
    assert_eq!(
        Keymap::default().action_for(KeyCode::Char('f'), KeyModifiers::CONTROL),
        Some(Action::TranscriptViewer),
        "the fullscreen transcript remains keyboard reachable"
    );

    config
        .bindings
        .insert("external_editor".into(), "ctrl+c".into());
    assert!(
        Keymap::from_config(Some(&config))
            .unwrap_err()
            .contains("reserved")
    );

    config
        .bindings
        .insert("external_editor".into(), "ctrl+r".into());
    assert!(
        Keymap::from_config(Some(&config))
            .unwrap_err()
            .contains("conflicts")
    );
}

#[test]
fn vim_insert_normal_and_double_delete_are_deterministic() {
    let mut vim = Vim::default();
    assert_eq!(
        vim.route(true, KeyCode::Esc, KeyModifiers::NONE),
        Some(VimAction::EnterNormal)
    );
    assert_eq!(vim.state(), VimState::Normal);
    assert_eq!(
        vim.route(true, KeyCode::Char('d'), KeyModifiers::NONE),
        Some(VimAction::Consumed)
    );
    assert_eq!(
        vim.route(true, KeyCode::Char('d'), KeyModifiers::NONE),
        Some(VimAction::Clear)
    );
    assert_eq!(
        vim.route(true, KeyCode::Char('a'), KeyModifiers::NONE),
        Some(VimAction::AppendInsert)
    );
    assert_eq!(vim.state(), VimState::Insert);
    assert_eq!(
        vim.route(true, KeyCode::Char('x'), KeyModifiers::NONE),
        None
    );

    assert_eq!(
        vim.route(true, KeyCode::Esc, KeyModifiers::NONE),
        Some(VimAction::EnterNormal)
    );
    assert_eq!(
        vim.route(true, KeyCode::Char('A'), KeyModifiers::SHIFT),
        Some(VimAction::AppendEndInsert)
    );

    vim.reset();
    assert_eq!(
        vim.route(true, KeyCode::Char('0'), KeyModifiers::ALT),
        Some(VimAction::Home)
    );
    assert_eq!(vim.state(), VimState::Normal);
}

#[test]
fn backtab_is_reserved_in_both_terminal_spellings() {
    for chord in ["shift+tab", "backtab"] {
        let mut config = Config::default();
        config
            .bindings
            .insert("external_editor".into(), chord.into());
        assert!(
            Keymap::from_config(Some(&config))
                .unwrap_err()
                .contains("reserved")
        );
    }
}

#[test]
fn watcher_reports_only_real_file_stamp_changes() {
    let path = std::env::temp_dir().join(format!(
        "core-keymap-watch-{}-{:?}.json",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    let mut watcher = Watcher::new(Some(path.clone()));
    assert!(!watcher.changed());
    std::fs::write(&path, b"{}").unwrap();
    assert!(watcher.changed());
    assert!(!watcher.changed());
    std::fs::write(&path, b"{\n}").unwrap();
    assert!(watcher.changed());
    let _ = std::fs::remove_file(path);
}

/// Visual mode, pinned as a state machine rather than through the frontend.
///
/// The vocabulary is closed on purpose: adding `VimState::Visual` and the five selection actions
/// made `tui.rs` fail to compile in two places until both were handled. That is the property worth
/// keeping — a future motion cannot be added and silently ignored by the renderer.
#[test]
fn visual_mode_anchors_extends_and_leaves_without_ever_replacing_the_selection() {
    let mut vim = Vim::default();
    // Reach normal mode the way the operator does.
    assert_eq!(
        vim.route(true, KeyCode::Esc, KeyModifiers::NONE),
        Some(VimAction::EnterNormal)
    );

    assert_eq!(
        vim.route(true, KeyCode::Char('v'), KeyModifiers::NONE),
        Some(VimAction::EnterVisual)
    );
    assert_eq!(vim.state(), VimState::Visual);

    for (key, motion) in [
        ('h', VimMotion::Left),
        ('l', VimMotion::Right),
        ('0', VimMotion::Home),
        ('$', VimMotion::End),
        ('b', VimMotion::WordLeft),
        ('w', VimMotion::WordRight),
    ] {
        assert_eq!(
            vim.route(true, KeyCode::Char(key), KeyModifiers::NONE),
            Some(VimAction::ExtendSelection(motion)),
            "`{key}` must extend the selection, not move the cursor"
        );
        assert_eq!(
            vim.state(),
            VimState::Visual,
            "a motion must not end the selection"
        );
    }

    // A stray printable key is swallowed. This is the one visual-mode mistake that destroys text
    // silently, so it is pinned rather than left to the frontend.
    assert_eq!(
        vim.route(true, KeyCode::Char('q'), KeyModifiers::NONE),
        Some(VimAction::Consumed)
    );
    assert_eq!(vim.state(), VimState::Visual);

    assert_eq!(
        vim.route(true, KeyCode::Esc, KeyModifiers::NONE),
        Some(VimAction::LeaveVisual)
    );
    assert_eq!(
        vim.state(),
        VimState::Normal,
        "esc returns to normal, not to insert"
    );
}

#[test]
fn a_visual_selection_ends_on_delete_yank_or_a_second_v() {
    for (key, expected) in [
        ('d', VimAction::DeleteSelection),
        ('x', VimAction::DeleteSelection),
        ('y', VimAction::YankSelection),
        ('v', VimAction::LeaveVisual),
    ] {
        let mut vim = Vim::default();
        vim.route(true, KeyCode::Esc, KeyModifiers::NONE);
        vim.route(true, KeyCode::Char('v'), KeyModifiers::NONE);
        assert_eq!(
            vim.route(true, KeyCode::Char(key), KeyModifiers::NONE),
            Some(expected),
            "`{key}` in visual mode"
        );
        assert_eq!(
            vim.state(),
            VimState::Normal,
            "`{key}` must return to normal so the next motion moves the cursor again"
        );
    }
}

#[test]
fn normal_mode_keeps_its_own_meaning_for_the_keys_visual_mode_reuses() {
    // `d` is the start of `dd` in normal mode and a selection delete in visual mode. If the two
    // ever shared a state, one of them would be wrong.
    let mut vim = Vim::default();
    vim.route(true, KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(
        vim.route(true, KeyCode::Char('d'), KeyModifiers::NONE),
        Some(VimAction::Consumed),
        "a lone `d` in normal mode is pending, not a delete"
    );
    assert_eq!(
        vim.route(true, KeyCode::Char('d'), KeyModifiers::NONE),
        Some(VimAction::Clear)
    );
    assert_eq!(
        vim.route(true, KeyCode::Char('x'), KeyModifiers::NONE),
        Some(VimAction::Delete),
        "`x` in normal mode deletes one character, not a selection"
    );
}

#[test]
fn leaving_vim_mode_entirely_drops_a_live_selection() {
    let mut vim = Vim::default();
    vim.route(true, KeyCode::Esc, KeyModifiers::NONE);
    vim.route(true, KeyCode::Char('v'), KeyModifiers::NONE);
    assert_eq!(vim.state(), VimState::Visual);
    // `enabled = false` is the operator turning vim mode off mid-selection.
    assert_eq!(
        vim.route(false, KeyCode::Char('l'), KeyModifiers::NONE),
        None
    );
    assert_eq!(
        vim.state(),
        VimState::Insert,
        "a disabled keymap must not leave a selection anchored behind it"
    );
}
