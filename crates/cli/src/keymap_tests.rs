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
