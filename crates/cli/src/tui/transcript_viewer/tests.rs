use super::render::{layout_rows, visible_rows};
use super::*;

fn user(id: u64, text: &str) -> Arc<block::Block> {
    Arc::new(block::Block::new(id, block::BlockKind::User(text.into())))
}

#[test]
fn index_reconciles_revisions_and_eviction_and_searches_unicode() {
    let mut viewer = Viewer::default();
    let mut blocks = vec![user(1, "alpha 你好"), user(2, "beta 😀")];
    viewer.open("你好", &blocks, 1);
    assert_eq!(viewer.results, vec![1]);
    assert_eq!(viewer.selected_id, Some(1));

    let changed = Arc::make_mut(&mut blocks[0]);
    changed.kind = block::BlockKind::User("changed 東京".into());
    changed.touch();
    blocks.remove(1);
    blocks.push(user(3, "emoji 😀 result"));
    viewer.sync_if_changed(&blocks, 2);
    assert!(viewer.entries.iter().all(|entry| entry.id != 2));
    viewer.query = "😀".into();
    viewer.query_revision = viewer.query_revision.wrapping_add(1);
    viewer.refresh_results_if_changed();
    assert_eq!(viewer.results, vec![3]);
    viewer.query = "東京".into();
    viewer.query_revision = viewer.query_revision.wrapping_add(1);
    viewer.refresh_results_if_changed();
    assert_eq!(viewer.results, vec![1]);
}

#[test]
fn navigation_raw_copy_and_filters_are_deterministic_and_bounded() {
    let blocks = vec![user(1, "first"), user(2, "second needle")];
    let mut viewer = Viewer::default();
    viewer.open("needle", &blocks, 1);
    assert_eq!(viewer.export_ids(ExportScope::Filtered), Ok(Some(vec![2])));
    viewer.editing_query = false;
    viewer.key(KeyCode::Char('r'), KeyModifiers::NONE, &blocks);
    let copied = viewer.key(KeyCode::Char('y'), KeyModifiers::NONE, &blocks);
    assert!(matches!(
        copied,
        Some(Effect::Copy { text, subject: "selected block" }) if text == "second needle"
    ));
    viewer.key(KeyCode::Char('n'), KeyModifiers::NONE, &blocks);
    assert_eq!(viewer.selected_id, Some(2));
}

#[test]
fn query_and_detail_escape_controls_and_limit_state() {
    let secret = format!("sk-{}", "b".repeat(48));
    let blocks = vec![user(1, &format!("{secret}\u{1b}]52;bad\u{7}"))];
    let mut viewer = Viewer::default();
    viewer.open("\u{1b}abc\n😀", &blocks, 1);
    assert_eq!(viewer.query, "abc😀");
    let detail = viewer.detail.as_ref().unwrap();
    assert!(!detail.text.contains(&secret));
    assert!(!detail.text.contains('\u{1b}'));
    assert!(viewer.entries[0].complete);
    assert!(viewer.entries[0].folded.len() <= MAX_INDEX_BLOCK_BYTES);
}

#[test]
fn viewport_materializes_only_visible_rows_and_reflows_cjk_on_resize() {
    let text = (0..200)
        .map(|index| format!("row-{index} 你好 😀"))
        .collect::<Vec<_>>()
        .join("\n");
    let narrow_layout = layout_rows(&text, 8);
    let wide_layout = layout_rows(&text, 40);
    let narrow = visible_rows(&text, &narrow_layout, 8, 40, 7);
    let wide = visible_rows(&text, &wide_layout, 40, 40, 7);
    assert_eq!(narrow.len(), 7);
    assert_eq!(wide.len(), 7);
    assert!(narrow_layout.len() > wide_layout.len());
    assert!(
        narrow
            .iter()
            .all(|line| crate::render::line_width(line) <= 8)
    );
    assert!(
        wide.iter()
            .all(|line| crate::render::line_width(line) <= 40)
    );
}

#[test]
fn search_matches_beyond_the_old_prefix_and_surfaces_any_unindexed_block() {
    let mut long = "x".repeat(8 * 1024);
    long.push_str(" late-needle");
    let blocks = vec![user(1, &long)];
    let mut viewer = Viewer::default();
    viewer.open("late-needle", &blocks, 1);
    assert_eq!(viewer.results, vec![1]);
    assert_eq!(viewer.incomplete_entries, 0);
    viewer.editing_query = false;
    assert!(matches!(
        viewer.key(
            KeyCode::Char('Y'),
            KeyModifiers::SHIFT,
            &blocks
        ),
        Some(Effect::Copy {
            text,
            subject: "matching block projection"
        }) if text.len() > 1536 && text.contains("late-needle")
    ));

    let oversized = vec![user(2, &"z".repeat(MAX_INDEX_BLOCK_BYTES + 1))];
    viewer.open("z", &oversized, 2);
    assert!(viewer.results.is_empty());
    assert_eq!(viewer.incomplete_entries, 1);
    assert!(!viewer.entries[0].complete);
    assert!(viewer.entries[0].folded.is_empty());
    assert!(viewer.export_ids(ExportScope::Filtered).is_err());
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 10)).unwrap();
    terminal
        .draw(|frame| super::render(frame, &mut viewer, &crate::theme::Theme::dark()))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let screen = (0..buffer.area.height)
        .flat_map(|y| (0..buffer.area.width).map(move |x| buffer[(x, y)].symbol()))
        .collect::<String>();
    assert!(screen.contains("search incomplete 1 blocks"));
    assert!(screen.contains("search-unindexed"));
}

#[test]
fn changed_live_blocks_reindex_only_after_an_authority_revision() {
    let mut blocks = vec![Arc::new(block::Block::new(
        9,
        block::BlockKind::Tool(block::ToolCard {
            name: "bash".into(),
            args: serde_json::Value::Null,
            status: block::ToolStatus::Running,
            output: "before".into(),
            diff: None,
            exit_code: None,
            started: std::time::Instant::now(),
            elapsed: None,
            open: true,
        }),
    ))];
    let mut viewer = Viewer::default();
    viewer.open("after", &blocks, 1);
    assert!(viewer.results.is_empty());
    let block = Arc::make_mut(&mut blocks[0]);
    let block::BlockKind::Tool(card) = &mut block.kind else {
        unreachable!()
    };
    card.output = "after".into();
    block.touch();
    viewer.sync_if_changed(&blocks, 2);
    assert_eq!(viewer.results, vec![9]);
}

#[test]
fn row_cache_handles_combining_wide_tiny_and_zero_surfaces() {
    let text = "e\u{301}写😀👨‍👩‍👧‍👦\nnext";
    for width in [1, 2, 4] {
        let layout = layout_rows(text, width);
        let rows = visible_rows(text, &layout, width, 0, 20);
        assert!(
            rows.iter()
                .all(
                    |line| unicode_width::UnicodeWidthStr::width(line.to_string().as_str())
                        <= width as usize
                )
        );
    }
    assert!(layout_rows(text, 0).is_empty());
    assert!(visible_rows(text, &[], 0, 0, 0).is_empty());
    let family = visible_rows("👨‍👩‍👧‍👦", &layout_rows("👨‍👩‍👧‍👦", 1), 1, 0, 1);
    assert_eq!(
        family[0].to_string(),
        "?",
        "a grapheme is never split across rows"
    );

    let blocks = vec![user(1, text)];
    let mut viewer = Viewer::default();
    viewer.open("", &blocks, 1);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(1, 1)).unwrap();
    terminal
        .draw(|frame| super::render(frame, &mut viewer, &crate::theme::Theme::dark()))
        .unwrap();

    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(20, 8)).unwrap();
    terminal
        .draw(|frame| super::render(frame, &mut viewer, &crate::theme::Theme::dark()))
        .unwrap();
    let cached = viewer.detail.as_ref().unwrap().row_ranges.as_ptr();
    terminal
        .draw(|frame| super::render(frame, &mut viewer, &crate::theme::Theme::dark()))
        .unwrap();
    assert_eq!(
        viewer.detail.as_ref().unwrap().row_ranges.as_ptr(),
        cached,
        "steady frames reuse cached row starts instead of rescanning detail"
    );
}

#[test]
fn result_count_and_query_bytes_are_hard_bounded() {
    let blocks = (0..(MAX_RESULTS + 20))
        .map(|id| user(id as u64, "same"))
        .collect::<Vec<_>>();
    let mut viewer = Viewer::default();
    viewer.open(&"x".repeat(MAX_QUERY_BYTES * 2), &blocks, 1);
    assert!(viewer.query.len() <= MAX_QUERY_BYTES);
    viewer.query = "same".into();
    viewer.query_revision = viewer.query_revision.wrapping_add(1);
    viewer.refresh_results_if_changed();
    assert_eq!(viewer.results.len(), MAX_RESULTS);
    assert!(viewer.results_truncated);
    assert!(viewer.export_ids(ExportScope::Filtered).is_err());
}

#[test]
fn one_hundred_stable_frames_do_zero_index_result_or_detail_rebuilds() {
    let blocks = vec![user(1, &"stable 你好 ".repeat(2_000))];
    let mut viewer = Viewer::default();
    viewer.open("stable", &blocks, 7);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 12)).unwrap();
    terminal
        .draw(|frame| super::render(frame, &mut viewer, &crate::theme::Theme::dark()))
        .unwrap();
    let before = viewer.work;

    for _ in 0..100 {
        viewer.sync_if_changed(&blocks, 7);
        terminal
            .draw(|frame| super::render(frame, &mut viewer, &crate::theme::Theme::dark()))
            .unwrap();
    }

    assert_eq!(viewer.work, before);
}

#[test]
fn one_changed_block_projects_once_while_unchanged_entries_are_reused() {
    let mut blocks = (0..100)
        .map(|id| user(id, &format!("stable-{id}")))
        .collect::<Vec<_>>();
    let mut viewer = Viewer::default();
    viewer.open("stable", &blocks, 1);
    let before = viewer.work;
    let changed = Arc::make_mut(&mut blocks[42]);
    changed.kind = block::BlockKind::User("changed needle".into());
    changed.touch();

    viewer.sync_if_changed(&blocks, 2);

    assert_eq!(viewer.work.index_syncs, before.index_syncs + 1);
    assert_eq!(
        viewer.work.index_projections,
        before.index_projections + 1,
        "only the changed revision may be scrubbed and folded"
    );
    assert_eq!(viewer.work.result_rebuilds, before.result_rebuilds + 1);
}

#[test]
fn unrelated_live_revision_does_not_rescrub_an_unchanged_oversized_entry() {
    let mut blocks = vec![
        user(1, &"x".repeat(MAX_INDEX_BLOCK_BYTES + 1)),
        user(2, "live-before"),
    ];
    let mut viewer = Viewer::default();
    viewer.open("live", &blocks, 1);
    assert_eq!(viewer.incomplete_entries, 1);
    let before = viewer.work;
    let live = Arc::make_mut(&mut blocks[1]);
    live.kind = block::BlockKind::User("live-after".into());
    live.touch();

    viewer.sync_if_changed(&blocks, 2);

    assert_eq!(viewer.incomplete_entries, 1);
    assert_eq!(
        viewer.work.index_projections,
        before.index_projections + 1,
        "the unchanged 2 MiB+ incomplete block must be reused"
    );
}

#[test]
fn pending_effect_state_is_visible_and_clears_on_completion() {
    let blocks = vec![user(1, "effect fixture")];
    let mut viewer = Viewer::default();
    viewer.open("", &blocks, 1);
    viewer.begin_effect("export");
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 10)).unwrap();
    terminal
        .draw(|frame| super::render(frame, &mut viewer, &crate::theme::Theme::dark()))
        .unwrap();
    let screen = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(screen.contains("export pending"));
    viewer.finish_effect("exported");
    assert_eq!(viewer.pending_effect, None);
}

#[test]
fn canonically_equivalent_unicode_queries_match_the_same_block() {
    let blocks = vec![user(1, "caf\u{e9}"), user(2, "Cafe\u{301}")];
    let mut viewer = Viewer::default();
    viewer.open("CAFE\u{301}", &blocks, 1);
    assert_eq!(viewer.results, vec![1, 2]);
}

#[test]
fn filtered_and_all_export_share_the_same_semantic_snapshot_builder() {
    let blocks = vec![user(1, "first"), user(2, "second needle")];
    let all =
        String::from_utf8(crate::tui::transcript_export_body(&blocks, None).unwrap()).unwrap();
    let filtered =
        String::from_utf8(crate::tui::transcript_export_body(&blocks, Some(&[2])).unwrap())
            .unwrap();
    assert!(all.contains("first") && all.contains("second needle"));
    assert!(!filtered.contains("first"));
    assert!(filtered.contains("second needle"));
    assert!(all.starts_with("# Core Code transcript\n\n"));
    assert!(filtered.starts_with("# Core Code transcript\n\n"));
}
