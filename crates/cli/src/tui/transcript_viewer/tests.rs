use super::render::{layout_rows, visible_rows};
use super::*;

fn user(id: u64, text: &str) -> Arc<block::Block> {
    Arc::new(block::Block::new(id, block::BlockKind::User(text.into())))
}

fn settle(viewer: &mut Viewer, blocks: &[Arc<block::Block>], revision: u64) {
    // A hang guard, not a performance budget: it exists so a viewer that never drains fails as a
    // test rather than hanging the suite. Ten seconds was not a guard, it was a coin flip --
    // `global_index_budget_stops_projecting_older_block_bytes` needs 8.6s on an M-series Mac and
    // over 10s on Linux/aarch64, where it failed deterministically on the required
    // `rust / ubuntu-24.04` lane while passing locally. Sixty seconds is far above any real settle
    // time on hardware this suite runs on, and still bounded.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while viewer.background_work_pending() {
        viewer.sync_if_changed(blocks, revision);
        if viewer.projection_worker.is_busy() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bounded viewer work did not settle before its test deadline"
        );
    }
}

fn replace_query(viewer: &mut Viewer, blocks: &[Arc<block::Block>], revision: u64, query: &str) {
    viewer.query = query.into();
    viewer.query_revision = viewer.query_revision.wrapping_add(1);
    viewer.query_changed();
    settle(viewer, blocks, revision);
}

#[test]
fn index_reconciles_revisions_and_eviction_and_searches_unicode() {
    let mut viewer = Viewer::default();
    let mut blocks = vec![user(1, "alpha 你好"), user(2, "beta 😀")];
    viewer.open("你好", &blocks, 1);
    settle(&mut viewer, &blocks, 1);
    assert_eq!(viewer.results, vec![1]);
    assert_eq!(viewer.selected_id, Some(1));

    let changed = Arc::make_mut(&mut blocks[0]);
    changed.kind = block::BlockKind::User("changed 東京".into());
    changed.touch();
    blocks.remove(1);
    blocks.push(user(3, "emoji 😀 result"));
    viewer.sync_if_changed(&blocks, 2);
    settle(&mut viewer, &blocks, 2);
    assert!(viewer.entries.iter().all(|entry| entry.id != 2));
    replace_query(&mut viewer, &blocks, 2, "😀");
    assert_eq!(viewer.results, vec![3]);
    replace_query(&mut viewer, &blocks, 2, "東京");
    assert_eq!(viewer.results, vec![1]);
}

#[test]
fn navigation_raw_copy_and_filters_are_deterministic_and_bounded() {
    let blocks = vec![user(1, "first"), user(2, "second needle")];
    let mut viewer = Viewer::default();
    viewer.open("needle", &blocks, 1);
    settle(&mut viewer, &blocks, 1);
    assert_eq!(
        viewer.export_ids(ExportScope::Filtered, 1),
        Ok(Some(vec![2]))
    );
    viewer.editing_query = false;
    viewer.key(KeyCode::Char('r'), KeyModifiers::NONE, &blocks, 1);
    settle(&mut viewer, &blocks, 1);
    let copied = viewer.key(KeyCode::Char('y'), KeyModifiers::NONE, &blocks, 1);
    assert!(matches!(
        copied,
        Some(Effect::Copy {
            text,
            subject: "selected block",
            snapshot_revision: 1,
        }) if text == "second needle"
    ));
    viewer.key(KeyCode::Char('n'), KeyModifiers::NONE, &blocks, 1);
    assert_eq!(viewer.selected_id, Some(2));
}

#[test]
fn detail_and_matching_copy_projection_never_run_in_the_key_handler() {
    let blocks = vec![user(1, &format!("{} needle", "x".repeat(512 * 1024)))];
    let mut viewer = Viewer::default();
    viewer.open("needle", &blocks, 11);
    settle(&mut viewer, &blocks, 11);
    viewer.editing_query = false;
    viewer.detail = None;
    let before = viewer.work.detail_rebuilds;

    assert!(
        viewer
            .key(KeyCode::Char('Y'), KeyModifiers::SHIFT, &blocks, 11)
            .is_none(),
        "a cache miss queues an off-thread copy projection"
    );
    assert_eq!(viewer.work.detail_rebuilds, before);
    assert!(viewer.desired_detail.is_some());
    assert!(!viewer.projection_worker.is_busy());

    viewer.sync_if_changed(&blocks, 11);
    assert!(viewer.projection_worker.is_busy());
    settle(&mut viewer, &blocks, 11);
    assert!(matches!(
        viewer.take_ready_effect(),
        Some(Effect::Copy {
            text,
            subject: "matching block projection",
            snapshot_revision: 11,
        }) if text.contains("detail truncated at 64 KiB") && text.len() <= MAX_DETAIL_BYTES
    ));
}

#[test]
fn projection_worker_close_owns_cancellation_and_joins_its_thread() {
    let mut worker = ProjectionWorker::default();
    worker
        .start_detail(
            DetailKey {
                authority_revision: 1,
                id: 1,
                revision: 0,
                raw: false,
            },
            user(1, &"x".repeat(MAX_INDEX_BLOCK_BYTES)),
        )
        .expect("start bounded detail projection");
    assert!(worker.is_busy());
    assert!(worker.owns_join_handle());

    let started = std::time::Instant::now();
    worker.close();
    assert!(!worker.is_busy());
    assert!(!worker.owns_join_handle());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "cancelled byte-capped projection must join within its finite test envelope"
    );
}

#[test]
fn bounded_semantic_projection_matches_authoritative_text_below_its_cap() {
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let blocks = vec![
        block::Block::new(1, block::BlockKind::User("hello".into())),
        block::Block::new(
            2,
            block::BlockKind::Assistant(crate::markdown::MarkdownDoc::parse(
                "## Heading\n\n- **item**\n",
            )),
        ),
        block::Block::new(
            3,
            block::BlockKind::Tool(block::ToolCard {
                name: "bash".into(),
                args: serde_json::json!({"command": "printf hello"}),
                status: block::ToolStatus::Ok,
                output: "hello".into(),
                diff: None,
                exit_code: Some(0),
                started: std::time::Instant::now(),
                elapsed: None,
                open: true,
            }),
        ),
        block::Block::new(
            4,
            block::BlockKind::Error {
                title: "failed".into(),
                detail: "bounded detail".into(),
                open: true,
            },
        ),
        block::Block::new(
            5,
            block::BlockKind::Panel {
                title: "status".into(),
                rows: vec![block::PanelRow::KeyValue {
                    key: "mode".into(),
                    value: "safe".into(),
                }],
            },
        ),
    ];
    for block in blocks {
        let (projected, truncated) =
            super::semantic_text::block_text(&block, 64 * 1024, &cancelled)
                .expect("projection is not cancelled");
        assert!(!truncated);
        assert_eq!(projected, block.to_text());
    }
}

#[test]
fn query_and_detail_escape_controls_and_limit_state() {
    let secret = format!("sk-{}", "b".repeat(48));
    let blocks = vec![user(1, &format!("{secret}\u{1b}]52;bad\u{7}"))];
    let mut viewer = Viewer::default();
    viewer.open("\u{1b}abc\n😀", &blocks, 1);
    settle(&mut viewer, &blocks, 1);
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
    settle(&mut viewer, &blocks, 1);
    assert_eq!(viewer.results, vec![1]);
    assert_eq!(viewer.incomplete_entries, 0);
    viewer.editing_query = false;
    assert!(matches!(
        viewer.key(
            KeyCode::Char('Y'),
            KeyModifiers::SHIFT,
            &blocks,
            1,
        ),
        Some(Effect::Copy {
            text,
            subject: "matching block projection",
            snapshot_revision: 1,
        }) if text.len() > 1536 && text.contains("late-needle")
    ));

    let oversized = vec![user(2, &"z".repeat(MAX_INDEX_BLOCK_BYTES + 1))];
    viewer.open("z", &oversized, 2);
    settle(&mut viewer, &oversized, 2);
    assert!(viewer.results.is_empty());
    assert_eq!(viewer.incomplete_entries, 1);
    assert!(!viewer.entries[0].complete);
    assert!(viewer.entries[0].folded.is_empty());
    assert!(viewer.export_ids(ExportScope::Filtered, 2).is_err());
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
    settle(&mut viewer, &blocks, 1);
    assert!(viewer.results.is_empty());
    let block = Arc::make_mut(&mut blocks[0]);
    let block::BlockKind::Tool(card) = &mut block.kind else {
        unreachable!()
    };
    card.output = "after".into();
    block.touch();
    viewer.sync_if_changed(&blocks, 2);
    settle(&mut viewer, &blocks, 2);
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
    settle(&mut viewer, &blocks, 1);
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
    settle(&mut viewer, &blocks, 1);
    assert!(viewer.query.len() <= MAX_QUERY_BYTES);
    replace_query(&mut viewer, &blocks, 1, "same");
    assert_eq!(viewer.results.len(), MAX_RESULTS);
    assert!(viewer.results_truncated);
    assert!(viewer.export_ids(ExportScope::Filtered, 1).is_err());
}

#[test]
fn one_hundred_stable_frames_do_zero_index_result_or_detail_rebuilds() {
    let blocks = vec![user(1, &"stable 你好 ".repeat(2_000))];
    let mut viewer = Viewer::default();
    viewer.open("stable", &blocks, 7);
    settle(&mut viewer, &blocks, 7);
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
    settle(&mut viewer, &blocks, 1);
    let before = viewer.work;
    let changed = Arc::make_mut(&mut blocks[42]);
    changed.kind = block::BlockKind::User("changed needle".into());
    changed.touch();

    viewer.sync_if_changed(&blocks, 2);
    settle(&mut viewer, &blocks, 2);

    assert_eq!(viewer.work.index_syncs, before.index_syncs + 1);
    assert_eq!(
        viewer.work.index_projections,
        before.index_projections + 1,
        "only the changed revision may be scrubbed and folded"
    );
    assert_eq!(viewer.work.result_rebuilds, before.result_rebuilds + 1);
}

#[test]
fn key_reconciles_a_no_draw_authority_update_before_emitting_snapshot_ids() {
    let mut blocks = vec![user(1, "needle before draw"), user(2, "stable")];
    let mut viewer = Viewer::default();
    viewer.open("needle", &blocks, 41);
    settle(&mut viewer, &blocks, 41);
    viewer.editing_query = false;
    assert_eq!(viewer.results, vec![1]);

    let changed = Arc::make_mut(&mut blocks[0]);
    changed.kind = block::BlockKind::User("changed without a draw".into());
    changed.touch();
    let stale_attempt = viewer.key(KeyCode::Char('e'), KeyModifiers::NONE, &blocks, 42);
    assert!(
        stale_attempt.is_none(),
        "no effect may escape while revision 42 is indexing"
    );
    assert!(viewer.export_ids(ExportScope::Filtered, 42).is_err());
    settle(&mut viewer, &blocks, 42);
    let current_effect = viewer
        .key(KeyCode::Char('e'), KeyModifiers::NONE, &blocks, 42)
        .expect("current export key");

    assert!(matches!(
        current_effect,
        Effect::Export {
            scope: ExportScope::Filtered,
            snapshot_revision: 42,
        }
    ));
    assert_eq!(
        viewer.export_ids(ExportScope::Filtered, 42),
        Ok(Some(Vec::new())),
        "stale result id 1 must not be combined with the revision-42 Arc snapshot"
    );
    assert!(viewer.export_ids(ExportScope::Filtered, 41).is_err());
}

#[test]
fn global_index_budget_stops_projecting_older_block_bytes() {
    let payload = "x".repeat(1024 * 1024);
    let blocks = (0..24).map(|id| user(id, &payload)).collect::<Vec<_>>();
    let mut viewer = Viewer::default();

    viewer.open("x", &blocks, 1);
    settle(&mut viewer, &blocks, 1);

    assert!(viewer.work.index_projections < blocks.len());
    assert!(viewer.entries.iter().any(|entry| entry.needs_projection));
    assert_eq!(
        viewer.work.index_projections, 16,
        "only the newest prefix through the first 16 MiB admission failure is projected"
    );
}

#[test]
fn unrelated_live_revision_does_not_rescrub_an_unchanged_oversized_entry() {
    let mut blocks = vec![
        user(1, &"x".repeat(MAX_INDEX_BLOCK_BYTES + 1)),
        user(2, "live-before"),
    ];
    let mut viewer = Viewer::default();
    viewer.open("live", &blocks, 1);
    settle(&mut viewer, &blocks, 1);
    assert_eq!(viewer.incomplete_entries, 1);
    let before = viewer.work;
    let live = Arc::make_mut(&mut blocks[1]);
    live.kind = block::BlockKind::User("live-after".into());
    live.touch();

    viewer.sync_if_changed(&blocks, 2);
    settle(&mut viewer, &blocks, 2);

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
    settle(&mut viewer, &blocks, 1);
    assert_eq!(viewer.results, vec![1, 2]);
}

#[test]
fn indexing_has_a_deterministic_one_projection_tick_budget_and_keeps_input_live() {
    let blocks = (0..12)
        .map(|id| user(id, &format!("block-{id} {}", "x".repeat(32 * 1024))))
        .collect::<Vec<_>>();
    let mut viewer = Viewer::default();

    viewer.open("", &blocks, 7);
    assert_eq!(viewer.work.index_projections, 1);
    assert_eq!(viewer.work_progress(), Some(("indexing", 0, 12)));
    assert!(
        viewer.projection_worker.is_busy(),
        "the expensive block projection is owned by the sole background worker"
    );

    viewer.key(KeyCode::Char('/'), KeyModifiers::NONE, &blocks, 7);
    let after_search_key = viewer.work.index_projections;
    assert_eq!(
        after_search_key, 1,
        "a key turn must not advance the loop-owned projection budget"
    );
    viewer.key(KeyCode::Char('n'), KeyModifiers::NONE, &blocks, 7);
    assert_eq!(
        viewer.query, "n",
        "query input remains active while indexing"
    );
    assert_eq!(
        viewer.work.index_projections, after_search_key,
        "query input cannot trigger a second projection in the same loop turn"
    );

    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(90, 10)).unwrap();
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
    assert!(screen.contains("indexing 0/12"));
    assert!(screen.contains("search> n"));
    assert!(viewer.export_ids(ExportScope::All, 7).is_err());
}

#[test]
fn repeated_authority_cancellation_prunes_reuse_to_exact_retained_ids_and_revisions() {
    let mut viewer = Viewer {
        authority_revision: Some(1),
        entries: (0..MAX_INDEX_ENTRIES as u64)
            .map(|id| Entry {
                id,
                revision: 0,
                label: "user",
                folded: "retained-payload".repeat(64),
                complete: true,
                required_bytes: None,
                needs_projection: false,
            })
            .collect(),
        ..Viewer::default()
    };

    let authority_b = (600..1800).map(|id| user(id, "b")).collect::<Vec<_>>();
    assert!(viewer.reconcile_if_changed(&authority_b, 2));
    let reusable_b = &viewer.index_job.as_ref().unwrap().reusable;
    assert_eq!(reusable_b.len(), 600);
    assert!(reusable_b.keys().all(|id| (600..1200).contains(id)));

    let authority_c = (1100..1200)
        .chain(1800..2900)
        .map(|id| user(id, "c"))
        .collect::<Vec<_>>();
    assert!(viewer.reconcile_if_changed(&authority_c, 3));
    let reusable_c = &viewer.index_job.as_ref().unwrap().reusable;
    assert_eq!(reusable_c.len(), 100);
    assert!(reusable_c.keys().all(|id| (1100..1200).contains(id)));
    assert!(
        reusable_c
            .values()
            .map(|entry| entry.folded.len())
            .sum::<usize>()
            <= MAX_INDEX_TOTAL_BYTES
    );

    let mut authority_d = authority_c;
    for block in &mut authority_d {
        Arc::make_mut(block).touch();
    }
    assert!(viewer.reconcile_if_changed(&authority_d, 4));
    assert!(
        viewer.index_job.as_ref().unwrap().reusable.is_empty(),
        "same ids with stale payload revisions are not reusable authority"
    );
}

#[test]
fn result_matching_is_incremental_and_snapshot_effects_wait_for_exact_query_revision() {
    let blocks = (0..6)
        .map(|id| user(id, if id == 5 { "needle" } else { "hay" }))
        .collect::<Vec<_>>();
    let mut viewer = Viewer::default();
    viewer.open("", &blocks, 9);
    settle(&mut viewer, &blocks, 9);

    replace_query_without_settle(&mut viewer, "needle");
    assert_eq!(viewer.work_progress(), Some(("searching", 0, 6)));
    viewer.sync_if_changed(&blocks, 9);
    assert_eq!(viewer.work_progress(), Some(("searching", 1, 6)));
    assert!(
        viewer.results.is_empty(),
        "partial results are not snapshot authority"
    );
    assert!(viewer.export_ids(ExportScope::Filtered, 9).is_err());

    settle(&mut viewer, &blocks, 9);
    assert_eq!(viewer.results, vec![5]);
    assert_eq!(
        viewer.export_ids(ExportScope::Filtered, 9),
        Ok(Some(vec![5]))
    );
}

fn replace_query_without_settle(viewer: &mut Viewer, query: &str) {
    viewer.query = query.into();
    viewer.query_revision = viewer.query_revision.wrapping_add(1);
    viewer.query_changed();
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
