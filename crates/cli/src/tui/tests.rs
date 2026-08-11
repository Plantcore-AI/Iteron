#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents_panel_renders_the_attached_catalog_after_the_filesystem_drifts() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let workspace = std::env::temp_dir().join(format!(
            "core-tui-agent-snapshot-{}-{nonce}",
            std::process::id()
        ));
        let definitions = workspace.join(".iteron/agents");
        std::fs::create_dir_all(&definitions).unwrap();
        let pinned_path = definitions.join("pinned.md");
        std::fs::write(
            &pinned_path,
            "---\nname: pinned-reviewer\ndescription: Pinned before attach.\n---\nReview the run.\n",
        )
        .unwrap();
        const SECRET: &str = "ghp_AbCdEf1234567890AbCdEf1234567890";
        std::fs::write(
            definitions.join(format!("{SECRET}.md")),
            "not front matter\n",
        )
        .unwrap();

        let pinned = iteron_agents::AgentCatalog::discover_without_user(&workspace);
        let pinned_digest = pinned.execution_digest();
        assert!(pinned.get("pinned-reviewer").is_some());
        assert!(
            pinned
                .errors()
                .iter()
                .any(|error| error.source.contains(SECRET)),
            "the fixture must put credential-shaped source text on the display path"
        );

        let (submissions, _submission_rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(submissions);
        session.facts.workspace = workspace.clone();
        session.facts.agent_catalog = Arc::new(pinned);

        std::fs::remove_file(pinned_path).unwrap();
        std::fs::write(
            definitions.join("late.md"),
            "---\nname: late-reviewer\ndescription: Added after attach.\n---\nReview later.\n",
        )
        .unwrap();
        let live = iteron_agents::AgentCatalog::discover_without_user(&workspace);
        assert!(live.get("pinned-reviewer").is_none());
        assert!(live.get("late-reviewer").is_some());

        let mut app = App::new();
        show_agent_catalog(&mut app, &session);
        let retained = app.transcript.last().expect("agents panel").to_text();
        assert!(retained.contains("pinned-reviewer"));
        assert!(!retained.contains("late-reviewer"));
        assert!(!retained.contains(SECRET));
        assert!(retained.contains("[REDACTED"));

        let screen = render_text(&mut app, 200, 32);
        assert!(screen.contains("pinned-reviewer"));
        assert!(!screen.contains("late-reviewer"));
        assert!(!screen.contains(SECRET));
        assert!(screen.contains("[REDACTED"), "{screen}");
        assert_eq!(session.agent_catalog().execution_digest(), pinned_digest);

        std::fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn continuously_refilled_1024_eq_yields_every_tick_to_control_and_draw_phases() {
        let mut queue = (0..1024usize).collect::<VecDeque<_>>();
        let mut next = 1024usize;
        let mut draws = 0usize;
        let mut inputs = 0usize;
        let mut effects = 0usize;
        let mut effect_pending = true;

        for _tick in 0..32 {
            let mut drained = 0usize;
            for _ in eq_tick_slots() {
                let _event = queue.pop_front().expect("permanent EQ backlog");
                drained += 1;
                queue.push_back(next);
                next += 1;
            }
            assert_eq!(drained, MAX_EQ_EVENTS_PER_TICK);
            assert_eq!(queue.len(), 1024, "the fixture remains permanently ready");

            // The draw phase precedes the select. With a one-shot effect and continuously ready
            // input, the production select consumes the effect first and input on every later
            // tick; the ready EQ never takes either control slot.
            draws += 1;
            if effect_pending {
                effects += 1;
                effect_pending = false;
            } else {
                inputs += 1;
            }
        }

        assert_eq!((draws, effects, inputs), (32, 1, 31));
        assert_eq!(next, 1024 + 32 * MAX_EQ_EVENTS_PER_TICK);

        // A lifecycle signal is the first biased branch and therefore wins its very first service
        // point even when effect, input, and EQ are simultaneously ready; the real loop then exits.
        let signal_ready = true;
        let effect_ready = true;
        let input_ready = true;
        let selected = [
            ("signal", signal_ready),
            ("effect", effect_ready),
            ("input", input_ready),
            ("eq", !queue.is_empty()),
        ]
        .into_iter()
        .find_map(|(lane, ready)| ready.then_some(lane));
        assert_eq!(selected, Some("signal"));
    }

    #[test]
    fn active_keyboard_panic_restore_pops_once_and_restores_terminal_modes() {
        let controller = keyboard_enhancement::Controller::default();
        let restorer = controller.restorer();
        let mut output = Vec::new();

        assert!(controller.negotiate_with(&mut output, true).unwrap());
        assert!(restore_terminal_after_panic_to(&restorer, &mut output));

        for sequence in [
            b"\x1b[<1u".as_slice(),
            b"\x1b[?2004l".as_slice(),
            b"\x1b[?25h".as_slice(),
            b"\x1b[?1049l".as_slice(),
        ] {
            assert!(
                output
                    .windows(sequence.len())
                    .any(|bytes| bytes == sequence),
                "panic restore omitted {sequence:?}"
            );
        }
        assert_eq!(
            output
                .windows(b"\x1b[<1u".len())
                .filter(|bytes| *bytes == b"\x1b[<1u")
                .count(),
            1
        );

        let after_panic_restore = output.clone();
        assert_eq!(
            restorer.restore(&mut output).unwrap(),
            keyboard_enhancement::RestoreOutcome::AlreadyInactive
        );
        assert_eq!(output, after_panic_restore);
    }

    fn turn_end(cost: f64, usage: Usage) -> UiEvent {
        let total = request_input_tokens(usage) as usize;
        UiEvent::TurnEnd {
            cost: CostState::Known {
                amount_microusd: (cost * 1_000_000.0).round() as u64,
                rate_card_digest: "sha256:test-rate-card".into(),
            },
            usage,
            context: ContextEstimate {
                system_tokens: total / 4,
                tool_tokens: total / 4,
                conversation_tokens: total / 2,
                tool_result_tokens: 0,
                lsp_result_tokens: 0,
                transcript_tokens: total / 2,
                framing_tokens: 0,
                total_tokens: total,
                provenance: iteron_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
            },
            model_context_window: None,
            reserved_output_tokens: 8_192,
            compaction_trigger_tokens: 120_000,
            effort: EffortApplication::Exact {
                requested: iteron_protocol::ReasoningEffort::Medium,
            },
        }
    }

    fn pick(label: &str, action: PickAction) -> PickItem {
        PickItem::flat(label, "", false, action)
    }

    #[allow(clippy::too_many_arguments)]
    fn tree_pick(
        label: &str,
        parent: Option<usize>,
        depth: usize,
        expandable: bool,
        expanded: bool,
        enabled: bool,
        reason: Option<&str>,
        action: PickAction,
    ) -> PickItem {
        PickItem {
            label: label.into(),
            hint: String::new(),
            is_current: false,
            action,
            parent,
            depth,
            expandable,
            expanded,
            enabled,
            disabled_reason: reason.map(str::to_owned),
        }
    }

    fn model_tree() -> Vec<PickItem> {
        vec![
            tree_pick("OpenAI", None, 0, true, false, true, None, PickAction::Info),
            tree_pick("GPT", Some(0), 1, true, false, true, None, PickAction::Info),
            tree_pick(
                "gpt-5",
                Some(1),
                2,
                false,
                false,
                true,
                None,
                PickAction::SetModel(ModelSelection {
                    provider_id: "openai".into(),
                    model_id: "gpt-5".into(),
                }),
            ),
            tree_pick(
                "gpt-4.1",
                Some(1),
                2,
                false,
                false,
                false,
                Some("insufficient quota"),
                PickAction::SetModel(ModelSelection {
                    provider_id: "openai".into(),
                    model_id: "gpt-4.1".into(),
                }),
            ),
            tree_pick(
                "Anthropic",
                None,
                0,
                true,
                false,
                true,
                None,
                PickAction::Info,
            ),
        ]
    }

    fn session_meta(
        run_id: &str,
        title: &str,
        updated_at: u64,
        provider_id: &str,
        model: &str,
        turns: u32,
    ) -> iteron_record::SessionMeta {
        iteron_record::SessionMeta {
            pricing_schema_version: 2,
            projection_schema_version: 1,
            content_revocation_generation: 0,
            run_id: iteron_protocol::RunId(run_id.into()),
            tenant: iteron_protocol::TenantId::default(),
            cwd: std::path::PathBuf::from("/tmp/project"),
            provider_id: provider_id.into(),
            model: model.into(),
            effort: Effort::Medium,
            agent_definition_tag: None,
            title: title.into(),
            created_at: updated_at.saturating_sub(10),
            updated_at,
            updated_at_subsec_nanos: 0,
            record_bytes: 100,
            record_tail_seq: None,
            record_tail_hash: String::new(),
            projection_digest: String::new(),
            ancestry: Vec::new(),
            turns,
            cost: CostState::Known {
                amount_microusd: 2_500_000,
                rate_card_digest: "sha256:test".into(),
            },
            cache_hit: 0.25,
            last_outcome: None,
            parent: None,
        }
    }

    #[test]
    fn picker_query_reveals_leaf_and_ancestors_then_accepts_with_one_enter() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            items: model_tree(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });

        for ch in "gpt-5".chars() {
            app.picker_key(KeyCode::Char(ch));
        }
        let picker = app.picker.as_ref().unwrap();
        assert_eq!(picker.visible_indices(), vec![0, 1, 2]);
        assert_eq!(picker.sel, 2, "search focuses the actionable matching leaf");
        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Accept(PickAction::SetModel(ModelSelection {
                provider_id,
                model_id,
            }))) if provider_id == "openai" && model_id == "gpt-5"
        ));
    }

    #[test]
    fn picker_query_is_cjk_safe_bounded_and_has_an_explicit_no_result_state() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            items: vec![
                pick("通义千问", PickAction::Info),
                pick("智谱 GLM", PickAction::SetEffort(Effort::High)),
            ],
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });
        for ch in "智谱".chars() {
            app.picker_key(KeyCode::Char(ch));
        }
        assert_eq!(app.picker.as_ref().unwrap().visible_indices(), vec![1]);
        assert_eq!(app.picker.as_ref().unwrap().sel, 1);

        app.picker_key(KeyCode::Char('x'));
        assert!(app.picker.as_ref().unwrap().visible_indices().is_empty());
        assert!(render_text(&mut app, 80, 18).contains("No matches"));
        for _ in 0..(MAX_PICKER_QUERY_CHARS + 20) {
            app.picker_key(KeyCode::Char('a'));
        }
        assert!(app.picker.as_ref().unwrap().query.chars().count() <= MAX_PICKER_QUERY_CHARS);

        app.picker_key(KeyCode::Esc);
        assert!(app.picker.is_some(), "first Esc clears the query");
        assert!(app.picker.as_ref().unwrap().query.is_empty());
        app.picker_key(KeyCode::Esc);
        assert!(app.picker.is_none(), "second Esc closes the picker");
    }

    #[test]
    fn picker_paste_is_bounded_sanitized_and_never_mutates_the_composer() {
        const IMAGE: &[u8] = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;";

        let mut app = App::new();
        app.editor.insert_str("draft-你好");
        app.editor.set_cursor(3);
        app.editor
            .attach_image_bytes("kept.gif", IMAGE)
            .expect("attach test image");
        let original_text = app.editor.text();
        let original_cursor = app.editor.cursor();
        let original_attachments = app.editor.attachments().clone();
        app.picker = Some(Picker {
            title: "model".into(),
            items: vec![
                pick("通义千问", PickAction::Info),
                pick("智谱 GLM", PickAction::SetEffort(Effort::High)),
            ],
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });

        assert!(app.picker_paste("智谱\n\u{1b}\u{202e}"));
        let picker = app.picker.as_ref().expect("picker remains open");
        assert_eq!(picker.query, "智谱 ");
        assert_eq!(picker.visible_indices(), vec![1]);
        assert_eq!(picker.sel, 1);

        let unsafe_codepoints: Vec<char> = (0x00..=0x1f)
            .chain(0x7f..=0x9f)
            .chain(std::iter::once(0x061c))
            .chain(0x200b..=0x200f)
            .chain(0x202a..=0x202e)
            .chain(0x2060..=0x206f)
            .chain(std::iter::once(0xfeff))
            .filter_map(char::from_u32)
            .collect();
        for unsafe_character in unsafe_codepoints {
            app.picker
                .as_mut()
                .expect("picker remains open")
                .query
                .clear();
            assert!(app.picker_paste(&format!("安全{unsafe_character}😀")));
            let query = &app.picker.as_ref().expect("picker remains open").query;
            assert!(query.contains("安全"));
            assert!(query.contains('😀'));
            assert!(!query.contains(unsafe_character));
            assert!(!query.chars().any(is_unsafe_display_char));
        }

        assert!(app.picker_paste(&"无匹配😀".repeat(2_000)));
        let picker = app.picker.as_ref().expect("picker remains open");
        assert!(picker.visible_indices().is_empty());
        assert!(picker.query.chars().count() <= MAX_PICKER_QUERY_CHARS);
        assert!(picker.query.len() <= MAX_PICKER_QUERY_BYTES);
        assert!(!picker.query.chars().any(is_unsafe_display_char));
        assert!(render_text(&mut app, 80, 18).contains("No matches"));

        assert_eq!(app.editor.text(), original_text);
        assert_eq!(app.editor.cursor(), original_cursor);
        assert_eq!(
            app.editor.attachments().as_slice(),
            original_attachments.as_slice()
        );
    }

    #[test]
    fn tunables_l0_search_and_l1_detail_are_terminal_rendered_and_truthful() {
        let mut app = App::new();
        let (submissions, _submitted) = tokio::sync::mpsc::channel(1);
        let session = Session::for_test(submissions);

        open_tunables_picker(&mut app, &session, "route_selection");
        let picker = app.picker.as_ref().expect("tunables picker opens");
        assert_eq!(picker.items.len(), iteron_tunables::EXPECTED_FAMILY_COUNT);
        assert_eq!(picker.query, "route_selection");
        assert_eq!(picker.visible_indices(), vec![0]);
        let l0 = render_text(&mut app, 110, 26);
        assert!(l0.contains("tunables · catalog"));
        assert!(l0.contains("provider"));
        assert!(l0.contains("simulation only"));

        let detail = match app.picker_key(KeyCode::Enter) {
            Some(PickerEvent::Accept(PickAction::InspectTunable(detail))) => detail,
            _ => panic!("Enter must select the one filtered tunable"),
        };
        show_tunable_detail(&mut app, detail);
        let l1 = render_text(&mut app, 120, 40);
        assert!(l1.contains("tunable · provider"));
        assert!(l1.contains("runtime_bound=false"));
        assert!(l1.contains("not supplied (no frozen request loaded)"));
        assert!(l1.contains("SWE-bench Pro"));
        assert!(l1.contains("does not edit config"));
    }

    /// UX-3 frontend surface: `/side` splits into exactly three requests, and only a bare
    /// reserved word is a verb.
    #[test]
    fn side_argument_resolves_to_status_close_or_a_question() {
        assert!(matches!(
            side_request_for(""),
            app_server::SideRequest::Status
        ));
        assert!(matches!(
            side_request_for("  status "),
            app_server::SideRequest::Status
        ));
        assert!(matches!(
            side_request_for("close"),
            app_server::SideRequest::Close
        ));
        assert!(matches!(
            side_request_for("end"),
            app_server::SideRequest::Close
        ));
        match side_request_for("  what is the status of the parser?  ") {
            app_server::SideRequest::Ask(question) => {
                assert_eq!(question, "what is the status of the parser?");
            }
            _ => panic!("a sentence containing a reserved word is still a question"),
        }
    }

    fn side_status_fixture(run_id: &str, asks: u32) -> crate::runtime::SideStatus {
        crate::runtime::SideStatus {
            run_id: run_id.into(),
            record_path: std::path::PathBuf::from("/tmp/runs/side/side-1.jsonl"),
            asks,
            turns: 2,
            cost: iteron_obs::CostState::Known {
                amount_microusd: 12_300,
                rate_card_digest: "digest".into(),
            },
            ledger_summary: "2 turns".into(),
        }
    }

    /// The answer is rendered as its OWN panel carrying its OWN run id and cost, and never as an
    /// assistant block — an assistant block IS this session's conversation.
    #[test]
    fn a_side_answer_renders_as_its_own_panel_with_its_own_run_and_cost() {
        let mut app = App::new();
        show_side_answer(
            &mut app,
            &crate::runtime::SideAnswer {
                text: "read crates/cli/src/tui.rs:1 for the composer".into(),
                outcome: iteron_protocol::Outcome::Done,
                status: side_status_fixture("side-run-1", 1),
            },
        );
        let screen = render_text(&mut app, 100, 24);
        assert!(screen.contains("side conversation"), "{screen}");
        assert!(screen.contains("side-run-1"), "{screen}");
        assert!(screen.contains("$0.0123"), "{screen}");
        assert!(screen.contains("crates/cli/src/tui.rs:1"), "{screen}");
        assert!(
            app.transcript.iter().all(|block| !matches!(
                block.kind,
                block::BlockKind::Assistant(_) | block::BlockKind::User(_)
            )),
            "a side answer must not enter the session transcript as a conversation turn"
        );
    }

    #[test]
    fn an_unopened_side_conversation_says_so_instead_of_showing_zero_cost() {
        let mut app = App::new();
        show_side_status(&mut app, None, false);
        let screen = render_text(&mut app, 100, 16);
        assert!(screen.contains("no side conversation yet"), "{screen}");
        assert!(
            !screen.contains("$0.0000"),
            "an absent conversation must never be rendered as a free one: {screen}"
        );
    }

    #[test]
    fn closing_reports_the_books_of_the_conversation_it_closed() {
        let mut app = App::new();
        show_side_status(&mut app, Some(&side_status_fixture("side-run-9", 3)), true);
        let screen = render_text(&mut app, 110, 24);
        assert!(screen.contains("closed"), "{screen}");
        assert!(screen.contains("side-run-9"), "{screen}");
        assert!(screen.contains("3 questions"), "{screen}");
        assert!(screen.contains("$0.0123"), "{screen}");
    }

    fn adopted_event(seq: u64, kind: iteron_protocol::EventKind) -> iteron_protocol::Event {
        iteron_protocol::Event {
            seq: iteron_protocol::Seq(seq),
            turn: iteron_protocol::TurnId(1),
            kind,
        }
    }

    fn adopted_message(
        role: iteron_protocol::Role,
        content: Vec<iteron_protocol::Block>,
    ) -> iteron_protocol::Message {
        iteron_protocol::Message { role, content }
    }

    #[test]
    fn an_adopted_record_renders_its_conversation_and_its_recorded_tool_results() {
        use iteron_protocol::{Block as MessageBlock, EventKind, Role};
        let events = vec![
            adopted_event(
                1,
                EventKind::Message {
                    message: iteron_protocol::Message::user_text("find the parser bug"),
                },
            ),
            adopted_event(
                2,
                EventKind::Message {
                    message: adopted_message(
                        Role::Assistant,
                        vec![
                            MessageBlock::Text {
                                text: "reading the parser".into(),
                            },
                            MessageBlock::ToolUse(iteron_protocol::ToolUse {
                                id: "call-1".into(),
                                name: "read_file".into(),
                                input: serde_json::json!({ "path": "src/parse.rs" }),
                            }),
                            MessageBlock::ToolUse(iteron_protocol::ToolUse {
                                id: "call-2".into(),
                                name: "bash".into(),
                                input: serde_json::json!({ "command": "cargo test" }),
                            }),
                        ],
                    ),
                },
            ),
            adopted_event(
                3,
                EventKind::Message {
                    message: adopted_message(
                        Role::User,
                        vec![MessageBlock::ToolResult(iteron_protocol::ToolResult {
                            tool_use_id: "call-1".into(),
                            content: "fn parse() {}".into(),
                            is_error: false,
                            trust: iteron_protocol::Trust::Workspace,
                            latency_ms: 12,
                        })],
                    ),
                },
            ),
        ];

        let (blocks, total) = adopted_transcript_blocks(&events);
        assert_eq!(total, 4, "user text, assistant text, and two tool calls");
        assert_eq!(blocks.len(), 4);
        assert!(
            matches!(&blocks[0], block::BlockKind::User(text) if text == "find the parser bug")
        );
        assert!(matches!(&blocks[1], block::BlockKind::Assistant(_)));
        let block::BlockKind::Tool(answered) = &blocks[2] else {
            panic!("the recorded tool call must render as a card")
        };
        assert_eq!(answered.name, "read_file");
        assert!(matches!(answered.status, block::ToolStatus::Ok));
        assert_eq!(answered.output, "fn parse() {}");
        assert_eq!(answered.elapsed, Some(Duration::from_millis(12)));
        let block::BlockKind::Tool(unanswered) = &blocks[3] else {
            panic!("a call with no recorded result is still real history")
        };
        // The run stopped between the call and its result. Saying so beats inventing a status.
        assert!(matches!(unanswered.status, block::ToolStatus::Err));
        assert!(unanswered.output.contains("no recorded result"));
        assert!(unanswered.elapsed.is_none());
    }

    #[test]
    fn an_adopted_transcript_is_bounded_on_screen_and_reports_what_it_left_out() {
        use iteron_protocol::EventKind;
        let events: Vec<iteron_protocol::Event> = (0..MAX_ADOPTED_BLOCKS as u64 + 40)
            .map(|index| {
                adopted_event(
                    index,
                    EventKind::Message {
                        message: iteron_protocol::Message::user_text(format!("message {index}")),
                    },
                )
            })
            .collect();
        let (blocks, total) = adopted_transcript_blocks(&events);
        assert_eq!(total, MAX_ADOPTED_BLOCKS + 40);
        assert_eq!(blocks.len(), MAX_ADOPTED_BLOCKS);
        // The TAIL is what a returning operator needs: the newest exchange, not the oldest.
        assert!(
            matches!(blocks.last(), Some(block::BlockKind::User(text)) if text.ends_with(&format!("{}", MAX_ADOPTED_BLOCKS + 39))),
            "the bound must keep the newest blocks"
        );
    }

    #[test]
    fn the_route_to_bind_comes_from_the_records_last_durable_selection() {
        use iteron_protocol::EventKind;
        let selection = |provider: &str, model: &str| EventKind::ModelSelected {
            provider_id: provider.into(),
            model_id: model.into(),
            catalog_digest: String::new(),
            capability_digest: String::new(),
        };
        let events = vec![
            adopted_event(1, selection("glm", "glm-5.1")),
            adopted_event(2, selection("anthropic", "sonnet")),
        ];
        assert_eq!(
            recorded_route(&events),
            Some((Some("anthropic".into()), "sonnet".into()))
        );
        // A journal with no selection at all offers no route, and its model is never used to guess
        // a provider that was never recorded.
        assert_eq!(recorded_route(&[]), None);
    }

    #[test]
    fn session_picker_is_latest_first_and_discloses_route_cost_turns_and_run() {
        let items = session_picker_items(
            vec![
                session_meta("older", "Older task", 10, "openai", "gpt-5", 2),
                session_meta("newer", "Newest task", 30, "glm", "glm-5.2", 7),
                session_meta("middle", "Middle task", 20, "anthropic", "sonnet", 4),
            ],
            "",
            Path::new("/nonexistent/session-picker-test"),
        );
        assert_eq!(items[0].label, "Newest task");
        assert!(matches!(&items[0].action, PickAction::AdoptRun(id) if id == "newer"));
        for expected in ["run newer", "7 turns", "$2.5000", "glm/glm-5.2"] {
            assert!(
                items[0].hint.contains(expected),
                "missing {expected}: {}",
                items[0].hint
            );
        }
    }

    #[test]
    fn session_picker_one_enter_selects_the_run_to_adopt_in_process() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "sessions".into(),
            items: session_picker_items(
                vec![session_meta(
                    "run-42",
                    "Fix parser",
                    42,
                    "glm",
                    "glm-5.2",
                    3,
                )],
                "",
                Path::new("/nonexistent/session-picker-test"),
            ),
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });
        let action = match app.picker_key(KeyCode::Enter) {
            Some(PickerEvent::Accept(action)) => action,
            _ => panic!("one Enter should select the session"),
        };
        let PickAction::AdoptRun(run_id) = action else {
            panic!("session selection returned the wrong action")
        };
        assert_eq!(run_id, "run-42");
        // The restart handoff is now the FALLBACK, taken when a run cannot be adopted here — most
        // often because another process holds its writer lock. It must still be exact.
        app.prepare_resume_handoff(&run_id);
        assert_eq!(app.editor.text(), "iteron --resume run-42");
        assert!(app.is_resume_handoff_draft());
        let screen = render_text(&mut app, 100, 18);
        assert!(screen.contains("iteron --resume run-42"));
        assert!(
            app.transcript
                .iter()
                .any(|block| block.to_text().contains("not resumed here"))
        );
        assert_eq!(
            format_resume_command("run with space"),
            "iteron --resume 'run with space'"
        );
    }

    #[test]
    fn mode_picker_hint_tracks_the_effective_code_grant() {
        let hint_for = |rules: &PermissionRules, mode: PermissionMode| {
            mode_picker_items(mode, rules)
                .into_iter()
                .find(|item| item.label == mode.label())
                .expect("every mode is offered")
                .hint
        };

        // Deny-by-default: nothing seeded, so acceptEdits really does still gate code.
        let none = PermissionRules::new();
        assert_eq!(
            hint_for(&none, PermissionMode::AcceptEdits),
            "edits auto; code still gated"
        );
        assert_eq!(
            hint_for(&none, PermissionMode::Default),
            "edits prompt live; code still gated"
        );

        // With the operator's code grant in the session the old hard-coded hint lied: the rule
        // outranks the mode table, so acceptEdits auto-runs bash.
        let mut allowed = PermissionRules::new();
        allowed.allow_cap(Capability::CodeExecuting);
        assert_eq!(
            hint_for(&allowed, PermissionMode::AcceptEdits),
            "edits auto; code auto"
        );

        let mut denied = PermissionRules::new();
        denied
            .try_set_cap(Capability::CodeExecuting, Verdict::Deny)
            .unwrap();
        assert_eq!(
            hint_for(&denied, PermissionMode::AcceptEdits),
            "edits auto; code denied"
        );

        // The two modes whose posture no session rule can change keep their fixed wording.
        assert_eq!(
            hint_for(&allowed, PermissionMode::Plan),
            "read-only; propose a plan first"
        );
        assert_eq!(
            hint_for(&allowed, PermissionMode::Yolo),
            "auto-approve (still asks for trust-mutating + egress)"
        );
        assert!(
            mode_picker_items(PermissionMode::Plan, &none)
                .iter()
                .any(|item| item.label == PermissionMode::Plan.label() && item.is_current),
            "the active mode stays pre-selected"
        );
    }

    #[test]
    fn the_permission_picker_states_the_bypass_instead_of_listing_rules_that_do_not_decide() {
        // The default posture auto-approves every tool. A picker that renders "ask every time"
        // rows without saying so would be describing a gate that is not running.
        let gated = permission_picker_items(&PermissionRules::new(), false)
            .into_iter()
            .map(|item| item.label)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!gated.contains("BYPASSED"), "{gated}");

        let bypassed = permission_picker_items(&PermissionRules::new(), true);
        let first = bypassed.first().expect("the picker is never empty");
        assert!(first.label.contains("BYPASSED"), "{}", first.label);
        assert!(
            first.hint.contains("--ask-permissions"),
            "the operator is told how to get the gate back: {}",
            first.hint
        );
        assert!(
            first.hint.contains("deny"),
            "an explicit deny still applies and the screen must not imply otherwise: {}",
            first.hint
        );
        assert!(!first.enabled, "the notice is not a selectable action");
        // Everything the gated screen offered is still present and still selectable, because
        // `--ask-permissions` makes those rows decide again.
        assert_eq!(
            bypassed.len(),
            permission_picker_items(&PermissionRules::new(), false).len() + 1
        );
    }

    #[test]
    fn permission_picker_uses_human_labels_only() {
        let text = permission_picker_items(&PermissionRules::new(), false)
            .into_iter()
            .map(|item| item.label)
            .collect::<Vec<_>>()
            .join("\n");
        for raw in [
            "read_only",
            "reversible_local",
            "code_executing",
            "trust_mutating",
            "irreversible_external",
        ] {
            assert!(!text.contains(raw), "raw schema spelling leaked: {raw}");
        }
        assert!(text.contains("Read-only operations"));
        assert!(text.contains("Reversible edits"));
        assert!(text.contains("External actions and network access"));
    }

    #[test]
    fn picker_nav_wraps_and_accept_returns_action() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "effort".into(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
            items: vec![
                pick("low", PickAction::SetEffort(Effort::Low)),
                pick("high", PickAction::SetEffort(Effort::High)),
            ],
        });
        app.picker_key(KeyCode::Down);
        assert_eq!(app.picker.as_ref().unwrap().sel, 1);
        let accepted = matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Accept(PickAction::SetEffort(Effort::High)))
        );
        assert!(accepted, "Enter returns the selected action");
        assert!(app.picker.is_none(), "picker closes on accept");
    }

    #[test]
    fn picker_initial_focus_prefers_current_leaf_over_provider_header() {
        let mut items = model_tree();
        items[0].is_current = true;
        items[0].expanded = true;
        items[1].expanded = true;
        items[2].is_current = true;
        assert_eq!(initial_picker_selection(&items), 2);
    }

    #[test]
    fn no_current_model_leaf_is_visible_and_accepts_with_one_enter() {
        let mut items = model_tree();
        let selection = initial_picker_selection(&items);
        assert_eq!(selection, 2, "first actionable model should be focused");
        expand_selection_ancestors(&mut items, selection);
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            items,
            sel: selection,
            query: String::new(),
            saved_theme: None,
        });
        assert!(
            app.picker
                .as_ref()
                .unwrap()
                .visible_indices()
                .contains(&selection)
        );
        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Accept(PickAction::SetModel(ModelSelection {
                provider_id,
                model_id,
            }))) if provider_id == "openai" && model_id == "gpt-5"
        ));
    }

    #[test]
    fn permissions_picker_starts_actionable_and_accepts_in_one_enter() {
        let mut rules = PermissionRules::new();
        let items = permission_picker_items(&rules, false);
        let selection = initial_picker_selection(&items);
        assert_ne!(
            selection, 0,
            "the fixed read-only note must not get initial focus"
        );
        assert!(items[selection].enabled);

        let mut app = App::new();
        app.picker = Some(Picker {
            title: "permissions".into(),
            items,
            sel: selection,
            query: String::new(),
            saved_theme: None,
        });
        let action = match app.picker_key(KeyCode::Enter) {
            Some(PickerEvent::Accept(action)) => action,
            _ => panic!("one Enter should accept the focused permission rule"),
        };
        let PickAction::SetCap(capability, verdict) = action else {
            panic!("permission picker returned a non-permission action");
        };
        rules.try_set_cap(capability, verdict).unwrap();
        assert_eq!(rules.cap_rule(capability), Some(verdict));
        assert!(app.picker.is_none());
    }

    #[test]
    fn permissions_picker_marks_current_rule_and_cannot_select_unsafe_auto() {
        let mut rules = PermissionRules::new();
        rules
            .try_set_cap(Capability::CodeExecuting, Verdict::Deny)
            .unwrap();
        let items = permission_picker_items(&rules, false);
        let current = initial_picker_selection(&items);
        assert!(matches!(
            &items[current].action,
            PickAction::SetCap(Capability::CodeExecuting, Verdict::Deny)
        ));

        let unsafe_auto = items
            .iter()
            .position(|item| {
                matches!(
                    &item.action,
                    PickAction::SetCap(Capability::TrustMutating, Verdict::Auto)
                )
            })
            .unwrap();
        assert!(!items[unsafe_auto].enabled);
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "permissions".into(),
            items,
            sel: unsafe_auto,
            query: String::new(),
            saved_theme: None,
        });
        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Consumed)
        ));
        assert!(app.picker.is_some(), "unsafe choice must remain unapplied");
        assert!(
            rules
                .try_set_cap(Capability::TrustMutating, Verdict::Auto)
                .is_err(),
            "the protocol boundary independently rejects the same choice"
        );
    }

    #[test]
    fn hierarchical_picker_expands_collapses_and_moves_to_parent() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
            items: model_tree(),
        });

        assert_eq!(app.picker.as_ref().unwrap().visible_indices(), vec![0, 4]);
        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Consumed)
        ));
        assert_eq!(
            app.picker.as_ref().unwrap().visible_indices(),
            vec![0, 1, 4],
            "Enter expands a provider header"
        );

        app.picker_key(KeyCode::Down);
        assert_eq!(app.picker.as_ref().unwrap().sel, 1);
        app.picker_key(KeyCode::Right);
        assert_eq!(
            app.picker.as_ref().unwrap().visible_indices(),
            vec![0, 1, 2, 3, 4],
            "Right expands a family header"
        );

        app.picker_key(KeyCode::Down);
        assert_eq!(app.picker.as_ref().unwrap().sel, 2);
        app.picker_key(KeyCode::Left);
        assert_eq!(
            app.picker.as_ref().unwrap().sel,
            1,
            "Left on a leaf moves to its parent"
        );
        app.picker_key(KeyCode::Left);
        assert_eq!(
            app.picker.as_ref().unwrap().visible_indices(),
            vec![0, 1, 4]
        );
        assert_eq!(app.picker.as_ref().unwrap().sel, 1);
        app.picker_key(KeyCode::Left);
        assert_eq!(app.picker.as_ref().unwrap().sel, 0);
        app.picker_key(KeyCode::Left);
        assert_eq!(app.picker.as_ref().unwrap().visible_indices(), vec![0, 4]);
    }

    #[test]
    fn hierarchical_navigation_uses_only_visible_rows() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
            items: model_tree(),
        });

        app.picker_key(KeyCode::Down);
        assert_eq!(app.picker.as_ref().unwrap().sel, 4);
        app.picker_key(KeyCode::Down);
        assert_eq!(
            app.picker.as_ref().unwrap().sel,
            0,
            "Down wraps across visible roots without entering hidden descendants"
        );
        app.picker_key(KeyCode::End);
        assert_eq!(app.picker.as_ref().unwrap().sel, 4);
        app.picker_key(KeyCode::Home);
        assert_eq!(app.picker.as_ref().unwrap().sel, 0);
        app.picker_key(KeyCode::PageDown);
        assert_eq!(app.picker.as_ref().unwrap().sel, 4);
    }

    #[test]
    fn disabled_model_cannot_be_accepted() {
        let mut items = model_tree();
        items[0].expanded = true;
        items[1].expanded = true;
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 3,
            query: String::new(),
            saved_theme: None,
            items,
        });

        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Consumed)
        ));
        assert!(app.picker.is_some(), "disabled model keeps the picker open");
        assert_eq!(app.picker.as_ref().unwrap().sel, 3);
        assert!(matches!(
            app.picker_key(KeyCode::Tab),
            Some(PickerEvent::Consumed)
        ));
        assert!(app.picker.is_some(), "Tab cannot bypass disabled state");
    }

    #[test]
    fn theme_picker_esc_restores_pre_open_theme() {
        // C1: live-preview on nav, Esc restores the snapshot.
        let mut app = App::new();
        let orig = app.theme.clone();
        let light = theme::Theme::light();
        app.picker = Some(Picker {
            title: "theme".into(),
            sel: 0,
            query: String::new(),
            saved_theme: Some(orig.clone()),
            items: vec![
                pick("dark", PickAction::SetTheme(orig.clone())),
                pick("light", PickAction::SetTheme(light.clone())),
            ],
        });
        app.picker_key(KeyCode::Down); // preview light
        assert_eq!(
            app.theme.fg,
            app.color_depth.project_color(light.fg),
            "nav previews the theme at the detected color depth"
        );
        app.picker_key(KeyCode::Esc); // restore
        assert_eq!(app.theme.fg, orig.fg, "Esc restores the pre-open theme");
        assert!(app.picker.is_none());
    }

    #[test]
    fn fused_picker_esc_and_slash_preserves_the_next_exact_command() {
        let mut app = App::new();
        let mut unavailable =
            PickItem::flat("unavailable", "missing credential", true, PickAction::Info);
        unavailable.enabled = false;
        unavailable.disabled_reason = Some("missing credential".into());
        app.picker = Some(Picker {
            title: "model".into(),
            items: vec![unavailable],
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });
        let repo = std::env::temp_dir();

        assert!(app.recover_picker_escape_prefixed_char(
            KeyCode::Char('/'),
            KeyModifiers::ALT,
            &repo,
        ));
        assert!(app.picker.is_none(), "the Esc half must cancel the picker");
        assert_eq!(app.editor.text(), "/", "the slash half must not be lost");

        // Exercise the same completion-to-submit path used by the event loop. This is the failure
        // mode seen in a real clean-HOME PTY: without the recovery above, every byte through Enter
        // is consumed by the disabled model picker and `/quit` can never reach dispatch.
        app.editor.insert_str("quit");
        app.refresh_completion(&repo);
        assert_eq!(
            app.completion
                .as_ref()
                .and_then(|menu| menu.items.get(menu.sel))
                .map(|item| item.0.as_str()),
            Some("quit")
        );
        assert!(app.accept_completion_for_enter());
        assert_eq!(app.editor.take_submit().trim(), "/quit");
    }

    #[test]
    fn theme_picker_first_row_enter_applies_without_prior_navigation() {
        let mut app = App::new();
        let original = theme::Theme::dark();
        let selected = theme::Theme::light();
        app.set_theme(original.clone());
        app.picker = Some(Picker {
            title: "theme".into(),
            sel: 0,
            query: String::new(),
            saved_theme: Some(original),
            items: vec![pick("light", PickAction::SetTheme(selected.clone()))],
        });
        let action = match app.picker_key(KeyCode::Enter) {
            Some(PickerEvent::Accept(action)) => action,
            _ => panic!("Enter should accept the first theme row"),
        };
        match action {
            PickAction::SetTheme(theme) => apply_theme_selection(&mut app, theme),
            _ => panic!("theme picker returned the wrong action"),
        }
        assert_eq!(app.theme.fg, app.color_depth.project_color(selected.fg));
    }

    #[test]
    fn picker_open_renders_on_short_terminals_without_panic() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new();
        let mut items = model_tree();
        items[0].expanded = true;
        items[1].expanded = true;
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 3,
            query: String::new(),
            saved_theme: None,
            items,
        });
        for (w, h) in [(80u16, 24u16), (40, 9), (20, 4), (10, 3), (6, 2), (3, 1)] {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
            assert!(
                t.backend().buffer().content().iter().any(|cell| {
                    cell.bg == app.theme.accent || cell.modifier.contains(Modifier::REVERSED)
                }),
                "picker focus remains visible at {w}x{h}"
            );
            if w == 80 {
                let rendered = t
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .map(|cell| cell.symbol())
                    .collect::<String>();
                assert!(
                    rendered.contains("insufficient quota"),
                    "the disabled reason is rendered in the hierarchy"
                );
            }
        }
    }

    #[test]
    fn mono_menu_reverses_exactly_the_selected_row() {
        // Finding R4: under NO_COLOR (accent == Reset) an `fg(Black).bg(accent)` bar is invisible; the
        // unified popup must fall back to REVERSED so the selection is still a visible full-width bar.
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new();
        app.theme = theme::Theme::mono();
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
            items: (0..4)
                .map(|i| PickItem::flat(format!("m{i}"), "", false, PickAction::Info))
                .collect(),
        });
        let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let buffer = t.backend().buffer();
        let row_text = |y: u16| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        };
        let selected_y = (0..buffer.area.height)
            .find(|y| row_text(*y).contains("m0"))
            .expect("selected model row");
        let adjacent_y = (0..buffer.area.height)
            .find(|y| row_text(*y).contains("m1"))
            .expect("adjacent model row");
        let left = (0..buffer.area.width)
            .find(|x| buffer[(*x, selected_y)].symbol() == "│")
            .expect("popup left edge");
        let right = (0..buffer.area.width)
            .rfind(|x| buffer[(*x, selected_y)].symbol() == "│")
            .expect("popup right edge");
        assert!(left < right);
        assert!(
            (left + 1..right).all(|x| buffer[(x, selected_y)]
                .modifier
                .contains(Modifier::REVERSED)),
            "the complete selected row is visible without color"
        );
        assert!(
            (left + 1..right).all(|x| !buffer[(x, adjacent_y)]
                .modifier
                .contains(Modifier::REVERSED)),
            "reversal expresses focus, not generic menu chrome"
        );
    }

    #[test]
    fn cap_label_is_human_not_debug() {
        // Finding R5: a security prompt must never surface the raw `{:?}` Debug of a Capability.
        assert_eq!(
            cap_label(Capability::IrreversibleExternal),
            "external egress"
        );
        assert_eq!(cap_label(Capability::ReadOnly), "read-only");
        for c in [
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ] {
            let l = cap_label(c);
            assert!(
                !l.contains("Irreversible")
                    && !l.contains("ReadOnly")
                    && !l.contains("CodeExecuting"),
                "no Debug spelling leaks: {l}"
            );
        }
    }

    #[test]
    fn stream_text_accumulates_then_flushes_to_a_block() {
        let mut app = App::new();
        let base = app.transcript.len();
        app.stream_text("hello ");
        app.stream_text("world");
        // still buffered as the in-flight block; no committed block yet
        assert_eq!(app.transcript.len(), base);
        assert_eq!(app.cur_text, "hello ");
        app.flush_text();
        assert_eq!(app.transcript.len(), base + 1);
        assert!(
            app.transcript
                .last()
                .unwrap()
                .to_text()
                .contains("hello world")
        );
    }

    #[test]
    fn streaming_markdown_is_reparsed_only_after_text_revision_changes() {
        let mut app = App::new();
        app.stream_text("**first** ");
        assert!(app.cur_doc.is_none());
        assert_ne!(app.cur_doc_revision, app.cur_text_revision);

        assert!(ensure_stream_doc(&mut app), "the first revision is parsed");
        assert!(
            !ensure_stream_doc(&mut app),
            "an unchanged frame skips the Markdown parser"
        );
        let first_screen = render_text(&mut app, 80, 18);
        assert!(first_screen.contains("first"));
        assert!(app.cur_doc.is_some());
        assert_eq!(app.cur_doc_revision, app.cur_text_revision);
        let first_revision = app.cur_doc_revision;
        let first_doc = app.cur_doc.clone();

        let second_screen = render_text(&mut app, 80, 18);
        assert!(second_screen.contains("first"));
        assert_eq!(app.cur_doc_revision, first_revision);
        assert_eq!(
            app.cur_doc, first_doc,
            "an unchanged frame reuses the parsed doc"
        );

        app.stream_text("_second_ ");
        assert_ne!(app.cur_doc_revision, app.cur_text_revision);
        assert!(
            ensure_stream_doc(&mut app),
            "a new source revision is parsed"
        );
        assert!(!ensure_stream_doc(&mut app));
        let updated_screen = render_text(&mut app, 80, 18);
        assert!(updated_screen.contains("first"));
        assert!(updated_screen.contains("second"));
        assert_eq!(app.cur_doc_revision, app.cur_text_revision);
        assert_ne!(app.cur_doc_revision, first_revision);
    }

    #[test]
    fn tui_never_renders_a_credential_split_across_provider_deltas() {
        let mut app = App::new();
        let secret = "sk-\
ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        app.stream_text("answer sk-ant-api03-AbCd");
        assert_eq!(app.cur_text, "answer ");
        app.stream_text("EfGhIjKlMnOpQrStUvWx");
        assert!(!app.cur_text.contains(secret));
        app.stream_text(" done");
        assert!(!app.cur_text.contains(secret));
        assert!(app.cur_text.contains("[REDACTED"));
        app.flush_text();
        assert!(
            !app.transcript
                .last()
                .expect("assistant block")
                .to_text()
                .contains(secret)
        );
    }

    #[tokio::test]
    async fn inline_shell_is_bounded_terminal_safe_and_secret_scrubbed() {
        let mut app = App::new();
        let secret = "sk-\
ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let command = format!(
            "printf '%s\\n' '{secret}'; head -c 180000 /dev/zero | tr '\\0' x; printf '\\377'"
        );
        let (_cancel, mut cancelled) = tokio::sync::watch::channel(false);
        let completion = inline_shell::run_bash_inline(
            &std::env::temp_dir(),
            &command,
            &[],
            PermissionMode::Default,
            &PermissionRules::new(),
            &mut cancelled,
        )
        .await;
        app.push_shell_card(
            &completion.command,
            completion.body,
            completion.ok,
            completion.code,
        );
        let text = app.transcript.last().expect("shell card").to_text();
        assert!(!text.contains(secret));
        assert!(text.contains("[REDACTED"));
        assert!(text.contains("truncated"));
        assert!(text.contains("invalid UTF-8 escaped"));
        assert!(!text.contains('�'));
        assert!(
            text.len() < 150_000,
            "capture remains bounded: {}",
            text.len()
        );
    }

    #[test]
    fn pending_input_is_globally_bounded_and_requeues_in_submission_order() {
        let mut app = App::new();
        app.queue_after_turn("queued first".into()).unwrap();
        assert_eq!(
            app.steer_admission("late steer"),
            SubmissionAdmission::Accept
        );
        app.track_steer("late steer".into());
        app.queue_after_turn("queued last".into()).unwrap();
        let (moved, unmatched) = app.requeue_unadmitted(vec!["late steer".into()]);
        assert_eq!((moved, unmatched), (1, 0));
        assert_eq!(
            app.queued
                .iter()
                .map(|input| input.text.as_str())
                .collect::<Vec<_>>(),
            vec!["queued first", "late steer", "queued last"]
        );

        while app.queued.len() < MAX_PENDING_SUBMISSIONS {
            app.queue_after_turn(format!("item {}", app.queued.len()))
                .unwrap();
        }
        let rejected = "must remain editable".to_string();
        assert_eq!(
            app.queue_after_turn(rejected.clone()),
            Err(rejected),
            "the 33rd item is rejected rather than dropping an older preview"
        );
    }

    #[test]
    fn unmatched_steer_previews_are_preserved_as_ordered_follow_ups() {
        let mut app = App::new();
        app.track_steer("returned by kernel".into());
        app.track_steer("preview missing from reclaim report".into());
        app.queue_after_turn("already queued".into()).unwrap();

        let (reported, preserved) = app.requeue_unadmitted(vec!["returned by kernel".into()]);

        assert_eq!((reported, preserved), (1, 1));
        assert!(app.steer_previews.is_empty());
        assert_eq!(
            app.queued
                .iter()
                .map(|input| input.text.as_str())
                .collect::<Vec<_>>(),
            vec![
                "returned by kernel",
                "preview missing from reclaim report",
                "already queued"
            ],
            "count mismatch must preserve at-least-once operator intent in submission order"
        );
    }

    #[test]
    fn settled_render_cache_keeps_one_revision_per_block() {
        let mut app = App::new();
        app.push_block(block::BlockKind::Thinking {
            text: "bounded cache".into(),
            open: false,
        });
        for _ in 0..64 {
            let _ = render_text(&mut app, 80, 18);
            app.toggle_last_fold();
        }
        let _ = render_text(&mut app, 80, 18);
        assert!(app.render_cache.len() <= app.transcript.len());
        assert!(app.render_cache.contains_key(&1));
        assert_eq!(
            app.render_cache.get(&1).map(|(revision, _)| *revision),
            Some(app.transcript[1].revision)
        );
    }

    #[test]
    fn transcript_is_bounded() {
        let mut app = App::new();
        for i in 0..(MAX_BLOCKS + 300) {
            app.push(dim(), format!("line {i}"));
        }
        assert!(
            app.transcript.len() <= MAX_BLOCKS,
            "transcript must be bounded, got {}",
            app.transcript.len()
        );
        assert!(
            app.transcript
                .last()
                .unwrap()
                .to_text()
                .contains(&format!("line {}", MAX_BLOCKS + 299))
        );
    }

    #[test]
    fn transcript_pressure_pins_active_workflow_until_terminal_truth_lands() {
        let mut app = App::new();
        let run_id = "workflow-under-pressure";
        app.workflow_event(WorkflowUiEvent::RunStarted {
            run_id: run_id.into(),
            name: "ultracode".into(),
            class: "repository-wide".into(),
        });
        let block_id = *app
            .workflow_index
            .get(run_id)
            .expect("active workflow is indexed");

        for i in 0..(MAX_BLOCKS + 300) {
            app.push(dim(), format!("pressure line {i}"));
        }
        assert!(app.transcript.len() <= MAX_BLOCKS);
        assert_eq!(app.workflow_index.get(run_id), Some(&block_id));
        assert!(app.transcript.iter().any(|block| block.id == block_id));

        app.workflow_event(WorkflowUiEvent::RunFinished {
            run_id: run_id.into(),
            outcome: WorkflowRunOutcomeUi::Degraded,
            reason: Some("one investigator failed".into()),
            elapsed_ms: 42,
            provider_attempts: 3,
            turns: 2,
            tokens: 900,
            tool_calls: 4,
            failed_tasks: 1,
            skipped_tasks: 0,
        });
        assert!(!app.workflow_index.contains_key(run_id));
        let card = app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .and_then(|block| match &block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
            .expect("terminal update lands on the pinned workflow card");
        assert_eq!(card.status, block::WorkflowStatus::Degraded);
        assert_eq!(card.reason.as_deref(), Some("one investigator failed"));
    }

    #[test]
    fn draw_renders_all_states_without_panic() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut app = App::new();
        app.push(fg(Color::White), "# a markdown header");
        app.push(fg(Color::Blue), "· read_file {\"path\":\"a\"}");
        app.push(fg(Color::White), "```rust");
        // idle + slash menu open
        app.editor.insert_str("/mo");
        app.refresh_completion(&std::env::temp_dir());
        term.draw(|f| draw(f, &mut app)).unwrap();
        // multi-line input
        app.editor.clear();
        app.editor.insert_str("line1");
        app.editor.newline();
        app.editor.insert_str("line2");
        app.completion = None;
        term.draw(|f| draw(f, &mut app)).unwrap();
        // running + a pending approval
        app.running = true;
        app.spin = 3;
        app.cost = CostState::Known {
            amount_microusd: 120_000,
            rate_card_digest: "sha256:test-rate-card".into(),
        };
        app.last_turn_usage = Some(Usage {
            input: 60,
            cache_read: 40,
            ..Usage::default()
        });
        app.pending = Some(Pending {
            id: SubmissionId(1),
            tool: "edit".into(),
            cap: Capability::ReversibleLocal,
            reason: "update src/main.rs".into(),
            arguments: serde_json::json!({"path": "src/main.rs"}),
            workspace: "/tmp/project".into(),
        });
        term.draw(|f| draw(f, &mut app)).unwrap();
        // CRITICAL regression: the completion menu OPEN on short terminals must not panic (the
        // popup rect must clamp to the frame). Sweep sizes below the popup height.
        app.running = false;
        app.pending = None;
        app.editor.clear();
        app.editor.insert_str("/"); // 25-command menu -> tall popup
        app.refresh_completion(&std::env::temp_dir());
        assert!(app.completion.is_some());
        for (w, h) in [
            (80u16, 24u16),
            (40, 9),
            (40, 5),
            (20, 4),
            (10, 3),
            (6, 2),
            (3, 1),
        ] {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
        }
        // selection windowing: move past the visible window, still no panic on a short terminal
        for _ in 0..20 {
            if let Some(c) = app.completion.as_mut() {
                c.sel = (c.sel + 1) % c.items.len();
            }
            let mut t = Terminal::new(TestBackend::new(40, 8)).unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
        }
    }

    /// Read a TestBackend buffer as one big string (cell symbols concatenated row by row).
    #[cfg(test)]
    fn buffer_text(term: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        let buf = term.backend().buffer();
        let area = buf.area;
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    fn render_text(app: &mut App, width: u16, height: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        buffer_text(&terminal)
    }

    #[test]
    fn mcp_status_panel_renders_live_server_lifecycle_evidence() {
        let mut app = App::new();
        mcp_command::render_reply(
            &mut app,
            app_server::McpControlReply {
                servers: vec![crate::mcp::McpServerHealth {
                    name: "docs".into(),
                    transport: "stdio",
                    phase: "ready".into(),
                    generation: Some(7),
                    reconnect_attempts: 1,
                    reconnect_limit: 4,
                    retry_after_ms: None,
                    retained_tools: 12,
                    catalog_current: true,
                    busy: false,
                    negotiated_protocol_version: Some("2025-03-26".into()),
                    last_failure: Some("transport".into()),
                }],
                notice: None,
            },
        );

        let screen = render_text(&mut app, 120, 20);
        for expected in [
            "1 session-owned MCP servers",
            "docs",
            "stdio",
            "ready",
            "generation 7",
            "protocol 2025-03-26",
            "reconnect 1/4",
            "last failure transport",
            "12 retained",
        ] {
            assert!(screen.contains(expected), "missing {expected:?}: {screen}");
        }
    }

    const PRODUCT_SIZES: [(u16, u16); 4] = [(40, 12), (80, 24), (120, 32), (200, 40)];

    #[test]
    fn composer_is_a_quiet_semantic_input_surface() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let mut terminal = Terminal::new(TestBackend::new(40, 3)).unwrap();
        terminal
            .draw(|frame| render_composer(frame, frame.area(), &mut app))
            .unwrap();
        let buf = terminal.backend().buffer();
        for y in 0..3 {
            for x in 0..40 {
                assert_eq!(
                    buf[(x, y)].bg,
                    app.theme.user_bg,
                    "the composer owns one neutral input surface at ({x},{y})"
                );
            }
        }
        let screen = buffer_text(&terminal);
        assert!(!screen.contains("Prompt"));
        assert!(screen.contains('›'));
        assert_eq!(buf[(0, 0)].symbol(), "▌");
        assert_eq!(buf[(0, 1)].symbol(), "▌");
        assert_eq!(buf[(0, 2)].symbol(), "▌");
        assert!(!screen.contains('╭') && !screen.contains('╯'));
    }

    #[test]
    fn composer_renders_attachment_chips_and_submit_preview_without_payload_bytes() {
        let mut app = App::new();
        app.editor.insert_str("inspect");
        app.editor
            .attach_image_bytes(
                "clipboard.png",
                b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;",
            )
            .unwrap();

        let screen = render_text(&mut app, 80, 14);
        assert!(screen.contains("▧ #1"));
        assert!(screen.contains("clipboard.png"));
        assert!(screen.contains("alt+backspace"));
        assert!(screen.contains("inspect"));
        assert!(!screen.contains("R0lGOD"));
    }

    #[test]
    fn composer_renders_image_file_and_paste_chips_on_separate_rows() {
        let root = std::env::temp_dir().join(format!("core-tui-file-chip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("test workspace");
        let secret = "SUPER_SECRET_FILE_BODY";
        std::fs::write(root.join("notes.md"), format!("# notes\n{secret}\n")).expect("fixture");

        let mut app = App::new();
        app.editor.insert_str("inspect");
        app.editor
            .attach_image_bytes(
                "clipboard.png",
                b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;",
            )
            .unwrap();
        app.editor
            .attach_file_path(&root, Path::new("notes.md"))
            .expect("a plain workspace file");
        let pasted = (0..12)
            .map(|index| format!("diagnostic line {index}: {}", "x".repeat(80)))
            .collect::<Vec<_>>()
            .join("\n");
        app.editor.capture_paste(&pasted).expect("a held paste");

        let screen = render_text(&mut app, 100, 18);
        assert!(screen.contains("▧ #1"), "{screen}");
        assert!(screen.contains("▤ [file] notes.md"), "{screen}");
        assert!(screen.contains("▥ #1 held paste"), "{screen}");
        assert!(
            screen.contains("04bade72"),
            "complete file digest is represented on the chip"
        );
        assert!(screen.contains("clipboard.png"), "{screen}");
        assert!(screen.contains("notes.md"), "{screen}");
        assert!(screen.contains("inspect"), "{screen}");
        let rows = screen.lines().collect::<Vec<_>>();
        let image_row = rows.iter().position(|row| row.contains("▧ #1")).unwrap();
        let file_row = rows
            .iter()
            .position(|row| row.contains("▤ [file] notes.md"))
            .unwrap();
        let paste_row = rows
            .iter()
            .position(|row| row.contains("▥ #1 held paste"))
            .unwrap();
        assert_eq!(file_row, image_row + 1, "each chip owns exactly one row");
        assert_eq!(paste_row, file_row + 1, "each chip owns exactly one row");
        assert!(
            !screen.contains(secret),
            "a chip is a reference; the composer never prints the file it stands for"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn composer_renders_typed_context_provenance_size_and_digest() {
        let mut app = App::new();
        app.editor
            .attach_context(
                crate::file_input::ContextKind::Diff,
                "working tree",
                "- before\n+ after\n".into(),
            )
            .unwrap();

        let screen = render_text(&mut app, 100, 14);
        let digest = app.editor.files().as_slice()[0].digest().get(..8).unwrap();
        assert!(screen.contains("± [diff] working tree"), "{screen}");
        assert!(screen.contains("17 B"), "{screen}");
        assert!(screen.contains(digest), "{screen}");
        assert!(
            !screen.contains("before"),
            "chip preview never leaks into composer"
        );
    }

    #[test]
    fn full_width_composer_precedes_a_stable_bottom_statusline() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        app.route.provider_id = "glm".into();
        app.route.model_id = "glm-5.2".into();
        app.model = "glm-5.2".into();
        app.effort = Effort::High;
        app.push_user("active sessions use the full terminal grid");
        let expected = surface::Surface::resolve(Rect::new(0, 0, 80, 12), 1, 0, 0, true, false);
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();

        assert_eq!(expected.composer.x, 0);
        assert_eq!(expected.composer.right(), 80);
        assert_eq!(
            expected.status.y,
            expected.composer.bottom() + expected.hint.height
        );
        assert_eq!(expected.status.bottom(), 12);
        assert_eq!(buffer[(0, expected.composer.y)].symbol(), "▌");
        assert_ne!(buffer[(79, expected.composer.y)].symbol(), "▐");
        let bottom: String = (0..80)
            .map(|x| buffer[(x, expected.status.y)].symbol())
            .collect();
        assert!(
            bottom.contains("glm/glm-5.2"),
            "route stays in bottom row: {bottom:?}"
        );
        assert!(
            bottom.contains("● high"),
            "effort stays in bottom row: {bottom:?}"
        );
        assert!(
            bottom.contains(" · ") && !bottom.contains(" │ "),
            "status metadata uses the compact Codex separator: {bottom:?}"
        );
    }

    /// A terminal too short for the workflow region drops it to zero rows before the status row
    /// gives up its own (`surface::Surface::resolve`), so the status row is the last place that can
    /// say a run is still going. It is also the row with the least space, so the bit is tiny and
    /// yields early: this pins both halves of that bargain.
    #[test]
    fn a_live_workflow_run_shows_on_the_status_row_and_yields_before_the_bits_that_matter_more() {
        const GLYPH: char = '\u{27f3}'; // ⟳
        let mut app = App::new();

        // Nothing running: the row does not spend a column saying so.
        let idle = status_right_bits(&app, surface::Density::Wide);
        assert!(
            !idle.iter().any(|bit| bit.contains(GLYPH)),
            "an idle session must not carry a workflow bit: {idle:?}"
        );

        app.workflow_monitor.ingest(
            "wf_status_a",
            workflow_region::WorkflowRunSignal::Live { block_id: 7 },
        );
        let one = status_right_bits(&app, surface::Density::Wide);
        assert!(
            one.iter().any(|bit| bit == &format!("{GLYPH} 1 run")),
            "one live run: {one:?}"
        );
        app.workflow_monitor.ingest(
            "wf_status_b",
            workflow_region::WorkflowRunSignal::Live { block_id: 8 },
        );
        let two = status_right_bits(&app, surface::Density::Wide);
        assert!(
            two.iter().any(|bit| bit == &format!("{GLYPH} 2 runs")),
            "two live runs: {two:?}"
        );

        // The bit tracks LIVE runs, not cards: a run whose engine future resolved stops counting.
        app.workflow_monitor
            .ingest("wf_status_b", workflow_region::WorkflowRunSignal::Settled);
        app.workflow_monitor
            .ingest("wf_status_a", workflow_region::WorkflowRunSignal::Settled);
        let settled = status_right_bits(&app, surface::Density::Wide);
        assert!(
            !settled.iter().any(|bit| bit.contains(GLYPH)),
            "settled runs must not keep claiming to be live: {settled:?}"
        );

        app.workflow_monitor.ingest(
            "wf_status_a",
            workflow_region::WorkflowRunSignal::Live { block_id: 9 },
        );
        // `render_status` drops right-hand bits from the FRONT, so position IS drop order: the
        // workflow bit sits ahead of context, mode, the pending count and the route/effort
        // identity, and behind only mouse ownership.
        for density in [
            surface::Density::Compact,
            surface::Density::Standard,
            surface::Density::Wide,
        ] {
            let bits = status_right_bits(&app, density);
            let at = bits
                .iter()
                .position(|bit| bit.contains(GLYPH))
                .unwrap_or_else(|| panic!("{density:?}: no workflow bit in {bits:?}"));
            assert_eq!(at, 1, "{density:?}: wrong drop rank in {bits:?}");
            assert!(at < bits.len() - 1, "{density:?}: it must not be the last");
        }

        // Width sweep through the real renderer: present while the row has room, gone once it does
        // not — and the route/effort identity it yields to is still on screen at that width.
        let identity = effort_status_label(&app);
        let mut widest_without = None;
        let mut narrowest_with = None;
        for width in [200u16, 160, 120, 100, 80, 60, 50, 40, 30, 24] {
            let screen = render_text(&mut app, width, 14);
            if screen.contains(&format!("{GLYPH} 1 run")) {
                narrowest_with = Some(width);
            } else if widest_without.is_none() {
                widest_without = Some(width);
            }
        }
        assert!(
            narrowest_with.is_some() && widest_without.is_some(),
            "the sweep must cross the drop point: with={narrowest_with:?} without={widest_without:?}"
        );
        assert!(
            widest_without.unwrap() < narrowest_with.unwrap(),
            "the bit must drop monotonically as the row narrows: \
             last seen at {narrowest_with:?}, first missing at {widest_without:?}"
        );
        // At the width that dropped it, what it yielded to is still readable.
        let narrow = render_text(&mut app, widest_without.unwrap(), 14);
        assert!(
            identity
                .chars()
                .next()
                .is_some_and(|symbol| narrow.contains(symbol)),
            "the route/effort identity ({identity}) must outlive the workflow bit:\n{narrow}"
        );
    }

    #[test]
    fn app_mouse_is_default_and_ctrl_t_selection_state_is_truthful() {
        let mut app = App::new();
        let rendered = render_text(&mut app, 240, 14);
        assert!(rendered.contains("mouse:on"));
        assert!(rendered.contains("wheel:transcript"));
        assert!(rendered.contains("ctrl+t selection"));

        app.mouse_capture = mouse_capture::State::Released;
        let released = render_text(&mut app, 240, 14);
        assert!(released.contains("selection:on"));
        assert!(released.contains("ctrl+t app mouse"));
    }

    #[test]
    fn effort_symbols_match_claude_grammar_without_hiding_enforcement_truth() {
        assert_eq!(effort_symbol(ReasoningEffort::Low), "○");
        assert_eq!(effort_symbol(ReasoningEffort::Medium), "◐");
        assert_eq!(effort_symbol(ReasoningEffort::High), "●");
        assert_eq!(effort_symbol(ReasoningEffort::XHigh), "⦿");
        assert_eq!(effort_symbol(ReasoningEffort::Max), "◉");

        let mut app = App::new();
        app.effort = Effort::Ultracode;
        assert_eq!(effort_status_label(&app), "◉ max · ultracode");
        app.effort = Effort::High;
        app.effort_application = Some(EffortApplication::Mapped {
            requested: ReasoningEffort::High,
            sent: ReasoningEffort::Max,
        });
        assert_eq!(effort_status_label(&app), "◉ max ← high requested");
        app.effort_application = Some(EffortApplication::Unsupported {
            requested: ReasoningEffort::High,
        });
        assert_eq!(effort_status_label(&app), "● high · not enforced");
    }

    #[test]
    fn terminal_native_surface_is_coherent_across_product_breakpoints() {
        for (width, height) in PRODUCT_SIZES {
            let mut app = App::new();
            app.theme = theme::Theme::dark();
            app.model = "claude-sonnet-4-5".into();
            app.route.provider_id = "anthropic".into();
            app.route.model_id = "claude-sonnet-4-5".into();
            let screen = render_text(&mut app, width, height);
            assert!(screen.contains("▄██"), "Plantcore icon at {width}x{height}");
            assert!(screen.contains('›'), "composer at {width}x{height}");
            assert!(
                screen.contains("commands"),
                "discoverability at {width}x{height}"
            );
            assert!(
                screen.contains('▌'),
                "quiet composer rail at {width}x{height}"
            );
            assert!(!screen.contains('╭') && !screen.contains('╯'));
            assert!(!screen.contains('�'), "valid unicode at {width}x{height}");
        }
    }

    #[test]
    fn one_app_survives_resize_round_trip_and_invalidates_width_cache() {
        let mut app = App::new();
        app.push_user("inspect the responsive surface across a deliberately long wrapped line");
        app.note(block::NoticeLevel::Info, "stable semantic block");
        app.stream_text("streaming **markdown** remains parsed across resize ");

        let mut cache_widths = Vec::new();
        for (width, height) in [(40, 12), (80, 24), (120, 32), (200, 40), (80, 24), (40, 12)] {
            let screen = render_text(&mut app, width, height);
            if height >= 24 {
                assert!(screen.contains("responsive"));
            }
            assert!(screen.contains("markdown"));
            assert!(!screen.contains('�'));
            cache_widths.push(app.render_cache_width);
            assert_eq!(app.cur_doc_revision, app.cur_text_revision);
        }
        assert_ne!(cache_widths[0], cache_widths[1]);
        assert_eq!(cache_widths[0], cache_widths[5]);
        assert_eq!(cache_widths[1], cache_widths[4]);
        // One column short of the terminal at every size: transcript content now yields the final
        // column to the scrollbar (`Surface::transcript_content_width`), so the cache is keyed by
        // the width text actually gets rather than by the width of the window. The relations above
        // -- distinct widths produce distinct entries, repeated widths reuse them -- are what this
        // test exists to pin, and they are unchanged.
        assert_eq!(cache_widths, vec![39, 79, 119, 199, 79, 39]);
    }

    #[test]
    fn running_surface_shows_real_steer_and_queue_lanes() {
        for (width, height) in PRODUCT_SIZES {
            let mut app = App::new();
            app.running = true;
            app.status = "verifying".into();
            app.run_started = Some(Instant::now());
            app.active_tools
                .push_back(("tool-1".into(), "Bash(cargo test -p iteron-cli)".into()));
            app.track_steer("also cover narrow terminals".into());
            app.queue_after_turn("then update the design record".into())
                .unwrap();
            let screen = render_text(&mut app, width, height);
            assert!(screen.contains("steer"), "steer lane at {width}x{height}");
            assert!(screen.contains("queued"), "queue lane at {width}x{height}");
            assert!(
                screen.contains("esc"),
                "interrupt remains visible at {width}x{height}"
            );
            assert!(
                screen.contains("also cover") || screen.contains("narrow"),
                "actual steer preview at {width}x{height}"
            );
        }
    }

    #[test]
    fn approval_is_a_blocking_decision_surface_with_reason() {
        for (width, height) in PRODUCT_SIZES {
            let mut app = App::new();
            app.running = true;
            apply_event(
                &mut app,
                UiEvent::ApprovalRequest {
                    id: SubmissionId(7),
                    tool: "bash".into(),
                    capability: Capability::CodeExecuting,
                    reason: "run repository tests".into(),
                    arguments: serde_json::json!({"command": "cargo test --workspace"}),
                    workspace: "/tmp/project".into(),
                },
            );
            let screen = render_text(&mut app, width, height);
            assert!(screen.contains("Permission"));
            assert!(screen.contains("runs code"));
            assert!(screen.contains("cargo test"));
            assert!(screen.contains("run repository tests"));
            assert!(screen.contains("once"));
            assert!(screen.contains("session"));
            assert!(screen.contains("deny"));
        }
    }

    #[test]
    fn approval_keeps_actions_on_short_screens_and_never_offers_impossible_remember() {
        for height in [3, 4, 5] {
            let mut app = App::new();
            app.running = true;
            apply_event(
                &mut app,
                UiEvent::ApprovalRequest {
                    id: SubmissionId(9),
                    tool: "write_trust_file".into(),
                    capability: Capability::TrustMutating,
                    reason: "update CI policy".into(),
                    arguments: serde_json::json!({"path": ".github/workflows/ci.yml"}),
                    workspace: "/tmp/project".into(),
                },
            );
            let screen = render_text(&mut app, 56, height);
            assert!(screen.contains("[y]"), "allow once at height {height}");
            assert!(screen.contains("deny"), "deny at height {height}");
            assert!(
                !screen.contains("[a]"),
                "trust-mutating work cannot be remembered at height {height}"
            );
        }
    }

    #[test]
    fn approval_default_deny_remains_visible_at_physical_minimums() {
        for width in [3, 6, 8, 12, 20] {
            for height in [1, 2] {
                let mut app = App::new();
                app.running = true;
                apply_event(
                    &mut app,
                    UiEvent::ApprovalRequest {
                        id: SubmissionId(91),
                        tool: "bash".into(),
                        capability: Capability::CodeExecuting,
                        reason: "verify the build".into(),
                        arguments: serde_json::json!({"command": "cargo test"}),
                        workspace: "/tmp/project".into(),
                    },
                );
                let screen = render_text(&mut app, width, height);
                assert!(
                    screen.contains("[n]"),
                    "fail-closed focus at {width}x{height}: {screen:?}"
                );
                assert_eq!(app.approval_choice, ApprovalChoice::Deny);
            }
        }
    }

    #[test]
    fn narrow_approval_keeps_canonical_order_or_uses_an_explicit_single_slot_pager() {
        let mut app = App::new();
        app.running = true;
        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(92),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "verify the build".into(),
                arguments: serde_json::json!({"command": "cargo test"}),
                workspace: "/tmp/project".into(),
            },
        );
        let text = |line: Line<'static>| {
            line.spans
                .into_iter()
                .map(|span| span.content.into_owned())
                .collect::<String>()
        };

        let canonical = text(approval_action_line(
            &app,
            app.pending.as_ref().unwrap(),
            20,
        ));
        assert!(canonical.find("[y]") < canonical.find("[a]"));
        assert!(canonical.find("[a]") < canonical.find("[n]"));
        assert_eq!(app.approval_key(KeyCode::Left), ApprovalInput::Consumed);
        let after_move = text(approval_action_line(
            &app,
            app.pending.as_ref().unwrap(),
            20,
        ));
        assert_eq!(
            canonical, after_move,
            "focus does not reorder visible actions"
        );

        let paged = text(approval_action_line(&app, app.pending.as_ref().unwrap(), 8));
        assert_eq!(paged, "[a] <>");
        assert_eq!(app.approval_key(KeyCode::Right), ApprovalInput::Consumed);
        let deny_page = text(approval_action_line(&app, app.pending.as_ref().unwrap(), 8));
        assert_eq!(deny_page, "[n] <>");
    }

    #[test]
    fn runtime_approval_is_focusable_and_enter_defaults_to_deny() {
        let mut app = App::new();
        app.running = true;
        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(10),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "verify the build".into(),
                arguments: serde_json::json!({"command": "cargo test"}),
                workspace: "/tmp/project".into(),
            },
        );
        assert_eq!(app.approval_choice, ApprovalChoice::Deny);
        for theme in [theme::Theme::dark(), theme::Theme::mono()] {
            app.theme = theme;
            let pending = app.pending.as_ref().expect("pending approval");
            let line = approval_action_line(&app, pending, 80);
            let deny = line
                .spans
                .iter()
                .find(|span| span.content.contains("[n]"))
                .expect("deny choice");
            let once = line
                .spans
                .iter()
                .find(|span| span.content.contains("[y]"))
                .expect("once choice");
            if app.theme.mono {
                assert!(deny.style.add_modifier.contains(Modifier::REVERSED));
                assert!(!once.style.add_modifier.contains(Modifier::REVERSED));
            } else {
                assert_eq!(deny.style.bg, Some(app.theme.accent));
                assert_ne!(once.style.bg, Some(app.theme.accent));
            }
        }
        assert_eq!(
            app.approval_key(KeyCode::Enter),
            ApprovalInput::Answer {
                approved: false,
                remember: false,
            }
        );

        assert_eq!(app.approval_key(KeyCode::Left), ApprovalInput::Consumed);
        assert_eq!(app.approval_choice, ApprovalChoice::Session);
        assert_eq!(
            app.approval_key(KeyCode::Enter),
            ApprovalInput::Answer {
                approved: true,
                remember: true,
            }
        );
        assert_eq!(app.approval_key(KeyCode::Right), ApprovalInput::Consumed);
        assert_eq!(app.approval_choice, ApprovalChoice::Deny);
    }

    #[test]
    fn runtime_approval_never_constructs_an_impossible_session_grant() {
        let mut app = App::new();
        app.running = true;
        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(11),
                tool: "write_trust_file".into(),
                capability: Capability::TrustMutating,
                reason: "change repository policy".into(),
                arguments: serde_json::json!({"path": ".github/workflows/ci.yml"}),
                workspace: "/tmp/project".into(),
            },
        );
        assert_eq!(app.approval_key(KeyCode::Left), ApprovalInput::Consumed);
        assert_eq!(app.approval_choice, ApprovalChoice::Once);
        assert_eq!(
            app.approval_key(KeyCode::Char('a')),
            ApprovalInput::Consumed
        );
        assert_ne!(app.approval_choice, ApprovalChoice::Session);
    }

    #[test]
    fn conversation_and_composer_structure_survive_color_and_mono() {
        for theme in [theme::Theme::dark(), theme::Theme::mono()] {
            let mut app = App::new();
            app.theme = theme;
            app.transcript.clear();
            app.push_user("请检查 provider 路由");
            app.stream_text("I found the route and its tests.");
            app.flush_text();
            let screen = render_text(&mut app, 80, 18);
            assert!(screen.contains("provider"));
            assert!(screen.contains("I found the route and its tests."));
            assert!(!screen.contains("YOU ›"));
            assert!(!screen.contains("CORE  I found"));
            assert!(
                screen.contains('▌') || screen.contains('┃'),
                "color and mono themes keep the same semantic left rail"
            );
            assert!(!screen.contains("Prompt"));
            assert!(!screen.contains('�'));
        }
    }

    #[test]
    fn running_command_draft_truthfully_switches_composer_route() {
        let mut app = App::new();
        app.running = true;
        app.editor.insert_str("/model");
        let command = render_text(&mut app, 80, 16);
        assert!(command.contains("/model"));
        assert!(command.contains("enter queues after this turn"));

        app.editor.clear();
        app.editor.insert_str("/mcp cancel docs");
        let immediate = render_text(&mut app, 80, 16);
        assert!(immediate.contains("/mcp cancel docs"));
        assert!(immediate.contains("enter runs this control now"));

        app.editor.clear();
        app.editor.insert_str("also inspect the tests");
        let prose = render_text(&mut app, 80, 16);
        assert!(prose.contains("also inspect the tests"));
        assert!(prose.contains("enter steer"));

        app.interrupting = true;
        let next_prompt = render_text(&mut app, 80, 16);
        assert!(next_prompt.contains("also inspect the tests"));
        assert!(next_prompt.contains("enter queues after this turn"));
        assert!(!next_prompt.contains("enter steer"));
    }

    #[test]
    fn one_input_destination_reducer_drives_enter_routing() {
        assert_eq!(
            input_destination(false, false, "/model"),
            InputDestination::StartTurn
        );
        assert_eq!(
            input_destination(true, false, "  /model"),
            InputDestination::AfterTurn
        );
        assert_eq!(
            input_destination(true, false, "  /mcp cancel docs"),
            InputDestination::ImmediateCommand
        );
        assert_eq!(
            input_destination(true, true, "/mcp stop docs"),
            InputDestination::ImmediateCommand,
            "MCP control remains reachable while the turn is already interrupting"
        );
        assert_eq!(
            input_destination(true, false, "!cargo test"),
            InputDestination::AfterTurn
        );
        assert_eq!(
            input_destination(true, false, "please inspect the failure"),
            InputDestination::SteerCurrentRun
        );
        assert_eq!(
            input_destination(true, true, "start the next task"),
            InputDestination::AfterTurn,
            "new prose after interrupt is the next prompt, never a last-moment steer"
        );
    }

    #[test]
    fn interrupt_keeps_the_composer_focused_and_enter_queues_the_next_prompt() {
        let mut app = App::new();
        app.running = true;
        app.interrupting = true;
        app.editor.insert_str("start the next task immediately");

        assert_eq!(
            input_destination(app.running, app.interrupting, &app.editor.text()),
            InputDestination::AfterTurn
        );
        let text = app.editor.take_submit();
        app.queue_after_turn(text).expect("next prompt is admitted");

        assert!(app.running, "only RunEnded may declare the old turn idle");
        assert!(app.interrupting);
        assert!(app.editor.is_empty(), "the focused composer accepted Enter");
        assert_eq!(app.queued.len(), 1);
        assert_eq!(
            app.queued.front().unwrap().text,
            "start the next task immediately"
        );
    }

    #[test]
    fn fused_interrupt_escape_and_first_character_interrupts_and_preserves_that_character() {
        let repo = std::env::temp_dir();
        let mut app = App::new();
        app.running = true;

        assert!(app.recover_running_escape_prefixed_char(
            KeyCode::Char('c'),
            KeyModifiers::ALT,
            &repo,
            true,
            true,
        ));
        assert!(app.interrupting);
        assert_eq!(app.editor.text(), "c");

        app.interrupting = false;
        assert!(!app.recover_running_escape_prefixed_char(
            KeyCode::Char('b'),
            KeyModifiers::ALT,
            &repo,
            true,
            true,
        ));
        assert_eq!(
            app.editor.text(),
            "c",
            "a later deliberate Alt binding is not turned into text"
        );
    }

    /// N-2: a file dropped on the terminal DURING a run was routed to the after-turn queue by the
    /// bare `starts_with('/')` test, and the drain then dispatched it as a slash command — so the
    /// path was destroyed instead of reaching the model. Every row here is a drop form that failed.
    #[test]
    fn a_drop_during_a_run_steers_instead_of_queueing_a_command() {
        let drops = [
            "/Users/op/IMG_0042.heic",
            "/Users/op/notes.pdf",
            "/Users/op/notes.txt",
            "/Users/op/logo.svg",
            "/Users/op/shot.png",
            "/Users/op/Pictures",
            "/Users/op/a.png /Users/op/b.png",
            r"/Users/op/My\ Trip.heic",
            "/Users/op/shot.png\n",
            "  /Users/op/shot.png",
        ];
        for drop in drops {
            assert_eq!(
                input_destination(true, false, drop),
                InputDestination::SteerCurrentRun,
                "{drop:?} was routed to the command queue"
            );
        }
        for command in ["/model", "/compact", "/?", "/perms", "/helpp", "/"] {
            assert_eq!(
                input_destination(true, false, command),
                InputDestination::AfterTurn,
                "{command:?} stopped queueing as a command"
            );
        }
        assert_eq!(
            input_destination(true, false, "!cargo test"),
            InputDestination::AfterTurn,
        );
    }

    /// The frontend's binding of the discriminator really consults the filesystem: `/tmp` and
    /// `/etc` are single-segment, so nothing but a `stat` can tell them from a mistyped command.
    #[cfg(unix)]
    #[test]
    fn the_drop_probe_reads_this_filesystem() {
        assert!(path_exists_on_disk(Path::new("/tmp")));
        assert_eq!(slash_command_body("/tmp"), None);
        assert_eq!(slash_command_body("/etc"), None);
        // A dropped folder created for this test, named like nothing in the registry.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dropped = std::env::temp_dir().join(format!(
            "core-tui-drop-{}-{nonce}/IMG_0042.heic",
            std::process::id()
        ));
        std::fs::create_dir_all(dropped.parent().unwrap()).unwrap();
        std::fs::write(&dropped, b"not really an image").unwrap();
        assert_eq!(slash_command_body(dropped.to_str().unwrap()), None);
        std::fs::remove_dir_all(dropped.parent().unwrap()).unwrap();
        // …while a name with no path evidence still reaches the unknown-command notice.
        assert!(!path_exists_on_disk(Path::new("/helpp")));
        assert_eq!(slash_command_body("/helpp"), Some("helpp"));
    }

    /// N-2 (draft loss): `take_submit` clears the composer BEFORE dispatch, so a name the registry
    /// does not serve used to consume the line as well as reject it. The Enter lane now puts an
    /// unknown command back; a recognized one is still consumed.
    #[test]
    fn an_unknown_command_returns_the_line_to_the_composer() {
        for (line, survives) in [("/helpp", true), ("/help", false)] {
            let mut app = App::new();
            app.editor.insert_str(line);
            let trimmed = app.editor.text().trim().to_string();
            let cmd = slash_command_body(&trimmed).expect("a typo is still a command");
            let restore = commands::parse(cmd).is_err().then(|| trimmed.clone());
            let _ = app.editor.take_submit();
            if let Some(draft) = restore {
                app.editor.insert_str(&draft);
            }
            assert_eq!(
                app.editor.text(),
                if survives { line } else { "" },
                "{line:?} draft handling regressed"
            );
        }
    }

    #[test]
    fn scrolling_up_holds_the_view_when_new_output_arrives() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new();
        for index in 0..40 {
            app.note(block::NoticeLevel::Info, format!("historical row {index}"));
        }
        let mut terminal = Terminal::new(TestBackend::new(60, 14)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let bottom_scroll = app.view_scroll;
        app.scroll_up(8);
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert_eq!(
            app.view_scroll,
            bottom_scroll.saturating_sub(8),
            "the first PageUp delta remains exact when the reading shelf appears"
        );
        let prior_scroll = app.view_scroll;
        let prior_offset = app.bottom_offset;
        app.note(block::NoticeLevel::Info, "new output while reading");
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(!app.follow_tail);
        assert_eq!(
            app.view_scroll, prior_scroll,
            "logical viewport stays anchored"
        );
        assert!(app.bottom_offset > prior_offset);
        assert_eq!(app.unread_updates, 1);
        assert!(buffer_text(&terminal).contains("new output"));
    }

    #[test]
    fn the_render_loop_is_event_driven_and_coalesces_a_delta_burst_into_one_frame() {
        // The loop used to block in a stdin poll for a fixed 100 ms while running and 1 s while
        // idle, and only afterwards drain the event queue — so a delta batch landing 1 ms into a
        // poll waited out the remaining 99 ms, and an idle session woke every second for nothing.
        // The wait is now a select whose only timeout is a deadline something actually asked for.
        let now = Instant::now();
        assert_eq!(
            next_wake(false, now, false, now, None),
            None,
            "an idle session schedules no wakeup at all: it sleeps on input and events"
        );
        // A burst costs one frame: the first change draws, the rest fold into the frame held until
        // the coalescing deadline, which is the only thing the loop waits for.
        let next_frame_at = now + FRAME_COALESCE;
        assert_eq!(
            next_wake(true, next_frame_at, false, now, None),
            Some(next_frame_at)
        );
        assert!(
            FRAME_COALESCE < SPINNER_TICK,
            "visible token latency is bounded by coalescing, not by the old input-poll period"
        );
        // A live run animates off its own clock, and a queued tool card has its own anti-flash
        // deadline. Whichever comes first wins; nothing polls for the others.
        assert_eq!(
            next_wake(false, next_frame_at, true, now, None),
            Some(now + SPINNER_TICK)
        );
        let reveal = now + Duration::from_millis(3);
        assert_eq!(
            next_wake(true, next_frame_at, true, now, Some(reveal)),
            Some(reveal)
        );
    }

    #[test]
    fn a_frame_materialises_only_the_viewport_and_reproduces_the_unwindowed_rows() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        // Transcript rows as text, minus the final column reserved for the overflow scrollbar.
        fn transcript_rows(
            term: &ratatui::Terminal<ratatui::backend::TestBackend>,
            top: u16,
            height: u16,
        ) -> Vec<String> {
            let buf = term.backend().buffer();
            (top..top.saturating_add(height))
                .map(|y| {
                    (0..buf.area.width.saturating_sub(1))
                        .map(|x| buf[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect()
        }

        let mut app = App::new();
        for index in 0..40 {
            app.note(
                block::NoticeLevel::Info,
                format!("historical row {index:03}"),
            );
        }
        // A terminal tall enough to hold the whole transcript needs no window, so its frame is the
        // reference the windowed frame has to reproduce exactly.
        let mut tall = Terminal::new(TestBackend::new(60, 120)).unwrap();
        tall.draw(|frame| draw(frame, &mut app)).unwrap();
        assert_eq!(app.view_scroll, 0, "the reference frame shows every row");
        let reference = transcript_rows(&tall, app.view_top, app.view_h);
        let total = usize::from(app.last_total_rows);
        assert!(total > 0 && total <= reference.len());

        let mut short = Terminal::new(TestBackend::new(60, 14)).unwrap();
        short.draw(|frame| draw(frame, &mut app)).unwrap();
        let view_h = usize::from(app.view_h);
        assert!(
            total > view_h,
            "the transcript has to overflow to be a test"
        );
        assert_eq!(
            usize::from(app.last_total_rows),
            total,
            "windowing changes what is built, never how tall the transcript is"
        );
        assert_eq!(
            app.row_map.len(),
            view_h,
            "the frame materialises one row per VISIBLE row, not one per transcript row"
        );
        assert_eq!(
            transcript_rows(&short, app.view_top, app.view_h),
            reference[total - view_h..total],
            "the tail window is byte-identical to the unwindowed render"
        );

        app.scroll_up(9);
        short.draw(|frame| draw(frame, &mut app)).unwrap();
        let scroll = usize::from(app.view_scroll);
        assert!(scroll > 0 && scroll + view_h <= total);
        let rows = transcript_rows(&short, app.view_top, app.view_h);
        assert_eq!(
            rows,
            reference[scroll..scroll + view_h],
            "a scrolled window is byte-identical to the same slice of the unwindowed render"
        );

        // `row_map` is what a mouse click indexes. It now covers the viewport only, so the click row
        // IS the index; the old scroll-relative index would run off the end of a scrolled frame.
        assert_eq!(app.row_map.len(), view_h);
        let mut checked = 0;
        for (idx, row) in rows.iter().enumerate() {
            let Some(at) = row.find("historical row ") else {
                continue;
            };
            let marker = row[at..at + "historical row 000".len()].to_string();
            let expected = app
                .transcript
                .iter()
                .position(|candidate| candidate.to_text().contains(&marker))
                .expect("the rendered notice is still in the transcript");
            assert_eq!(
                app.row_map[idx], expected,
                "viewport row {idx} must fold the block drawn on it"
            );
            checked += 1;
        }
        assert!(checked >= 3, "the window showed {checked} notice rows");

        // Frame cost is independent of session length: ten times the history, same materialisation.
        app.follow_latest();
        for index in 40..440 {
            app.note(
                block::NoticeLevel::Info,
                format!("historical row {index:03}"),
            );
        }
        short.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(usize::from(app.last_total_rows) > total * 5);
        assert_eq!(app.row_map.len(), view_h);
    }

    #[test]
    fn overflow_scrollbar_never_overwrites_the_final_transcript_cell() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let target = format!("{}Z", "x".repeat(114));
        let mut rows = (0..40)
            .map(|index| block::PanelRow::Note(format!("historical row {index:03}")))
            .collect::<Vec<_>>();
        rows.push(block::PanelRow::Note(target.clone()));
        let mut app = App::new();
        app.panel("", "commands", rows);

        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(
            app.last_total_rows > app.view_h,
            "the scrollbar must be visible"
        );

        let buffer = terminal.backend().buffer();
        let content = (app.view_top..app.view_top.saturating_add(app.view_h))
            .flat_map(|y| {
                (0..buffer.area.width.saturating_sub(1))
                    .flat_map(move |x| buffer[(x, y)].symbol().chars())
            })
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(
            content.contains(&target),
            "the scrollbar gutter must not erase the last content cell"
        );
    }

    #[test]
    fn unread_signal_tracks_visible_change_not_transport_noise() {
        let mut app = App::new();
        app.scroll_up(1);
        app.stream_text("sk-ant-api03-AbCd");
        assert_eq!(
            app.unread_updates, 0,
            "a scrubber-held credential fragment produced no visible output"
        );
        app.workflow_event(WorkflowUiEvent::PhaseChanged {
            run_id: "unknown-run".into(),
            phase: WorkflowPhaseUi::Exploring,
        });
        assert_eq!(app.unread_updates, 0, "unknown workflow event is a no-op");
        app.stream_text(" plain text ");
        assert_eq!(app.unread_updates, 1);
    }

    #[test]
    fn popup_keeps_selected_detail_discoverable_on_compact_width() {
        let mut app = App::new();
        app.editor.insert_str("/m");
        app.completion = Some(Completion {
            items: vec![(
                "model".into(),
                "choose a provider, family, and available model".into(),
            )],
            sel: 0,
            token_start: 1,
            lead: '/',
        });
        let screen = render_text(&mut app, 56, 18);
        assert!(screen.contains("/model"));
        assert!(screen.contains("provider, family"));
    }

    #[test]
    fn popup_detail_wraps_by_screen_rows_instead_of_clipping_to_one_line() {
        let rows = popup_detail_lines(
            "credential is missing; configure the provider in settings before selecting this model",
            24,
            4,
            Style::default(),
        );
        assert!(
            rows.len() > 1,
            "long detail must occupy multiple screen rows"
        );
        assert!(
            rows.iter()
                .all(|line| crate::render::line_width(line) <= 24),
            "every detail row stays within the popup's cell width"
        );
        let text = rows
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(
            text.contains("settings"),
            "later wrapped detail remains visible"
        );
    }

    #[test]
    fn short_popup_keeps_a_list_row_and_action_legend() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let rows = vec![
            PopupRow {
                lead: "model-a".into(),
                lead_accent: false,
                aux: "a long model explanation that cannot own the short screen".into(),
                enabled: true,
            },
            PopupRow {
                lead: "model-b".into(),
                lead_accent: false,
                aux: String::new(),
                enabled: true,
            },
        ];
        let mut terminal = Terminal::new(TestBackend::new(56, 4)).unwrap();
        terminal
            .draw(|frame| {
                render_list_popup(
                    frame,
                    Rect::new(0, 4, 56, 0),
                    "model",
                    &rows,
                    0,
                    None,
                    &theme::Theme::dark(),
                );
            })
            .unwrap();
        let screen = buffer_text(&terminal);
        assert!(screen.contains("model-a"), "navigation row survives");
        assert!(screen.contains("enter"), "accept action survives");
        assert!(screen.contains("esc"), "cancel action survives");
    }

    #[test]
    fn standard_popup_has_one_rounded_frame_left_aligned_to_its_anchor() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let rows = vec![PopupRow {
            lead: "glm-5.2".into(),
            lead_accent: false,
            aux: "current route".into(),
            enabled: true,
        }];
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                render_list_popup(
                    frame,
                    Rect::new(3, 20, 74, 3),
                    "Model",
                    &rows,
                    0,
                    None,
                    &theme::Theme::dark(),
                );
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let corner = (0..24)
            .flat_map(|y| (0..80).map(move |x| (x, y)))
            .find(|(x, y)| buffer[(*x, *y)].symbol() == "╭")
            .expect("rounded popup corner");
        assert_eq!(corner.0, 3, "popup begins on the anchor's text column");
        let rounded = (0..24)
            .flat_map(|y| (0..80).map(move |x| (x, y)))
            .filter(|(x, y)| matches!(buffer[(*x, *y)].symbol(), "╭" | "╮" | "╰" | "╯"))
            .count();
        assert_eq!(rounded, 4, "one popup frame has exactly four corners");
    }

    #[test]
    fn terminal_native_surface_does_not_paint_desktop_layers() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();
        let painted = buffer
            .content()
            .iter()
            .filter(|cell| cell.bg == app.theme.user_bg)
            .count();
        assert!(
            painted > 0 && painted <= usize::from(surface::LANDING_MAX_WIDTH) * 3,
            "only the bounded composer paints its neutral input surface: {painted} cells"
        );
        assert!(
            buffer
                .content()
                .iter()
                .all(|cell| cell.bg == Color::Reset || cell.bg == app.theme.user_bg),
            "the terminal stage and brand entrance remain unpainted"
        );
        let screen = buffer_text(&terminal);
        assert!(screen.contains("▄██"), "Plantcore icon is visible");
        assert!(!screen.contains("Prompt"));
        assert!(screen.contains('▌'));
        assert!(screen.contains('›'));
    }

    #[test]
    fn composer_shows_prompt_marker_and_ghost_placeholder() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(80, 12)).unwrap();
        let mut app = App::new();
        // Empty + idle → the › prompt marker and the ghost placeholder are both visible.
        term.draw(|f| draw(f, &mut app)).unwrap();
        let screen = buffer_text(&term);
        assert!(
            screen.contains('›'),
            "empty composer shows the › prompt marker"
        );
        assert!(
            screen.contains("ask about this codebase"),
            "empty composer shows a quiet task placeholder"
        );
        // A `!shell` buffer flips the marker to `!` (bash mode) and hides the placeholder.
        app.editor.insert_str("!ls");
        let mut term2 = Terminal::new(TestBackend::new(80, 12)).unwrap();
        term2.draw(|f| draw(f, &mut app)).unwrap();
        let s2 = buffer_text(&term2);
        assert!(s2.contains("ls"), "typed shell command is shown");
        assert!(
            !s2.contains("ask Core"),
            "placeholder hidden once typing starts"
        );

        // Running keeps a real composer and teaches the steer/queue split instead of claiming Send.
        app.editor.clear();
        app.running = true;
        app.track_steer("also cover narrow terminals".into());
        let mut term3 = Terminal::new(TestBackend::new(100, 12)).unwrap();
        term3.draw(|f| draw(f, &mut app)).unwrap();
        let s3 = buffer_text(&term3);
        assert!(s3.contains("steer the current run"));
        assert!(s3.contains("also cover narrow terminals"));
        assert!(s3.contains("steer"));
        assert!(s3.contains("tab queue"));
        assert!(s3.contains("1 pending"));
    }

    #[test]
    fn command_token_first_token_coloring() {
        // TUI v3 §8: the leading sigil token is colored so you SEE the mode as you type.
        let th = theme::Theme::dark();
        let (tok, rest, col) = command_token("/model foo", &th).expect("slash token");
        assert_eq!(tok, "/model");
        assert_eq!(rest, " foo");
        assert_eq!(col, th.accent);
        assert_eq!(
            command_token("!ls -la", &th).unwrap().2,
            th.warn,
            "! shell token = warn"
        );
        assert_eq!(command_token("@src/x.rs", &th).unwrap().0, "@src/x.rs");
        assert!(
            command_token("just a task", &th).is_none(),
            "plain prose has no command token"
        );
    }

    #[derive(Clone)]
    struct ClientParityCapture {
        one_shot: serde_json::Value,
        headless: serde_json::Value,
        tui: serde_json::Value,
        tui_status: String,
    }

    fn pairwise_result_equality(capture: &ClientParityCapture) -> [bool; 3] {
        [
            capture.one_shot == capture.headless,
            capture.headless == capture.tui,
            capture.tui == capture.one_shot,
        ]
    }

    fn one_shot_terminal_result(summary: &app_server::TerminalSummary) -> serde_json::Value {
        // This is the exact constructor used by the one-shot client after it receives RunEnded.
        // Do not route this leg through TerminalSummary::result_v5: an accidental sibling-client
        // normalizer must remain observable to this parity proof.
        crate::output::final_result(
            &summary.outcome,
            &summary.assistant_text,
            &summary.run_id,
            &summary.cost,
            summary.turns,
            summary.kernel_tax,
            summary.error.as_deref(),
        )
    }

    fn tui_terminal_result(summary: &app_server::TerminalSummary) -> (serde_json::Value, String) {
        let mut app = App::new();
        app.running = true;
        let (sq, _rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(sq);
        let event = app_server::ServerEvent::RunEnded {
            snapshot: Box::new(app_server::SessionSnapshot {
                mode: PermissionMode::default(),
                effort: Effort::default(),
                model: "test-model".into(),
                cost: summary.cost.clone(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                ledger_summary: String::new(),
                rate_limit: None,
                mcp_health: Vec::new(),
            }),
            summary: Box::new(summary.clone()),
        };
        let mut notifier = notification::TerminalNotifier::new(false);
        notifier.begin_run();
        let mut notification_bytes = Vec::new();
        let interrupt = Arc::new(AtomicBool::new(false));
        let drain = Arc::new(AtomicBool::new(false));

        // Exercise the TUI's real RunEnded branch, including its native status projection. The
        // canonical object is retained internally for parity; it is not printed as machine JSON.
        apply_server_event(
            &mut app,
            &mut session,
            event,
            &mut notifier,
            &mut notification_bytes,
            &interrupt,
            &drain,
        );

        (
            app.last_result
                .expect("RunEnded stores the canonical result"),
            app.status,
        )
    }

    fn capture_client_parity(summary: &app_server::TerminalSummary) -> ClientParityCapture {
        let one_shot = one_shot_terminal_result(summary);
        // Destructuring the versioned transport frame is the sole normalization in this proof.
        // Every result-v5 field remains untouched and participates in raw Value equality.
        let (protocol_version, seq, headless) =
            headless::capture_terminal_result_frame(41, summary);
        assert_eq!(protocol_version, iteron_protocol::PROTOCOL_VERSION);
        assert_eq!(seq, 41);
        let (tui, tui_status) = tui_terminal_result(summary);
        ClientParityCapture {
            one_shot,
            headless,
            tui,
            tui_status,
        }
    }

    #[test]
    fn three_client_production_paths_are_pairwise_identical_for_every_terminal_outcome() {
        let cases = [
            (iteron_protocol::Outcome::Done, "done", 0_u64),
            (iteron_protocol::Outcome::Drained, "drained", 0),
            (
                iteron_protocol::Outcome::BudgetExhausted("max_turns"),
                "budget_exhausted",
                3,
            ),
            (iteron_protocol::Outcome::Interrupted, "interrupted", 130),
            (iteron_protocol::Outcome::Stuck, "stuck", 4),
            (iteron_protocol::Outcome::HarnessError, "harness_error", 2),
        ];

        for (outcome, expected_outcome, expected_exit_code) in cases {
            let summary = app_server::TerminalSummary {
                error: matches!(&outcome, iteron_protocol::Outcome::HarnessError)
                    .then(|| "synthetic harness failure".into()),
                outcome,
                assistant_text: "parity reply".into(),
                run_id: "run-client-parity".into(),
                cost: CostState::default(),
                turns: 1,
                kernel_tax: iteron_obs::KernelTax::default(),
                memo_hits: 0,
                memo_misses: 0,
            };
            let capture = capture_client_parity(&summary);

            assert_eq!(
                pairwise_result_equality(&capture),
                [true, true, true],
                "{expected_outcome} diverged across production client projections"
            );
            for result in [&capture.one_shot, &capture.headless, &capture.tui] {
                assert_eq!(result["outcome"], expected_outcome);
                assert_eq!(
                    result["exit_code"].as_u64(),
                    Some(expected_exit_code),
                    "{expected_outcome} changed its process contract"
                );
            }
            assert_eq!(
                capture.tui_status,
                format!("idle · last: {expected_outcome}"),
                "native TUI presentation is checked separately from machine-object parity"
            );

            // Normalizer canary: a substantive field changed in only one captured result must not
            // be erased by envelope handling or a presentation-oriented comparison.
            let mut divergent = capture.clone();
            divergent.headless["assistant_text"] =
                serde_json::Value::String("headless-only mutation".into());
            assert_eq!(
                pairwise_result_equality(&divergent),
                [false, false, true],
                "raw pairwise equality must expose a one-client result-v5 mutation"
            );

            // Source-mutation canary: changing the shared authority must move all three production
            // outputs together and preserve parity, proving the assertion is not three literals.
            let mut changed_summary = summary.clone();
            changed_summary.assistant_text = "parity reply after summary mutation".into();
            let changed = capture_client_parity(&changed_summary);
            assert_eq!(pairwise_result_equality(&changed), [true, true, true]);
            assert_ne!(changed.one_shot, capture.one_shot);
            assert_ne!(changed.headless, capture.headless);
            assert_ne!(changed.tui, capture.tui);
            assert_eq!(
                changed.one_shot["assistant_text"],
                "parity reply after summary mutation"
            );
        }
    }

    #[test]
    fn run_terminal_chrome_is_derived_from_the_canonical_result_v5_object() {
        let mut app = App::new();
        app.running = true;
        let (sq, _rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(sq);
        let summary = app_server::TerminalSummary {
            outcome: iteron_protocol::Outcome::Done,
            assistant_text: "the typed answer".into(),
            run_id: "run-tui-parity".into(),
            cost: CostState::default(),
            turns: 3,
            kernel_tax: iteron_obs::KernelTax::default(),
            error: None,
            memo_hits: 0,
            memo_misses: 0,
        };
        let expected = crate::output::final_result(
            &summary.outcome,
            &summary.assistant_text,
            &summary.run_id,
            &summary.cost,
            summary.turns,
            summary.kernel_tax,
            summary.error.as_deref(),
        );
        let event = app_server::ServerEvent::RunEnded {
            snapshot: Box::new(app_server::SessionSnapshot {
                mode: PermissionMode::default(),
                effort: Effort::default(),
                model: "test-model".into(),
                cost: CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                ledger_summary: String::new(),
                rate_limit: None,
                mcp_health: Vec::new(),
            }),
            summary: Box::new(summary),
        };
        let mut notifier = notification::TerminalNotifier::new(true);
        notifier.begin_run();
        let mut notification_bytes = Vec::new();
        let interrupt = Arc::new(AtomicBool::new(false));
        let drain = Arc::new(AtomicBool::new(false));

        apply_server_event(
            &mut app,
            &mut session,
            event,
            &mut notifier,
            &mut notification_bytes,
            &interrupt,
            &drain,
        );

        assert_eq!(app.last_result.as_ref(), Some(&expected));
        assert_eq!(app.status, "idle · last: done");
        assert_eq!(
            notification_bytes, b"\x07",
            "the authoritative RunEnded boundary emits one run-complete notification"
        );
    }

    #[test]
    fn interrupted_run_ended_releases_input_and_preserves_the_next_prompt_for_dispatch() {
        let mut app = App::new();
        app.running = true;
        app.interrupting = true;
        app.draining = true;
        app.queue_after_turn("continue with the next task".into())
            .unwrap();
        let queued = app.queued.front().cloned().unwrap();
        let (sq, _rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(sq);
        let event = app_server::ServerEvent::RunEnded {
            snapshot: Box::new(app_server::SessionSnapshot {
                mode: PermissionMode::default(),
                effort: Effort::default(),
                model: "test-model".into(),
                cost: CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                ledger_summary: String::new(),
                rate_limit: None,
                mcp_health: Vec::new(),
            }),
            summary: Box::new(app_server::TerminalSummary {
                outcome: iteron_protocol::Outcome::Interrupted,
                assistant_text: String::new(),
                run_id: "run-interrupt-handoff".into(),
                cost: CostState::default(),
                turns: 1,
                kernel_tax: iteron_obs::KernelTax::default(),
                error: None,
                memo_hits: 0,
                memo_misses: 0,
            }),
        };
        let mut notifier = notification::TerminalNotifier::new(false);
        notifier.begin_run();
        let mut notification_bytes = Vec::new();
        let interrupt = Arc::new(AtomicBool::new(true));
        let drain = Arc::new(AtomicBool::new(true));

        apply_server_event(
            &mut app,
            &mut session,
            event,
            &mut notifier,
            &mut notification_bytes,
            &interrupt,
            &drain,
        );

        assert!(!app.running, "RunEnded returns the composer to idle");
        assert!(!app.interrupting);
        assert!(!app.draining);
        assert!(!interrupt.load(Ordering::Relaxed));
        assert!(!drain.load(Ordering::Relaxed));
        assert_eq!(app.queued.front(), Some(&queued));
        assert_eq!(app.status, "idle · last: interrupted");
    }

    /// A budget stop is not an error, so it produced no block at all: the operator saw
    /// `idle · last: budget_exhausted` and nothing about the session turn ceiling being raisable
    /// in place. The terminal boundary has to say what clears the ceiling it just hit.
    #[test]
    fn a_budget_stop_tells_the_operator_which_ceiling_and_how_to_clear_it() {
        let mut app = App::new();
        app.running = true;
        let (sq, _rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(sq);
        let event = app_server::ServerEvent::RunEnded {
            snapshot: Box::new(app_server::SessionSnapshot {
                mode: PermissionMode::default(),
                effort: Effort::default(),
                model: "test-model".into(),
                cost: CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                ledger_summary: String::new(),
                rate_limit: None,
                mcp_health: Vec::new(),
            }),
            summary: Box::new(app_server::TerminalSummary {
                outcome: iteron_protocol::Outcome::BudgetExhausted("max_turns"),
                assistant_text: String::new(),
                run_id: "run-budget-remedy".into(),
                cost: CostState::default(),
                turns: 40,
                kernel_tax: iteron_obs::KernelTax::default(),
                error: None,
                memo_hits: 0,
                memo_misses: 0,
            }),
        };
        let mut notifier = notification::TerminalNotifier::new(false);
        notifier.begin_run();
        let mut notification_bytes = Vec::new();
        let interrupt = Arc::new(AtomicBool::new(false));
        let drain = Arc::new(AtomicBool::new(false));

        apply_server_event(
            &mut app,
            &mut session,
            event,
            &mut notifier,
            &mut notification_bytes,
            &interrupt,
            &drain,
        );

        assert_eq!(app.status, "idle · last: budget_exhausted");
        let notice = app
            .transcript
            .last()
            .expect("the budget stop leaves a notice")
            .to_text();
        assert!(notice.contains("max_turns"), "{notice:?} names the ceiling");
        assert!(
            notice.contains("/budget"),
            "{notice:?} names the in-session command that raises the ceiling"
        );
    }

    #[test]
    fn welcome_is_a_responsive_plantcore_icon_in_the_transcript() {
        let app = App::new();
        let wide: String = app.transcript[0]
            .render(80, &app.theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(wide.contains("▄██"), "Plantcore icon present: {wide:?}");
        assert!(
            wide.contains("Build, explain, and verify"),
            "tagline present: {wide:?}"
        );
        let rows = app.transcript[0].render(20, &app.theme, 0);
        for r in &rows {
            assert!(
                crate::render::line_width(r) <= 20,
                "narrow welcome stays within width"
            );
        }
        let narrow: String = rows
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(narrow.contains("iteron"), "narrow Core marker: {narrow:?}");
    }

    #[test]
    fn welcome_icon_is_one_startup_block_and_scrolls_away() {
        let mut app = App::new();
        assert_eq!(
            app.transcript
                .iter()
                .filter(|block| matches!(block.kind, block::BlockKind::Welcome { .. }))
                .count(),
            1
        );
        let first = render_text(&mut app, 40, 12);
        assert!(first.contains("▄██"));
        for index in 0..32 {
            app.push_user(format!(
                "later task {index}: keep the active transcript at the tail"
            ));
        }
        let tail = render_text(&mut app, 40, 12);
        assert!(!tail.contains("▄██"), "the brand is entrance, not chrome");
        assert_eq!(
            app.transcript
                .iter()
                .filter(|block| matches!(block.kind, block::BlockKind::Welcome { .. }))
                .count(),
            1,
            "redraw and scrolling never duplicate the welcome"
        );
    }

    #[test]
    fn newest_line_visible_when_transcript_wraps() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(40, 12)).unwrap();
        let mut app = App::new();
        // many LONG lines that wrap at width 40, then a short newest line.
        for i in 0..40 {
            app.push(fg(Color::White), format!("row {i} {}", "x".repeat(80)));
        }
        app.push(fg(Color::White), "NEWESTMARKER");
        app.bottom_offset = 0; // pinned to bottom
        term.draw(|f| draw(f, &mut app)).unwrap();
        let content: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            content.contains("NEWESTMARKER"),
            "the newest line must render when earlier lines wrap (CRITICAL scroll fix)"
        );
    }

    #[test]
    fn slash_completion_menu_opens_and_accepts() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("/mod");
        app.refresh_completion(&repo);
        let comp = app.completion.as_ref().expect("slash menu should open");
        assert!(
            comp.items.iter().any(|(n, _)| n == "model" || n == "mode"),
            "expected model/mode"
        );
        assert_eq!(comp.lead, '/');
        app.accept_completion();
        let text = app.editor.text();
        assert!(
            text.starts_with('/') && text.ends_with(' '),
            "accepted: {text:?}"
        );
    }

    #[test]
    fn slash_completion_enter_submits_optional_command_exactly_once() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("/per");
        app.refresh_completion(&repo);
        assert!(
            app.accept_completion_for_enter(),
            "permissions is runnable without an argument and should activate on Enter"
        );
        assert_eq!(app.editor.text(), "/permissions ");
        assert!(app.completion.is_none());
        assert!(
            !app.accept_completion_for_enter(),
            "the consumed completion cannot emit a second submit signal"
        );
    }

    #[test]
    fn slash_completion_enter_keeps_required_arguments_editable() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("/mem");
        app.refresh_completion(&repo);
        assert!(
            !app.accept_completion_for_enter(),
            "memory requires an argument, so Enter completes without dispatching"
        );
        assert_eq!(app.editor.text(), "/memory ");
        assert!(app.completion.is_none());
    }

    #[test]
    fn at_file_completion_lists_and_accepts() {
        let dir = std::env::temp_dir().join(format!("core-tuifc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hello.txt"), "x").unwrap();
        let mut app = App::new();
        app.editor.insert_str("look @hel");
        app.refresh_completion(&dir);
        let comp = app.completion.as_ref().expect("@file menu should open");
        assert_eq!(comp.lead, '@');
        assert!(comp.items.iter().any(|(p, _)| p == "hello.txt"));
        app.accept_completion();
        assert!(
            app.editor.text().contains("@hello.txt"),
            "got {:?}",
            app.editor.text()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_completion_replaces_whole_token_mid_cursor() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("/model");
        app.editor.home();
        for _ in 0..4 {
            app.editor.right();
        } // cursor in the middle: "/mod|el"
        app.refresh_completion(&repo);
        assert!(app.completion.is_some());
        app.accept_completion();
        let t = app.editor.text();
        assert!(
            t.starts_with("/model "),
            "whole token replaced, no leftover suffix: {t:?}"
        );
        assert!(
            !t.contains("modelel") && !t.contains("modele"),
            "no corruption: {t:?}"
        );
    }

    #[test]
    fn complete_path_refuses_traversal() {
        assert!(complete_path(std::path::Path::new("/tmp"), "../etc").is_empty());
        assert!(complete_path(std::path::Path::new("/tmp"), "/etc/passwd").is_empty());
    }

    #[test]
    fn no_menu_for_plain_text_or_multiline() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("just a task");
        app.refresh_completion(&repo);
        assert!(app.completion.is_none());
        app.editor.clear();
        app.editor.insert_str("/mode");
        app.editor.newline();
        app.refresh_completion(&repo);
        assert!(app.completion.is_none(), "no menu in multi-line");

        app.editor.clear();
        app.editor.insert_str("/mod");
        app.running = true;
        app.refresh_completion(&repo);
        assert!(
            app.completion.is_some(),
            "running follow-ups keep slash/@ completion"
        );
    }

    #[test]
    fn apply_event_updates_state() {
        let mut app = App::new();
        let before_start = app.transcript.len();
        apply_event(
            &mut app,
            UiEvent::ToolStart {
                id: "t1".into(),
                name: "read_file".into(),
                args: serde_json::json!({"path":"a"}),
            },
        );
        // Activity is immediate, but the transcript waits out the anti-flash reveal delay.
        assert!(!app.tool_index.contains_key("t1"));
        assert_eq!(app.pending_tools.len(), 1);
        assert_eq!(app.transcript.len(), before_start);
        assert!(app.active_tools.iter().any(|(id, _)| id == "t1"));
        let reveal_at = app.pending_tools.front().unwrap().reveal_deadline;
        assert!(app.advance_tool_presentations(reveal_at));
        assert!(app.tool_index.contains_key("t1"));
        assert!(
            app.transcript
                .last()
                .unwrap()
                .to_text()
                .contains("read_file")
        );
        // ToolEnd mutates the SAME card (by id, R2), not a new sibling
        let before = app.transcript.len();
        apply_event(
            &mut app,
            UiEvent::ToolEnd {
                id: "t1".into(),
                ok: true,
                exit_code: None,
                output: "ok".into(),
                diff: None,
            },
        );
        assert_eq!(
            app.transcript.len(),
            before,
            "ToolEnd mutates the originating card, not a new block"
        );
        let theme = theme::Theme::dark();
        let rendered: String = app
            .transcript
            .last()
            .unwrap()
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        // Completion is the marker + `  ⎿  ` connector summary now (no ✓ dingbat — TUI v3 §4).
        assert!(
            rendered.contains(block::CONNECTOR),
            "completed card shows the '  ⎿  ' result connector"
        );
        assert!(
            rendered.contains("Read"),
            "completed card shows the CC-style result summary"
        );
        assert!(
            !rendered.contains('✓'),
            "status is the marker color, not a ✓ glyph"
        );
        apply_event(
            &mut app,
            turn_end(
                0.05,
                Usage {
                    input: 50,
                    cache_read: 50,
                    ..Usage::default()
                },
            ),
        );
        assert_eq!(app.cost.usd(), Some(0.05));
        assert_eq!(
            app.last_turn_usage.map(|usage| usage.cache_hit_ratio()),
            Some(0.5)
        );
        app.track_steer("first".into());
        app.track_steer("second".into());
        apply_event(&mut app, UiEvent::SteerApplied { count: 1 });
        assert_eq!(app.steer_previews.len(), 1);
        assert_eq!(app.steer_previews.front().unwrap().text, "second");
    }

    #[test]
    fn tool_projection_is_hidden_for_300ms_then_reveals_deterministically() {
        let mut app = App::new();
        let base = app.transcript.len();
        let started = Instant::now();
        app.tool_start_at(
            "slow-read".into(),
            "read_file".into(),
            serde_json::json!({"path":"src/lib.rs"}),
            started,
        );

        assert_eq!(app.transcript.len(), base);
        assert!(app.active_tools.iter().any(|(id, _)| id == "slow-read"));
        assert!(
            !app.advance_tool_presentations(started + TOOL_REVEAL_DELAY - Duration::from_millis(1))
        );
        assert_eq!(app.transcript.len(), base);
        assert!(app.advance_tool_presentations(started + TOOL_REVEAL_DELAY));
        assert_eq!(app.transcript.len(), base + 1);
        assert!(app.tool_index.contains_key("slow-read"));
        assert!(matches!(
            app.transcript.last().map(|block| &block.kind),
            Some(block::BlockKind::Tool(block::ToolCard {
                status: block::ToolStatus::Running,
                ..
            }))
        ));
    }

    #[test]
    fn fast_tool_completion_inserts_one_settled_audit_card_without_running_flash() {
        let mut app = App::new();
        let base = app.transcript.len();
        let started = Instant::now();
        app.tool_start_at(
            "fast-read".into(),
            "read_file".into(),
            serde_json::json!({"path":"src/lib.rs"}),
            started,
        );
        app.tool_end_at(
            "fast-read",
            true,
            None,
            "1\tpub fn run() {}".into(),
            None,
            started + Duration::from_millis(42),
        );

        assert_eq!(app.transcript.len(), base + 1);
        assert!(app.pending_tools.is_empty());
        assert!(app.active_tools.is_empty());
        assert!(!app.tool_index.contains_key("fast-read"));
        let block::BlockKind::Tool(card) = &app.transcript.last().unwrap().kind else {
            panic!("expected a settled tool card");
        };
        assert_eq!(card.status, block::ToolStatus::Ok);
        assert_eq!(card.elapsed, Some(Duration::from_millis(42)));
        assert_eq!(card.output, "1\tpub fn run() {}");
    }

    #[test]
    fn run_completion_terminalizes_pending_and_revealed_tool_cards() {
        let mut app = App::new();
        let started = Instant::now();
        app.tool_start_at(
            "pending".into(),
            "read_file".into(),
            serde_json::json!({"path":"a"}),
            started,
        );
        app.tool_start_at(
            "revealed".into(),
            "bash".into(),
            serde_json::json!({"command":"true"}),
            started,
        );
        assert!(app.advance_tool_presentations(started + TOOL_REVEAL_DELAY));

        app.settle_unfinished_tools();

        assert!(app.pending_tools.is_empty());
        assert!(app.tool_index.is_empty());
        assert!(app.active_tools.is_empty());
        let cards: Vec<_> = app
            .transcript
            .iter()
            .filter_map(|block| match &block.kind {
                block::BlockKind::Tool(card) => Some(card),
                _ => None,
            })
            .collect();
        assert_eq!(cards.len(), 2);
        assert!(
            cards
                .iter()
                .all(|card| card.status == block::ToolStatus::Err)
        );
        assert!(
            cards
                .iter()
                .all(|card| card.output.contains("without a terminal event"))
        );
    }

    #[test]
    fn fast_failures_and_diffs_are_never_suppressed() {
        let mut app = App::new();
        let started = Instant::now();
        app.tool_start_at(
            "failed".into(),
            "grep".into(),
            serde_json::json!({"pattern":"needle"}),
            started,
        );
        app.tool_end_at(
            "failed",
            false,
            Some(2),
            "permission denied".into(),
            None,
            started + Duration::from_millis(10),
        );
        app.tool_start_at(
            "edited".into(),
            "edit".into(),
            serde_json::json!({"path":"src/lib.rs"}),
            started,
        );
        app.tool_end_at(
            "edited",
            true,
            None,
            "updated".into(),
            Some(iteron_protocol::FileDiff::from_replacement(
                "src/lib.rs",
                "old",
                "new",
            )),
            started + Duration::from_millis(20),
        );

        let cards = app
            .transcript
            .iter()
            .filter_map(|block| match &block.kind {
                block::BlockKind::Tool(card) => Some(card),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].status, block::ToolStatus::Err);
        assert_eq!(cards[0].output, "permission denied");
        assert!(cards[1].diff.is_some());
    }

    #[test]
    fn revealed_success_persists_beyond_the_hook_linger_floor() {
        let mut app = App::new();
        let started = Instant::now();
        app.tool_start_at(
            "visible".into(),
            "list_dir".into(),
            serde_json::json!({"path":"."}),
            started,
        );
        app.advance_tool_presentations(started + TOOL_REVEAL_DELAY);
        let count = app.transcript.len();
        app.tool_end_at(
            "visible",
            true,
            None,
            "src/lib.rs".into(),
            None,
            started + TOOL_REVEAL_DELAY + Duration::from_millis(1),
        );

        // Codex's hook cell lingers a quiet success for 600 ms. Core model-tool events are
        // audit-bearing and have no Ephemeral flag, so the stronger policy is to persist them.
        app.advance_tool_presentations(started + TOOL_REVEAL_DELAY + Duration::from_millis(601));
        assert_eq!(app.transcript.len(), count);
        assert!(matches!(
            app.transcript.last().map(|block| &block.kind),
            Some(block::BlockKind::Tool(block::ToolCard {
                status: block::ToolStatus::Ok,
                ..
            }))
        ));
    }

    #[test]
    fn workflow_run_started_event_pushes_the_live_tree_variant() {
        let mut app = App::new();
        app.workflow_run_ui_event(crate::workflow::WorkflowRunUiEvent::Started {
            run_id: "wf_reachable".into(),
            name: "audit".into(),
            phases: Vec::new(),
        });

        assert!(matches!(
            app.transcript.last().map(|block| &block.kind),
            Some(block::BlockKind::WorkflowRun(card)) if card.run_id == "wf_reachable"
        ));
    }

    #[test]
    fn kernel_activity_updates_status_without_leaking_internal_draft_text() {
        let mut app = App::new();
        app.cur_text = "visible answer".into();
        app.cur_think = "visible reasoning".into();
        app.awaiting_first_token_since = Some(Instant::now());
        let transcript_len = app.transcript.len();

        app.workflow_run_ui_event(crate::workflow::WorkflowRunUiEvent::KernelActivity {
            kind: crate::workflow::KernelActivityKind::Planning,
            output_chars: 1_240,
            thinking_chars: 320,
        });

        assert_eq!(app.status, "planning · 1.2k chars · 320 reasoning");
        assert!(app.awaiting_first_token_since.is_none());
        assert_eq!(app.cur_text, "visible answer");
        assert_eq!(app.cur_think, "visible reasoning");
        assert_eq!(app.transcript.len(), transcript_len);
    }

    #[test]
    fn quickjs_workflow_run_events_upsert_one_live_tree() {
        use iteron_workflow::events::{ProgressEvent, WorkflowState};

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let run_id = "wf_run_1";

        // First event mints the card; subsequent events upsert into the SAME block by run id.
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::Phase {
                index: 1,
                title: "Explore".into(),
            },
        );
        let block_id = app
            .workflow_monitor
            .block_id(run_id)
            .expect("indexed run card");
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::Log {
                message: "scanning".into(),
            },
        );
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::AgentStarted {
                index: 0,
                label: "scan modules".into(),
                phase: Some("Explore".into()),
                model: Some("haiku".into()),
            },
        );
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::AgentFinished {
                index: 0,
                label: "scan modules".into(),
                state: WorkflowState::Done,
                tokens: 1_200,
                tool_calls: 2,
                duration_ms: 3_200,
                result_preview: None,
                last_tool_summary: None,
                error: None,
            },
        );

        // Exactly one WorkflowRun block, still keyed by run id, mutated in place.
        let run_blocks = app
            .transcript
            .iter()
            .filter(|b| matches!(b.kind, block::BlockKind::WorkflowRun(_)))
            .count();
        assert_eq!(run_blocks, 1, "one live tree, not a line-per-event log");
        assert_eq!(app.workflow_monitor.block_id(run_id).unwrap(), block_id);
        let card = match &app
            .transcript
            .iter()
            .find(|b| b.id == block_id)
            .unwrap()
            .kind
        {
            block::BlockKind::WorkflowRun(card) => card,
            _ => unreachable!(),
        };
        assert_eq!(card.agents.len(), 1);
        assert_eq!(card.agents[0].state, WorkflowState::Done);
        assert_eq!(card.phases.len(), 1);
        assert_eq!(card.logs, vec!["scanning".to_string()]);
        assert!(!card.finished);

        // It renders through the transcript draw path.
        let screen = render_text(&mut app, 80, 20);
        assert!(screen.contains("Explore"));
        assert!(screen.contains("ctrl+o expand"));
        assert!(
            !screen.contains("scanning"),
            "the live tree is folded by default"
        );

        // Terminal transition flips `finished` and drops the live index.
        app.workflow_run_finished(run_id);
        assert!(!app.workflow_monitor.is_live(run_id));
        let finished = match &app
            .transcript
            .iter()
            .find(|b| b.id == block_id)
            .unwrap()
            .kind
        {
            block::BlockKind::WorkflowRun(card) => card.finished,
            _ => unreachable!(),
        };
        assert!(finished);
    }

    /// The workflow region's store owns the collapse bit; the card carries the copy the renderer
    /// reads. One fold has to move both, because two bits that can be moved independently is
    /// exactly the drift a parallel store must not introduce.
    #[test]
    fn folding_a_run_tree_moves_the_store_and_the_card_together() {
        use iteron_workflow::events::ProgressEvent;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let run_id = "wf_fold_1";
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::Log {
                message: "scanning".into(),
            },
        );
        let index = app
            .transcript
            .iter()
            .position(|block| matches!(block.kind, block::BlockKind::WorkflowRun(_)))
            .expect("the run minted its card");
        let verbose = |app: &App| match &app.transcript[index].kind {
            block::BlockKind::WorkflowRun(card) => card.verbose,
            _ => unreachable!(),
        };

        assert!(!verbose(&app), "a fresh card collapses its finished agents");
        assert_eq!(app.workflow_monitor.collapsed(run_id), Some(true));

        app.toggle_fold(index);
        assert!(verbose(&app), "the card the renderer reads expanded");
        assert_eq!(
            app.workflow_monitor.collapsed(run_id),
            Some(false),
            "and the store that owns the bit says the same thing"
        );

        app.toggle_fold(index);
        assert!(!verbose(&app));
        assert_eq!(app.workflow_monitor.collapsed(run_id), Some(true));
    }

    /// The wire this slice built: a workflow launched from inside the interactive TUI arrives as
    /// `app_server::ServerEvent::WorkflowRun`, and the operator watches a live tree instead of a
    /// silent turn. Everything below crosses the real seam — `crate::workflow::UiProgressSink` is
    /// what the kernel installs, `workflow_run_ui_event` is what the frontend dispatches to.
    #[test]
    fn a_workflow_launched_in_the_tui_renders_a_live_progress_tree() {
        use iteron_workflow::events::{ProgressEvent, ProgressSink, WorkflowState};

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let run_id = "wf_repl_1";

        // Declared `meta.phases` lay the boxes out before the first agent runs.
        app.workflow_run_ui_event(crate::workflow::WorkflowRunUiEvent::Started {
            run_id: run_id.into(),
            name: "audit".into(),
            phases: vec!["Explore".into(), "Report".into()],
        });
        let block_id = app
            .workflow_monitor
            .block_id(run_id)
            .expect("the card exists before the engine emits anything");

        // The kernel's sink is the only thing between the engine and this channel.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = crate::workflow::UiProgressSink::new(run_id, tx);
        sink.emit(ProgressEvent::Phase {
            index: 1,
            title: "Explore".into(),
        });
        sink.emit(ProgressEvent::Log {
            message: "scanning modules".into(),
        });
        sink.emit(ProgressEvent::AgentQueued {
            index: 0,
            label: "scan modules".into(),
            phase: Some("Explore".into()),
            model: Some("core-model-1".into()),
        });
        sink.emit(ProgressEvent::AgentStarted {
            index: 0,
            label: "scan modules".into(),
            phase: Some("Explore".into()),
            model: Some("core-model-1".into()),
        });
        sink.emit(ProgressEvent::AgentActivity {
            index: 0,
            tokens: 900,
            tool_calls: 1,
            last_tool_summary: Some("read src/lib.rs".into()),
        });
        sink.emit(ProgressEvent::AgentFinished {
            index: 0,
            label: "scan modules".into(),
            state: WorkflowState::Done,
            tokens: 1_200,
            tool_calls: 2,
            duration_ms: 3_200,
            result_preview: Some("14 modules, 2 without tests".into()),
            last_tool_summary: None,
            error: None,
        });
        drop(sink);
        while let Ok(event) = rx.try_recv() {
            app.workflow_run_ui_event(event);
        }

        let card = match &app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .expect("the run keeps its one block")
            .kind
        {
            block::BlockKind::WorkflowRun(card) => card.clone(),
            _ => unreachable!("the block is the phase→agent tree"),
        };
        assert_eq!(card.name, "audit");
        assert_eq!(
            card.phases.len(),
            2,
            "a declared phase reached at runtime binds back by title instead of opening a \
             second box"
        );
        assert_eq!(card.agents.len(), 1, "one agent(), one row");
        assert_eq!(card.agents[0].state, WorkflowState::Done);
        assert_eq!(card.agents[0].tokens, 1_200);
        assert_eq!(
            card.logs,
            vec!["scanning modules".to_string()],
            "log() has no counterpart in the native vocabulary and is carried, not dropped"
        );
        assert!(!card.finished, "the run has not settled yet");

        let folded = render_text(&mut app, 100, 30);
        assert!(folded.contains("ctrl+o expand"), "{folded}");
        assert!(!folded.contains("Report"), "{folded}");
        assert!(!folded.contains("scan modules"), "{folded}");
        app.toggle_last_fold();
        let live = render_text(&mut app, 100, 30);
        assert!(live.contains("Explore"), "{live}");
        assert!(live.contains("Report"), "{live}");
        assert!(live.contains("scan modules"), "{live}");
        assert!(live.contains("scanning modules"), "{live}");

        // Settling is a separate message because `ingest` never sets it; without it the tree spins.
        app.workflow_run_ui_event(crate::workflow::WorkflowRunUiEvent::Finished {
            run_id: run_id.into(),
            terminal: crate::workflow::WorkflowRunTerminal::Completed,
        });
        assert!(!app.workflow_monitor.is_live(run_id));
        let settled = match &app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .unwrap()
            .kind
        {
            block::BlockKind::WorkflowRun(card) => card.finished,
            _ => unreachable!(),
        };
        assert!(settled);
    }

    /// The region is where a run in flight is watched, and the conversation is where it is recorded
    /// once it is over. Both halves are checked against the two numbers `draw` leaves behind:
    /// `last_total_rows` is how many rows the CONVERSATION rendered, and `view_h` is how many rows
    /// the conversation was GIVEN. A live run must move the second and not the first — the region
    /// takes rows from the same frame, while the transcript draws nothing for the run at all, not
    /// the tree and not even the blank line that would normally precede its block.
    #[test]
    fn a_live_run_is_watched_in_the_region_and_recorded_in_the_transcript_when_it_settles() {
        use iteron_workflow::events::ProgressEvent;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        app.push(fg(Color::White), "conversation marker");

        let before = render_text(&mut app, 100, 30);
        assert!(before.contains("conversation marker"), "{before}");
        let conversation_rows = app.last_total_rows;
        let conversation_height = app.view_h;

        let run_id = "wf_region_1";
        app.workflow_run_started(run_id, "region audit", &["Explore".to_string()]);
        app.workflow_run_event(
            run_id,
            "region audit",
            ProgressEvent::AgentStarted {
                index: 0,
                label: "scan modules".into(),
                phase: Some("Explore".into()),
                model: Some("haiku".into()),
            },
        );
        let block_id = app
            .workflow_monitor
            .block_id(run_id)
            .expect("the run minted its card");
        assert_eq!(app.workflow_monitor.region_block(), Some(block_id));

        let folded = render_text(&mut app, 100, 30);
        assert!(folded.contains("region audit"), "{folded}");
        assert!(!folded.contains("scan modules"), "{folded}");
        app.toggle_last_fold();
        let live = render_text(&mut app, 100, 30);
        assert!(
            live.contains("region audit"),
            "the tree is on screen: {live}"
        );
        assert!(live.contains("scan modules"), "{live}");
        assert!(
            live.contains("conversation marker"),
            "the conversation is still readable behind it: {live}"
        );
        assert_eq!(
            app.last_total_rows, conversation_rows,
            "the transcript renders nothing for a live run — not the tree, not a gap in front of it"
        );
        let region_height = conversation_height - app.view_h;
        assert!(
            region_height > 0,
            "the region took its rows from the same frame"
        );
        assert!(
            region_height <= workflow_region_cap(30),
            "and never more than its half of it"
        );

        // The handover. The region lets go the instant the run settles, because from that instant
        // the tree has stopped moving and the conversation owes the reader its record.
        app.workflow_run_finished(run_id);
        let settled = render_text(&mut app, 100, 30);
        assert_eq!(
            app.workflow_monitor.region_block(),
            None,
            "nothing is running, so the region is back to costing nothing"
        );
        assert_eq!(
            app.view_h, conversation_height,
            "the rows it borrowed go back to the conversation"
        );
        assert!(
            app.last_total_rows > conversation_rows,
            "which now renders the run's permanent record"
        );
        assert!(
            settled.contains("region audit") && settled.contains("scan modules"),
            "the same tree, at the point in the conversation where the run began: {settled}"
        );
        assert!(
            app.transcript.iter().any(|block| block.id == block_id),
            "one card, moved between surfaces rather than copied"
        );
    }

    /// The region must be free until it is earned: a session in which no workflow ever runs has the
    /// geometry it had before the region existed.
    #[test]
    fn a_session_without_a_workflow_pays_no_rows_for_the_region() {
        let mut app = App::new();
        app.theme = theme::Theme::dark();
        app.push(fg(Color::White), "conversation only");

        assert_eq!(app.workflow_monitor.region_block(), None);
        assert!(app.workflow_region_rows(100).is_empty());

        for (width, height) in PRODUCT_SIZES {
            let screen = render_text(&mut app, width, height);
            let unchanged =
                surface::Surface::resolve(Rect::new(0, 0, width, height), 1, 0, 0, true, false);
            assert_eq!(unchanged.workflow.height, 0);
            assert_eq!(
                app.view_h, unchanged.transcript.height,
                "the transcript keeps every row it had at {width}x{height}: {screen}"
            );
        }
    }

    /// `/clear` clears the CONVERSATION, and a QuickJS run does not stop because the conversation
    /// did. The run still in flight keeps the card the region draws — losing it would blank a
    /// running workflow with nothing able to restore it. The run that already finished leaves with
    /// its record, exactly like every other block of the cleared conversation.
    #[test]
    fn clearing_the_conversation_keeps_a_running_workflow_and_drops_a_finished_one() {
        use iteron_workflow::events::ProgressEvent;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        app.push(fg(Color::White), "conversation marker");

        let finished_run = "wf_clear_done";
        app.workflow_run_started(finished_run, "finished audit", &["Explore".to_string()]);
        let finished_block = app
            .workflow_monitor
            .block_id(finished_run)
            .expect("the finished run minted its card");
        app.workflow_run_finished(finished_run);

        let live_run = "wf_clear_live";
        app.workflow_run_started(live_run, "running audit", &["Explore".to_string()]);
        app.workflow_run_event(
            live_run,
            "running audit",
            ProgressEvent::Log {
                message: "still scanning".into(),
            },
        );
        let live_block = app
            .workflow_monitor
            .block_id(live_run)
            .expect("the live run minted its card");

        clear_conversation(&mut app);

        assert!(
            app.transcript.iter().any(|block| block.id == live_block),
            "the running workflow keeps the card the region draws"
        );
        assert!(
            !app.transcript
                .iter()
                .any(|block| block.id == finished_block),
            "the finished run's record leaves with the conversation it belonged to"
        );
        assert_eq!(
            app.workflow_monitor.region_block(),
            Some(live_block),
            "and the region is still pointed at what is still running"
        );
        assert_eq!(app.workflow_monitor.live_count(), 1);
        assert_eq!(
            app.workflow_monitor.collapsed(finished_run),
            None,
            "the settled binding is dropped, not left pointing at a block that was just removed"
        );

        let folded = render_text(&mut app, 100, 30);
        assert!(folded.contains("running audit"), "{folded}");
        assert!(folded.contains("ctrl+o expand"), "{folded}");
        assert!(!folded.contains("still scanning"), "{folded}");
        app.toggle_last_fold();
        let screen = render_text(&mut app, 100, 30);
        assert!(screen.contains("still scanning"), "{screen}");
        assert!(screen.contains("transcript cleared"), "{screen}");
        assert!(!screen.contains("conversation marker"), "{screen}");
        assert!(!screen.contains("finished audit"), "{screen}");
    }

    /// Moving the live tree out of the transcript takes it out of the row map the mouse fold uses,
    /// so the fold has to stay reachable from the keyboard — and it has to move the store's bit and
    /// the card's mirror together, exactly as the transcript fold does.
    #[test]
    fn ctrl_o_folds_the_run_the_region_is_drawing() {
        use iteron_workflow::events::ProgressEvent;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        app.push(fg(Color::White), "conversation marker");

        let run_id = "wf_region_fold";
        app.workflow_run_started(run_id, "region audit", &["Explore".to_string()]);
        app.workflow_run_event(
            run_id,
            "region audit",
            ProgressEvent::Log {
                message: "scanning".into(),
            },
        );
        let block_id = app
            .workflow_monitor
            .block_id(run_id)
            .expect("the run minted its card");
        let verbose = |app: &App| {
            app.transcript
                .iter()
                .find(|block| block.id == block_id)
                .map(|block| match &block.kind {
                    block::BlockKind::WorkflowRun(card) => card.verbose,
                    _ => unreachable!(),
                })
                .expect("the region's card is still in the transcript")
        };

        assert!(!verbose(&app));
        app.toggle_last_fold();
        assert!(verbose(&app), "the card the region renders expanded");
        assert_eq!(
            app.workflow_monitor.collapsed(run_id),
            Some(false),
            "through the store that owns the bit, not around it"
        );
        app.toggle_last_fold();
        assert!(!verbose(&app));
        assert_eq!(app.workflow_monitor.collapsed(run_id), Some(true));

        // Once nothing is running, Ctrl-O goes back to the last collapsible transcript block.
        app.workflow_run_finished(run_id);
        app.tool_start(
            "t1".into(),
            "read_file".into(),
            serde_json::json!({"path": "a"}),
        );
        app.toggle_last_fold();
        assert!(
            !verbose(&app),
            "the settled run is a record now, not the thing Ctrl-O reaches for"
        );
    }

    #[test]
    fn the_region_never_asks_for_more_than_half_the_frame() {
        assert_eq!(workflow_region_cap(0), 0);
        assert_eq!(
            workflow_region_cap(1),
            0,
            "a one-row frame belongs to the composer, not to inspection chrome"
        );
        assert_eq!(workflow_region_cap(2), 1);
        assert_eq!(workflow_region_cap(24), 12);
        assert_eq!(workflow_region_cap(41), 21);
        for height in 2..=64u16 {
            assert!(
                height - workflow_region_cap(height) >= height / 2,
                "the conversation keeps its half at height {height}"
            );
        }
    }

    /// A frame too small to spare the region a single row must not make a running workflow vanish:
    /// the region is where a live run is watched, but "nowhere" is never an option.
    #[test]
    fn a_frame_too_small_for_the_region_keeps_the_run_in_the_conversation() {
        use iteron_workflow::events::ProgressEvent;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        // The landing already has a conversation (the welcome block), so the run is measured as a
        // DELTA against it rather than against an empty transcript.
        let _ = render_text(&mut app, 60, 30);
        let conversation_rows = app.last_total_rows;

        let run_id = "wf_region_tiny";
        app.workflow_run_started(run_id, "tiny frame audit", &["Explore".to_string()]);
        app.workflow_run_event(
            run_id,
            "tiny frame audit",
            ProgressEvent::Log {
                message: "scanning".into(),
            },
        );

        // Four rows leave the status line, the transcript floor and the composer frame nothing to
        // give away, so the region is granted zero — and the tree renders through the transcript.
        let tiny = render_text(&mut app, 60, 4);
        assert!(
            app.last_total_rows > conversation_rows,
            "the transcript drew the run rather than dropping it: {tiny}"
        );

        // The same run on a frame with room is drawn by the region and by nothing else.
        let roomy = render_text(&mut app, 60, 30);
        assert_eq!(
            app.last_total_rows, conversation_rows,
            "the conversation renders nothing for it: {roomy}"
        );
        assert!(roomy.contains("tiny frame audit"), "{roomy}");
    }

    /// A wide fan renders a tree taller than any terminal. The cap keeps it from swallowing the
    /// conversation, and the window states what it hid instead of clipping the tree in silence.
    #[test]
    fn a_tree_taller_than_the_terminal_windows_instead_of_eating_the_conversation() {
        use iteron_workflow::events::ProgressEvent;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        app.push(fg(Color::White), "conversation marker");
        let _ = render_text(&mut app, 100, 30);
        let conversation_height = app.view_h;

        let run_id = "wf_region_fan";
        app.workflow_run_started(run_id, "wide fan", &["Explore".to_string()]);
        for index in 0..40 {
            app.workflow_run_event(
                run_id,
                "wide fan",
                ProgressEvent::AgentStarted {
                    index,
                    label: format!("investigator {index:02}"),
                    phase: Some("Explore".into()),
                    model: Some("haiku".into()),
                },
            );
        }

        app.toggle_last_fold();
        let screen = render_text(&mut app, 100, 30);
        assert!(
            conversation_height - app.view_h <= workflow_region_cap(30),
            "the region is capped however tall the tree is"
        );
        assert!(
            screen.contains("more"),
            "the window says how many rows it hid: {screen}"
        );
        assert!(
            screen.contains("conversation marker"),
            "and the conversation is still readable: {screen}"
        );
    }

    /// A workflow script is untrusted input and the interactive transcript is retained state, so
    /// nothing hostile in a label or a narrator line survives the trip.
    #[test]
    fn a_hostile_workflow_script_cannot_write_control_sequences_into_the_transcript() {
        use iteron_workflow::events::{ProgressEvent, ProgressSink};

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let run_id = "wf_repl_hostile";
        app.workflow_run_ui_event(crate::workflow::WorkflowRunUiEvent::Started {
            run_id: run_id.into(),
            name: "audit\u{1b}[2J".into(),
            phases: vec!["Explore\u{1b}[2J".into()],
        });

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = crate::workflow::UiProgressSink::new(run_id, tx);
        sink.emit(ProgressEvent::Log {
            message: "narrating\u{1b}[2J\u{7}".into(),
        });
        sink.emit(ProgressEvent::AgentStarted {
            index: 0,
            label: "row\u{1b}[2J".into(),
            phase: None,
            model: None,
        });
        drop(sink);
        while let Ok(event) = rx.try_recv() {
            app.workflow_run_ui_event(event);
        }

        let screen = render_text(&mut app, 100, 30);
        assert!(
            !screen.chars().any(|c| c == '\u{1b}' || c == '\u{7}'),
            "a raw control character reached the frame buffer: {screen:?}"
        );
    }

    #[test]
    fn workflow_events_mutate_one_live_card_and_collapse_on_success() {
        let mut app = App::new();
        let run_id = "workflow-9";
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::RunStarted {
                run_id: run_id.into(),
                name: "ultracode".into(),
                class: "multi-file".into(),
            }),
        );
        let block_count = app.transcript.len();
        let block_id = *app.workflow_index.get(run_id).expect("indexed workflow");
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::PlanReady {
                run_id: run_id.into(),
                tasks: vec![crate::runtime::WorkflowTaskUi {
                    id: 0,
                    label: "inspect the runtime".into(),
                }],
                dropped: 0,
                duplicates_removed: 0,
                invalid_removed: 0,
                execution_mode: crate::runtime::WorkflowExecutionModeUi::Sequential,
                fan_turn_budget: 4,
                writer_turn_reserve: 20,
                fan_wall_secs: 60,
                writer_wall_reserve_secs: 120,
            }),
        );
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::PhaseChanged {
                run_id: run_id.into(),
                phase: WorkflowPhaseUi::Exploring,
            }),
        );
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::AgentStarted {
                run_id: run_id.into(),
                agent_id: 0,
                sub_run: "fan-0".into(),
                turn_budget: 4,
            }),
        );
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::AgentActivity {
                run_id: run_id.into(),
                agent_id: 0,
                activity: "read_file · crates/kernel/src/lib.rs".into(),
            }),
        );
        let live = render_text(&mut app, 120, 32);
        // The running investigator keeps its own branch row (I-04): no NOW hoist, no filtered row.
        assert!(live.contains("inspect the runtime · running"));
        assert!(live.contains("read_file"));
        assert!(live.contains("RESERVE"));
        assert!(live.contains("sequential"));
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::AgentFinished {
                run_id: run_id.into(),
                agent_id: 0,
                outcome: WorkflowAgentOutcomeUi::Done,
                turns: 2,
                tokens: 1_200,
                tool_calls: 3,
                elapsed_ms: 800,
                summary_preview: Some("found runtime owner".into()),
                error_preview: None,
            }),
        );
        assert_eq!(
            app.transcript.len(),
            block_count,
            "lifecycle updates must not append sibling log lines"
        );
        let card = app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .and_then(|block| match &block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
            .expect("workflow block");
        assert_eq!(card.status, block::WorkflowStatus::Exploring);
        assert_eq!(card.tasks[0].status, block::WorkflowTaskStatus::Done);
        assert_eq!(card.tasks[0].tokens, 1_200);

        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::PhaseChanged {
                run_id: run_id.into(),
                phase: WorkflowPhaseUi::Writing,
            }),
        );
        let writing = render_text(&mut app, 80, 24);
        assert!(writing.contains("writing"));
        assert!(writing.contains("WRITE"));

        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::RunFinished {
                run_id: run_id.into(),
                outcome: WorkflowRunOutcomeUi::Done,
                reason: None,
                elapsed_ms: 1_000,
                provider_attempts: 4,
                turns: 4,
                tokens: 2_000,
                tool_calls: 3,
                failed_tasks: 0,
                skipped_tasks: 0,
            }),
        );
        assert!(!app.workflow_index.contains_key(run_id));
        let card = app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .and_then(|block| match &block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
            .expect("workflow block");
        assert_eq!(card.status, block::WorkflowStatus::Done);
        assert!(
            !card.open,
            "an all-success workflow collapses to its summary"
        );
    }

    #[test]
    fn terminal_workflow_never_freezes_nonterminal_children_in_cache() {
        let mut app = App::new();
        let run_id = "workflow-stopped";
        app.workflow_event(WorkflowUiEvent::RunStarted {
            run_id: run_id.into(),
            name: "ultracode".into(),
            class: "multi-file".into(),
        });
        app.workflow_event(WorkflowUiEvent::PlanReady {
            run_id: run_id.into(),
            tasks: vec![
                crate::runtime::WorkflowTaskUi {
                    id: 0,
                    label: "running child".into(),
                },
                crate::runtime::WorkflowTaskUi {
                    id: 1,
                    label: "queued child".into(),
                },
            ],
            dropped: 0,
            duplicates_removed: 0,
            invalid_removed: 0,
            execution_mode: crate::runtime::WorkflowExecutionModeUi::Sequential,
            fan_turn_budget: 6,
            writer_turn_reserve: 20,
            fan_wall_secs: 60,
            writer_wall_reserve_secs: 120,
        });
        app.workflow_event(WorkflowUiEvent::AgentStarted {
            run_id: run_id.into(),
            agent_id: 0,
            sub_run: "fan-0".into(),
            turn_budget: 3,
        });
        app.workflow_event(WorkflowUiEvent::RunFinished {
            run_id: run_id.into(),
            outcome: WorkflowRunOutcomeUi::Stopped,
            reason: Some("stopped by operator".into()),
            elapsed_ms: 500,
            provider_attempts: 1,
            turns: 0,
            tokens: 0,
            tool_calls: 0,
            failed_tasks: 1,
            skipped_tasks: 1,
        });
        let card = app
            .transcript
            .iter()
            .find_map(|block| match &block.kind {
                block::BlockKind::Workflow(card) if card.run_id == run_id => Some(card),
                _ => None,
            })
            .unwrap();
        assert!(
            card.tasks
                .iter()
                .all(|task| task.status == block::WorkflowTaskStatus::Unknown)
        );
        let screen = render_text(&mut app, 80, 24);
        assert!(screen.contains("stopped"));
        assert!(!screen.contains("running child  running"));
        assert!(!screen.contains("queued child  queued"));
    }

    #[test]
    fn cjk_text_does_not_panic_the_transcript() {
        // streamed multibyte text must not panic anywhere in the state path
        let mut app = App::new();
        app.stream_text("写代码 ");
        app.stream_text("测试😀");
        app.flush_text();
        assert!(app.transcript.iter().any(|b| b.to_text().contains("测试")));
    }

    #[test]
    fn huge_single_line_paste_cursor_does_not_overflow() {
        // round-4 review: display_col saturates at 65535, and the cursor-position math must not form
        // a >u16 intermediate (which panics with overflow-checks on, i.e. every debug/test build).
        // A single-line paste of >65535 display cells must draw cleanly.
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut app = App::new();
        app.editor.insert_str(&"a".repeat(66_000));
        term.draw(|f| draw(f, &mut app)).unwrap();
        // and with the cursor pulled back to the start (scroll_x == 0, cur_disp large is not in play,
        // but exercise the other branch) it must also be fine.
        app.editor.home();
        term.draw(|f| draw(f, &mut app)).unwrap();
    }

    #[test]
    fn turn_counter_increments_on_turn_end() {
        // The usage projection increments once per completed provider turn.
        let mut app = App::new();
        assert_eq!(app.turns, 0);
        apply_event(&mut app, turn_end(0.01, Usage::default()));
        apply_event(&mut app, turn_end(0.03, Usage::default()));
        assert_eq!(app.turns, 2, "turns++ per completed turn");
    }

    #[test]
    fn only_an_accepted_submission_arms_run_completion_notification() {
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(1);
        let accepted_session = Session::for_test(accepted_tx);
        let mut accepted_app = App::new();
        let mut accepted_notifier = notification::TerminalNotifier::new(true);

        assert!(submit_turn(
            &mut accepted_app,
            &accepted_session,
            &mut accepted_notifier,
            "accepted".into(),
        ));

        assert!(accepted_app.running);
        assert_eq!(accepted_app.session_name, "accepted");
        assert!(matches!(
            accepted_rx
                .try_recv()
                .expect("accepted task reaches the SQ")
                .into_current()
                .expect("current protocol envelope"),
            Op::UserInput { text } if text == "accepted"
        ));
        assert_eq!(
            accepted_notifier.run_completed(),
            Some(notification::Trigger::RunComplete)
        );

        let (busy_tx, _busy_rx) = tokio::sync::mpsc::channel(1);
        busy_tx
            .try_send(iteron_protocol::SqEnvelope::current(Op::Interrupt))
            .expect("fixture fills the bounded SQ");
        let busy_session = Session::for_test(busy_tx);
        let mut busy_app = App::new();
        let mut busy_notifier = notification::TerminalNotifier::new(true);

        assert!(!submit_turn(
            &mut busy_app,
            &busy_session,
            &mut busy_notifier,
            "refused".into(),
        ));

        assert!(!busy_app.running);
        assert_eq!(busy_app.session_name, "New session");
        assert_eq!(busy_app.retryable_task, None);
        assert_eq!(busy_notifier.run_completed(), None);
        assert!(
            busy_app
                .transcript
                .iter()
                .any(|block| block.to_text().contains("submission was not accepted"))
        );
    }

    #[test]
    fn a_refused_queue_dispatch_returns_the_exact_prompt_and_never_draws_a_ghost_user_row() {
        let mut app = App::new();
        app.queue_after_turn("preserve me exactly".into()).unwrap();
        let item = app.queued.pop_front().unwrap();

        let (busy_tx, _busy_rx) = tokio::sync::mpsc::channel(1);
        busy_tx
            .try_send(iteron_protocol::SqEnvelope::current(Op::Interrupt))
            .expect("fixture fills the bounded SQ");
        let busy_session = Session::for_test(busy_tx);
        let mut notifier = notification::TerminalNotifier::new(false);

        let returned =
            submit_queued_model_input(&mut app, &busy_session, &mut notifier, item.clone())
                .expect_err("a saturated SQ cannot consume the queue item");
        assert_eq!(*returned, item);
        assert!(!app.running);
        assert!(
            app.transcript
                .iter()
                .all(|block| !matches!(&block.kind, block::BlockKind::User(_))),
            "a refused prompt must not appear as admitted conversation"
        );

        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(1);
        let accepted_session = Session::for_test(accepted_tx);
        submit_queued_model_input(&mut app, &accepted_session, &mut notifier, *returned)
            .expect("the preserved item is accepted exactly once when capacity returns");
        assert!(app.running);
        assert!(matches!(
            accepted_rx
                .try_recv()
                .expect("one model submission")
                .into_current()
                .expect("current protocol envelope"),
            Op::UserInput { text } if text == "preserve me exactly"
        ));
        assert_eq!(
            app.transcript
                .iter()
                .filter(|block| matches!(&block.kind, block::BlockKind::User(_)))
                .count(),
            1
        );
    }

    /// A block big enough that the paste path holds it aside instead of typing it out.
    fn pasted_log() -> String {
        (0..40)
            .map(|line| format!("line {line}: connection reset by peer"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_pasted_block_submits_as_its_own_bytes_and_cannot_smuggle_a_file_mention() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(tx);
        let mut app = App::new();
        let mut notifier = notification::TerminalNotifier::new(false);
        // The pasted text names a file mention. It is not the operator's request, it is content,
        // and it must reach the model as the characters it is rather than making the composer
        // read a file.
        let pasted = format!("@file(Cargo.toml)\n{}", pasted_log());
        app.editor.insert_str("explain ");
        app.editor.capture_paste(&pasted).expect("a bounded paste");
        assert_eq!(app.editor.text(), "explain [Pasted text #1 +40 lines]");

        submit_composer(&mut app, &session, &mut notifier);

        let op = rx
            .try_recv()
            .expect("composer submits through the bounded SQ")
            .into_current()
            .expect("current protocol envelope");
        let Op::UserInput { text } = op else {
            panic!("a pasted block is text; it must not become an attachment operation");
        };
        assert_eq!(text, format!("explain {pasted}"));
        assert!(
            app.editor.has_submission(),
            "local enqueue is not the runtime receipt that clears a draft"
        );
        let submission_id = app.pending_turn_receipt.as_ref().unwrap().id;
        apply_server_event(
            &mut app,
            &mut session,
            app_server::ServerEvent::Submission {
                id: submission_id,
                state: iteron_protocol::SubmissionLifecycleState::Received,
                reason_code: None,
            },
            &mut notifier,
            &mut Vec::new(),
            &Arc::new(AtomicBool::new(false)),
            &Arc::new(AtomicBool::new(false)),
        );
        assert!(!app.editor.has_submission());
    }

    #[test]
    fn the_composer_shows_a_paste_tag_and_never_the_pasted_body() {
        let mut app = App::new();
        app.editor.insert_str("why? ");
        app.editor
            .capture_paste(&pasted_log())
            .expect("a bounded paste");

        let screen = render_text(&mut app, 100, 14);
        assert!(screen.contains("[Pasted text #1 +39 lines]"), "{screen}");
        assert!(
            !screen.contains("connection reset by peer"),
            "a tag is a reference; the composer never prints the block it stands for"
        );
    }

    #[test]
    fn composer_attachment_submits_one_multimodal_sq_envelope() {
        let image_bytes = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;";
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(tx);
        let mut app = App::new();
        app.editor.insert_str("describe this ");
        app.editor
            .attach_image_bytes("clipboard.png", image_bytes)
            .unwrap();
        let mut notifier = notification::TerminalNotifier::new(false);

        submit_composer(&mut app, &session, &mut notifier);

        assert!(app.running);
        assert!(
            app.editor.has_submission(),
            "an SQ send is not yet the runtime's receipt"
        );
        let submission_id = app
            .pending_turn_receipt
            .as_ref()
            .expect("accepted local enqueue owns a receipt")
            .id;
        let mut notification_bytes = Vec::new();
        apply_server_event(
            &mut app,
            &mut session,
            app_server::ServerEvent::Submission {
                id: submission_id,
                state: iteron_protocol::SubmissionLifecycleState::Received,
                reason_code: None,
            },
            &mut notifier,
            &mut notification_bytes,
            &Arc::new(AtomicBool::new(false)),
            &Arc::new(AtomicBool::new(false)),
        );
        assert!(!app.editor.has_submission());
        let op = rx
            .try_recv()
            .expect("composer submits through the bounded SQ")
            .into_current()
            .expect("current protocol envelope");
        let Op::UserInputV2 { segments } = op else {
            panic!("image composer must use the additive multimodal operation");
        };
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, image_bytes);
        assert_eq!(
            serde_json::to_value(&segments).expect("serialize composer segments"),
            serde_json::json!([
                {"type": "text", "text": "describe this [Image #1]"},
                {
                    "type": "image",
                    "image": {
                        "media_type": "image/gif",
                        "data": encoded,
                    },
                },
            ]),
            "the composer must preserve ordered text and the exact attached bytes"
        );
        assert_eq!(segments.text(), "describe this [Image #1]");
        let images = segments.images().collect::<Vec<_>>();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].media_type, iteron_protocol::ImageMediaType::Gif);
        apply_server_event(
            &mut app,
            &mut session,
            app_server::ServerEvent::Submission {
                id: submission_id,
                state: iteron_protocol::SubmissionLifecycleState::Applied,
                reason_code: None,
            },
            &mut notifier,
            &mut notification_bytes,
            &Arc::new(AtomicBool::new(false)),
            &Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(
            app.transcript
                .iter()
                .filter(|block| block.to_text().contains("describe this"))
                .count(),
            1,
            "the submit preview is projected once without image bytes"
        );
    }

    #[test]
    fn file_tag_chip_and_payload_submit_and_clear_on_the_runtime_receipt() {
        let root = std::env::temp_dir().join(format!(
            "core-tui-file-tag-submit-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("notes.md"), "exact file body").unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(tx);
        session.facts.workspace = root.clone();
        let mut app = App::new();
        app.editor.insert_str("review ");
        app.editor
            .attach_file_path(&root, Path::new("notes.md"))
            .unwrap();
        assert_eq!(app.editor.text(), "review [File #1]");
        assert_eq!(app.editor.chip_count(), 1);

        let mut notifier = notification::TerminalNotifier::new(false);
        submit_composer(&mut app, &session, &mut notifier);
        let submission_id = app.pending_turn_receipt.as_ref().unwrap().id;
        assert!(app.editor.has_submission());

        let op = rx.try_recv().unwrap().into_current().unwrap();
        let Op::UserInputV3 { text, files, .. } = op else {
            panic!("a file chip must use the structured file operation");
        };
        assert_eq!(text, "review [File #1]");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "notes.md");
        assert_eq!(files[0].text, "exact file body");

        apply_server_event(
            &mut app,
            &mut session,
            app_server::ServerEvent::Submission {
                id: submission_id,
                state: iteron_protocol::SubmissionLifecycleState::Received,
                reason_code: None,
            },
            &mut notifier,
            &mut Vec::new(),
            &Arc::new(AtomicBool::new(false)),
            &Arc::new(AtomicBool::new(false)),
        );
        assert!(!app.editor.has_submission());
        assert_eq!(app.editor.chip_count(), 0);

        let _ = std::fs::remove_dir_all(root);
    }

    /// A screenshot dropped onto a working agent used to become a line of path text: the paste lane
    /// skipped image parsing while `running`, so the one piece of evidence the operator has that the
    /// attachment landed — the chip — never appeared.
    #[test]
    fn a_draft_composed_during_a_run_keeps_its_chips_and_is_queued_with_them() {
        let (gif, _) = distinct_gifs();
        let mut app = App::new();
        app.running = true;
        app.editor.insert_str("look at ");
        app.editor
            .attach_image_bytes("shot.png", gif)
            .expect("a canonical GIF");
        assert_eq!(app.editor.chip_count(), 1);

        assert!(
            queue_draft_with_chips(&mut app),
            "a chip-carrying draft is admissible while a run is in flight"
        );
        assert_eq!(
            app.editor.chip_count(),
            0,
            "the chips leave the composer with the text, not after it"
        );
        assert!(app.editor.is_empty(), "the draft was consumed");
        let queued = app.queued.front().expect("one queued submission");
        assert_eq!(
            queued.images.len(),
            1,
            "the image travels with the words it was composed with"
        );
        assert!(queued.text.contains("look at"), "{}", queued.text);
        assert!(
            queued.text.contains("[Image #1]"),
            "the anchor survives into the queued text: {}",
            queued.text
        );
    }

    /// A command is a frontend action and cannot carry an attachment. Queuing one with chips would
    /// either send `/model` to the model as prose or drop the images on the way — both silent.
    #[test]
    fn a_command_carrying_chips_is_refused_with_everything_left_intact() {
        let (gif, _) = distinct_gifs();
        let mut app = App::new();
        app.running = true;
        app.editor.insert_str("/model");
        app.editor
            .attach_image_bytes("shot.png", gif)
            .expect("a canonical GIF");

        assert!(
            !queue_draft_with_chips(&mut app),
            "a slash command with chips is not queued"
        );
        assert_eq!(app.editor.chip_count(), 1, "the chip is still on the draft");
        assert!(
            app.editor.text().starts_with("/model"),
            "the command is still in the composer: {}",
            app.editor.text()
        );
        assert!(app.queued.is_empty(), "nothing was queued");
        assert!(
            app.transcript
                .iter()
                .any(|block| block.to_text().contains("cannot carry attachments")),
            "the operator is told why"
        );
    }

    /// The exact failure from a live session: a screenshot dragged onto the composer arrived as
    /// keystrokes, not as a bracketed paste, so the paste lane never saw it and the operator got a
    /// line of escaped path text where a chip should have been.
    #[test]
    fn a_dropped_path_that_arrived_as_typing_still_becomes_a_chip_and_an_anchor() {
        let (gif, _) = distinct_gifs();
        let dir = std::env::temp_dir().join(format!("core-drop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch dir");
        // A canonical GIF under a .gif name: the declared extension has to agree with the bytes,
        // which is the same rule a real screenshot .png meets. The mechanism under test is the
        // typed path becoming a chip, not the codec.
        let shot = dir.join("Screenshot 2026-08-06 at 3.57.44 PM.gif");
        std::fs::write(&shot, gif).expect("a canonical GIF");

        let mut app = App::new();
        // Typed, not pasted: exactly what the terminal wrote, escapes and all.
        app.editor.insert_str("look at ");
        for character in shot.to_string_lossy().replace(' ', "\\ ").chars() {
            app.editor.insert(character);
        }
        assert_eq!(
            app.editor.chip_count(),
            0,
            "typing attaches nothing by itself"
        );

        attach_bare_image_paths(&mut app, std::path::Path::new("/"));
        assert_eq!(app.editor.chip_count(), 1, "the path became a chip");
        assert_eq!(
            app.editor.text(),
            "look at [Image #1]",
            "the anchor stands where the path stood"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Prose that merely names a path must not be rewritten, and a path that cannot be read as an
    /// image must leave the draft exactly as the operator typed it.
    #[test]
    fn a_path_that_is_not_a_readable_image_is_left_as_the_text_it_was() {
        let mut app = App::new();
        app.editor
            .insert_str("compare /nope/definitely-missing.png with the old one");
        attach_bare_image_paths(&mut app, std::path::Path::new("/"));
        assert_eq!(app.editor.chip_count(), 0);
        assert_eq!(
            app.editor.text(),
            "compare /nope/definitely-missing.png with the old one"
        );
    }

    /// A canonical 1×1 PNG.
    ///
    /// The failure being regressed is a macOS SCREENSHOT, which is always `.png`, and the loader
    /// refuses a file whose extension disagrees with its bytes — a `.gif` stand-in would not have
    /// exercised the extension an operator actually drops.
    fn png_1x1() -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(concat!(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42",
                "mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
            ))
            .expect("a canonical 1x1 PNG")
    }

    /// A screenshot file plus the exact token a terminal writes when it is dropped on the composer.
    struct ScreenshotDrop {
        dir: PathBuf,
        token: String,
    }

    impl Drop for ScreenshotDrop {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    /// Reproduce a macOS screenshot drag as the terminal delivers it.
    ///
    /// The file name is the one macOS has given every screenshot since the system time format
    /// changed: three ASCII spaces and, before `PM`, a U+202F NARROW NO-BREAK SPACE. The token is
    /// built by escaping ASCII spaces and nothing else, which is exactly what a terminal does — it
    /// escapes what a SHELL splits on. Taken from a recorded session, not from imagination.
    fn macos_screenshot_drop(label: &str, on_disk: bool) -> ScreenshotDrop {
        let dir = std::env::temp_dir().join(format!(
            "core-drop-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("a scratch dir");
        let path = dir.join("Screenshot 2026-08-06 at 5.26.07\u{202f}PM.png");
        if on_disk {
            std::fs::write(&path, png_1x1()).expect("a canonical PNG on disk");
        }
        let token = path.to_string_lossy().replace(' ', "\\ ");
        assert!(
            token.contains('\u{202f}'),
            "the terminal leaves the narrow no-break space unescaped: {token}"
        );
        ScreenshotDrop { dir, token }
    }

    /// The bug, at the boundary where it lived: the token the terminal wrote is one path, and every
    /// lane below this asked the wrong question about it because U+202F answers `true` to
    /// `char::is_whitespace` while a terminal does not escape it.
    #[test]
    fn a_narrow_no_break_space_in_a_dropped_name_is_part_of_the_path_not_a_separator() {
        let drop = macos_screenshot_drop("reference", true);
        let resolved = dropped_image_reference(&drop.token)
            .expect("a dropped screenshot path is not an error")
            .expect("the drop names one image");
        assert_eq!(
            resolved.file_name().and_then(|name| name.to_str()),
            Some("Screenshot 2026-08-06 at 5.26.07\u{202f}PM.png"),
            "the resolved path keeps the character the file actually has"
        );
    }

    /// The paste lane, driven the way a terminal drives it. This is the lane the operator's drop
    /// took: it fell through to "ordinary pasted text", and because a paste is not a `KeyCode::Char`
    /// the keystroke hook that would have rescued it never ran.
    #[test]
    fn a_macos_screenshot_drop_that_arrives_as_a_paste_becomes_a_chip() {
        let drop = macos_screenshot_drop("paste", true);
        let mut app = App::new();

        handle_composer_paste(&mut app, &drop.dir, &drop.token);

        assert_eq!(
            app.editor.chip_count(),
            1,
            "the drop became a chip, not a line of escaped path text: {:?}",
            app.editor.text()
        );
        assert_eq!(
            app.editor.text(),
            "[Image #1]",
            "the anchor stands where the path would have"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_dropped_iphone_heic_becomes_a_provider_safe_jpeg_chip() {
        let dir = std::env::temp_dir().join(format!(
            "core-heic-drop-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("a scratch dir");
        let source = dir.join("source.png");
        let heic = dir.join("iPhone Photo.heic");
        std::fs::write(&source, png_1x1()).expect("a canonical source PNG");
        let status = std::process::Command::new("/usr/bin/sips")
            .args(["-s", "format", "heic", "-o"])
            .arg(&heic)
            .arg(&source)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("macOS sips is available");
        assert!(
            status.success(),
            "create a real HEIC fixture through ImageIO"
        );

        let mut app = App::new();
        let token = heic.to_string_lossy().replace(' ', "\\ ");
        handle_composer_paste(&mut app, &dir, &token);

        assert_eq!(app.editor.chip_count(), 1);
        assert_eq!(app.editor.text(), "[Image #1]");
        let attachment = &app.editor.attachments().as_slice()[0];
        assert_eq!(attachment.display_name(), "iPhone Photo.heic");
        assert_eq!(
            attachment.media_type(),
            iteron_protocol::ImageMediaType::Jpeg,
            "the provider never receives HEIC bytes"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    /// The same drop on the terminals that replay it as keystrokes, converted by the same scan the
    /// event loop runs once the draft holds a readable path.
    #[test]
    fn a_macos_screenshot_drop_that_arrives_as_typing_becomes_a_chip() {
        let drop = macos_screenshot_drop("typed", true);
        let mut app = App::new();
        app.editor.insert_str("look at ");
        for character in drop.token.chars() {
            app.editor.insert(character);
        }
        assert_eq!(app.editor.chip_count(), 0, "typing attaches nothing itself");

        attach_bare_image_paths(&mut app, &drop.dir);

        assert_eq!(app.editor.chip_count(), 1);
        assert_eq!(app.editor.text(), "look at [Image #1]");
    }

    /// A drop that lands inside a longer paste, or arrives split across more than one paste event,
    /// is only a whole path once it is in the buffer. Nothing else was going to look at it there.
    #[test]
    fn a_dropped_path_surrounded_by_pasted_words_still_becomes_a_chip() {
        let drop = macos_screenshot_drop("inline", true);
        let mut app = App::new();

        handle_composer_paste(
            &mut app,
            &drop.dir,
            &format!("look at {} please", drop.token),
        );

        assert_eq!(app.editor.chip_count(), 1);
        assert_eq!(app.editor.text(), "look at [Image #1] please");
    }

    /// The `NSIRD_screencaptureui_*` directory a screenshot is dragged out of is torn down when the
    /// drag ends, so the path a terminal wrote can already name nothing. That must look different
    /// from a feature that does not exist: the operator keeps their text AND is told why.
    #[test]
    fn a_dropped_screenshot_whose_temp_file_is_gone_is_refused_out_loud() {
        let drop = macos_screenshot_drop("vanished", false);
        let mut app = App::new();

        handle_composer_paste(&mut app, &drop.dir, &drop.token);

        assert_eq!(app.editor.chip_count(), 0, "nothing was attached");
        assert!(
            app.editor.text().contains("Screenshot"),
            "the operator keeps what they dropped: {:?}",
            app.editor.text()
        );
        assert!(
            app.transcript
                .iter()
                .any(|block| block.to_text().contains("image attachment refused")),
            "a drop that did not attach is never silent"
        );
    }

    /// The draft is rescanned on every keystroke, so an unreadable path left in the composer would
    /// otherwise emit one notice per character typed and bury the transcript it warns in.
    #[test]
    fn an_unattachable_path_is_announced_once_not_once_per_keystroke() {
        let mut app = App::new();
        app.editor
            .insert_str("compare /nope/definitely-missing.png with the old one");
        for _ in 0..5 {
            attach_bare_image_paths(&mut app, std::path::Path::new("/"));
        }
        assert_eq!(
            app.editor.text(),
            "compare /nope/definitely-missing.png with the old one",
            "the words are still the operator's"
        );
        let refusals = app
            .transcript
            .iter()
            .filter(|block| block.to_text().contains("image attachment refused"))
            .count();
        assert_eq!(refusals, 1, "one path, one notice");
    }

    /// A terminal writes an absolute path when a file is dropped, so a relative one is prose until
    /// proven otherwise. Pasting a changelog that names a dozen images must not fill the transcript
    /// with warnings about files the operator was only talking about.
    #[test]
    fn a_relative_image_name_in_prose_attaches_nothing_and_says_nothing() {
        let mut app = App::new();
        app.editor
            .insert_str("renamed report.png to summary.png in the release notes");
        attach_bare_image_paths(&mut app, std::path::Path::new("/"));
        assert_eq!(app.editor.chip_count(), 0);
        assert_eq!(
            app.editor.text(),
            "renamed report.png to summary.png in the release notes"
        );
        assert!(
            !app.transcript
                .iter()
                .any(|block| block.to_text().contains("image attachment refused")),
            "prose that names a file is not a failed drop"
        );
    }

    /// The queue drains into the same staging the composer uses, so an image that waited behind a
    /// run is on the wire rather than lost between the two lanes.
    #[test]
    fn a_queued_submission_sends_the_image_it_was_queued_with() {
        let (gif, _) = distinct_gifs();
        let mut app = App::new();
        app.running = true;
        app.editor.insert_str("describe ");
        app.editor
            .attach_image_bytes("shot.png", gif)
            .expect("a canonical GIF");
        assert!(queue_draft_with_chips(&mut app));
        let item = app.queued.pop_front().expect("one queued submission");

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let session = Session::for_test(tx);
        let mut notifier = notification::TerminalNotifier::new(false);
        let text = item.text.trim().to_owned();
        let anchor_order = paste_input::anchored_image_ids(&text, &item.images);
        assert!(submit_staged_input(
            &mut app,
            &session,
            &mut notifier,
            text,
            item.images,
            item.files,
            anchor_order,
            false,
        ));
        let op = rx
            .try_recv()
            .expect("the drained submission goes out through the bounded SQ")
            .into_current()
            .expect("current protocol envelope");
        match op {
            Op::UserInputV2 { segments } => {
                assert_eq!(
                    segments.images().count(),
                    1,
                    "the queued image is on the wire"
                );
                assert!(segments.text().contains("describe"));
            }
            other => panic!("expected a multimodal envelope, got {other:?}"),
        }
    }

    /// Two images that differ in one byte, so "which picture arrived first" is decidable from the
    /// payload alone rather than from the order we hoped it was in.
    fn distinct_gifs() -> (&'static [u8], &'static [u8]) {
        (
            b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;",
            b"GIF89a\x01\0\x01\0\x80\0\0\xff\xff\xff\0\0\0!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;",
        )
    }

    fn submitted_segments(app: &mut App) -> iteron_protocol::input::ContentSegments {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let session = Session::for_test(tx);
        let mut notifier = notification::TerminalNotifier::new(false);
        submit_composer(app, &session, &mut notifier);
        let op = rx
            .try_recv()
            .expect("composer submits through the bounded SQ")
            .into_current()
            .expect("current protocol envelope");
        match op {
            Op::UserInputV2 { segments } => segments,
            other => panic!("expected a multimodal envelope, got {other:?}"),
        }
    }

    #[test]
    fn the_image_payload_arrives_in_the_order_the_sentence_anchors_it() {
        let (first, second) = distinct_gifs();
        let mut app = App::new();
        app.editor.insert_str("compare ");
        app.editor
            .attach_image_bytes("left.png", first)
            .expect("a canonical GIF");
        app.editor.insert_str(" with ");
        app.editor
            .attach_image_bytes("right.png", second)
            .expect("a second canonical GIF");
        assert_eq!(app.editor.text(), "compare [Image #1] with [Image #2]");

        // Move the second anchor in front of the first: the sentence now argues the other way, and
        // the payload has to agree with it or the anchors mean nothing.
        app.editor.home();
        app.editor.insert_str("[Image #2] then ");
        let encode =
            |bytes| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
        let segments = submitted_segments(&mut app);
        assert_eq!(
            segments.text(),
            "[Image #2] then compare [Image #1] with [Image #2]"
        );
        let payload: Vec<&str> = segments.images().map(|image| image.data.as_str()).collect();
        assert_eq!(
            payload,
            vec![encode(second), encode(first)],
            "the anchored images lead in the order the sentence names them"
        );
    }

    #[test]
    fn deleting_image_tags_removes_their_chips_and_payloads_too() {
        let (first, second) = distinct_gifs();
        let mut app = App::new();
        app.editor.insert_str("describe these");
        app.editor
            .attach_image_bytes("left.png", first)
            .expect("a canonical GIF");
        app.editor
            .attach_image_bytes("right.png", second)
            .expect("a second canonical GIF");
        // Each live tag and its chip/payload are one object in both directions. Backspace inside a
        // tag removes the complete tag and the corresponding attachment.
        app.editor.backspace();
        app.editor.backspace();
        assert_eq!(app.editor.text(), "describe these");
        assert_eq!(app.editor.chip_count(), 0);

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let session = Session::for_test(tx);
        let mut notifier = notification::TerminalNotifier::new(false);
        submit_composer(&mut app, &session, &mut notifier);
        let op = rx
            .try_recv()
            .expect("the text-only draft submits")
            .into_current()
            .expect("current protocol envelope");
        let Op::UserInput { text } = op else {
            panic!("no deleted image payload may survive on the wire");
        };
        assert_eq!(text, "describe these");
    }

    #[test]
    fn a_hand_typed_anchor_attaches_nothing_and_says_so() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let session = Session::for_test(tx);
        let mut app = App::new();
        let mut notifier = notification::TerminalNotifier::new(false);
        app.editor.insert_str("show me [Image #7]");

        submit_composer(&mut app, &session, &mut notifier);

        let op = rx
            .try_recv()
            .expect("composer submits through the bounded SQ")
            .into_current()
            .expect("current protocol envelope");
        let Op::UserInput { text } = op else {
            panic!("a typed anchor names no attachment, so this is a text-only turn");
        };
        assert_eq!(text, "show me [Image #7 — attachment no longer available]");
    }

    #[test]
    fn an_anchor_cannot_be_answered_by_an_image_that_never_had_a_chip() {
        let root = std::env::temp_dir().join(format!("core-anchor-mention-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("test workspace");
        let (first, _) = distinct_gifs();
        let fixture = root.join("shot.gif");
        std::fs::write(&fixture, first).expect("fixture");

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let session = Session::for_test(tx);
        let mut app = App::new();
        let mut notifier = notification::TerminalNotifier::new(false);
        // The mention's image is admitted at submit time and gets id 1 inside the staged store, but
        // it never had a chip — so the typed `[Image #1]` names nothing the operator could see.
        app.editor
            .insert_str(&format!("look at [Image #1] @image({})", fixture.display()));

        submit_composer(&mut app, &session, &mut notifier);

        let op = rx
            .try_recv()
            .expect("composer submits through the bounded SQ")
            .into_current()
            .expect("current protocol envelope");
        let Op::UserInputV2 { segments } = op else {
            panic!("the mention still attaches its image");
        };
        assert_eq!(
            segments.text(),
            "look at [Image #1 — attachment no longer available]",
            "numbering coincidence must not turn a typed anchor into a live reference"
        );
        assert_eq!(segments.images().count(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_chip_row_carries_the_identity_the_anchor_names() {
        let (first, second) = distinct_gifs();
        let mut app = App::new();
        app.editor.insert_str("compare ");
        app.editor
            .attach_image_bytes("left.png", first)
            .expect("a canonical GIF");
        app.editor.insert_str(" with ");
        app.editor
            .attach_image_bytes("right.png", second)
            .expect("a second canonical GIF");

        let screen = render_text(&mut app, 100, 14);
        assert!(screen.contains("#1 left.png"), "{screen}");
        assert!(screen.contains("#2 right.png"), "{screen}");
        assert!(screen.contains("[Image #1] with [Image #2]"), "{screen}");
        assert!(
            !screen.contains("R0lGOD"),
            "the chip and the anchor are both references; neither prints the bytes"
        );
    }

    #[test]
    fn clipboard_helper_environment_cannot_inherit_provider_credentials_or_proxies() {
        let environment = clipboard_child_environment_with(|name| {
            Some(
                match name {
                    "WAYLAND_DISPLAY" => "wayland-1",
                    "XDG_RUNTIME_DIR" => "/tmp/core-runtime",
                    "DISPLAY" => ":1",
                    "XAUTHORITY" => "/tmp/core-xauthority",
                    "SystemRoot" | "SYSTEMROOT" | "WINDIR" => r"C:\Windows",
                    "PATHEXT" => ".EXE;.CMD",
                    "TEMP" | "TMP" => r"C:\Temp",
                    _ => "must-not-cross",
                }
                .into(),
            )
        });
        let keys = environment
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<std::collections::BTreeSet<_>>();
        for forbidden in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "ITERON_RELEASE_SMOKE_KEY",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
        ] {
            assert!(
                !keys.contains(forbidden),
                "{forbidden} crossed the allowlist"
            );
        }
        assert!(
            environment
                .iter()
                .all(|(_, value)| value != "must-not-cross"),
            "an unrecognized parent value crossed the clipboard helper boundary"
        );
    }

    /// I-64: the response-header deadline is 60s and the stream idle deadline 120s, so a dead
    /// connection and a slow prefill used to look identical for a full minute. The interface must
    /// say which one it is watching, and must stop saying it the instant a token arrives.
    #[test]
    fn a_stalled_provider_is_described_differently_from_a_slow_one_before_the_deadline() {
        let mut app = App::new();
        app.running = true;
        apply_event(&mut app, UiEvent::Phase(iteron_protocol::Phase::Model));

        // An ordinary wait says nothing at all; the phase label already covers it.
        assert!(app.first_token_stall().is_none());

        app.awaiting_first_token_since = Some(Instant::now() - FIRST_TOKEN_SLOW_AFTER);
        let slow = app
            .first_token_stall()
            .expect("a slow prefill is described");
        assert_eq!(slow.state, FirstTokenState::Slow);
        assert!(slow.label().contains("waiting for the first token"));

        app.awaiting_first_token_since = Some(Instant::now() - FIRST_TOKEN_STALL_AFTER);
        let stalled = app
            .first_token_stall()
            .expect("a stalled stream is described");
        assert_eq!(stalled.state, FirstTokenState::Stalled);
        assert!(stalled.label().contains("may be stalled"));
        assert_ne!(
            slow.label(),
            stalled.label(),
            "the two failures must not share one sentence"
        );
        assert!(
            FIRST_TOKEN_STALL_AFTER < std::time::Duration::from_secs(60),
            "the operator must learn this before the response-header deadline expires"
        );

        // Extended thinking is the model producing tokens, so it clears the clock exactly like
        // text does — the same rule `TurnEnd.ttft_ms` measures by.
        apply_event(&mut app, UiEvent::Thinking("reasoning".into()));
        assert!(app.first_token_stall().is_none());

        app.awaiting_first_token_since = Some(Instant::now() - FIRST_TOKEN_STALL_AFTER);
        apply_event(&mut app, UiEvent::Text("answer".into()));
        assert!(app.first_token_stall().is_none());

        // Leaving the model phase stops the clock: only a provider request can be waiting on one.
        apply_event(&mut app, UiEvent::Phase(iteron_protocol::Phase::Model));
        app.awaiting_first_token_since = Some(Instant::now() - FIRST_TOKEN_STALL_AFTER);
        apply_event(&mut app, UiEvent::Phase(iteron_protocol::Phase::Tools));
        assert!(app.first_token_stall().is_none());
    }

    #[test]
    fn windows_clipboard_plan_ignores_parent_roots_and_uses_fixed_stock_powershell_path() {
        fn simulated_windows_root(path: &Path) -> bool {
            let text = path.to_string_lossy();
            if text.starts_with("\\\\?\\") || text.starts_with("\\\\.\\") {
                return false;
            }
            let bytes = text.as_bytes();
            (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/'))
                || text.starts_with(r"\\")
        }

        let environment = windows_clipboard_environment_with(
            Some(r"C:\Windows".into()),
            |name| {
                Some(
                    match name {
                        "TEMP" | "TMP" => r"C:\Temp",
                        "SystemRoot" | "SYSTEMROOT" | "WINDIR" => r"D:\attacker",
                        _ => "must-not-cross",
                    }
                    .into(),
                )
            },
            simulated_windows_root,
        );
        assert_eq!(
            windows_clipboard_powershell_program(&environment),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into())
        );
        assert_eq!(
            environment
                .iter()
                .find_map(|(name, value)| (name == "PATH").then_some(value))
                .map(OsString::as_os_str),
            Some(std::ffi::OsStr::new(
                r"C:\Windows\System32\WindowsPowerShell\v1.0;C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem"
            ))
        );
        let keys = environment
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            ["PATH", "SystemRoot", "TEMP", "TMP", "WINDIR"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        for forbidden in ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"] {
            assert!(!keys.contains(forbidden));
        }

        let ignored_parent_root = windows_clipboard_environment_with(
            Some(r"D:\Windows".into()),
            |name| {
                matches!(name, "SystemRoot" | "SYSTEMROOT" | "WINDIR")
                    .then(|| r"C:\attacker".into())
            },
            simulated_windows_root,
        );
        assert_eq!(
            windows_clipboard_powershell_program(&ignored_parent_root),
            Some(r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into())
        );
        for invalid in [
            r"relative\Windows",
            r"\\?\C:\Windows",
            r"\\.\C:\Windows",
            r"C:\Windows;C:\attacker",
        ] {
            assert!(
                windows_clipboard_environment_with(
                    Some(invalid.into()),
                    |_| None,
                    simulated_windows_root,
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn notifications_use_only_the_out_of_band_writer_and_never_stream_deltas() {
        let mut app = App::new();
        let mut output = Vec::new();
        let mut notifier = notification::TerminalNotifier::new(true);
        notifier.begin_run();

        apply_live_event(
            &mut app,
            UiEvent::Text("visible streamed answer".into()),
            &mut notifier,
            &mut output,
        );
        assert!(
            output.is_empty(),
            "a streamed delta must remain byte-silent"
        );

        apply_live_event(
            &mut app,
            turn_end(0.01, Usage::default()),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            UiEvent::Phase(iteron_protocol::Phase::Model),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            turn_end(0.02, Usage::default()),
            &mut notifier,
            &mut output,
        );
        assert!(
            output.is_empty(),
            "a provider TurnEnd is not the authoritative run-complete boundary"
        );

        let approval = UiEvent::ApprovalRequest {
            id: SubmissionId(41),
            tool: "hostile\x1b]9;injected".into(),
            capability: Capability::CodeExecuting,
            reason: "fixture".into(),
            arguments: serde_json::json!({"command": "true"}),
            workspace: "/fixture".into(),
        };
        apply_live_event(&mut app, approval.clone(), &mut notifier, &mut output);
        apply_live_event(&mut app, approval, &mut notifier, &mut output);
        assert_eq!(
            output, b"\x07",
            "a repeated approval id is notified only once"
        );
        apply_live_event(
            &mut app,
            UiEvent::Done("legacy presentation".into()),
            &mut notifier,
            &mut output,
        );
        assert_eq!(
            output, b"\x07",
            "UiEvent::Done cannot masquerade as App Server run completion"
        );
        assert!(
            !String::from_utf8_lossy(&output).contains("injected"),
            "untrusted event content must not enter a control sequence"
        );

        app.flush_text();
        for block in &app.transcript {
            let retained = block.to_text();
            assert!(!retained.contains('\x1b'));
            assert!(!retained.contains('\x07'));
        }
    }

    #[test]
    fn provider_turns_and_done_wait_for_the_authoritative_run_boundary() {
        let mut app = App::new();
        let mut output = Vec::new();
        let mut notifier = notification::TerminalNotifier::new(true);
        notifier.begin_run();

        apply_live_event(
            &mut app,
            UiEvent::Phase(iteron_protocol::Phase::Model),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            turn_end(0.01, Usage::default()),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            UiEvent::Done("Done".into()),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            UiEvent::Done("duplicate transport delivery".into()),
            &mut notifier,
            &mut output,
        );
        assert_eq!(
            output, b"",
            "model phases, provider turns, and Done are all run-completion byte-silent"
        );

        let trigger = notifier
            .run_completed()
            .expect("the accepted run owns one terminal boundary");
        notifier.emit(&mut output, trigger);
        assert_eq!(
            output, b"\x07",
            "the authoritative run boundary emits exactly one notification"
        );
        assert_eq!(notifier.run_completed(), None);
    }

    #[test]
    fn route_or_effort_change_clears_request_telemetry_but_not_static_capacity() {
        let usage = Usage {
            input: 10,
            cache_read: 20,
            ..Usage::default()
        };
        let mut app = App::new();
        app.last_turn_usage = Some(usage);
        app.last_context = Some(ContextEstimate {
            system_tokens: 1,
            tool_tokens: 2,
            conversation_tokens: 3,
            tool_result_tokens: 0,
            lsp_result_tokens: 0,
            transcript_tokens: 3,
            framing_tokens: 4,
            total_tokens: 10,
            provenance: iteron_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
        });
        app.model_context_window = Some(200_000);
        app.effort_application = Some(EffortApplication::Unsupported {
            requested: iteron_protocol::ReasoningEffort::High,
        });
        // The runtime clears the ledger's last-turn usage on a model change (see
        // `app_server::apply_control`) and reports the result on the snapshot; the frontend adopts
        // whatever the snapshot says rather than deciding for itself.
        let state = app_server::SessionSnapshot {
            mode: iteron_protocol::PermissionMode::default(),
            effort: iteron_protocol::Effort::default(),
            model: "claude-opus-5".into(),
            cost: iteron_obs::CostState::default(),
            last_turn_usage: None,
            unadmitted_steers: Vec::new(),
            permission_rules: PermissionRules::new(),
            ledger_summary: String::new(),
            rate_limit: None,
            mcp_health: Vec::new(),
        };

        clear_last_turn_telemetry_from(&mut app, &state);

        assert!(app.last_turn_usage.is_none());
        assert!(app.last_context.is_none());
        assert_eq!(app.model_context_window, Some(200_000));
        assert!(app.effort_application.is_none());
    }

    #[test]
    fn status_uses_last_turn_truth_and_never_invents_a_context_window() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.model = "gpt-5".into();
        app.route.provider_id = "openai".into();
        app.route.model_id = "gpt-5".into();
        app.effort = Effort::High;
        let usage = Usage {
            input: 30,
            cache_read: 70,
            output: 9,
            ..Usage::default()
        };
        let mut event = turn_end(0.02, usage);
        if let UiEvent::TurnEnd {
            effort,
            model_context_window,
            ..
        } = &mut event
        {
            *effort = EffortApplication::Unsupported {
                requested: iteron_protocol::ReasoningEffort::High,
            };
            *model_context_window = None;
        }
        apply_event(&mut app, event);

        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|frame| draw(frame, &mut app)).unwrap();
        let screen = buffer_text(&term);
        assert!(screen.contains("cache 70%"), "cache is the last-turn ratio");
        assert!(
            screen.contains("ctx 100 used"),
            "unknown window reports only provider-observed input"
        );
        assert!(
            !screen.contains("ctx 120.0k") && !screen.contains("% left"),
            "the compaction trigger must never masquerade as a model window"
        );
        assert!(
            screen.contains("● high · not enforced"),
            "effort degradation is visible instead of implied exact"
        );
    }

    #[test]
    fn active_shelf_progressively_discloses_run_metrics() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new();
        app.running = true;
        app.status = "thinking".into();
        app.cost = CostState::Known {
            amount_microusd: 80_000,
            rate_card_digest: "sha256:test-rate-card".into(),
        };
        app.last_turn_usage = Some(Usage {
            input: 39,
            cache_read: 61,
            ..Usage::default()
        });
        app.turns = 4;
        app.effort = Effort::Ultracode;
        app.run_started = Some(Instant::now());
        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let s = buffer_text(&term);
        let statusline = s.lines().last().unwrap_or_default();
        assert!(
            !statusline.contains('█') && !statusline.contains('░'),
            "statusline has no permanent gauge chrome: {statusline:?}"
        );
        assert!(s.contains("cache 61%"), "wide shelf shows cache-hit text");
        assert!(s.contains("turn 4"), "wide shelf shows the turn counter");
        assert!(s.contains("$0.08"), "wide shelf shows cost");
        assert!(s.contains("thinking"), "shelf shows the live phase word");
        assert!(
            s.contains("ultracode"),
            "shelf shows the special effort mode"
        );
        // m:ss run clock present (0:00 at t≈0).
        assert!(s.contains("0:0"), "HUD shows an m:ss run clock: {s:?}");
    }

    #[test]
    fn interrupt_state_replaces_stale_phase_in_active_shelf() {
        let mut app = App::new();
        app.running = true;
        app.interrupting = true;
        app.status = "verifying".into();
        let screen = render_text(&mut app, 80, 16);
        assert!(screen.contains("interrupt requested"));
        assert!(screen.contains("stopping now"));
        assert!(!screen.contains("✢ verifying"));
    }

    #[test]
    fn running_ctrl_d_requests_exactly_one_drain_without_requiring_git() {
        let mut app = App::new();
        app.running = true;
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session = Session::for_test(tx);
        let drain = Arc::new(AtomicBool::new(false));

        request_drain(&mut app, &session, &drain, true);
        request_drain(&mut app, &session, &drain, true);

        assert!(app.draining);
        assert!(drain.load(Ordering::Relaxed));
        assert!(app.status.contains("draining session"));
        assert!(matches!(
            rx.try_recv()
                .expect("Ctrl-D submits one control envelope")
                .into_current()
                .expect("current protocol envelope"),
            Op::Drain
        ));
        assert!(
            rx.try_recv().is_err(),
            "repeated Ctrl-D must not spam drain submissions"
        );
        let screen = render_text(&mut app, 80, 16);
        assert!(screen.contains("draining"));
    }

    #[test]
    fn running_ctrl_d_is_available_without_a_workspace_checkpoint() {
        let mut app = App::new();
        app.running = true;
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session = Session::for_test(tx);
        let drain = Arc::new(AtomicBool::new(false));

        request_drain(&mut app, &session, &drain, false);

        assert!(app.draining);
        assert!(drain.load(Ordering::Relaxed));
        assert!(matches!(
            rx.try_recv().unwrap().into_current().unwrap(),
            Op::Drain
        ));
    }

    #[test]
    fn a_second_interrupt_force_cancels_without_draining_or_consuming_the_queue() {
        let mut app = App::new();
        app.running = true;
        app.interrupting = true;
        app.queue_after_turn("the next prompt".into()).unwrap();
        let queued = app.queued.front().cloned().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session = Session::for_test(tx);
        force_cancel_turn(&mut app, &session);
        force_cancel_turn(&mut app, &session);

        assert!(app.running, "RunEnded remains the only idle boundary");
        assert!(app.interrupting);
        assert!(app.force_cancelling);
        assert!(!app.draining);
        assert_eq!(app.queued.front(), Some(&queued));
        assert!(matches!(
            rx.try_recv()
                .expect("the escalation submits one force-cancel")
                .into_current()
                .expect("current protocol envelope"),
            Op::ForceCancel
        ));
        assert!(rx.try_recv().is_err(), "repeated escalation is idempotent");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn export_path_uses_the_shared_capability_snapshot_writer() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("core-export-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let blocks = vec![
            Arc::new(block::Block::new(
                1,
                block::BlockKind::User("first semantic record".into()),
            )),
            Arc::new(block::Block::new(
                2,
                block::BlockKind::Notice {
                    level: block::NoticeLevel::Info,
                    text: "second semantic record".into(),
                },
            )),
        ];
        let exported = export_transcript(&root, &blocks, Some(&[2]), "reports/session.md").unwrap();
        assert_eq!(exported, root.join("reports/session.md"));
        assert_eq!(
            std::fs::read(&exported).unwrap(),
            transcript_export_body(&blocks, Some(&[2])).unwrap(),
            "viewer and slash export persist the exact semantic snapshot builder bytes"
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn export_refuses_symlink_target_and_parent_escape() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "core-export-symlink-{}-{nonce}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "core-export-outside-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("target"), "outside").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.join("target"), root.join("linked.md")).unwrap();
        let blocks = vec![Arc::new(block::Block::new(
            1,
            block::BlockKind::User("safe".into()),
        ))];
        assert!(export_transcript(&root, &blocks, None, "escape/new.md").is_err());
        assert!(export_transcript(&root, &blocks, None, "linked.md").is_err());
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }

    #[cfg(unix)]
    #[test]
    fn init_directory_refuses_a_workspace_symlink() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("core-init-symlink-{}-{nonce}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("core-init-outside-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".iteron")).unwrap();

        assert!(ensure_real_workspace_dir(&root, ".iteron").is_err());
        assert!(!outside.join("config.json").exists());

        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }

    #[test]
    fn approval_event_preempts_an_open_transcript_viewer_immediately() {
        let mut app = App::new();
        app.transcript_viewer
            .open("", &app.transcript, app.transcript_revision);
        assert!(app.transcript_viewer.is_open());
        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(77),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "fixture".into(),
                arguments: serde_json::json!({"command": "true"}),
                workspace: "/fixture".into(),
            },
        );
        assert!(!app.transcript_viewer.is_open());
        assert!(app.pending.is_some());
        assert_eq!(app.approval_choice, ApprovalChoice::Deny);
    }

    #[tokio::test]
    async fn pending_transcript_effect_never_blocks_an_approval_transition() {
        let mut app = App::new();
        app.transcript_viewer
            .open("", &app.transcript, app.transcript_revision);
        let mut effects = transcript_effect::Supervisor::default();
        effects
            .start(transcript_effect::Request::Delay {
                duration: Duration::from_millis(50),
                origin: transcript_effect::Origin::Viewer,
            })
            .unwrap();
        app.transcript_viewer.begin_effect("test effect");

        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(78),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "must preempt background UI effects".into(),
                arguments: serde_json::json!({"command": "true"}),
                workspace: "/fixture".into(),
            },
        );

        assert!(effects.is_active());
        assert!(!app.transcript_viewer.is_open());
        assert!(app.pending.is_some());
        effects.shutdown().await;
    }

    #[tokio::test]
    async fn reopening_viewer_restores_the_authoritative_pending_effect_marker() {
        let mut app = App::new();
        let mut effects = transcript_effect::Supervisor::default();
        effects
            .start(transcript_effect::Request::Delay {
                duration: Duration::from_millis(50),
                origin: transcript_effect::Origin::Viewer,
            })
            .unwrap();
        open_transcript_viewer(&mut app, &effects, "");
        assert_eq!(
            app.transcript_viewer.pending_effect_label(),
            Some("test effect")
        );

        app.transcript_viewer.close();
        open_transcript_viewer(&mut app, &effects, "");
        assert_eq!(
            app.transcript_viewer.pending_effect_label(),
            Some("test effect"),
            "reopen must derive pending state from the live single-flight supervisor"
        );
        effects.shutdown().await;
    }
}
#[test]
fn window_title_is_capability_gated_and_restored_exactly_once() {
    let capabilities = iteron_statusline::Capabilities::detect(|name| match name {
        "TERM" => Some("xterm-256color".into()),
        _ => None,
    });
    let active = AtomicBool::new(false);
    let mut bytes = Vec::new();
    assert!(set_terminal_title_to(&mut bytes, capabilities, "Iteron · repo", &active).unwrap());
    assert!(bytes.starts_with(iteron_statusline::title_stack_push().as_bytes()));
    assert!(bytes.windows(4).any(|window| window == b"]2;C"));
    assert!(
        replace_terminal_title_to(
            &mut bytes,
            capabilities,
            "Iteron · session name",
            &active,
        )
        .unwrap()
    );
    let push = iteron_statusline::title_stack_push().as_bytes();
    assert_eq!(
        bytes
            .windows(push.len())
            .filter(|window| *window == push)
            .count(),
        1,
        "renaming a tab replaces the owned title without nesting another restore frame"
    );
    restore_terminal_title_to(&mut bytes, &active);
    let after_first = bytes.len();
    assert!(bytes.ends_with(iteron_statusline::restore_title().as_bytes()));
    restore_terminal_title_to(&mut bytes, &active);
    assert_eq!(
        bytes.len(),
        after_first,
        "cleanup may pop only the frame it owns"
    );

    let multiplexed = iteron_statusline::Capabilities::detect(|name| match name {
        "TERM" => Some("screen-256color".into()),
        "TMUX" => Some("session".into()),
        _ => None,
    });
    let active = AtomicBool::new(false);
    let mut bytes = Vec::new();
    assert!(!set_terminal_title_to(&mut bytes, multiplexed, "iteron", &active).unwrap());
    assert!(bytes.is_empty());
}
