use super::*;
use iteron_protocol::ToolUse;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let serial = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "iteron-tools-grep-{label}-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn grep_call(id: &str, pattern: &str, regex: bool) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "grep".into(),
        input: serde_json::json!({"pattern":pattern,"regex":regex}),
    }
}

fn grep_call_auto(id: &str, pattern: &str) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "grep".into(),
        input: serde_json::json!({"pattern":pattern}),
    }
}

fn registry(root: &Path) -> Registry {
    let registry = Registry::read_only(root).unwrap();
    registry
        .install_observation_tool_policy(crate::ObservationToolPolicy::default())
        .unwrap();
    registry
}

#[tokio::test]
async fn d3_08_g1_regex_finds_a_match_ten_directories_deep() {
    let root = TestRoot::new("deep-regex");
    let mut nested = root.0.clone();
    for depth in 0..10 {
        nested.push(format!("level-{depth}"));
    }
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        nested.join("deep.rs"),
        "fn ordinary() {}\nfn deeply_nested_test() {}\n",
    )
    .unwrap();
    let registry = registry(&root.0);

    let first = registry
        .dispatch(grep_call("regex-1", r"fn \w+_test", true))
        .await;
    let second = registry
        .dispatch(grep_call("regex-2", r"fn \w+_test", true))
        .await;

    assert!(!first.is_error, "{}", first.content);
    assert!(
        first
            .content
            .contains("level-9/deep.rs:2: fn deeply_nested_test")
    );
    assert!(!first.content.contains("ordinary"));
    assert_eq!(first.content, second.content, "search order must be stable");
}

#[tokio::test]
async fn omitted_regex_mode_detects_common_intent_and_explicit_false_stays_literal() {
    let root = TestRoot::new("auto-regex");
    std::fs::write(
        root.0.join("patterns.txt"),
        "alpha only\nbeta only\nalpha|beta literal\nitem-42\nitem-x\n",
    )
    .unwrap();
    let registry = registry(&root.0);

    let alternation = registry
        .dispatch(grep_call_auto("auto-alternation", "alpha|beta"))
        .await;
    assert!(!alternation.is_error, "{}", alternation.content);
    assert!(alternation.content.contains("patterns.txt:1: alpha only"));
    assert!(alternation.content.contains("patterns.txt:2: beta only"));

    let shorthand = registry
        .dispatch(grep_call_auto("auto-shorthand", r"^item-\d+$"))
        .await;
    assert!(!shorthand.is_error, "{}", shorthand.content);
    assert!(shorthand.content.contains("patterns.txt:4: item-42"));
    assert!(!shorthand.content.contains("item-x"));

    let literal = registry
        .dispatch(grep_call("literal-alternation", "alpha|beta", false))
        .await;
    assert!(!literal.is_error, "{}", literal.content);
    assert!(
        literal
            .content
            .contains("patterns.txt:3: alpha|beta literal")
    );
    assert!(!literal.content.contains("patterns.txt:1:"));
    assert!(!literal.content.contains("patterns.txt:2:"));
}

#[tokio::test]
async fn omitted_regex_mode_keeps_dots_brackets_and_paths_literal() {
    let root = TestRoot::new("auto-literal");
    std::fs::write(
        root.0.join("paths.txt"),
        "src/main.rs[0]\nsrc/mainXrs0\n[alpha|beta]\n",
    )
    .unwrap();
    let registry = registry(&root.0);

    let result = registry
        .dispatch(grep_call_auto("auto-literal", "src/main.rs[0]"))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert!(result.content.contains("paths.txt:1: src/main.rs[0]"));
    assert!(!result.content.contains("paths.txt:2:"));

    let bracketed = registry
        .dispatch(grep_call_auto("auto-bracketed", "[alpha|beta]"))
        .await;
    assert!(!bracketed.is_error, "{}", bracketed.content);
    assert!(bracketed.content.contains("paths.txt:3: [alpha|beta]"));
}

#[tokio::test]
async fn contextual_search_exposes_a_bounded_call_edge() {
    let root = TestRoot::new("context");
    std::fs::write(
        root.0.join("caller.rs"),
        "fn load(path: &str) {\n    let bytes = read(path);\n    let record = decode_record(&bytes);\n    persist(record);\n}\n",
    )
    .unwrap();
    let registry = registry(&root.0);
    let result = registry
        .dispatch(ToolUse {
            id: "context".into(),
            name: "grep".into(),
            input: serde_json::json!({
                "pattern":"decode_record",
                "path":"caller.rs",
                "context_lines":3,
                "max_results":1
            }),
        })
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert!(
        result
            .content
            .contains("> caller.rs:3:     let record = decode_record(&bytes);")
    );
    assert!(result.content.contains("caller.rs:4:     persist(record);"));
    assert_eq!(result.content.matches("caller.rs:1-5").count(), 1);
}

#[tokio::test]
async fn related_terms_filter_shared_symbols_to_a_coherent_task_context() {
    let root = TestRoot::new("related-context");
    std::fs::write(
        root.0.join("unrelated.js"),
        "format: 'plain_text'\nrender_document(input)\nescape: 'minimal'\n",
    )
    .unwrap();
    std::fs::write(
        root.0.join("target.js"),
        "format: 'markdown'\nrender_document(input)\nsanitizer: 'sanitize_html'\n",
    )
    .unwrap();
    let registry = registry(&root.0);

    let result = registry
        .dispatch(ToolUse {
            id: "related-context".into(),
            name: "grep".into(),
            input: serde_json::json!({
                "pattern":"render_document",
                "related_terms":["markdown", "sanitize_html"],
                "proximity_lines":4,
                "context_lines":1
            }),
        })
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert!(
        result.content.contains("target.js:1-3"),
        "{}",
        result.content
    );
    assert!(result.content.contains("markdown@1"), "{}", result.content);
    assert!(
        result.content.contains("sanitize_html@3"),
        "{}",
        result.content
    );
    assert!(
        !result.content.contains("unrelated.js"),
        "{}",
        result.content
    );
    assert!(result.content.contains("filter out contexts"));
}

#[tokio::test]
async fn related_terms_and_proximity_are_bounded_at_the_tool_boundary() {
    let root = TestRoot::new("related-bounds");
    std::fs::write(root.0.join("source.txt"), "needle\nrelated\n").unwrap();
    let registry = registry(&root.0);

    let empty = registry
        .dispatch(ToolUse {
            id: "empty-related".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern":"needle", "related_terms":[]}),
        })
        .await;
    assert!(empty.is_error);
    assert!(empty.content.contains("between 1 and"));

    let unbounded = registry
        .dispatch(ToolUse {
            id: "unbounded-proximity".into(),
            name: "grep".into(),
            input: serde_json::json!({
                "pattern":"needle",
                "related_terms":["related"],
                "proximity_lines":MAX_GREP_PROXIMITY_LINES + 1
            }),
        })
        .await;
    assert!(unbounded.is_error);
    assert!(unbounded.content.contains("policy limit"));
}

#[tokio::test]
async fn broad_search_retains_hits_coherent_with_the_recent_exact_read() {
    let root = TestRoot::new("working-set-ranking");
    std::fs::write(
        root.0.join("a-unrelated.js"),
        "target: 'wasm'\ncompile_asset(source)\ncompressor: 'size'\n",
    )
    .unwrap();
    std::fs::write(
        root.0.join("m-focus.js"),
        "target: 'ios'\ncompile_asset(source)\noptimizer: 'llvm'\n",
    )
    .unwrap();
    std::fs::write(
        root.0.join("z-reference.js"),
        "target: 'ios'\ncompile_asset(source)\nbackend: 'llvm'\n",
    )
    .unwrap();
    let registry = registry(&root.0);
    let search_call = |id: &str| ToolUse {
        id: id.into(),
        name: "grep".into(),
        input: serde_json::json!({"pattern":"compile_asset", "max_results":2}),
    };
    let before_focus = registry.dispatch(search_call("before-focus")).await;
    assert!(!before_focus.is_error, "{}", before_focus.content);
    assert!(before_focus.content.contains("a-unrelated.js"));
    assert!(!before_focus.content.contains("z-reference.js"));
    let focus = registry
        .dispatch(ToolUse {
            id: "focus-read".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":"m-focus.js"}),
        })
        .await;
    assert!(!focus.is_error, "{}", focus.content);

    let result = registry.dispatch(search_call("ranked-search")).await;

    assert!(!result.is_error, "{}", result.content);
    let focused_index = result
        .content
        .find("m-focus.js")
        .unwrap_or_else(|| panic!("{}", result.content));
    let reference_index = result
        .content
        .find("z-reference.js")
        .unwrap_or_else(|| panic!("{}", result.content));
    assert!(focused_index < reference_index, "{}", result.content);
    assert!(
        !result.content.contains("a-unrelated.js"),
        "{}",
        result.content
    );
}

#[tokio::test]
async fn symbol_searches_auto_render_definition_and_schema_contexts_without_prior_focus() {
    let root = TestRoot::new("auto-structural-context");
    std::fs::write(
        root.0.join("target.js"),
        "fn decode_record(raw: &[u8]) -> Record {\n    Record::from_bytes(raw)\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.0.join("reference.js"),
        "trait RecordDecoder {\n    fn decode_record(raw: &[u8]) -> Record;\n}\n",
    )
    .unwrap();
    let registry = registry(&root.0);

    let result = registry
        .dispatch(ToolUse {
            id: "auto-definition-schema".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern":"decode_record", "max_results":2}),
        })
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert!(result.content.contains("[auto structural context]"));
    assert!(
        result
            .content
            .contains("fn decode_record(raw: &[u8]) -> Record")
    );
    assert!(result.content.contains("trait RecordDecoder"));
}

#[tokio::test]
async fn structural_expansion_keeps_budget_for_compact_cross_repository_breadth() {
    let root = TestRoot::new("structural-breadth-budget");
    for index in 0..8 {
        let fields = (0..12)
            .map(|field| format!("      field{field}: value{field},\n"))
            .collect::<String>();
        std::fs::write(
            root.0.join(format!("caller-{index}.js")),
            format!(
                "fn serialize_variant_{index}() {{\n  let schema = SerializationSchema {{\n{fields}  }};\n  encode_schema(&schema);\n}}\n"
            ),
        )
        .unwrap();
    }
    let registry = Registry::read_only(&root.0).unwrap();
    let mut policy = crate::ObservationToolPolicy::default();
    policy.grep.max_matches = 8;
    policy.grep.output_max_bytes = 4 * 1024;
    registry.install_observation_tool_policy(policy).unwrap();

    let result = registry
        .dispatch(ToolUse {
            id: "structural-breadth-budget".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern":"SerializationSchema", "max_results":8}),
        })
        .await;

    assert!(!result.is_error, "{}", result.content);
    let expanded = result.content.matches("[auto structural context]").count();
    assert!(expanded > 0 && expanded < 8, "{}", result.content);
    for index in 0..8 {
        assert!(
            result.content.contains(&format!("caller-{index}.js")),
            "{}",
            result.content
        );
    }
}

#[tokio::test]
async fn cross_file_siblings_never_become_causal_authority() {
    let root = TestRoot::new("structural-context-comparison");
    std::fs::write(
        root.0.join("target.js"),
        "function loadConfig(input) {\n  const config = parse_config(input);\n  return config.withDefaults();\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.0.join("alternative.js"),
        "function validateConfig(input) {\n  const schema = config_schema();\n  return parse_config_with_schema(input, schema);\n}\n",
    )
    .unwrap();
    let registry = registry(&root.0);
    let focused = registry
        .dispatch(ToolUse {
            id: "focus-target".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":"target.js"}),
        })
        .await;
    assert!(!focused.is_error, "{}", focused.content);

    let result = registry
        .dispatch(ToolUse {
            id: "compare-sibling".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern":"parse_config", "max_results":2}),
        })
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(
        crate::workspace_evidence_outcome(&result.content),
        Some(crate::WorkspaceEvidenceOutcome::Insufficient)
    );
    assert!(result.content.contains("focused=1"), "{}", result.content);
    assert!(result.content.contains("files=2"), "{}", result.content);
    assert!(
        result.content.contains(
            "reason=causal_contrast_unproven; remediation=add_related_terms_or_submit_existing_exact_source_spans"
        ),
        "{}",
        result.content
    );
    assert!(
        result.content.contains("parse_config(input)"),
        "{}",
        result.content
    );
    assert!(
        result
            .content
            .contains("parse_config_with_schema(input, schema)"),
        "{}",
        result.content
    );

    let explicit_contrast = registry
        .dispatch(ToolUse {
            id: "compare-sibling-related".into(),
            name: "grep".into(),
            input: serde_json::json!({
                "pattern":"parse_config",
                "related_terms":["input"],
                "max_results":2
            }),
        })
        .await;
    assert!(!explicit_contrast.is_error, "{}", explicit_contrast.content);
    assert_eq!(
        crate::workspace_evidence_outcome(&explicit_contrast.content),
        Some(crate::WorkspaceEvidenceOutcome::Insufficient)
    );
    assert!(
        explicit_contrast.content.contains(
            "reason=source_anchors_required; remediation=submit_role_labelled_exact_source_spans"
        ),
        "{}",
        explicit_contrast.content
    );
    assert!(!explicit_contrast.content.contains("comparison complete"));
    assert!(explicit_contrast.content.contains("input@"));
}

#[tokio::test]
async fn same_file_definition_and_caller_still_require_source_anchors() {
    let root = TestRoot::new("same-file-evidence");
    std::fs::write(
        root.0.join("transform.rs"),
        "fn transform_record(value: &str) -> String {\n    // RecordContract\n    value.trim().to_owned()\n}\n\nfn persist_record(raw: &str) {\n    // RecordContract\n    save(transform_record(raw));\n}\n",
    )
    .unwrap();
    let registry = registry(&root.0);
    let call = |id: &str, related_terms: Option<&[&str]>| ToolUse {
        id: id.into(),
        name: "grep".into(),
        input: match related_terms {
            Some(terms) => serde_json::json!({
                "pattern":"transform_record",
                "path":"transform.rs",
                "related_terms":terms,
                "max_results":2
            }),
            None => serde_json::json!({
                "pattern":"transform_record",
                "path":"transform.rs",
                "context_lines":3,
                "max_results":2
            }),
        },
    };

    let plain = registry.dispatch(call("same-file-plain", None)).await;
    assert!(!plain.is_error, "{}", plain.content);
    assert_eq!(
        crate::workspace_evidence_outcome(&plain.content),
        Some(crate::WorkspaceEvidenceOutcome::Insufficient)
    );
    assert!(plain.content.contains("contexts=2"), "{}", plain.content);
    assert!(plain.content.contains("files=1"), "{}", plain.content);
    assert!(
        plain.content.contains("facets=definition,caller/callee"),
        "{}",
        plain.content
    );
    assert!(
        plain.content.contains(
            "reason=causal_contrast_unproven; remediation=add_related_terms_or_submit_existing_exact_source_spans"
        ),
        "{}",
        plain.content
    );

    let explicit = registry
        .dispatch(call(
            "same-file-explicit-contrast",
            Some(&["RecordContract"]),
        ))
        .await;
    assert!(!explicit.is_error, "{}", explicit.content);
    assert_eq!(
        crate::workspace_evidence_outcome(&explicit.content),
        Some(crate::WorkspaceEvidenceOutcome::Insufficient)
    );
    assert!(explicit.content.contains("reason=source_anchors_required"));
    assert!(!explicit.content.contains("comparison complete"));
    assert!(
        explicit.content.contains("facets=definition,caller/callee"),
        "{}",
        explicit.content
    );
}

#[tokio::test]
async fn definitions_call_edges_and_tests_remain_neutral_observations() {
    let root = TestRoot::new("generic-evidence-comparison");
    std::fs::create_dir(root.0.join("module")).unwrap();
    std::fs::write(
        root.0.join("module/normalize.rs"),
        "// RecordContract\nfn normalize_record(value: &str) -> String {\n    value.trim().to_owned()\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.0.join("module/caller.rs"),
        "// RecordContract\nfn store(value: &str) {\n    persist(normalize_record(value));\n}\n",
    )
    .unwrap();
    std::fs::create_dir(root.0.join("module/tests")).unwrap();
    std::fs::write(
        root.0.join("module/tests/normalize_test.rs"),
        "// RecordContract\n#[test]\nfn trims_input() {\n    assert_eq!(normalize_record(\" x \"), \"x\");\n}\n",
    )
    .unwrap();
    let registry = registry(&root.0);
    let unfocused = registry
        .dispatch(ToolUse {
            id: "generic-evidence-unfocused".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern":"normalize_record", "max_results":3}),
        })
        .await;

    assert!(!unfocused.is_error, "{}", unfocused.content);
    assert!(
        unfocused
            .content
            .contains(crate::WORKSPACE_EVIDENCE_INSUFFICIENT_MARKER),
        "{}",
        unfocused.content
    );
    assert!(
        unfocused.content.contains("reason=no_focused_context"),
        "{}",
        unfocused.content
    );
    assert!(
        unfocused
            .content
            .contains("remediation=rerun_with_explicit_narrow_path_or_read_exact_file"),
        "{}",
        unfocused.content
    );
    assert!(
        unfocused.content.contains("focused=0"),
        "{}",
        unfocused.content
    );
    assert_eq!(
        crate::workspace_evidence_outcome(&unfocused.content),
        Some(crate::WorkspaceEvidenceOutcome::Insufficient)
    );

    let result = registry
        .dispatch(ToolUse {
            id: "generic-evidence-comparison".into(),
            name: "grep".into(),
            input: serde_json::json!({
                "pattern":"normalize_record",
                "path":"module",
                "related_terms":["RecordContract"],
                "max_results":3
            }),
        })
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert!(result.content.contains("reason=source_anchors_required"));
    assert!(!result.content.contains("comparison complete"));
    assert!(
        result
            .content
            .contains("facets=definition,caller/callee,test")
    );
    assert!(!result.content.contains("focused=0"), "{}", result.content);
    assert!(result.content.contains("module/normalize.rs"));
    assert!(result.content.contains("module/caller.rs"));
    assert!(result.content.contains("module/tests/normalize_test.rs"));
    assert_eq!(
        crate::workspace_evidence_outcome(&result.content),
        Some(crate::WorkspaceEvidenceOutcome::Insufficient)
    );

    let repeated_broad = registry
        .dispatch(ToolUse {
            id: "generic-evidence-repeated-broad".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern":"normalize_record", "max_results":3}),
        })
        .await;
    assert!(!repeated_broad.is_error, "{}", repeated_broad.content);
    assert_eq!(
        crate::workspace_evidence_outcome(&repeated_broad.content),
        Some(crate::WorkspaceEvidenceOutcome::Insufficient)
    );
    assert!(
        repeated_broad.content.contains("focused=0"),
        "{}",
        repeated_broad.content
    );

    let missing = registry
        .dispatch(ToolUse {
            id: "generic-evidence-insufficient".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern":"missing_symbol", "path":"module"}),
        })
        .await;
    assert!(!missing.is_error, "{}", missing.content);
    assert!(
        missing
            .content
            .contains(crate::WORKSPACE_EVIDENCE_INSUFFICIENT_MARKER),
        "{}",
        missing.content
    );
    assert!(missing.content.contains("reason=no_match"));
    assert_eq!(
        crate::workspace_evidence_outcome(&missing.content),
        Some(crate::WorkspaceEvidenceOutcome::Insufficient)
    );
}

#[test]
fn fair_admission_reaches_a_late_top_level_path_and_marks_partial_absence() {
    let root = TestRoot::new("fair-corpus-admission");
    std::fs::create_dir(root.0.join("a-early")).unwrap();
    std::fs::create_dir(root.0.join("z-late")).unwrap();
    std::fs::write(root.0.join("a-early/00.rs"), "ordinary_value\n").unwrap();
    std::fs::write(root.0.join("a-early/01.rs"), "ordinary_value\n").unwrap();
    std::fs::write(root.0.join("z-late/hit.rs"), "late_symbol___\n").unwrap();
    let policy = crate::ObservationToolPolicy::default().grep;
    let focus = crate::ObservationFocusSnapshot::default();
    let related_terms = Vec::new();
    let run = |pattern: &str| {
        let matcher = Matcher::compile(pattern, false).unwrap();
        search_with_source_limits(
            &root.0,
            &root.0,
            &matcher,
            SearchOptions {
                policy,
                context_lines: 0,
                auto_structural_context: true,
                stable_anchor_context: true,
                evidence_anchor: true,
                structural_context_max_lines: MAX_GREP_CONTEXT_LINES,
                related_terms: &related_terms,
                proximity_lines: DEFAULT_GREP_PROXIMITY_LINES,
                focus: &focus,
            },
            SearchSourceLimits {
                max_file_bytes: 1_024,
                max_total_source_bytes: 30,
                max_files: MAX_GREP_ENTRIES,
            },
        )
        .unwrap()
        .render(
            pattern,
            policy,
            &related_terms,
            DEFAULT_GREP_PROXIMITY_LINES,
            true,
            false,
        )
    };

    let hit = run("late_symbol");
    assert!(hit.contains("z-late/hit.rs"), "{hit}");
    assert!(
        hit.contains(
            "corpus coverage: eligible_files=3; admitted_files=2; eligible_bytes=45; admitted_bytes=30"
        ),
        "{hit}"
    );
    assert!(hit.contains("incomplete_paths=\"a-early\""), "{hit}");
    assert!(
        hit.contains("repeat same grep with path=\"a-early\""),
        "{hit}"
    );

    let missing = run("missing_symbol");
    assert!(
        missing
            .contains("reason=coverage_incomplete; remediation=repeat_same_grep_with_narrow_path"),
        "{missing}"
    );
    assert!(
        missing.contains("no matches for `missing_symbol` in the admitted corpus"),
        "{missing}"
    );
    assert!(!missing.contains("reason=no_match"), "{missing}");
}

#[tokio::test]
async fn contextual_match_budget_scales_with_window_size() {
    let root = TestRoot::new("context-budget");
    std::fs::write(
        root.0.join("many.txt"),
        "hit one\nseparator\nhit two\nseparator\nhit three\nseparator\n",
    )
    .unwrap();
    let registry = Registry::read_only(&root.0).unwrap();
    let mut policy = crate::ObservationToolPolicy::default();
    policy.grep.max_matches = 6;
    registry.install_observation_tool_policy(policy).unwrap();
    let result = registry
        .dispatch(ToolUse {
            id: "context-budget".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern":"hit","context_lines":1,"max_results":6}),
        })
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(result.content.matches("\n> many.txt:").count(), 2);
    assert!(result.content.contains("results capped at 2 matches"));
}

#[tokio::test]
async fn d3_08_g2_multi_gigabyte_file_is_skipped_before_reading() {
    let root = TestRoot::new("huge");
    let huge = std::fs::File::create(root.0.join("huge.log")).unwrap();
    huge.set_len(3 * 1024 * 1024 * 1024).unwrap();
    std::fs::write(root.0.join("small.txt"), "needle stays reachable\n").unwrap();
    let registry = registry(&root.0);

    let result = registry.dispatch(grep_call("huge", "needle", false)).await;

    assert!(!result.is_error, "{}", result.content);
    assert!(
        result
            .content
            .contains("small.txt:1: needle stays reachable")
    );
    assert!(result.content.contains("1 files skipped"));
    assert!(result.content.contains("per-file limit"));
    assert!(
        result.content.len()
            <= crate::ObservationToolPolicy::default()
                .grep
                .output_max_bytes
    );
}

#[tokio::test]
async fn d3_08_g3_repo_gitignore_and_default_vendor_filters_are_honored() {
    let root = TestRoot::new("gitignore");
    std::fs::write(
        root.0.join(".gitignore"),
        "ignored-by-repo/\ntarget/\nnode_modules/\n",
    )
    .unwrap();
    for directory in ["ignored-by-repo", "target", "node_modules"] {
        std::fs::create_dir_all(root.0.join(directory)).unwrap();
        std::fs::write(
            root.0.join(directory).join("hidden.txt"),
            "forbidden-match\n",
        )
        .unwrap();
    }
    std::fs::write(root.0.join("visible.txt"), "forbidden-match visible\n").unwrap();
    let registry = registry(&root.0);

    let result = registry
        .dispatch(grep_call("ignore", "forbidden-match", false))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert!(result.content.contains("visible.txt:1"));
    assert!(!result.content.contains("ignored-by-repo"));
    assert!(!result.content.contains("target/"));
    assert!(!result.content.contains("node_modules"));
}

#[tokio::test]
async fn d3_08_g4_match_cap_is_explicit_and_output_is_bounded() {
    let root = TestRoot::new("cap");
    let max_matches = crate::ObservationToolPolicy::default().grep.max_matches;
    let content = (0..max_matches + 20)
        .map(|index| format!("needle-{index}\n"))
        .collect::<String>();
    std::fs::write(root.0.join("many.txt"), content).unwrap();
    let registry = registry(&root.0);

    let result = registry
        .dispatch(grep_call("cap", r"needle-\d+", true))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(result.content.matches("many.txt:").count(), max_matches);
    assert!(
        result
            .content
            .contains(&format!("results capped at {max_matches} matches")),
        "{}",
        result.content
    );
    assert!(
        result.content.len()
            <= crate::ObservationToolPolicy::default()
                .grep
                .output_max_bytes
    );
}

#[tokio::test]
async fn pinned_match_limit_distinguishes_exact_boundary_from_n_plus_one() {
    let root = TestRoot::new("pinned-boundary");
    std::fs::write(
        root.0.join("matches.txt"),
        "exact one\nexact two\noverflow one\noverflow two\noverflow three\n",
    )
    .unwrap();

    let unpinned = Registry::read_only(&root.0).unwrap();
    let refused = unpinned
        .dispatch(grep_call("unpinned", "exact", false))
        .await;
    assert!(refused.is_error);
    assert!(refused.content.contains("policy was not installed"));

    let pinned = Registry::read_only(&root.0).unwrap();
    let mut policy = crate::ObservationToolPolicy::default();
    policy.grep.max_matches = 2;
    pinned.install_observation_tool_policy(policy).unwrap();

    let exact = pinned.dispatch(grep_call("exact", "exact", false)).await;
    assert!(!exact.is_error, "{}", exact.content);
    assert_eq!(exact.content.matches("matches.txt:").count(), 2);
    assert!(
        !exact.content.contains("results capped"),
        "{}",
        exact.content
    );

    let overflow = pinned
        .dispatch(grep_call("overflow", "overflow", false))
        .await;
    assert!(!overflow.is_error, "{}", overflow.content);
    assert_eq!(overflow.content.matches("matches.txt:").count(), 2);
    assert!(overflow.content.contains("results capped at 2 matches"));
}

#[tokio::test]
async fn invalid_or_unbounded_regex_is_rejected_before_traversal() {
    let root = TestRoot::new("invalid-regex");
    let registry = registry(&root.0);

    let invalid = registry.dispatch(grep_call("invalid", "(", true)).await;
    assert!(invalid.is_error);
    assert!(invalid.content.contains("invalid or oversized regex"));

    let oversized = registry
        .dispatch(grep_call(
            "oversized",
            &"x".repeat(MAX_GREP_PATTERN_BYTES + 1),
            false,
        ))
        .await;
    assert!(oversized.is_error);
    assert!(oversized.content.contains("pattern exceeds"));

    let ignore = std::fs::File::create(root.0.join(".gitignore")).unwrap();
    ignore.set_len(MAX_GITIGNORE_FILE_BYTES as u64 + 1).unwrap();
    let unsafe_ignore = registry
        .dispatch(grep_call("ignore-bound", "anything", false))
        .await;
    assert!(unsafe_ignore.is_error);
    assert!(unsafe_ignore.content.contains("safely read .gitignore"));
    assert!(unsafe_ignore.content.contains("byte limit"));
}
