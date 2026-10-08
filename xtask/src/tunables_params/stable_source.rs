//! Exact stable runtime identities for declarations moved to their real source owners.
//! This mapping changes identity/classification provenance only; owner and use-site paths remain actual.

pub(super) fn original_source(relative: &str, name: &str) -> Option<&'static str> {
    match (relative, name) {
        ("crates/cli/src/block/diff.rs", "HUNK_DEFAULT_START_LINE") => {
            Some("crates/cli/src/block.rs")
        }
        (
            "crates/cli/src/client_effects/path_completion.rs",
            "COMPLETION_DIRECTORY_CACHE_ENTRIES" | "COMPLETION_DIRECTORY_CACHE_TTL",
        ) => Some("crates/cli/src/tui/driver_support.rs"),
        (
            "crates/ctx/src/memory/selection.rs",
            "MEMORY_SLOT_VERSION"
            | "MAX_MEMORY_CANDIDATES"
            | "MAX_MEMORY_TASK_BYTES"
            | "MAX_MEMORY_CANDIDATE_TEXT_BYTES"
            | "MAX_MEMORY_SLUG_BYTES"
            | "CACHE_LIMIT"
            | "CACHE",
        ) => Some("crates/ctx/src/memory.rs"),
        ("crates/record/src/session/cache_receipts.rs", "RECEIPT_SCAN_CHUNK_BYTES") => {
            Some("crates/record/src/session.rs")
        }
        (
            "crates/record/src/session/index.rs",
            "BACKGROUND_SESSION_COMPACTIONS"
            | "DEFAULT_SESSION_DELTA_COMPACT_BYTES"
            | "DEFAULT_SESSION_DELTA_COMPACT_ROWS"
            | "DEFAULT_SESSION_PAGE_SIZE"
            | "INDEX_SCAN_LINES_PER_LIVE_RUN"
            | "MAX_BACKGROUND_SESSION_COMPACTIONS"
            | "MAX_SESSION_PAGE_SCAN_LINES"
            | "MAX_SESSION_PAGE_SIZE"
            | "SESSION_DELTA_HARD_LIMITS"
            | "SESSION_DELTA_INDEX_FILE"
            | "SESSION_DELTA_INDEX_VERSION"
            | "SESSION_DELTA_REFS_DIR"
            | "SESSION_DELTA_STATE_FILE"
            | "SESSION_INDEX_DIRTY_FILE"
            | "SESSION_INDEX_HEADER",
        ) => Some("crates/record/src/session.rs"),
        ("crates/record/src/session/model.rs", "MAX" | "MAX_FORK_DEPTH") => {
            Some("crates/record/src/session.rs")
        }
        ("crates/record/src/session/paths.rs", "MICROUSD_PER_USD" | "PRE_EPOCH_TIMESTAMP_SECS") => {
            Some("crates/record/src/session.rs")
        }
        (
            "crates/record/src/session/replay.rs",
            "RUN_ID_NANOS_FALLBACK" | "UNBOUNDED_SCOPE_ADMITS_LINE",
        ) => Some("crates/record/src/session.rs"),
        (
            "crates/cli/src/runtime/context_runtime.rs",
            "IMAGE_INPUT_INSPECTION_FAILED_REASON" | "IMAGE_INPUT_UNSUPPORTED_REASON",
        ) => Some("crates/cli/src/runtime.rs"),
        ("crates/cli/src/runtime/effect_descriptor.rs", "EFFECT_REASON_MAX_BYTES") => {
            Some("crates/cli/src/runtime.rs")
        }
        (
            "crates/cli/src/runtime/inbound_control.rs",
            "INBOUND_DRAIN_POLL_INTERVAL"
            | "MAX_INBOUND_OPS_PER_POLL"
            | "UNSUPPORTED_SUBMISSION_NOTICE"
            | "VERSION_MISMATCH_SUBMISSION_NOTICE",
        ) => Some("crates/cli/src/runtime.rs"),
        (
            "crates/cli/src/runtime/provider_accounting.rs",
            "MAX_COMMITTED_PROVIDER_RUN_NOTICES"
            | "PROVIDER_RUN_NOTICE_KEY_BODY_LEN"
            | "PROVIDER_RUN_NOTICE_LABEL"
            | "PROVIDER_RUN_NOTICE_PREFIX",
        ) => Some("crates/cli/src/runtime.rs"),
        (
            "crates/cli/src/runtime/provider_response_recovery.rs",
            "INTERRUPTED_STREAM_MAX_BYTES" | "INTERRUPTED_STREAM_MARKER",
        ) => Some("crates/cli/src/runtime.rs"),
        ("crates/cli/src/runtime/provider_route_events.rs", "PROVIDER_INTERRUPT_POLL_INTERVAL") => {
            Some("crates/cli/src/runtime.rs")
        }
        (
            "crates/cli/src/runtime/provider_usage_journal.rs",
            "INCOMPLETE_USAGE_NOTICE" | "UNPRICEABLE_CACHE_CREATION_NOTICE",
        ) => Some("crates/cli/src/runtime.rs"),
        (
            "crates/cli/src/runtime/request_context_publication.rs",
            "CONTEXT_HIGH_WATERMARK_DIVISOR",
        ) => Some("crates/cli/src/runtime/decision_observability.rs"),
        ("crates/cli/src/runtime/steering_admission.rs", "MAX_STEER_BYTES") => {
            Some("crates/cli/src/runtime.rs")
        }
        ("crates/cli/src/runtime/stream_progress.rs", "INTERNAL_STREAM_PROGRESS_INTERVAL") => {
            Some("crates/cli/src/runtime.rs")
        }
        ("crates/cli/src/runtime/stream_tool_events.rs", "NO_TOOL_OUTPUT_BYTES") => {
            Some("crates/cli/src/runtime/decision_observability.rs")
        }
        (
            "crates/cli/src/runtime/tool_presentation.rs",
            "MAX_UI_APPROVAL_ARGS_BYTES" | "UI_PROJECTION_TRUNCATED_WHEN_UNMARKED",
        ) => Some("crates/cli/src/runtime.rs"),
        ("crates/cli/src/runtime/verification_execution.rs", "VERIFY_CANCEL_POLL") => {
            Some("crates/cli/src/runtime/verification.rs")
        }
        (
            "crates/cli/src/runtime/workflow_preparation.rs",
            "CLOCK_BEFORE_EPOCH_SECS" | "DEFAULT_WORKFLOW_BACKGROUND",
        ) => Some("crates/cli/src/runtime/workflow_prepare.rs"),
        ("crates/cli/src/runtime/workflow_spawner.rs", "MAX_DELEGATION_DEPTH") => {
            Some("crates/cli/src/runtime.rs")
        }
        ("crates/cli/src/workflow/progress.rs", "MAX_PARTIAL_RESULT_BYTES") => {
            Some("crates/cli/src/workflow.rs")
        }
        (
            "crates/cli/src/workflow/run_store.rs",
            "MAX_RECENT_JOURNAL_BYTES"
            | "MISSING_MANIFEST_CREATED_AT"
            | "UNIX_SECS_ON_UNUSABLE_CLOCK"
            | "UNREADABLE_ENTRY_IS_RUN_DIR",
        ) => Some("crates/cli/src/workflow.rs"),
        (
            "crates/cli/src/workflow/supervisor.rs",
            "MAX_OPERATOR_INVENTORY_RUNS"
            | "MAX_RETAINED_SUMMARY_BYTES"
            | "MAX_TASK_NOTIFICATION_RESULT_BYTES"
            | "OWNERSHIP"
            | "SHUTDOWN_GRACE",
        ) => Some("crates/cli/src/workflow.rs"),
        (
            "crates/cli/src/runtime/request_accounting.rs",
            "NO_ACTIVE_TASK_TOKENS" | "NO_ATTACHMENT_TOKENS",
        ) => Some("crates/cli/src/runtime/context_runtime.rs"),
        ("crates/cli/src/runtime/memory_request_exposure.rs", "NO_RECALLED_FACTS") => {
            Some("crates/cli/src/runtime/decision_observability.rs")
        }
        ("crates/cli/src/runtime/provider_route_binding.rs", "GOVERNOR_ROUTE_BOUND_ABSENT") => {
            Some("crates/cli/src/runtime/route_state.rs")
        }
        ("crates/cli/src/runtime/direct_child_execution.rs", "CHILD_CONTROL_POLL") => {
            Some("crates/cli/src/runtime/subagent_control.rs")
        }
        ("crates/cli/src/runtime/workflow_execution.rs", "WORKFLOW_CONTROL_POLL") => {
            Some("crates/cli/src/runtime/workflow_prepare.rs")
        }
        (
            "crates/cli/src/runtime/kernel_special_assembly.rs",
            "DEADLINE_FREE_PARENT_REMAINING_WALL_SECS",
        ) => Some("crates/cli/src/runtime/workflow_collect.rs"),
        ("crates/cli/src/runtime/request_context_evidence.rs", "DOMAIN") => {
            Some("crates/cli/src/runtime/decision_observability.rs")
        }
        (
            "crates/workflow/src/bindings/attempt_executor.rs",
            "AGENT_ACTIVITY_INTERVAL" | "DEFAULT_CANCEL_ACK_TIMEOUT" | "HARD_CANCEL_ACK_TIMEOUT",
        ) => Some("crates/workflow/src/bindings.rs"),
        (
            "crates/workflow/src/bindings/run_state.rs",
            "DEFAULT_MAX_LOG_CALLS_PER_RUN" | "HARD_MAX_LOG_CALLS_PER_RUN",
        ) => Some("crates/workflow/src/bindings.rs"),
        ("crates/workflow/src/lib.rs", "LIFETIME_CAP") => Some("crates/workflow/src/bindings.rs"),
        ("crates/tools/src/lib.rs", "WORKFLOW_TOOL") => Some("crates/tools/src/workflow_tool.rs"),
        (
            "crates/cli/src/app_server/event_publisher.rs",
            "EQ_BYTE_CAPACITY"
            | "MAX_PENDING_COSMETIC_BYTES"
            | "MAX_PENDING_COSMETIC_SEGMENTS"
            | "MAX_TRACKED_WORKFLOW_PHASES",
        ) => Some("crates/cli/src/app_server.rs"),
        ("crates/cli/src/app_server/messages.rs", "ENVELOPE")
        | ("crates/cli/src/app_server/text_spill.rs", "NEXT_EQ_TERMINAL_TEXT_SPILL") => {
            Some("crates/cli/src/app_server.rs")
        }
        ("crates/cli/src/app_server/queue_client.rs", "SUBMISSION_DEDUP_WINDOW") => {
            Some("crates/cli/src/app_server.rs")
        }
        (
            "crates/cli/src/app_server/thread_presentation.rs",
            "MAX_GENERATIONS"
            | "MAX_STATE_BYTES"
            | "MAX_TITLE_BYTES"
            | "RETAINED_GENERATIONS"
            | "SCHEMA",
        ) => Some("crates/cli/src/tui/session_management.rs"),
        (
            "crates/cli/src/cli_entry/build_identity.rs",
            "BUILD_COMMIT" | "BUILD_DATE" | "BUILD_STALE_AFTER_DAYS" | "LONG",
        ) => Some("crates/cli/src/main.rs"),
        ("crates/cli/src/cli_entry/catalog.rs", "CONTENT_BYTES" | "MAX_BYTES" | "TRUNCATED") => {
            Some("crates/cli/src/main.rs")
        }
        (
            "crates/cli/src/cli_entry/clocks.rs",
            "UNIX_NANOS_ON_UNUSABLE_CLOCK"
            | "UNIX_SECS_ON_UNUSABLE_CLOCK"
            | "RUN_ID_NANOS_WITHOUT_FRESH_CLOCK",
        ) => Some("crates/cli/src/main.rs"),
        ("crates/cli/src/cli_entry/prompts.rs", "SYSTEM_PROMPT") => Some("crates/cli/src/main.rs"),
        (
            "crates/cli/src/cli_entry/provider_bootstrap.rs",
            "BUILTIN_DEFAULT_PROVIDER" | "CLI_OVERRIDE_PROVIDER_ID" | "REQUIRED_ENV",
        ) => Some("crates/cli/src/main.rs"),
        ("crates/cli/src/cli_entry/records.rs", "UNIX_MS_ON_UNUSABLE_CLOCK") => {
            Some("crates/cli/src/main.rs")
        }
        (
            "crates/cli/src/client_effects/capability_fs.rs",
            "MAX_CAPABILITY_COMPONENTS" | "MAX_CAPABILITY_PATH_BYTES" | "SAME_FILE_UNPROVEN",
        ) => Some("crates/cli/src/tui/capability_fs.rs"),
        (
            "crates/cli/src/client_effects/experiment_lab.rs",
            "MAX_REQUEST_BYTES" | "MAX_LISTED_REQUESTS" | "MAX_LISTED_BUNDLES",
        ) => Some("crates/cli/src/tui/experiment_lab.rs"),
        (
            "crates/cli/src/client_effects/experiment_lab/model.rs",
            "MAX_VALUE_BYTES" | "ONE_LINE_VALUE_MAX_CHARS",
        ) => Some("crates/cli/src/tui/experiment_lab.rs"),
        (
            "crates/cli/src/client_effects/export.rs",
            "MAX_EXPORT_COMPONENTS"
            | "MAX_EXPORT_PATH_BYTES"
            | "MAX_TRANSCRIPT_EXPORT_BYTES"
            | "MAX_VERSION_ATTEMPTS"
            | "REBIND_UNPROVEN",
        ) => Some("crates/cli/src/tui/transcript_export.rs"),
        (
            "crates/cli/src/client_effects/payload.rs",
            "EXPORT_STORE_BUSY_RETRY_ATTEMPTS"
            | "EXPORT_STORE_BUSY_RETRY_DELAY"
            | "EXPORT_SEQUENCE_BASE"
            | "NEXT_EXPORT_SEQUENCE",
        ) => Some("crates/cli/src/tui/transcript_effect.rs"),
        (
            "crates/cli/src/client_effects/process.rs",
            "CLOSE_REAP_WAIT" | "CLOSE_REAP_WAKE_LIMIT" | "SYNC_REAP_PAUSE" | "SYNC_REAP_POLLS",
        ) => Some("crates/cli/src/tui/transcript_effect/process.rs"),
        (
            "crates/cli/src/client_effects/shell.rs",
            "HEAD_BYTES" | "POST_KILL_DRAIN" | "TAIL_BYTES" | "TIMEOUT" | "NO_EXIT_CODE",
        ) => Some("crates/cli/src/tui/inline_shell.rs"),
        ("crates/cli/src/client_effects/worker.rs", "EXPORT_DEADLINE") => {
            Some("crates/cli/src/tui/transcript_effect/worker.rs")
        }
        (
            "crates/cli/src/client_effects/worker/protocol.rs",
            "MAX_WORKER_FRAME_BYTES"
            | "MAX_WORKER_RESPONSE_BYTES"
            | "MAX_WORKSPACE_BYTES"
            | "OVERSIZED"
            | "WORKER_HEADER_BYTES"
            | "WORKER_ENV"
            | "WORKER_MAGIC",
        ) => Some("crates/cli/src/tui/transcript_effect/worker/protocol.rs"),
        (
            "crates/cli/src/machine_projection.rs",
            "MAX_PENDING_STREAM_TOKEN_BYTES"
            | "MAX_STREAM_UI_DELTA_BYTES"
            | "DEFAULT_SCHEMA_VERSION"
            | "EXIT_BUDGET"
            | "EXIT_HARNESS"
            | "EXIT_INTERRUPTED"
            | "EXIT_STUCK"
            | "EXIT_SUCCESS"
            | "EXIT_WORKFLOW_FAILED"
            | "LEGACY_SCHEMA_VERSION"
            | "PREVIOUS_SCHEMA_VERSION"
            | "SCHEMA_VERSION"
            | "SUPPORTED_SCHEMA_VERSIONS"
            | "V7_SCHEMA_VERSION",
        ) => Some("crates/cli/src/output.rs"),
        ("crates/cli/src/machine_projection/v7.rs", "MAX_EVENT_BYTES" | "HEX") => {
            Some("crates/cli/src/output/v7.rs")
        }
        ("crates/cli/src/providers/instance_factory.rs", "BUILTINS")
        | (
            "crates/cli/src/providers/cache_storage.rs",
            "CACHE_TEMP_NONCE" | "FILE_ATTRIBUTE_REPARSE_POINT",
        ) => Some("crates/cli/src/providers.rs"),
        (
            "crates/cli/src/queue_policy.rs",
            "EQ_CAPACITY"
            | "SQ_BYTE_CAPACITY"
            | "SQ_CAPACITY"
            | "SQ_CONTROL_RESERVE_BYTES"
            | "SQ_ENTRY_OVERHEAD_BYTES"
            | "SQ_PRIORITY_CAPACITY",
        ) => Some("crates/cli/src/app_server.rs"),
        ("crates/cli/src/tui/clipboard_image.rs", "MAX_CLIPBOARD_ENV_BYTES" | "SCRIPT") => {
            Some("crates/cli/src/tui.rs")
        }
        ("crates/cli/src/tui/frame_render.rs", "KEYS")
        | ("crates/cli/src/tui/status_render.rs", "LINE") => Some("crates/cli/src/tui.rs"),
        ("crates/cli/src/tui/headless/commands.rs", "MAX_RECORDED_COMMANDS") => {
            Some("crates/cli/src/tui/headless.rs")
        }
        (
            "crates/cli/src/tui/input_lanes.rs",
            "MAX_PENDING_SUBMISSIONS" | "MAX_SUBMISSION_BYTES",
        ) => Some("crates/cli/src/tui/driver_support.rs"),
        (
            "crates/cli/src/tui/picker.rs",
            "MAX_PICKER_PASTE_SCAN_BYTES" | "MAX_PICKER_QUERY_BYTES" | "MAX_PICKER_QUERY_CHARS",
        ) => Some("crates/cli/src/tui.rs"),
        ("crates/cli/src/tui/product_presentation.rs", "MAX_TERMINAL_TEXT_BYTES") => {
            Some("crates/cli/src/tui/product_projection.rs")
        }
        ("crates/cli/src/cli_entry/permissions.rs", "DEFAULT_ALLOW_CODE") => {
            Some("crates/cli/src/main.rs")
        }
        (
            "crates/cli/src/session_transcript.rs",
            "MAX_ADOPTED_BLOCKS" | "MAX_ADOPTED_TOOL_OUTPUT_BYTES",
        ) => Some("crates/cli/src/tui/session_adoption.rs"),
        ("crates/cli/src/tui/workspace_command/rewind_view.rs", "REWIND_TARGET_ROWS") => {
            Some("crates/cli/src/tui/workspace_command.rs")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn moved_client_identities_keep_only_their_exact_original_source() {
        for (path, names, original) in [
            (
                "crates/cli/src/app_server/messages.rs",
                &["ENVELOPE"][..],
                "crates/cli/src/app_server.rs",
            ),
            (
                "crates/cli/src/app_server/text_spill.rs",
                &["NEXT_EQ_TERMINAL_TEXT_SPILL"][..],
                "crates/cli/src/app_server.rs",
            ),
            (
                "crates/cli/src/cli_entry/provider_bootstrap.rs",
                &["CLI_OVERRIDE_PROVIDER_ID", "REQUIRED_ENV"][..],
                "crates/cli/src/main.rs",
            ),
            (
                "crates/cli/src/cli_entry/build_identity.rs",
                &["LONG"][..],
                "crates/cli/src/main.rs",
            ),
            (
                "crates/cli/src/cli_entry/clocks.rs",
                &["RUN_ID_NANOS_WITHOUT_FRESH_CLOCK"][..],
                "crates/cli/src/main.rs",
            ),
            (
                "crates/cli/src/machine_projection.rs",
                &[
                    "EXIT_HARNESS",
                    "EXIT_INTERRUPTED",
                    "EXIT_STUCK",
                    "EXIT_SUCCESS",
                    "EXIT_WORKFLOW_FAILED",
                    "LEGACY_SCHEMA_VERSION",
                    "PREVIOUS_SCHEMA_VERSION",
                    "SCHEMA_VERSION",
                    "SUPPORTED_SCHEMA_VERSIONS",
                    "V7_SCHEMA_VERSION",
                ][..],
                "crates/cli/src/output.rs",
            ),
            (
                "crates/cli/src/machine_projection/v7.rs",
                &["HEX"][..],
                "crates/cli/src/output/v7.rs",
            ),
            (
                "crates/cli/src/providers/instance_factory.rs",
                &["BUILTINS"][..],
                "crates/cli/src/providers.rs",
            ),
            (
                "crates/cli/src/providers/cache_storage.rs",
                &["CACHE_TEMP_NONCE", "FILE_ATTRIBUTE_REPARSE_POINT"][..],
                "crates/cli/src/providers.rs",
            ),
            (
                "crates/cli/src/client_effects/capability_fs.rs",
                &["SAME_FILE_UNPROVEN"][..],
                "crates/cli/src/tui/capability_fs.rs",
            ),
            (
                "crates/cli/src/client_effects/shell.rs",
                &["NO_EXIT_CODE"][..],
                "crates/cli/src/tui/inline_shell.rs",
            ),
            (
                "crates/cli/src/tui/frame_render.rs",
                &["KEYS"][..],
                "crates/cli/src/tui.rs",
            ),
            (
                "crates/cli/src/tui/status_render.rs",
                &["LINE"][..],
                "crates/cli/src/tui.rs",
            ),
            (
                "crates/cli/src/app_server/thread_presentation.rs",
                &["SCHEMA"][..],
                "crates/cli/src/tui/session_management.rs",
            ),
            (
                "crates/cli/src/client_effects/payload.rs",
                &["EXPORT_SEQUENCE_BASE", "NEXT_EXPORT_SEQUENCE"][..],
                "crates/cli/src/tui/transcript_effect.rs",
            ),
            (
                "crates/cli/src/client_effects/worker/protocol.rs",
                &["WORKER_ENV", "WORKER_MAGIC"][..],
                "crates/cli/src/tui/transcript_effect/worker/protocol.rs",
            ),
        ] {
            for name in names {
                assert_eq!(super::original_source(path, name), Some(original));
                assert_eq!(
                    super::super::base_param_id("cli", path, name),
                    super::super::base_param_id("cli", original, name),
                );
                assert_eq!(
                    super::original_source("crates/cli/src/unrelated.rs", name),
                    None
                );
            }
            assert_eq!(super::original_source(path, "UNRELATED_VALUE"), None);
        }
        for owner in ["load_existing_scope_key", "prepare_private_cache_directory"] {
            assert_eq!(
                super::super::qualified_param_id(
                    "cli",
                    "crates/cli/src/providers/cache_storage.rs",
                    &format!("{owner}::FILE_ATTRIBUTE_REPARSE_POINT"),
                    "FILE_ATTRIBUTE_REPARSE_POINT",
                ),
                format!("cli.providers.{owner}.file_attribute_reparse_point"),
            );
        }
    }

    struct ActualHelper<'a> {
        id: &'a str,
        name: &'a str,
        matches: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for ActualHelper<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(function) = call.func.as_ref()
                && function.path.segments.len() == 2
                && function.path.segments[0].ident == "iteron_tunables"
                && function.path.segments[1].ident == "param_integer"
                && call.args.len() == 2
                && matches!(&call.args[0], syn::Expr::Lit(value) if matches!(&value.lit, syn::Lit::Str(id) if id.value() == self.id))
                && matches!(&call.args[1], syn::Expr::Path(value) if value.path.is_ident(self.name))
            {
                self.matches += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    #[test]
    fn moved_live_client_controls_bind_the_advertised_id_to_the_actual_native_consumer() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        for (path, name, id) in [
            (
                "crates/cli/src/session_transcript.rs",
                "MAX_ADOPTED_BLOCKS",
                "cli.tui.session_adoption.max_adopted_blocks",
            ),
            (
                "crates/cli/src/session_transcript.rs",
                "MAX_ADOPTED_TOOL_OUTPUT_BYTES",
                "cli.tui.session_adoption.max_adopted_tool_output_bytes",
            ),
            (
                "crates/cli/src/client_effects/experiment_lab.rs",
                "MAX_LISTED_REQUESTS",
                "cli.tui.experiment_lab.max_listed_requests",
            ),
            (
                "crates/cli/src/client_effects/experiment_lab.rs",
                "MAX_LISTED_BUNDLES",
                "cli.tui.experiment_lab.max_listed_bundles",
            ),
            (
                "crates/cli/src/client_effects/experiment_lab/model.rs",
                "MAX_VALUE_BYTES",
                "cli.tui.experiment_lab.max_value_bytes",
            ),
            (
                "crates/cli/src/client_effects/experiment_lab/model.rs",
                "ONE_LINE_VALUE_MAX_CHARS",
                "cli.tui.experiment_lab.one_line_value_max_chars",
            ),
            (
                "crates/cli/src/tui/workspace_command/rewind_view.rs",
                "REWIND_TARGET_ROWS",
                "cli.tui.workspace_command.rewind_target_rows",
            ),
        ] {
            assert_eq!(super::super::base_param_id("cli", path, name), id);
            let source = std::fs::read_to_string(root.join(path)).unwrap();
            let parsed = syn::parse_file(&source).unwrap();
            let mut probe = ActualHelper {
                id,
                name,
                matches: 0,
            };
            syn::visit::Visit::visit_file(&mut probe, &parsed);
            assert_eq!(
                probe.matches, 1,
                "{path} must consume {id} with its actual default"
            );
            let redirected = source.replace(id, "cli.unrelated.value");
            assert_ne!(redirected, source);
            let mut negative = ActualHelper {
                id,
                name,
                matches: 0,
            };
            syn::visit::Visit::visit_file(&mut negative, &syn::parse_file(&redirected).unwrap());
            assert_eq!(
                negative.matches, 0,
                "a renamed consumer is not evidence for the old address"
            );
        }
        for (path, name) in [
            (
                "crates/cli/src/tui/session_picker/native_history_fixtures.rs",
                "SESSION_INDEX_REBUILDS",
            ),
            ("crates/cli/src/tui/driver_support.rs", "CACHE"),
            (
                "crates/cli/src/tui/context_chips.rs",
                "UNREPORTED_INPUT_TOKENS",
            ),
        ] {
            assert_eq!(
                super::original_source(path, name),
                None,
                "removed or fixture-only state gets no invented production identity"
            );
        }
    }

    #[test]
    fn moved_defaults_keep_actual_public_addresses_and_unrelated_bounds_have_no_alias() {
        assert_eq!(
            super::super::base_param_id(
                "cli",
                "crates/cli/src/block/diff.rs",
                "HUNK_DEFAULT_START_LINE"
            ),
            "cli.block.hunk_default_start_line"
        );
        assert_eq!(
            super::super::base_param_id(
                "cli",
                "crates/cli/src/client_effects/path_completion.rs",
                "COMPLETION_DIRECTORY_CACHE_TTL"
            ),
            "cli.tui.driver_support.completion_directory_cache_ttl"
        );
        assert_eq!(
            super::super::qualified_param_id(
                "cli",
                "crates/cli/src/workflow/supervisor.rs",
                "WorkflowSupervisor::OWNERSHIP",
                "OWNERSHIP",
            ),
            "cli.workflow.workflowsupervisor.ownership"
        );
        assert_eq!(
            super::original_source("crates/cli/src/block/diff.rs", "UNRELATED"),
            None
        );
        assert_eq!(
            super::original_source("crates/cli/src/other.rs", "HUNK_DEFAULT_START_LINE"),
            None
        );
    }
}

#[cfg(test)]
mod runtime_control_migration_tests {
    #[test]
    fn seven_live_runtime_control_addresses_follow_only_their_actual_owned_declarations() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let evidence = super::super::applied_evidence(root).unwrap();
        for (path, name, expected) in [
            (
                "request_accounting.rs",
                "NO_ACTIVE_TASK_TOKENS",
                "cli.runtime.context_runtime.no_active_task_tokens",
            ),
            (
                "request_accounting.rs",
                "NO_ATTACHMENT_TOKENS",
                "cli.runtime.context_runtime.no_attachment_tokens",
            ),
            (
                "memory_request_exposure.rs",
                "NO_RECALLED_FACTS",
                "cli.runtime.decision_observability.no_recalled_facts",
            ),
            (
                "provider_route_binding.rs",
                "GOVERNOR_ROUTE_BOUND_ABSENT",
                "cli.runtime.route_state.governor_route_bound_absent",
            ),
            (
                "direct_child_execution.rs",
                "CHILD_CONTROL_POLL",
                "cli.runtime.subagent_control.child_control_poll",
            ),
            (
                "workflow_execution.rs",
                "WORKFLOW_CONTROL_POLL",
                "cli.runtime.workflow_prepare.workflow_control_poll",
            ),
            (
                "kernel_special_assembly.rs",
                "DEADLINE_FREE_PARENT_REMAINING_WALL_SECS",
                "cli.runtime.workflow_collect.deadline_free_parent_remaining_wall_secs",
            ),
        ] {
            let relative = format!("crates/cli/src/runtime/{path}");
            assert_eq!(
                super::super::base_param_id("cli", &relative, name),
                expected
            );
            assert!(
                evidence
                    .get(expected)
                    .is_some_and(|sites| sites.iter().any(|site| site.path == relative)),
                "actual runtime resolution disappeared: {expected}"
            );
            assert_eq!(super::original_source(&relative, "UNRELATED_BOUND"), None);
        }
        assert_eq!(
            super::original_source("crates/cli/src/foreign.rs", "CHILD_CONTROL_POLL"),
            None
        );
    }
}
