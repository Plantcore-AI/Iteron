//! Exact non-CLI constants owned by fixed admission, evidence and native boundaries.
//! A missing helper is not a reason: relocated live controls and policy defaults stay separate.

use super::InvariantReason;

pub(super) fn reason(relative: &str, name: &str, owner: &str) -> Option<InvariantReason> {
    // These are module-level constants; three pinned filenames belong to the actual Unix store
    // module. A local or associated value cannot inherit a decision from its short name.
    let expected_owner = match (relative, name) {
        ("crates/workflow/src/live_scheduler/file_journal.rs", "LEASE") => "unix::LEASE",
        ("crates/workflow/src/live_scheduler/file_journal.rs", "PENDING") => "unix::PENDING",
        ("crates/workflow/src/live_scheduler/file_journal.rs", "SNAPSHOT") => "unix::SNAPSHOT",
        _ => name,
    };
    if owner != expected_owner {
        return None;
    }
    match (relative, name) {
        // The operator may lower installed agent capacity/budgets. These constants bound the
        // actual controller tree and ancestor walk independently of that admitted configuration.
        ("crates/agents/src/controller.rs", "MAX_AGENTS" | "MAX_HIERARCHY_DEPTH") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Exact replay receipts cannot be evicted to make new commands appear fresh. Snapshot
        // publication and monotone CAS revisions have the same fixed durable envelope on reopen.
        (
            "crates/agents/src/controller.rs",
            "MAX_RECEIPTS" | "MAX_REVISION" | "MAX_SNAPSHOT_BYTES",
        )
        | ("crates/agents/src/controller/provider_budget.rs", "MAX_PROVIDER_RECEIPTS")
        | ("crates/agents/src/controller_file.rs", "MAX_FILE_BYTES")
        | ("crates/agents/src/mailbox.rs", "MAX_MESSAGES") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // All ancestors stay pinned while the controller writer is live. Malicious depth/path
        // expansion cannot increase that retained filesystem capability population.
        (
            "crates/agents/src/controller_directory.rs",
            "MAX_COMPONENTS" | "MAX_PATH_BYTES" | "MAX_PINS",
        ) => Some(InvariantReason::Security),

        // Actual captured source and renderer bytes share one fixed host evidence envelope;
        // context/memory selection budgets remain separate real caller inputs.
        (
            "crates/ctx/src/context_provenance.rs",
            "MAX_CONTEXT_MATERIAL_BYTES" | "MAX_CONTEXT_MATERIALS" | "MAX_CONTEXT_PROVENANCE_BYTES",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // Record count, tombstones and whole-snapshot bytes must agree in the writer and reopen
        // decoder. DEFAULT_CONFIDENCE_PPM/default lifetime are deliberately not included.
        (
            "crates/ctx/src/memory_records.rs",
            "MAX_RECORD_BODY_BYTES" | "MAX_RECORD_SNAPSHOT_BYTES" | "MAX_RECORDS",
        ) => Some(InvariantReason::DurabilityReplay),
        // Missing historical confidence has a fixed conservative decoder meaning. A runtime
        // profile must not retroactively change the interpretation of an archived observation.
        ("crates/ctx/src/memory_records.rs", "LEGACY_CONFIDENCE_PPM") => {
            Some(InvariantReason::WireCompatibility)
        }

        // Native porcelain branch bytes are rejected before terminal-safe expansion. This fixed
        // hostile-input envelope is independent of presentation choices and cannot be enlarged.
        ("crates/tools/src/git_observe.rs", "MAX_ENVIRONMENT_BRANCH_BYTES") => {
            Some(InvariantReason::Security)
        }

        // Descriptor and installed-binding bounds are checked before ordinary native bindings
        // can enter the host. Per-binding arguments/status/subscription capacity remain explicit.
        ("crates/extension-sdk/src/descriptors.rs", "MAX_BINDINGS" | "MAX_DESCRIPTOR_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Untrusted package traversal/copy/reconciliation is finite before any registry receipt;
        // these bounds constrain real physical bytes, not a selectable package strategy.
        (
            "crates/marketplace/src/package/storage.rs",
            "MAX_DEPTH" | "MAX_ENTRIES" | "MAX_FILE_BYTES" | "MAX_TREE_BYTES",
        ) => Some(InvariantReason::Security),
        // Unclosed physical pricing evidence stays retained. Overflow refuses instead of
        // evicting modern evidence and permitting an unrelated legacy monetary fallback.
        ("crates/obs/src/pricing/physical_replay.rs", "MAX_ATTEMPTS_PER_SCOPE" | "MAX_SCOPES") => {
            Some(InvariantReason::DurabilityReplay)
        }

        // Cold cohort bindings persist their original owner and exclusive physical scopes.
        ("crates/protocol/src/agent_cohort.rs", "MAX_COHORT_MAIN_RUNS") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // These are the closed public parser/producer envelopes, not operator text preferences.
        (
            "crates/protocol/src/agent_control.rs",
            "MAX_AGENT_LABEL_BYTES" | "MAX_AGENT_REQUEST_ID_BYTES" | "MAX_AGENT_TEXT_BYTES",
        )
        | ("crates/protocol/src/agent_input.rs", "MAX_AGENT_INPUT_SOURCES")
        | ("crates/protocol/src/client_artifact.rs", "MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES")
        | (
            "crates/protocol/src/task_plan.rs",
            "MAX_PLAN_BYTES" | "MAX_PLAN_OBLIGATIONS" | "MAX_PLAN_STEPS",
        )
        | (
            "crates/protocol/src/thread_lifecycle.rs",
            "MAX_THREAD_EXPORT_BYTES" | "MAX_THREAD_RUN_ID_BYTES" | "MAX_THREAD_TITLE_BYTES",
        )
        | (
            "crates/protocol/src/tool_image.rs",
            "MAX_TOOL_IMAGE_ENCODED_BYTES" | "MAX_TOOL_IMAGES_PER_MESSAGE",
        ) => Some(InvariantReason::WireCompatibility),
        // Agent writable-path declarations are authority, not optimizer-authored scope.
        (
            "crates/protocol/src/agent_control.rs",
            "MAX_AGENT_WRITE_PATH_BYTES" | "MAX_AGENT_WRITE_PATHS",
        ) => Some(InvariantReason::CapabilityAuthority),
        // The same fixed retained-event population is enforced by the actual incremental owner.
        ("crates/protocol/src/turn_publication.rs", "MAX_TURN_PUBLICATION_EVENTS") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // The prepared byte buffer is the exact dispatched HTTP body. Its checked writer must
        // remain bounded even when no capture observer is installed.
        ("crates/provider/src/request_capture.rs", "MAX_WIRE_BODY_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }

        // Native child context selection validates the physical hash chain before scope binding.
        ("crates/record/src/native_child_context.rs", "MAX_BYTES" | "MAX_LINE") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // Online repair refuses before replacing an index when enumeration, verified hydrated
        // metadata or elapsed work exceeds the finite host envelope. Offline reindex is separate.
        (
            "crates/record/src/session/bounded_reindex.rs",
            "MAX_ENTRIES" | "MAX_METADATA_BYTES" | "MAX_RUNS" | "MAX_WALL",
        ) => Some(InvariantReason::HardBudgetEffectLedger),

        // Bounded DACL inspection and retained NTFS reads are part of native capability proof.
        ("crates/support/src/durable_windows_state.rs", "MAX_ACES" | "MAX_SECURITY_BYTES")
        | (
            "crates/support/src/durable_windows_state/contained_read.rs",
            "MAX_BYTES" | "MAX_READER_BYTES",
        ) => Some(InvariantReason::Security),
        ("crates/support/src/durable_windows_state.rs", "HARD_MAX_BYTES") => {
            Some(InvariantReason::DurabilityReplay)
        }
        (
            "crates/support/src/durable_windows_state/workspace_directory_read.rs",
            "BUFFER_BYTES",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // Suspended creation, exact primary-thread lookup, Job membership and retained cleanup
        // custody form one host-owned native process boundary. Timeout never proves Job0.
        (
            "crates/support/src/owned_windows_job.rs",
            "MAX_ACTIVE_PROCESSES"
            | "MAX_CLEANUP_WAIT"
            | "MAX_THREAD_ROWS"
            | "MAX_THREAD_SCAN"
            | "CLEANUP_POLL",
        ) => Some(InvariantReason::CapabilityAuthority),
        ("crates/support/src/owned_windows_job/custody.rs", "MAX_CUSTODIES" | "POLL") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }

        // Captured outputs and guarded before/after snapshots have fixed aggregate host bounds;
        // exceeding them makes evidence unavailable, never changes physical certainty.
        (
            "crates/tools/src/captured_execution.rs",
            "MAX_OUTPUT_BYTES" | "MAX_OUTPUTS" | "MAX_TOTAL_BYTES",
        )
        | (
            "crates/tools/src/native_mutation.rs",
            "MAX_FILES" | "MAX_NATIVE_CAPTURE_FILE_BYTES" | "MAX_TOTAL_BYTES",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        ("crates/tools/src/contained_source.rs", "MAX_COMPONENTS" | "MAX_PATH_BYTES") => {
            Some(InvariantReason::Security)
        }
        ("crates/tools/src/contained_source.rs", "MAX_SOURCE_BYTES" | "MAX_WORKERS") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Failure to prove a namespace identity must stay false; it cannot be learned as success.
        ("crates/tools/src/lsp/capability.rs", "IDENTITY_UNPROVABLE") => {
            Some(InvariantReason::Security)
        }
        // Oversized/incomplete classification retains broad execution/write/trust authority.
        // The parser envelope cannot be a model or strategy capability-narrowing declaration.
        (
            "crates/tools/src/operation_effects.rs",
            "MAX_COMMAND_BYTES" | "MAX_TARGET_BYTES" | "MAX_TARGETS",
        ) => Some(InvariantReason::CapabilityAuthority),
        // Actual guarded native registration/argument translation is bounded before execution.
        (
            "crates/tools/src/ordinary_recipe.rs",
            "MAX_CALL_BYTES" | "MAX_ORDINARY_RECIPES" | "MAX_RECIPE_BYTES",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        ("crates/tools/src/task_plan.rs", "UPDATE_PLAN") => Some(InvariantReason::Identity),

        // The disabled profile is a compile-time fact, not a runtime strategy toggle.
        ("crates/workflow/src/lib.rs", "SCRIPT_WORKFLOWS_ENABLED") => {
            Some(InvariantReason::Identity)
        }
        // Filename identities are pinned by the existing single-writer/CAS publication protocol.
        (
            "crates/workflow/src/live_scheduler/file_journal.rs",
            "LEASE" | "PENDING" | "SNAPSHOT",
        ) => Some(InvariantReason::DurabilityReplay),
        // Caller plan/concurrency/node budgets may tighten these ceilings. Validation, journal
        // reopen and monotone request/event/revision accounting share these immutable bounds.
        (
            "crates/workflow/src/live_scheduler/types.rs",
            "MAX_DIAGNOSTIC_BYTES"
            | "MAX_NODE_TASK_BYTES"
            | "MAX_PLAN_CHANGES"
            | "MAX_PLAN_DEPTH"
            | "MAX_PLAN_EDGES"
            | "MAX_PLAN_NODES"
            | "MAX_PLAN_REQUESTS"
            | "MAX_PLAN_REVISIONS"
            | "MAX_PLAN_STORE_BYTES"
            | "MAX_SCHEDULER_EVENTS",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{InvariantReason, reason};

    #[test]
    fn exact_native_scope_and_replay_boundaries_have_closed_reasons() {
        for (path, name, expected) in [
            (
                "crates/tools/src/git_observe.rs",
                "MAX_ENVIRONMENT_BRANCH_BYTES",
                InvariantReason::Security,
            ),
            (
                "crates/tools/src/lsp/capability.rs",
                "IDENTITY_UNPROVABLE",
                InvariantReason::Security,
            ),
            (
                "crates/agents/src/controller/provider_budget.rs",
                "MAX_PROVIDER_RECEIPTS",
                InvariantReason::DurabilityReplay,
            ),
            (
                "crates/tools/src/task_plan.rs",
                "UPDATE_PLAN",
                InvariantReason::Identity,
            ),
            (
                "crates/protocol/src/agent_control.rs",
                "MAX_AGENT_WRITE_PATHS",
                InvariantReason::CapabilityAuthority,
            ),
        ] {
            assert_eq!(reason(path, name, name), Some(expected));
            assert_eq!(reason(path, name, &format!("unrelated::{name}")), None);
            assert_eq!(reason("crates/demo/src/lib.rs", name, name), None);
        }
    }

    #[test]
    fn real_policy_defaults_and_relocated_live_controls_are_not_fixed() {
        for (path, name) in [
            ("crates/ctx/src/memory_records.rs", "DEFAULT_CONFIDENCE_PPM"),
            (
                "crates/ctx/src/memory_records.rs",
                "DEFAULT_LIFETIME_SECONDS",
            ),
            ("crates/workflow/src/lib.rs", "LIFETIME_CAP"),
            (
                "crates/workflow/src/bindings/attempt_executor.rs",
                "DEFAULT_CANCEL_ACK_TIMEOUT",
            ),
            (
                "crates/workflow/src/bindings/run_state.rs",
                "DEFAULT_MAX_LOG_CALLS_PER_RUN",
            ),
            ("crates/tools/src/lib.rs", "WORKFLOW_TOOL"),
        ] {
            assert_eq!(reason(path, name, name), None);
        }
        assert_eq!(
            reason(
                "crates/tools/src/git_observe.rs",
                "ENVIRONMENT_GIT_TIMEOUT",
                "ENVIRONMENT_GIT_TIMEOUT"
            ),
            None
        );
        assert_eq!(
            reason(
                "crates/tools/src/git_observe.rs",
                "MAX_FUTURE_BRANCH_BYTES",
                "MAX_FUTURE_BRANCH_BYTES"
            ),
            None
        );
        assert_eq!(
            reason(
                "crates/tools/src/contained_source.rs",
                "MAX_FUTURE_BOUND",
                "MAX_FUTURE_BOUND"
            ),
            None
        );
    }

    #[test]
    fn journal_names_require_the_actual_unix_module() {
        let path = "crates/workflow/src/live_scheduler/file_journal.rs";
        assert_eq!(
            reason(path, "LEASE", "unix::LEASE"),
            Some(InvariantReason::DurabilityReplay)
        );
        assert_eq!(reason(path, "LEASE", "LEASE"), None);
        assert_eq!(reason(path, "LEASE", "unrelated::LEASE"), None);
    }
}
