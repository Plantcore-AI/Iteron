//! Fixed CLI execution guarantees, distinct from the existing runtime strategy controls.
//!
//! This is an exact declaration allowlist. Moved controls retain their original identities in
//! `stable_source`; missing helper evidence alone never makes a value an invariant here.

use super::InvariantReason;

pub(super) fn reason(relative: &str, name: &str, owner: &str) -> Option<InvariantReason> {
    // A same-named local/associated declaration is not the audited file-level ceiling. The one
    // local bound below belongs to the actual native Git names reader, not an unrelated helper.
    let expected_owner = match (relative, name) {
        ("crates/cli/src/runtime/workflow_spawner/worktree/persistent.rs", "MAX_NAMES_BYTES") => {
            "bounded_names::MAX_NAMES_BYTES"
        }
        _ => name,
    };
    if owner != expected_owner {
        return None;
    }

    match (relative, name) {
        // The maintenance snapshot has a fixed replay envelope and retained identity count.
        (
            "crates/cli/src/runtime/advisory_maintenance/mod.rs",
            "MAX_JOBS" | "MAX_JOURNAL_BYTES",
        ) => Some(InvariantReason::DurabilityReplay),
        // This public observation port enforces the same maximum for reads and wait snapshots.
        ("crates/cli/src/runtime/advisory_maintenance/mod.rs", "MAX_READ_JOBS") => {
            Some(InvariantReason::WireCompatibility)
        }
        // Native maintenance writers retain physical slots/target leases after uncertain IO.
        // Queue/output/time bounds cannot be changed by a learned policy while jobs are live.
        (
            "crates/cli/src/runtime/advisory_maintenance/mod.rs",
            "MAX_INPUT_BYTES" | "QUEUE_DEADLINE",
        )
        | (
            "crates/cli/src/runtime/advisory_maintenance/pool.rs",
            "QUEUE" | "WORKERS" | "TARGETS" | "DEADLINE",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // These are the retained actual Verify intent/task and feedback capacities. They do not
        // choose an oracle, a command, a verdict, or whether the operator enabled verification.
        ("crates/cli/src/runtime/bounded_verify.rs", "MAX_TASKS" | "MAX_STREAM_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Pre-change identities survive candidate revisions; exceeding this ceiling reports an
        // unavailable baseline rather than silently forgetting an already observed identity.
        ("crates/cli/src/runtime/candidate_workspace.rs", "MAX_BASELINE_PATHS") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // Receipt publication observes known physical effects independently from accounting.
        // The bounds are checked before deep capture and never manufacture a financial receipt.
        (
            "crates/cli/src/runtime/child_ledger_evidence.rs",
            "MAX_RECEIPT_BYTES" | "MAX_RETAINED_BYTES",
        )
        | ("crates/cli/src/runtime/kernel_workflow_ledgers.rs", "PER_RECEIPT" | "AGGREGATE") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // This is a bounded observation copy, not a mutable tool/skill/agent registration limit.
        ("crates/cli/src/runtime/client_inventory.rs", "MAX_RUNTIME_ENTRIES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Exact admitted claims and bounded terminal observation stay with the physical child.
        // Changing either does not grant authority to treat an interrupt request as cleanup.
        ("crates/cli/src/runtime/controller_engine_children.rs", "MAX_CLAIMS" | "POLL_MS")
        | ("crates/cli/src/runtime/execution_deadline.rs", "MAX_DEADLINE_LEASES")
        | (
            "crates/cli/src/runtime/persistent_agents.rs",
            "MAX_INPUT_BATCH" | "MAX_PARALLEL_AGENTS" | "MAX_WAIT_MS",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // Native prepared-field witnesses authorize a durable Consumed receipt only for the
        // exact input/source digest. The proof parser's limits are not model strategy choices.
        (
            "crates/cli/src/runtime/persistent_agents/prepared_mailbox.rs",
            "MAX_BODY_BYTES" | "MAX_FIELDS" | "MAX_PROJECTIONS",
        )
        | ("crates/cli/src/runtime/request_inclusion.rs", "MAX_TEXT_FIELDS") => {
            Some(InvariantReason::Security)
        }
        // Native contexts retain immutable executable/authority generations for their exact WAL
        // scope. No learned capacity can evict a committed resident's held execution reference.
        (
            "crates/cli/src/runtime/persistent_native_generations.rs",
            "MAX_CURRENT_SCOPES" | "MAX_HISTORICAL_GENERATIONS" | "MAX_GENERATIONS",
        )
        | ("crates/cli/src/runtime/workflow_spawner/native_context.rs", "MAX_CAPTURE_BYTES") => {
            Some(InvariantReason::CapabilityAuthority)
        }
        (
            "crates/cli/src/runtime/persistent_native_generations/archive.rs",
            "MAX_ARCHIVE_BYTES",
        ) => Some(InvariantReason::DurabilityReplay),
        // The existing INTERRUPTED_STREAM_MAX_BYTES strategy still narrows this physical ceiling.
        ("crates/cli/src/runtime/provider_turn_evidence.rs", "MAX_INTERRUPTED_PREFIX_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Correlating pending physical intents with signed terminal charges is bounded; overflow
        // requires reconciliation, and must never be learned into an incomplete replay proof.
        (
            "crates/cli/src/runtime/route_attempt_accounting/replay_evidence.rs",
            "MAX_PHYSICAL_ATTEMPTS",
        ) => Some(InvariantReason::DurabilityReplay),
        // Accepted queued submissions retain exact input ownership independently of the existing
        // per-message MAX_STEER_BYTES and polling controls, which remain runtime-settable.
        (
            "crates/cli/src/runtime/session_inbox.rs",
            "MAX_PENDING_STEERS" | "MAX_PENDING_STEER_BYTES",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // Recovered tool results and captured-pixel witnesses cannot be silently dropped and then
        // replaced with a second physical dispatch or an unsupported image provenance claim.
        (
            "crates/cli/src/runtime/submitted_turn_state.rs",
            "MAX_RECOVERED_RESULTS" | "MAX_RECOVERED_BYTES",
        )
        | ("crates/cli/src/runtime/tool_image_replay.rs", "MAX_WITNESSES") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // Actual Git writer process, pipe, and capture limits bound native cleanup/publication.
        // They do not add a verification gate or turn timeout into known process-tree cleanup.
        (
            "crates/cli/src/runtime/workflow_spawner/worktree/git_process.rs",
            "PROCESS_DEADLINE" | "PIPE_DEADLINE" | "POLL_INTERVAL",
        )
        | ("crates/cli/src/runtime/workflow_spawner/worktree/persistent.rs", "MAX_NAMES_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        ("crates/cli/src/workflow/live_session/store.rs", "MAX_INDEX_BYTES") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // The live registry's lifetime graph reservation, command semaphore, pump work, and
        // background lifetime are immutable host admission bounds, not graph planner weights.
        (
            "crates/cli/src/workflow/live_session/types.rs",
            "MAX_WORKFLOWS" | "MAX_REQUESTS" | "MAX_PUMP_OPERATIONS" | "MAX_BACKGROUND_TICKS",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{InvariantReason, reason};

    #[test]
    fn existing_controls_are_not_hidden_by_fixed_resource_classification() {
        for (path, name) in [
            ("runtime/inbound_control.rs", "MAX_INBOUND_OPS_PER_POLL"),
            ("runtime/steering_admission.rs", "MAX_STEER_BYTES"),
            (
                "runtime/provider_response_recovery.rs",
                "INTERRUPTED_STREAM_MAX_BYTES",
            ),
            (
                "runtime/provider_accounting.rs",
                "MAX_COMMITTED_PROVIDER_RUN_NOTICES",
            ),
            ("runtime/workflow_spawner.rs", "MAX_DELEGATION_DEPTH"),
            ("runtime/verification_execution.rs", "VERIFY_CANCEL_POLL"),
            ("workflow/supervisor.rs", "SHUTDOWN_GRACE"),
            ("workflow/progress.rs", "MAX_PARTIAL_RESULT_BYTES"),
        ] {
            assert_eq!(reason(&format!("crates/cli/src/{path}"), name, name), None);
        }
    }

    #[test]
    fn fixed_proofs_require_the_actual_declaration_owner() {
        let path = "crates/cli/src/runtime/persistent_agents/prepared_mailbox.rs";
        assert_eq!(
            reason(path, "MAX_FIELDS", "MAX_FIELDS"),
            Some(InvariantReason::Security)
        );
        assert_eq!(reason(path, "MAX_FIELDS", "unrelated::MAX_FIELDS"), None);
        assert_eq!(reason(path, "NEW_BOUND", "NEW_BOUND"), None);
        assert_eq!(
            reason(
                "crates/cli/src/runtime/unrelated.rs",
                "MAX_FIELDS",
                "MAX_FIELDS"
            ),
            None
        );

        let path = "crates/cli/src/runtime/workflow_spawner/worktree/persistent.rs";
        assert_eq!(
            reason(path, "MAX_NAMES_BYTES", "bounded_names::MAX_NAMES_BYTES"),
            Some(InvariantReason::HardBudgetEffectLedger),
        );
        assert_eq!(reason(path, "MAX_NAMES_BYTES", "MAX_NAMES_BYTES"), None);
        assert_eq!(
            reason(path, "MAX_NAMES_BYTES", "other::MAX_NAMES_BYTES"),
            None
        );
    }

    #[test]
    fn native_generation_and_replay_limits_have_different_guarantees() {
        assert_eq!(
            reason(
                "crates/cli/src/runtime/persistent_native_generations.rs",
                "MAX_GENERATIONS",
                "MAX_GENERATIONS"
            ),
            Some(InvariantReason::CapabilityAuthority),
        );
        assert_eq!(
            reason(
                "crates/cli/src/runtime/route_attempt_accounting/replay_evidence.rs",
                "MAX_PHYSICAL_ATTEMPTS",
                "MAX_PHYSICAL_ATTEMPTS"
            ),
            Some(InvariantReason::DurabilityReplay),
        );
        assert_eq!(
            reason(
                "crates/cli/src/workflow/live_session/types.rs",
                "MAX_WORKFLOWS",
                "MAX_WORKFLOWS"
            ),
            Some(InvariantReason::HardBudgetEffectLedger),
        );
    }
}
