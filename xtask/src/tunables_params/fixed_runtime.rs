//! Fixed CLI execution guarantees, distinct from the existing runtime strategy controls.
//!
//! This is an exact declaration allowlist. Moved controls retain their original identities in
//! `stable_source`; missing helper evidence alone never makes a value an invariant here.

use super::InvariantReason;

pub(super) fn reason(relative: &str, name: &str, owner: &str) -> Option<InvariantReason> {
    // A same-named local/associated declaration is not the audited file-level ceiling. The one
    // local bound below belongs to the actual native Git names reader, not an unrelated helper.
    let expected_owner = match (relative, name) {
        ("crates/host/src/runtime/workflow_spawner/worktree/persistent.rs", "MAX_NAMES_BYTES") => {
            "bounded_names::MAX_NAMES_BYTES"
        }
        _ => name,
    };
    if owner != expected_owner {
        return None;
    }

    match (relative, name) {
        // These caches retain exact source bytes already checked by the fixed redactor. The
        // memory envelope cannot grant a different scrub policy or reuse a receipt for new text.
        (
            "crates/host/src/runtime/model_context_projection.rs",
            "MAX_CLEAN_TEXT_ENTRIES" | "MAX_CLEAN_TEXT_BYTES",
        ) => Some(InvariantReason::Security),
        // Physical evidence copies are optional and content-derived; pressure recomputes them.
        // The conservative allocation charge includes JSON nodes, not just serialized bytes.
        (
            "crates/host/src/runtime/request_context_evidence/cache.rs",
            "MAX_ENTRIES" | "MAX_RETAINED_BYTES" | "VALUE_ALLOCATION_FACTOR",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // Captured diagnostics retain reservations through queued and active publication. The
        // fixed drain limit reports incomplete capture; it cannot manufacture a drained receipt.
        (
            "crates/host/src/runtime/request_manifest/archive.rs",
            "MAX_PENDING_REQUESTS" | "MAX_PENDING_BYTES" | "DRAIN_BUDGET",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // These exact bytes identify the owned discovery envelope and its canonical prefix.
        // Changing the discriminator independently would redirect the complete-schema path.
        (
            "crates/host/src/runtime/tool_output_spill/mcp_search.rs",
            "KIND" | "CANONICAL_KIND" | "MARKER",
        ) => Some(InvariantReason::Identity),
        // This bounded prefix probe recognizes the owned envelope before parsing hostile text.
        // Actual MCP search result/byte budgets remain independently resolved runtime controls.
        ("crates/host/src/runtime/tool_output_spill/mcp_search.rs", "PROBE_BYTES") => {
            Some(InvariantReason::Security)
        }
        // Complete-schema/refusal wording is part of the model-visible contract: projection can
        // omit whole tools or refuse, but cannot claim a rewritten schema is complete.
        (
            "crates/host/src/runtime/tool_output_spill/mcp_search.rs",
            "BUDGET_NOTE" | "EMPTY_NOTE" | "BUDGET_NOTICE" | "SENSITIVE_NOTICE" | "INVALID_NOTICE",
        ) => Some(InvariantReason::WireCompatibility),
        // The maintenance snapshot has a fixed replay envelope and retained identity count.
        (
            "crates/host/src/runtime/advisory_maintenance/mod.rs",
            "MAX_JOBS" | "MAX_JOURNAL_BYTES",
        ) => Some(InvariantReason::DurabilityReplay),
        // This public observation port enforces the same maximum for reads and wait snapshots.
        ("crates/host/src/runtime/advisory_maintenance/mod.rs", "MAX_READ_JOBS") => {
            Some(InvariantReason::WireCompatibility)
        }
        // Native maintenance writers retain physical slots/target leases after uncertain IO.
        // Queue/output/time bounds cannot be changed by a learned policy while jobs are live.
        (
            "crates/host/src/runtime/advisory_maintenance/mod.rs",
            "MAX_INPUT_BYTES" | "QUEUE_DEADLINE",
        )
        | (
            "crates/host/src/runtime/advisory_maintenance/pool.rs",
            "QUEUE" | "WORKERS" | "TARGETS" | "DEADLINE",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // These are the retained actual Verify intent/task and feedback capacities. They do not
        // choose an oracle, a command, a verdict, or whether the operator enabled verification.
        ("crates/host/src/runtime/bounded_verify.rs", "MAX_TASKS" | "MAX_STREAM_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Pre-change identities survive candidate revisions; exceeding this ceiling reports an
        // unavailable baseline rather than silently forgetting an already observed identity.
        ("crates/host/src/runtime/candidate_workspace.rs", "MAX_BASELINE_PATHS") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // Receipt publication observes known physical effects independently from accounting.
        // The bounds are checked before deep capture and never manufacture a financial receipt.
        (
            "crates/host/src/runtime/child_ledger_evidence.rs",
            "MAX_RECEIPT_BYTES" | "MAX_RETAINED_BYTES",
        )
        | ("crates/host/src/runtime/kernel_workflow_ledgers.rs", "PER_RECEIPT" | "AGGREGATE") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // This is a bounded observation copy, not a mutable tool/skill/agent registration limit.
        ("crates/host/src/runtime/client_inventory.rs", "MAX_RUNTIME_ENTRIES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Exact admitted claims and bounded terminal observation stay with the physical child.
        // Changing either does not grant authority to treat an interrupt request as cleanup.
        ("crates/host/src/runtime/controller_engine_children.rs", "MAX_CLAIMS" | "POLL_MS")
        | ("crates/host/src/runtime/execution_deadline.rs", "MAX_DEADLINE_LEASES")
        | (
            "crates/host/src/runtime/persistent_agents.rs",
            "MAX_INPUT_BATCH" | "MAX_PARALLEL_AGENTS" | "MAX_WAIT_MS",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // Native prepared-field witnesses authorize a durable Consumed receipt only for the
        // exact input/source digest. The proof parser's limits are not model strategy choices.
        (
            "crates/host/src/runtime/persistent_agents/prepared_mailbox.rs",
            "MAX_BODY_BYTES" | "MAX_FIELDS" | "MAX_PROJECTIONS",
        )
        | ("crates/host/src/runtime/request_inclusion.rs", "MAX_TEXT_FIELDS") => {
            Some(InvariantReason::Security)
        }
        // Native contexts retain immutable executable/authority generations for their exact WAL
        // scope. No learned capacity can evict a committed resident's held execution reference.
        (
            "crates/host/src/runtime/persistent_native_generations.rs",
            "MAX_CURRENT_SCOPES" | "MAX_HISTORICAL_GENERATIONS" | "MAX_GENERATIONS",
        )
        | ("crates/host/src/runtime/workflow_spawner/native_context.rs", "MAX_CAPTURE_BYTES") => {
            Some(InvariantReason::CapabilityAuthority)
        }
        (
            "crates/host/src/runtime/persistent_native_generations/archive.rs",
            "MAX_ARCHIVE_BYTES",
        ) => Some(InvariantReason::DurabilityReplay),
        // The existing INTERRUPTED_STREAM_MAX_BYTES strategy still narrows this physical ceiling.
        ("crates/host/src/runtime/provider_turn_evidence.rs", "MAX_INTERRUPTED_PREFIX_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // Correlating pending physical intents with signed terminal charges is bounded; overflow
        // requires reconciliation, and must never be learned into an incomplete replay proof.
        (
            "crates/host/src/runtime/route_attempt_accounting/replay_evidence.rs",
            "MAX_PHYSICAL_ATTEMPTS",
        ) => Some(InvariantReason::DurabilityReplay),
        // Accepted queued submissions retain exact input ownership independently of the existing
        // per-message MAX_STEER_BYTES and polling controls, which remain runtime-settable.
        (
            "crates/host/src/runtime/session_inbox.rs",
            "MAX_PENDING_STEERS" | "MAX_PENDING_STEER_BYTES",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // Recovered tool results and captured-pixel witnesses cannot be silently dropped and then
        // replaced with a second physical dispatch or an unsupported image provenance claim.
        (
            "crates/host/src/runtime/submitted_turn_state.rs",
            "MAX_RECOVERED_RESULTS" | "MAX_RECOVERED_BYTES",
        )
        | ("crates/host/src/runtime/tool_image_replay.rs", "MAX_WITNESSES") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // Actual Git writer process, pipe, and capture limits bound native cleanup/publication.
        // They do not add a verification gate or turn timeout into known process-tree cleanup.
        (
            "crates/host/src/runtime/workflow_spawner/worktree/git_process.rs",
            "PROCESS_DEADLINE" | "PIPE_DEADLINE" | "POLL_INTERVAL",
        )
        | ("crates/host/src/runtime/workflow_spawner/worktree/persistent.rs", "MAX_NAMES_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        ("crates/host/src/workflow/live_session/store.rs", "MAX_INDEX_BYTES") => {
            Some(InvariantReason::DurabilityReplay)
        }
        // The live registry's lifetime graph reservation, command semaphore, pump work, and
        // background lifetime are immutable host admission bounds, not graph planner weights.
        (
            "crates/host/src/workflow/live_session/types.rs",
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
            assert_eq!(reason(&format!("crates/host/src/{path}"), name, name), None);
        }
    }

    #[test]
    fn retained_evidence_and_schema_contracts_do_not_capture_runtime_policy_controls() {
        let cache = "crates/host/src/runtime/request_context_evidence/cache.rs";
        assert_eq!(
            reason(cache, "MAX_ENTRIES", "MAX_ENTRIES"),
            Some(InvariantReason::HardBudgetEffectLedger)
        );
        assert_eq!(reason(cache, "MAX_ENTRIES", "unrelated::MAX_ENTRIES"), None);
        assert_eq!(reason(cache, "NEW_CACHE_POLICY", "NEW_CACHE_POLICY"), None);
        let search = "crates/host/src/runtime/tool_output_spill/mcp_search.rs";
        assert_eq!(
            reason(search, "BUDGET_NOTE", "BUDGET_NOTE"),
            Some(InvariantReason::WireCompatibility)
        );
        // Actual user/profile budgets are declared and resolved by the MCP supervisor.
        assert_eq!(
            reason(
                "crates/mcp/src/supervisor/catalog.rs",
                "MAX_MCP_SEARCH_OUTPUT_BYTES",
                "MAX_MCP_SEARCH_OUTPUT_BYTES"
            ),
            None
        );
        assert_eq!(
            reason(
                search,
                "MAX_MCP_SEARCH_OUTPUT_BYTES",
                "MAX_MCP_SEARCH_OUTPUT_BYTES"
            ),
            None
        );
    }

    #[test]
    fn fixed_proofs_require_the_actual_declaration_owner() {
        let path = "crates/host/src/runtime/persistent_agents/prepared_mailbox.rs";
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

        let path = "crates/host/src/runtime/workflow_spawner/worktree/persistent.rs";
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
                "crates/host/src/runtime/persistent_native_generations.rs",
                "MAX_GENERATIONS",
                "MAX_GENERATIONS"
            ),
            Some(InvariantReason::CapabilityAuthority),
        );
        assert_eq!(
            reason(
                "crates/host/src/runtime/route_attempt_accounting/replay_evidence.rs",
                "MAX_PHYSICAL_ATTEMPTS",
                "MAX_PHYSICAL_ATTEMPTS"
            ),
            Some(InvariantReason::DurabilityReplay),
        );
        assert_eq!(
            reason(
                "crates/host/src/workflow/live_session/types.rs",
                "MAX_WORKFLOWS",
                "MAX_WORKFLOWS"
            ),
            Some(InvariantReason::HardBudgetEffectLedger),
        );
    }
}
