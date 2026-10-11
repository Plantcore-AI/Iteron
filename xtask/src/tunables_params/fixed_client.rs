//! Closed client invariants, identified by their real declaration and owning symbol.
//!
//! Moved runtime controls are deliberately absent: their original helper address must be
//! preserved by the source identity map. A missing helper is not evidence of an invariant.

use super::InvariantReason;

pub(super) fn reason(relative: &str, name: &str, owner: &str) -> Option<InvariantReason> {
    // These names are local to their owners; a same-named constant elsewhere is a new decision.
    match (relative, name, owner) {
        ("crates/cli/src/app_server/client_bootstrap.rs", "MAX_BYTES", "admissible::MAX_BYTES") => {
            // Charge retained String capacities before admitting a prompt-history write.
            return Some(InvariantReason::Security);
        }
        (
            "crates/cli/src/artifacts/material_provenance.rs",
            "BOUNDARY",
            "MaterialArchive::retain::BOUNDARY",
        ) => {
            // Fixed archive framing separates independently scrubbed retained fields.
            return Some(InvariantReason::WireCompatibility);
        }
        _ => {}
    }
    // All remaining declarations are module constants, not associated or function-local values.
    if owner != name {
        return None;
    }
    match (relative, name) {
        // Shared callback retention, source-shaped JSON and live refusal rows are fixed host
        // envelopes. The existing MCP queue capacity keeps its independent lowering helper.
        (
            "crates/cli/src/app_server/mcp_input.rs",
            "MAX_CLOSED_INPUTS" | "MAX_PROMPT_BYTES" | "MAX_INPUT_WAIT",
        )
        | (
            "crates/cli/src/app_server/mcp_input/request_bounds.rs",
            "MAX_SCHEMA_NODES" | "MAX_SCHEMA_DEPTH",
        )
        | (
            "crates/cli/src/app_server/refusal_projection.rs",
            "MAX_REFUSALS" | "MAX_SUBJECT_BYTES",
        )
        | ("crates/cli/src/tui/headless/side.rs", "MAX_ANSWER_BYTES") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        (
            "crates/protocol/src/client_mcp_input.rs",
            "MAX_MCP_INPUT_RESPONSE_BYTES"
            | "MAX_MCP_INPUT_RESPONSE_NODES"
            | "MAX_MCP_INPUT_RESPONSE_DEPTH"
            | "MAX_MCP_INPUT_REQUEST_FIELDS",
        )
        | ("crates/protocol/src/client_interaction.rs", "MAX_SIDE_QUESTION_BYTES") => {
            Some(InvariantReason::WireCompatibility)
        }
        // New attached clients retain only bounded transport/presentation buffers. UI polling
        // cadence and text page size remain actual runtime helpers and are deliberately absent.
        (
            "crates/cli/src/tui/remote.rs",
            "MAX_DRAFT_BYTES" | "MAX_PENDING_COMMANDS" | "REPLY_DEADLINE",
        )
        | (
            "crates/cli/src/tui/remote_transport.rs",
            "MAX_FRAME_BYTES" | "MAX_LOGICAL_BYTES" | "MAX_COMMAND_BYTES" | "IO_DEADLINE"
            | "ASSEMBLY_DEADLINE",
        )
        | (
            "crates/cli/src/tui/product_tools.rs",
            "MAX_TOOLS" | "MAX_TOOL_BYTES" | "MAX_PENDING_BYTES",
        )
        | (
            "crates/cli/src/tui/artifact_view.rs",
            "MAX_ARTIFACT_BYTES"
            | "MAX_ARTIFACT_DESCRIPTORS"
            | "MAX_IMAGE_PIXELS"
            | "MAX_IMAGE_DIMENSION"
            | "MAX_DECODE_BYTES"
            | "READ_DEADLINE",
        )
        | (
            "crates/cli/src/runtime/model_context_projection.rs",
            "MAX_JSON_NODES" | "MAX_JSON_DEPTH",
        ) => Some(InvariantReason::Security),
        ("crates/cli/src/tui/session_changes.rs", "READ_CAPACITY") => {
            Some(InvariantReason::RuntimeStateNotAValue)
        }
        ("crates/cli/src/tui/picker_owner.rs", "REMOTE_SESSION_TITLE") => {
            Some(InvariantReason::Identity)
        }
        ("crates/protocol/src/resident_service.rs", "RESIDENT_SERVICE_VERSION") => {
            Some(InvariantReason::WireCompatibility)
        }
        // Admission and projection ceilings bound physically retained work/bytes. Neither an
        // observer nor a learned policy may enlarge the verified owner envelope.
        ("crates/cli/src/app_server/agent_control.rs", "MAX_PENDING_CONTROLS")
        | ("crates/cli/src/app_server/live_workflow_control.rs", "MAX_PENDING_CONTROLS")
        | (
            "crates/cli/src/app_server/client_artifacts.rs",
            "MAX_ARTIFACT_BYTES" | "MAX_ARTIFACTS" | "MAX_CATALOG_BYTES",
        )
        | ("crates/cli/src/app_server/ordinary_extensions/projection.rs", "MAX_REPLY_BYTES")
        | (
            "crates/cli/src/app_server/session_factory/workspace_rewind.rs",
            "MAX_PATH_DISPLAY" | "MAX_POINTS",
        )
        | (
            "crates/cli/src/app_server/thread_inspection.rs",
            "MAX_GOAL_BYTES"
            | "MAX_INSPECTION_EVENTS"
            | "MAX_INSPECTION_RECORD_BYTES"
            | "MAX_INSPECTION_RECORDS"
            | "MAX_TRACE_DISPLAY_BYTES"
            | "MAX_TRACE_PAGE_BYTES",
        )
        | ("crates/cli/src/app_server/thread_lifecycle.rs", "MAX_PHYSICAL_EXPORT_BYTES")
        | (
            "crates/cli/src/artifacts/material_provenance.rs",
            "MAX_ARCHIVE_BYTES" | "MAX_WIRE_CONTEXT_VERIFY_BYTES" | "MAX_WIRE_TEXT_FIELDS",
        )
        | (
            "crates/cli/src/client_effects/experiment_lab/comparison.rs",
            "MAX_FILE_READ" | "MAX_TOTAL_READ",
        )
        | ("crates/cli/src/client_effects/experiment_lab.rs", "MAX_SCAN")
        | (
            "crates/cli/src/client_effects/path_completion.rs",
            "MAX_SCAN" | "MAX_ROW_BYTES" | "MAX_ENTRY_BYTES" | "MAX_CACHE_BYTES" | "MAX_ENTRIES",
        )
        | ("crates/cli/src/client_effects/tunables_simulation.rs", "MAX_VIEW_BYTES")
        | (
            "crates/cli/src/client_effects/workspace_read.rs",
            "MAX_BYTES" | "MAX_COMPONENTS" | "MAX_PATH_BYTES",
        )
        | ("crates/cli/src/client_inventory.rs", "MAX_ID_BYTES" | "MAX_MODELS" | "MAX_PROVIDERS")
        | ("crates/cli/src/plugin_runtime/inventory.rs", "MAX_BOUND_SURFACES" | "MAX_PACKAGES")
        | ("crates/cli/src/session_transcript.rs", "MAX_BLOCKS" | "MAX_BYTES")
        | (
            "crates/cli/src/tui/activity_presentation.rs",
            "MAX_ACTIVE" | "MAX_ACTIVE_BYTES" | "MAX_RETIRED",
        )
        | ("crates/cli/src/tui/live_workflows.rs", "MAX_COMMAND_BYTES" | "MAX_RENDERED_NODES")
        | ("crates/cli/src/tui/picker_owner.rs", "MAX_SESSION_ROWS")
        | ("crates/cli/src/tui/run_presentation.rs", "MAX_RETRY_BYTES")
        | ("crates/cli/src/tui/transcript_geometry.rs", "MAX_CACHE_BYTES") => {
            Some(InvariantReason::Security)
        }

        // Retained CAS catalogs commit dependencies and sources under a single writer lease.
        // Their eviction/revocation and recovery validation use these same finite envelopes.
        ("crates/cli/src/artifacts.rs", "MAX_ARTIFACTS" | "MAX_CATALOG_BYTES" | "MAX_SOURCES")
        | ("crates/cli/src/artifacts/storage.rs", "MAX_MANIFEST_BYTES") => {
            Some(InvariantReason::DurabilityReplay)
        }

        // An unprovable parent identity always refuses publication. This false sentinel was
        // incorrectly exposed in the old catalog despite its explicit "Not a tunable" contract.
        ("crates/cli/src/client_effects/export.rs", "REBIND_UNPROVEN") => {
            Some(InvariantReason::CapabilityAuthority)
        }
        // An I/O failure exposes only a closed refusal, never a raw native path or OS diagnostic.
        ("crates/cli/src/client_effects/workspace_read.rs", "SAFE_READ_REFUSAL") => {
            Some(InvariantReason::Security)
        }

        // These bytes describe an actual frame layout or the closed parser grammar. Changing
        // them independently cannot configure a compatible worker or introduce a command.
        ("crates/cli/src/client_effects/worker/protocol.rs", "WORKER_HEADER_BYTES")
        | ("crates/cli/src/tui/experiment_lab.rs", "USAGE")
        | ("crates/cli/src/tui/live_workflows.rs", "HELP") => {
            Some(InvariantReason::WireCompatibility)
        }

        // Fixed scaffold bytes are part of this host operation's shipped implementation, not a
        // live scalar configuration. Editing an existing project instruction remains separate.
        ("crates/cli/src/client_effects/project_init.rs", "INSTRUCTIONS") => {
            Some(InvariantReason::RuntimeStateNotAValue)
        }

        // Legacy compatibility only: the map reserves actual capacity before any SQ effect and
        // never evicts an admitted receipt. These bounds confer no default company capability.
        (
            "crates/cli/src/tui/headless/commands.rs",
            "COMMAND_RECORD_AND_REPLY_RESERVE"
            | "MAX_COMMAND_REPLAY_BYTES"
            | "MAX_RECORDED_COMMANDS",
        ) => Some(InvariantReason::HardBudgetEffectLedger),
        // Once kill has been requested, this fixed deadline bounds the native wait before the
        // retained process owner falls back to reaping or reports an unobserved outcome. It is
        // not an export strategy timeout or authority to release unresolved cleanup custody.
        ("crates/cli/src/client_effects/worker.rs", "REAP_DEADLINE") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::reason;
    use crate::tunables_params::InvariantReason;

    #[test]
    fn a_new_symbol_or_wrong_owner_does_not_inherit_a_fixed_envelope() {
        let path = "crates/cli/src/app_server/thread_inspection.rs";
        assert!(matches!(
            reason(path, "MAX_INSPECTION_EVENTS", "MAX_INSPECTION_EVENTS"),
            Some(InvariantReason::Security)
        ));
        assert!(reason(path, "MAX_OTHER_EVENTS", "MAX_OTHER_EVENTS").is_none());
        assert!(
            reason(
                path,
                "MAX_INSPECTION_EVENTS",
                "Other::MAX_INSPECTION_EVENTS"
            )
            .is_none()
        );
        assert!(
            reason(
                "crates/cli/src/other.rs",
                "MAX_INSPECTION_EVENTS",
                "MAX_INSPECTION_EVENTS"
            )
            .is_none()
        );
    }

    #[test]
    fn local_bounds_require_the_actual_owner_and_frame_bytes_are_not_controls() {
        let path = "crates/cli/src/app_server/client_bootstrap.rs";
        assert!(matches!(
            reason(path, "MAX_BYTES", "admissible::MAX_BYTES"),
            Some(InvariantReason::Security)
        ));
        assert!(reason(path, "MAX_BYTES", "MAX_BYTES").is_none());
        assert!(matches!(
            reason(
                "crates/cli/src/artifacts/material_provenance.rs",
                "BOUNDARY",
                "MaterialArchive::retain::BOUNDARY"
            ),
            Some(InvariantReason::WireCompatibility)
        ));
        assert!(matches!(
            reason(
                "crates/cli/src/client_effects/export.rs",
                "REBIND_UNPROVEN",
                "REBIND_UNPROVEN"
            ),
            Some(InvariantReason::CapabilityAuthority)
        ));
    }

    #[test]
    fn migration_failure_cannot_make_existing_runtime_controls_read_only() {
        for (path, names) in [
            (
                "crates/cli/src/cli_entry/prompts.rs",
                &["SYSTEM_PROMPT"][..],
            ),
            (
                "crates/cli/src/cli_entry/provider_bootstrap.rs",
                &["BUILTIN_DEFAULT_PROVIDER"][..],
            ),
            (
                "crates/cli/src/cli_entry/build_identity.rs",
                &["BUILD_STALE_AFTER_DAYS"][..],
            ),
            (
                "crates/cli/src/queue_policy.rs",
                &["SQ_CAPACITY", "EQ_CAPACITY"][..],
            ),
            (
                "crates/cli/src/client_effects/shell.rs",
                &["TIMEOUT", "POST_KILL_DRAIN"][..],
            ),
            (
                "crates/cli/src/client_effects/experiment_lab.rs",
                &["MAX_REQUEST_BYTES"][..],
            ),
            (
                "crates/cli/src/client_effects/export.rs",
                &["MAX_TRANSCRIPT_EXPORT_BYTES"][..],
            ),
            (
                "crates/cli/src/tui/workflow_region.rs",
                &["RESTORE_LIMIT"][..],
            ),
        ] {
            for name in names {
                assert!(reason(path, name, name).is_none(), "{path}::{name}");
            }
        }
    }

    #[test]
    fn only_the_actual_native_reap_deadline_is_a_fixed_cleanup_bound() {
        let path = "crates/cli/src/client_effects/worker.rs";
        assert!(matches!(
            reason(path, "REAP_DEADLINE", "REAP_DEADLINE"),
            Some(InvariantReason::HardBudgetEffectLedger)
        ));
        assert!(reason(path, "EXPORT_DEADLINE", "EXPORT_DEADLINE").is_none());
        assert!(reason(path, "REAP_DEADLINE", "Other::REAP_DEADLINE").is_none());
        assert!(reason("crates/cli/src/other.rs", "REAP_DEADLINE", "REAP_DEADLINE").is_none());
        assert!(
            reason(
                "crates/cli/src/tui/clipboard_image.rs",
                "MAX_WINDOWS_SYSTEM_ROOT_BYTES",
                "MAX_WINDOWS_SYSTEM_ROOT_BYTES"
            )
            .is_none(),
            "the existing native allocation helper remains a live lowering-only control"
        );
    }
}
