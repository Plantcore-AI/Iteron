//! Exact native physical envelopes. These declarations constrain retained OS resources and
//! capability proofs, independently of operator-selected runtime policies and presentation.
use super::InvariantReason;

pub(super) fn reason(relative: &str, name: &str, owner: &str) -> Option<InvariantReason> {
    if owner != name {
        return None;
    }
    match (relative, name) {
        // A poisoned or unresolved native resource cannot free its slot by changing a profile.
        (
            "crates/support/src/owned_windows_job/conpty/console.rs",
            "MAX_CONSOLES" | "MAX_DIMENSION",
        )
        | (
            "crates/support/src/owned_windows_job/conpty/pipes.rs",
            "PIPE_BUFFER_BYTES" | "PIPE_CONNECT_LIMIT",
        )
        | ("crates/support/src/owned_windows_job/native_setup.rs", "MAX_SETUP_WAIT")
        | ("crates/sandbox/src/pty_size.rs", "MAX_WINDOW_DIMENSION")
        | ("crates/sandbox/src/windows_launch_plan.rs", "MAX_PREPARATIONS" | "PREPARATION_WAIT")
        | ("crates/tools/src/lsp/capability_windows.rs", "MAX_SOURCE_READS") => {
            Some(InvariantReason::HardBudgetEffectLedger)
        }
        // The native ABI capture and actual held-object walk refuse oversized or uninspectable
        // capabilities before installation; no learned profile may broaden these grants.
        (
            "crates/support/src/owned_windows_job/native_launch.rs",
            "MAX_COMMAND_UNITS" | "MAX_ENV_ENTRIES" | "MAX_ENV_UNITS" | "MAX_ATTRIBUTE_BYTES",
        )
        | (
            "crates/sandbox/src/windows_launch_plan.rs",
            "MAX_ENVIRONMENT_ENTRIES" | "MAX_ENVIRONMENT_BYTES" | "MAX_SHELL_PATH_ENTRIES",
        )
        | (
            "crates/support/src/windows_process_isolation/tree.rs",
            "MAX_SCOPE_OBJECTS" | "MAX_SCOPE_DEPTH" | "MAX_SCOPE_PATH_UNITS",
        )
        | ("crates/support/src/windows_process_isolation/acl_lock.rs", "ACL_LOCK_WAIT_MS")
        | (
            "crates/support/src/durable_windows_state/private_scratch.rs",
            "MAX_OBJECTS" | "MAX_DEPTH",
        ) => Some(InvariantReason::Security),
        // These are process-wide census state, not independently selectable integer budgets.
        ("crates/support/src/owned_windows_job/conpty/console.rs", "POOL")
        | ("crates/support/src/owned_windows_job/custody.rs", "POOL")
        | ("crates/sandbox/src/windows_launch_plan.rs", "PREPARATIONS")
        | ("crates/tools/src/lsp/capability_windows.rs", "READS") => {
            Some(InvariantReason::RuntimeStateNotAValue)
        }
        ("crates/support/src/owned_windows_job.rs", "CLEANUP_EXIT_CODE") => {
            Some(InvariantReason::Identity)
        }
        _ => None,
    }
}
