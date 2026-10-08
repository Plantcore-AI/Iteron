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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
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
            super::original_source("crates/cli/src/block/diff.rs", "UNRELATED"),
            None
        );
        assert_eq!(
            super::original_source("crates/cli/src/other.rs", "HUNK_DEFAULT_START_LINE"),
            None
        );
    }
}
