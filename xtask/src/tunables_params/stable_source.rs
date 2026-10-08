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
            | "MAX_MEMORY_SLUG_BYTES",
        ) => Some("crates/ctx/src/memory.rs"),
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
