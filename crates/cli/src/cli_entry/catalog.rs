//! Agent catalog discovery and cache identity; owns no resident agent state.

use super::records::erasure_now_unix_ms;
use crate::{config, plugin_runtime};

/// Resolve the executable agent catalog once at the composition root. Rejections remain visible,
/// while the accepted set is moved into an immutable `Arc` by the runtime and never re-read by a
/// child. `ITERON_CONFIG_HOME` uses the same trusted root as the rest of the CLI.
pub(crate) fn discover_agent_catalog(
    repo: &std::path::Path,
    plugin_agents: &[plugin_runtime::AgentArtifact],
) -> iteron_agents::AgentCatalog {
    let catalog = scan_agent_catalog(repo, plugin_agents);
    report_agent_catalog_scan(&catalog);
    catalog
}

pub(crate) fn scan_agent_catalog(
    repo: &std::path::Path,
    plugin_agents: &[plugin_runtime::AgentArtifact],
) -> iteron_agents::AgentCatalog {
    let plugin_files = plugin_agents
        .iter()
        .map(|artifact| {
            (
                artifact.root.clone(),
                artifact.path.clone(),
                artifact.name.clone(),
            )
        })
        .collect::<Vec<_>>();
    let home = config::config_home();
    iteron_agents::AgentCatalog::discover_with_plugin_agents(home.as_deref(), repo, &plugin_files)
}

pub(crate) fn report_agent_catalog_scan(catalog: &iteron_agents::AgentCatalog) {
    // A skipped symlink and a truncated directory are SCAN STEPS, not rejected agent definitions.
    // Printing one line each turned startup in a large tree into 150 lines of noise that buried the
    // three lines an operator actually needs — and called every `node_modules/.bin` entry a rejected
    // agent, which is not what happened to it.
    //
    // Real rejections (a definition that exists and is malformed, over-broad, or unsafe) still print
    // one line each: those are the operator's own files failing, and they have to stay loud.
    let mut skipped = 0usize;
    for error in catalog.errors() {
        let source = safe_agent_diagnostic(&error.source);
        let reason = safe_agent_diagnostic(&error.reason);
        if is_scan_limit(&error.reason) {
            skipped += 1;
            continue;
        }
        eprintln!("agent definition rejected: {} ({})", source, reason);
    }
    if skipped > 0 {
        eprintln!(
            "agent scan: {skipped} path{} skipped (symlinks not followed, or a directory past its scan bound); no definition was rejected",
            if skipped == 1 { "" } else { "s" }
        );
    }
}

/// One private snapshot per canonical workspace. A snapshot is only a previously verified
/// bootstrap: physical discovery always refreshes it after paint and the running session never
/// swaps its pinned catalog underneath an active turn.
pub(crate) fn agent_catalog_snapshot_path(
    home_core: Option<&std::path::Path>,
    repo: &std::path::Path,
    plugin_agents: &[plugin_runtime::AgentArtifact],
) -> Option<std::path::PathBuf> {
    use sha2::{Digest as _, Sha256};

    let home_core = home_core?;
    let mut digest = Sha256::new();
    digest.update(b"iteron-agent-catalog-snapshot-scope-v1");
    for bytes in std::iter::once(repo.as_os_str().as_encoded_bytes()).chain(
        plugin_agents.iter().flat_map(|artifact| {
            [
                artifact.name.as_bytes(),
                artifact.root.as_os_str().as_encoded_bytes(),
                artifact.path.as_os_str().as_encoded_bytes(),
            ]
        }),
    ) {
        digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(bytes);
    }
    Some(
        home_core
            .join("cache")
            .join("agent-catalog")
            .join(format!("{:x}.json", digest.finalize())),
    )
}

pub(crate) fn agent_discovery_activity(
    state: iteron_protocol::ActivityState,
    started_at_unix_ms: u64,
) -> iteron_protocol::ActivityEvent {
    let updated_at_unix_ms = erasure_now_unix_ms().max(started_at_unix_ms);
    iteron_protocol::ActivityEvent {
        schema_version: iteron_protocol::ACTIVITY_SCHEMA_VERSION,
        id: "startup:agent_discovery".into(),
        parent_id: None,
        kind: iteron_protocol::ActivityKind::Startup,
        state,
        owner: iteron_protocol::ActivityOwner::Runtime,
        started_at_unix_ms,
        updated_at_unix_ms,
        attempt: 1,
        limit: 1,
        next_retry_at_unix_ms: None,
        deadline_unix_ms: None,
        cancelability: iteron_protocol::ActivityCancelability::None,
        detail_code: Some(iteron_protocol::ActivityDetailCode::AgentDiscovery),
        progress: None,
    }
}

/// Whether a catalog error describes the SCAN refusing to walk further, rather than a definition
/// being refused. Matched on the reason the scanner writes, because the scanner is the only thing
/// that produces these and the operator never sees the enum.
pub(crate) fn is_scan_limit(reason: &str) -> bool {
    reason.contains("skipped a symlink") || reason.contains("truncated")
}

pub(crate) fn safe_agent_diagnostic(value: &str) -> String {
    const MAX_BYTES: usize = 2 * 1024;
    const TRUNCATED: &str = "[truncated]";
    const CONTENT_BYTES: usize = MAX_BYTES - TRUNCATED.len();
    let scrubbed = iteron_record::redact::scrub(value);
    let mut safe = String::with_capacity(scrubbed.len().min(iteron_tunables::param_integer(
        "cli.main.max_bytes",
        MAX_BYTES,
    )));
    for character in scrubbed.chars() {
        let rendered = if character.is_control() {
            character.escape_default().to_string()
        } else {
            character.to_string()
        };
        if safe.len().saturating_add(rendered.len())
            > iteron_tunables::param_integer("cli.main.content_bytes", CONTENT_BYTES)
        {
            safe.push_str(iteron_tunables::param_str("cli.main.truncated", TRUNCATED));
            break;
        }
        safe.push_str(&rendered);
    }
    safe
}
