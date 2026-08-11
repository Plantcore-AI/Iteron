//! `read_memory` — pull one remembered fact by slug on demand (R5 memory model, progressive
//! disclosure). The always-injected index (REC-INJECT) lists each fact's slug + summary; when a
//! line looks relevant mid-run the model calls this to read the full body — the same shape as
//! skills' on-demand load.
//!
//! `Pure`/`ReadOnly`: it reads a file, so it is early-dispatchable and memoized. It goes through
//! `ctx::FileMemory::read_fact`, so the fact carries its store's trust tier and is bidi-scanned;
//! the returned body is framed as "hints, not overrides" (a fact read from an Untrusted store
//! taints the turn's egress via its `ToolResult.trust`).

use crate::{Registry, ToolError, boxfut, err_result};
use iteron_ctx::{FileMemory, MemStore, MemTier, MemoryStrategy};
use iteron_protocol::{Capability, Purity, ToolResult, ToolSpec, Trust};

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: "read_memory".into(),
            description: "Read one remembered fact by its slug (from the memory index shown in \
                          the system prompt). Use when an index line looks relevant to the task."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"slug":{"type":"string","description":"the fact slug from the memory index"}},
                "required":["slug"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let slug = call.input.get("slug").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                if slug.is_empty() {
                    return err_result(id, "read_memory needs a `slug`".into());
                }
                // The same stores REC-INJECT recalls from, so any fact whose slug appears in the
                // injected index is readable (security review: a User-tier fact was unreadable
                // because only the Project store was built here). User (~/.core/memory) is
                // Trusted; Project (this repo) is Workspace.
                let mut stores = Vec::new();
                if let Some(home) = iteron_protocol::home::operator()
                    && iteron_protocol::home::path(&home, "memory").exists()
                {
                    stores.push(MemStore::user(&home));
                }
                stores.push(MemStore::new(
                    iteron_protocol::home::path(&root, "memory"),
                    MemTier::Project,
                    true,
                ));
                match FileMemory.read_fact(&stores, &slug) {
                    Ok(fact) => {
                        // Carry the fact's store trust so an Untrusted fact taints the turn (ADR-007).
                        let trust = fact.trust();
                        ToolResult {
                            tool_use_id: id,
                            content: fact.framed(),
                            is_error: false,
                            trust: if trust == Trust::Trusted { Trust::Workspace } else { trust },
                            latency_ms: 0,
                        }
                    }
                    Err(e) => err_result(id, format!("no memory `{slug}`: {e}")),
                }
            })
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_memory_is_pure_readonly() {
        // read_only already registers read_memory; assert it is present as Pure/ReadOnly.
        let dir = std::env::temp_dir();
        let r = Registry::read_only(&dir).unwrap();
        assert_eq!(r.purity_of("read_memory"), Some(Purity::Pure));
        assert_eq!(r.capability_of("read_memory"), Some(Capability::ReadOnly));
    }
}
