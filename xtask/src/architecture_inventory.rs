//! Rebuildable physical production/test and responsibility inventory for refactoring decisions.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use syn::spanned::Spanned;
use syn::visit::Visit;

const MAX_SOURCE_BYTES: u64 = 2 * 1_024 * 1_024;
const PRODUCTION_TARGET: usize = 1_200;

struct Surface {
    path: &'static str,
    boundary: &'static str,
    responsibilities: &'static [&'static str],
    next_seams: &'static [&'static str],
}

const SURFACES: &[Surface] = &[
    Surface {
        path: "crates/cli/src/runtime.rs",
        boundary: "cli-host",
        responsibilities: &[
            "turn admission and ordered control",
            "provider/tool orchestration and accounting",
            "operation authorization and effect dispatch",
            "context packing and compaction",
            "verification and ticket policy adaptation",
        ],
        next_seams: &[
            "turn state owner and typed command handler",
            "provider/tool supervisors with narrow receipts",
            "default-off ticket strategy adapter",
            "independent candidate workspace baseline",
        ],
    },
    Surface {
        path: "crates/cli/src/app_server.rs",
        boundary: "cli-host",
        responsibilities: &[
            "public wire negotiation and client sessions",
            "thread/run lifecycle",
            "request/control routing",
            "event stream and observer backpressure",
            "checkpoint/runtime assembly",
        ],
        next_seams: &[
            "typed public-client command service",
            "permission-checked thread/artifact service",
            "observer projection independent of execution owner",
            "transport-only server adapter",
        ],
    },
    Surface {
        path: "crates/cli/src/main.rs",
        boundary: "cli-host",
        responsibilities: &[
            "command parsing and dispatch",
            "provider/config/profile binding",
            "interactive/headless startup",
            "maintenance and standalone tools",
            "standalone workflow setup",
        ],
        next_seams: &[
            "composition root only",
            "command-specific adapters",
            "profile/route assembly service",
            "standalone workflow command adapter",
        ],
    },
    Surface {
        path: "crates/cli/src/tui.rs",
        boundary: "cli-interaction",
        responsibilities: &[
            "terminal lifecycle and rendering",
            "input/edit interaction",
            "event/transcript projection",
            "approval and session control",
            "workflow activity projection",
        ],
        next_seams: &[
            "terminal adapter",
            "shared typed client control service",
            "immutable frontend projections",
            "input and activity components",
        ],
    },
    Surface {
        path: "crates/cli/src/workflow.rs",
        boundary: "cli-host",
        responsibilities: &[
            "workflow module assembly",
            "public immutable contracts and owner exports",
        ],
        next_seams: &[
            "maintain explicit independent owner interfaces; final integration evidence remains",
        ],
    },
    Surface {
        path: "crates/workflow/src/bindings.rs",
        boundary: "workflow-engine",
        responsibilities: &[
            "QuickJS wire adapter",
            "schema repair and journal attribution coordinator",
        ],
        next_seams: &["future narrow schema-repair port if this coordinator grows"],
    },
    Surface {
        path: "crates/cli/src/workflow/supervisor.rs",
        boundary: "cli-host",
        responsibilities: &[
            "detached run handle ownership",
            "cancellation and actual settlement",
            "bounded summary retention and shutdown",
        ],
        next_seams: &["final host/provider cleanup and restart integration evidence"],
    },
    Surface {
        path: "crates/cli/src/workflow/progress.rs",
        boundary: "cli-host",
        responsibilities: &[
            "partial and degraded result retention",
            "frontend progress delivery and bounded projections",
        ],
        next_seams: &["retain separate effect-free progress contracts"],
    },
    Surface {
        path: "crates/cli/src/workflow/run_store.rs",
        boundary: "cli-host",
        responsibilities: &[
            "workflow sidecar filesystem adapter",
            "bounded restart inventory readers",
        ],
        next_seams: &[
            "sidecar publication and namespace hardening remain distinct from live journal durability",
        ],
    },
    Surface {
        path: "crates/cli/src/workflow/launch.rs",
        boundary: "cli-host",
        responsibilities: &[
            "directional launch/collect/cancel contract",
            "in-turn engine adapter",
        ],
        next_seams: &["no mutable detached owner state"],
    },
    Surface {
        path: "crates/cli/src/workflow/summary.rs",
        boundary: "cli-host",
        responsibilities: &["pure settled/interrupted evidence projections"],
        next_seams: &["no filesystem or process state"],
    },
    Surface {
        path: "crates/workflow/src/bindings/run_state.rs",
        boundary: "workflow-engine",
        responsibilities: &[
            "run admission counters and phase ownership",
            "immutable runtime port bundle",
        ],
        next_seams: &["retain opaque counters and narrow actions"],
    },
    Surface {
        path: "crates/workflow/src/bindings/attempt_executor.rs",
        boundary: "workflow-engine",
        responsibilities: &[
            "physical child execution and bounded cleanup",
            "durable attempt settlement coordination",
        ],
        next_seams: &["future explicit controller adapter integration for legacy scripts"],
    },
    Surface {
        path: "crates/support/src/durable_windows_state.rs",
        boundary: "support-bundle",
        responsibilities: &[
            "private pinned-handle Windows byte publication",
            "exclusive lease and unknown-outcome poison",
        ],
        next_seams: &["native Windows and device-fault evidence remains"],
    },
    Surface {
        path: "crates/workflow/src/live_scheduler/owner.rs",
        boundary: "workflow-engine",
        responsibilities: &[
            "live graph revisions and readiness",
            "bounded attempt reservations and attribution",
            "durable command publication",
            "restart/effect reconciliation",
        ],
        next_seams: &[
            "actual live session consumes controller/journal ports; final product/provider evidence remains",
        ],
    },
    Surface {
        path: "crates/cli/src/workflow/live_session/registry.rs",
        boundary: "cli-host",
        responsibilities: &[
            "durable live graph instance admission and retained aggregate reservations",
            "single registry and live scheduler instance ownership",
            "initializing-to-active graph publication and restart restoration",
        ],
        next_seams: &["final product/provider/native platform journey evidence"],
    },
    Surface {
        path: "crates/cli/src/workflow/live_session/mod.rs",
        boundary: "cli-host",
        responsibilities: &[
            "bounded owned operator command admission and observer cancellation",
            "trusted controller budget policy minting",
            "finite background pump lifecycle",
        ],
        next_seams: &["maintain provider-independent typed controller composition"],
    },
    Surface {
        path: "crates/cli/src/workflow/live_session/store.rs",
        boundary: "cli-host",
        responsibilities: &[
            "private durable registry CAS/filesystem adapter",
            "exclusive namespace lease and indexed graph journal admission",
        ],
        next_seams: &["native Windows and storage fault evidence remains"],
    },
    Surface {
        path: "crates/cli/src/workflow/live_session/pump.rs",
        boundary: "cli-host",
        responsibilities: &[
            "bounded graph/controller command coordination",
            "exact persisted task/epoch/terminal receipt authentication",
        ],
        next_seams: &["no independently mutable graph or agent state"],
    },
    Surface {
        path: "crates/cli/src/runtime/frontend_events.rs",
        boundary: "cli-host",
        responsibilities: &["immutable frontend event/control-resolution contract"],
        next_seams: &["never treat presentation values as execution authority"],
    },
    Surface {
        path: "crates/cli/src/runtime/tool_presentation.rs",
        boundary: "cli-host",
        responsibilities: &["pure bounded tool/UI output and approval evidence projection"],
        next_seams: &["canonical raw output belongs to publication/spill owners"],
    },
    Surface {
        path: "crates/cli/src/runtime/stream_progress.rs",
        boundary: "cli-host",
        responsibilities: &["single output/thinking counter and coalesced emission owner"],
        next_seams: &["immutable stream timing evidence"],
    },
    Surface {
        path: "crates/cli/src/runtime/deferred_batch_executor.rs",
        boundary: "cli-host",
        responsibilities: &[
            "already-admitted physical tool futures and governor permits",
            "cancellation, structural correlation and ordered execution receipts",
            "raw publication before spill/model projection",
        ],
        next_seams: &["WAL admission/settlement stay with the journal owner"],
    },
    Surface {
        path: "crates/cli/src/runtime/early_tool_gate.rs",
        boundary: "cli-host",
        responsibilities: &[
            "bounded operator-configured hook predispatch coordinator",
            "immutable gate context and typed summary/refusal",
        ],
        next_seams: &["hook journal and kernel effect admission remain independent owners"],
    },
    Surface {
        path: "crates/cli/src/runtime/kernel_effect_bridge.rs",
        boundary: "cli-host",
        responsibilities: &[
            "typed non-registry effect descriptor and single kernel broker adapter",
            "bounded terminal/workspace evidence projection",
        ],
        next_seams: &["disjoint journal/admission ports; no executor receives mutable Agent"],
    },
    Surface {
        path: "crates/cli/src/runtime/submitted_turn_state.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single submission recovery receipt/error/continuation owner",
            "encoded receipt identity/count/byte bounds and immutable first receipts",
        ],
        next_seams: &["private state; typed context/recovery mutations only"],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_turn_evidence.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single transport/semantic/timing/quota observation owner",
            "bounded interrupted text/thinking prefix retention",
        ],
        next_seams: &["physical provider dispatch and monetary admission remain independent"],
    },
];

#[derive(Serialize)]
struct Inventory {
    version: u32,
    production_line_target: usize,
    interpretation: &'static str,
    modules: Vec<ModuleInventory>,
}

#[derive(Serialize)]
struct ModuleInventory {
    path: &'static str,
    boundary_id: &'static str,
    source_sha256: String,
    physical_lines: usize,
    production_lines: usize,
    test_lines: usize,
    exceeds_production_target: bool,
    responsibilities: &'static [&'static str],
    remaining_seams: &'static [&'static str],
}

pub(crate) fn print(root: &Path) -> Result<()> {
    let modules = SURFACES
        .iter()
        .filter(|surface| root.join(surface.path).is_file())
        .map(|surface| measure(root, surface))
        .collect::<Result<Vec<_>>>()?;
    let inventory = Inventory {
        version: 1,
        production_line_target: PRODUCTION_TARGET,
        interpretation: "Physical source lines; syntactically test-only items excluded via Rust AST spans. Comments and blanks are counted. This is a refactoring inventory, not architecture or release acceptance.",
        modules,
    };
    println!("{}", serde_json::to_string_pretty(&inventory)?);
    Ok(())
}

fn measure(root: &Path, surface: &Surface) -> Result<ModuleInventory> {
    let mut source = String::new();
    std::fs::File::open(root.join(surface.path))?
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_string(&mut source)?;
    if source.len() as u64 > MAX_SOURCE_BYTES {
        bail!("architecture inventory source exceeded byte ceiling");
    }
    let parsed = syn::parse_file(&source).with_context(|| format!("parse {}", surface.path))?;
    let physical_lines = source.lines().count();
    let mut visitor = TestLines {
        lines: BTreeSet::new(),
        physical_lines,
    };
    visitor.visit_file(&parsed);
    let test_lines = visitor.lines.len();
    let production_lines = physical_lines - test_lines;
    Ok(ModuleInventory {
        path: surface.path,
        boundary_id: surface.boundary,
        source_sha256: hex_digest(source.as_bytes()),
        physical_lines,
        production_lines,
        test_lines,
        exceeds_production_target: production_lines > PRODUCTION_TARGET,
        responsibilities: surface.responsibilities,
        remaining_seams: surface.next_seams,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct TestLines {
    lines: BTreeSet<usize>,
    physical_lines: usize,
}

impl<'ast> Visit<'ast> for TestLines {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attributes = match item {
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            _ => return syn::visit::visit_item(self, item),
        };
        if test_only(attributes) {
            self.include(item.span());
        } else {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attributes = match item {
            syn::ImplItem::Const(i) => &i.attrs,
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => return syn::visit::visit_impl_item(self, item),
        };
        if test_only(attributes) {
            self.include(item.span());
        } else {
            syn::visit::visit_impl_item(self, item);
        }
    }
}

impl TestLines {
    fn include(&mut self, span: proc_macro2::Span) {
        let start = span.start().line.max(1);
        let end = span.end().line.min(self.physical_lines);
        self.lines.extend(start..=end);
    }
}

fn test_only(attributes: &[syn::Attribute]) -> bool {
    attributes
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .filter_map(|attribute| attribute.parse_args::<syn::Meta>().ok())
        .any(|meta| requires_test(&meta))
}

fn requires_test(meta: &syn::Meta) -> bool {
    use syn::parse::Parser;
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") => {
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .is_ok_and(|items| items.iter().any(requires_test))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_excludes_only_test_items_and_retains_conditional_product_code() {
        let source = "struct Owner {}\n#[cfg(test)]\nmod tests {\n fn one() {}\n}\n#[cfg(any(test, feature = \"optional\"))]\nfn product() {}\nimpl Owner {\n #[cfg(all(test, unix))]\n fn helper() {}\n}\n";
        let parsed = syn::parse_file(source).unwrap();
        let mut visitor = TestLines {
            lines: BTreeSet::new(),
            physical_lines: source.lines().count(),
        };
        visitor.visit_file(&parsed);
        assert!(visitor.lines.contains(&2) && visitor.lines.contains(&5));
        assert!(visitor.lines.contains(&9) && visitor.lines.contains(&10));
        assert!(!visitor.lines.contains(&6) && !visitor.lines.contains(&7));
    }
}
