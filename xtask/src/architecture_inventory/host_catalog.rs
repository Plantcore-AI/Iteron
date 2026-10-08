//! Maintained responsibility specifications for host, frontend, native and shared tooling owners.
use super::Surface;

pub(super) const SURFACES: &[Surface] = &[
    Surface {
        path: "crates/record/src/session/model.rs",
        boundary: "record-sessions",
        responsibilities: &["retain unchanged public session projection and provenance schemas"],
        next_seams: &["same-candidate compiler, restart and native evidence remain required"],
    },
    Surface {
        path: "crates/record/src/session/paths.rs",
        boundary: "record-sessions",
        responsibilities: &["resolve exact session record paths and clock or currency defaults"],
        next_seams: &["same-candidate compiler, restart and native evidence remain required"],
    },
    Surface {
        path: "crates/record/src/session/replay.rs",
        boundary: "record-sessions",
        responsibilities: &["retain cumulative verified logical ancestry read and fork budgets"],
        next_seams: &["same-candidate compiler, restart and native evidence remain required"],
    },
    Surface {
        path: "crates/record/src/session/cache_receipts.rs",
        boundary: "record-sessions",
        responsibilities: &[
            "verify exact record and ancestor receipts before accepting a rebuildable cache",
        ],
        next_seams: &["same-candidate compiler, restart and native evidence remain required"],
    },
    Surface {
        path: "crates/record/src/session/projection.rs",
        boundary: "record-sessions",
        responsibilities: &[
            "own incremental projection state and prepare immutable record-bound publication facts",
        ],
        next_seams: &["same-candidate compiler, restart and native evidence remain required"],
    },
    Surface {
        path: "crates/record/src/session/index.rs",
        boundary: "record-sessions",
        responsibilities: &[
            "retain real paging snapshots and cross-process index publication transactions",
        ],
        next_seams: &["same-candidate compiler, restart and native evidence remain required"],
    },
    Surface {
        path: "crates/record/src/session/lifecycle.rs",
        boundary: "record-sessions",
        responsibilities: &[
            "hold exact journal and derivative leases through deletion and explicit retention",
        ],
        next_seams: &["same-candidate compiler, restart and native evidence remain required"],
    },
    Surface {
        path: "crates/record/src/session.rs",
        boundary: "record-sessions",
        responsibilities: &[
            "assemble stable public session contracts over private replay, projection, index and lifecycle owners",
        ],
        next_seams: &["same-candidate compiler and behavior evidence remain required"],
    },
    Surface {
        path: "crates/ctx/src/memory.rs",
        boundary: "context-knowledge",
        responsibilities: &[
            "join bounded source materialization and its exact same-decision audit through the stable public facade",
        ],
        next_seams: &["same-candidate compiler and behavioral evidence remain required"],
    },
    Surface {
        path: "crates/ctx/src/memory/file_store.rs",
        boundary: "context-knowledge",
        responsibilities: &["own confined store metadata, index reads and the retained body cache"],
        next_seams: &["same-candidate compiler and behavioral evidence remain required"],
    },
    Surface {
        path: "crates/ctx/src/memory/operator_store.rs",
        boundary: "context-knowledge",
        responsibilities: &[
            "publish operator reference edits through the sole versioned memory record owner",
        ],
        next_seams: &["same-candidate compiler and behavioral evidence remain required"],
    },
    Surface {
        path: "crates/ctx/src/memory/selection.rs",
        boundary: "context-knowledge",
        responsibilities: &[
            "own pure gathered-value selection and deterministic score retention without physical storage authority",
        ],
        next_seams: &["same-candidate compiler and behavioral evidence remain required"],
    },
    Surface {
        path: "xtask/src/tunables_params/stable_source.rs",
        boundary: "build-release",
        responsibilities: &[
            "retain exact runtime lookup identities for moved declarations while recording actual source provenance",
        ],
        next_seams: &["same-candidate compiler and behavioral evidence remain required"],
    },
    Surface {
        path: "crates/provider/src/catalog.rs",
        boundary: "provider-core",
        responsibilities: &[
            "retain configured provider identity, credentials, injected transport and immutable catalog or pricing evidence",
        ],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "crates/provider/src/catalog/discovery.rs",
        boundary: "provider-core",
        responsibilities: &["own bounded physical catalog or account discovery and page decoding"],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "crates/provider/src/catalog/health.rs",
        boundary: "provider-core",
        responsibilities: &["own bounded provider and model health state plus evidence merging"],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "crates/provider/src/catalog/routing.rs",
        boundary: "provider-core",
        responsibilities: &[
            "choose only from already resolved model identities through a pure closed strategy contract",
        ],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "xtask/src/tunables_params.rs",
        boundary: "build-release",
        responsibilities: &[
            "harvest and classify maintained source declarations without runtime authority",
        ],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "xtask/src/tunables_params/source_wiring.rs",
        boundary: "build-release",
        responsibilities: &["own explicit maintainer AST source rewrites and replacement spans"],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "xtask/src/tunables_params/use_evidence.rs",
        boundary: "build-release",
        responsibilities: &[
            "collect read-only actual runtime helper evidence from production AST and macros",
        ],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/app_server/path_completion.rs",
        boundary: "cli-host",
        responsibilities: &[
            "bind actual current workspace read scope and retain finite native worker custody independently of presentation",
        ],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/path_completion.rs",
        boundary: "cli-host",
        responsibilities: &[
            "read held directory metadata beneath the captured workspace and own bounded identity-checked completion cache",
        ],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/block.rs",
        boundary: "cli-render",
        responsibilities: &["own presentation block identity and tool or timer state"],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/block/diff.rs",
        boundary: "cli-render",
        responsibilities: &[
            "render immutable standalone or embedded diffs with shared complete gutter and wrap geometry",
        ],
        next_seams: &["same-candidate compiler, behavioral and native evidence remain required"],
    },
    Surface {
        path: "crates/protocol/src/image_record.rs",
        boundary: "protocol-compat",
        responsibilities: &[
            "select versioned durable message and compaction tags for captured pixels while preserving ordinary record vocabulary",
            "refuse new nested pixel blocks under old writable tags before native record publication",
        ],
        next_seams: &[
            "same-candidate compiler, actual old-reader and native replay evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/app_server/experiment_lab.rs",
        boundary: "cli-host",
        responsibilities: &[
            "admit existing offline lab intent and retain native publication and session exclusion independently of the observer",
        ],
        next_seams: &["same-candidate compiler, native and client evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/experiment_lab.rs",
        boundary: "cli-host",
        responsibilities: &[
            "execute bounded native request publication and offline inventory under the captured host authority",
        ],
        next_seams: &["same-candidate compiler, native and client evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/experiment_lab/model.rs",
        boundary: "cli-host",
        responsibilities: &[
            "validate existing immutable request identity and project bounded redacted offline facts without runtime activation",
        ],
        next_seams: &["same-candidate compiler and client evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/experiment_lab/comparison.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain a bounded native evidence source and project only the actual signed recomputed comparison",
        ],
        next_seams: &["same-candidate compiler and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/workspace_storage.rs",
        boundary: "cli-host",
        responsibilities: &[
            "select the actual finite native workspace directory capability and closed publication outcomes",
        ],
        next_seams: &["same-candidate compiler and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/workspace_storage/unix.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain Unix namespace and regular file identities through finite enumeration, read and create-only publication",
        ],
        next_seams: &["same-candidate compiler and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/workspace_storage/windows.rs",
        boundary: "cli-host",
        responsibilities: &[
            "compose held ordinary NTFS read and private staged by-handle publication capabilities",
        ],
        next_seams: &["same-candidate compiler and native evidence remain required"],
    },
    Surface {
        path: "crates/support/src/durable_windows_state/workspace_directory_read.rs",
        boundary: "support-bundle",
        responsibilities: &[
            "enumerate actual held native directory pages under independent operation, row and buffer bounds",
        ],
        next_seams: &["same-candidate compiler and actual Windows evidence remain required"],
    },
    Surface {
        path: "crates/support/src/owned_windows_job.rs",
        boundary: "support-bundle",
        responsibilities: &[
            "retain actual suspended Windows child and private non-breakaway JobObject through assignment and resume",
            "cache actual exit status and retire process references before observing native job population",
        ],
        next_seams: &["same-candidate compiler and actual Windows execution remain required"],
    },
    Surface {
        path: "crates/support/src/owned_windows_job/custody.rs",
        boundary: "support-bundle",
        responsibilities: &[
            "admit bounded native cleanup capacity before process creation and retain dropped real child and job handles",
            "retire custody only after actual wait and empty job observations; quarantine worker failures without claiming effect completion",
        ],
        next_seams: &["same-candidate compiler and actual Windows execution remain required"],
    },
    Surface {
        path: "crates/sandbox/src/collected_child.rs",
        boundary: "sandbox",
        responsibilities: &[
            "adapt actual Unix and Windows child pipes and wait observations for the shared bounded collector",
        ],
        next_seams: &["same-candidate compiler and native execution remain required"],
    },
    Surface {
        path: "crates/cli/src/app_server/tunables_simulation.rs",
        boundary: "cli-host",
        responsibilities: &[
            "admit existing simulation file read under actual host policy and retain submission and adoption custody",
        ],
        next_seams: &["same-candidate compiler, native and real client evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/workspace_read.rs",
        boundary: "cli-host",
        responsibilities: &[
            "read actual bounded regular workspace bytes through held native handles and version and path rebinding",
        ],
        next_seams: &["same-candidate compiler, native and real client evidence remain required"],
    },
    Surface {
        path: "crates/agents/src/controller/native_spawn.rs",
        boundary: "agent-controller",
        responsibilities: &[
            "bind ordinary child native lifetime in the actual durable Spawn transaction",
        ],
        next_seams: &[
            "same-candidate model switch, resident and native restart evidence remain required",
        ],
    },
    Surface {
        path: "crates/record/src/native_child_context.rs",
        boundary: "record-core",
        responsibilities: &[
            "select exact bounded native context publication through actual scoped physical hash chain",
        ],
        next_seams: &[
            "same-candidate model switch, resident and native restart evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/app_server/model_preferences.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain actual selected-route preference write under submission and adoption custody",
            "publish bounded run-scoped native write receipt independent of presentation observer",
        ],
        next_seams: &[
            "same-candidate native custody, failure and frontend evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/config/preferences.rs",
        boundary: "cli-host",
        responsibilities: &[
            "capture existing user preference path and own bounded global config lock and atomic native write",
            "distinguish pre-install refusal from installation uncertainty without repeating model selection",
        ],
        next_seams: &[
            "same-candidate native custody, failure and frontend evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/app_server/project_init.rs",
        boundary: "cli-host",
        responsibilities: &[
            "capture existing project scaffold intent under actual host write authority and session scope",
        ],
        next_seams: &["same-candidate compiler and native integrated evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/project_init.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain real bounded native initialization worker and create-only publication through physical completion",
        ],
        next_seams: &["same-candidate compiler and native integrated evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/app_server/client_shell.rs",
        boundary: "cli-host",
        responsibilities: &[
            "capture actual idle host authority and scope for existing operator shell execution",
            "retain real submission and adoption leases until native cleanup is observed",
        ],
        next_seams: &["native Windows job ownership and same-candidate execution remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/shell.rs",
        boundary: "cli-host",
        responsibilities: &[
            "own actual bounded shell process, cancellation, sanitized environment and output",
            "prove cleanup only for its retained owned process group before releasing host custody",
        ],
        next_seams: &["native Windows job ownership and same-candidate execution remain required"],
    },
    Surface {
        path: "crates/tools/src/contained_source.rs",
        boundary: "tools-core",
        responsibilities: &[
            "bounded retained regular source reads and real physical worker capacity",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/support/src/durable_windows_state/contained_read.rs",
        boundary: "support-bundle",
        responsibilities: &[
            "ordinary readonly pinned local NTFS namespace and held regular source",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/support/src/durable_windows_state/workspace_publication.rs",
        boundary: "support-bundle",
        responsibilities: &[
            "private exact Windows staged inode and create-only by-handle workspace publication",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/client_effects/export_macos.rs",
        boundary: "cli-host",
        responsibilities: &[
            "anonymous same-volume source and create-only APFS descriptor clone publication",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/sandbox/src/owned_process_cleanup.rs",
        boundary: "sandbox",
        responsibilities: &[
            "bounded native absence observation for the exact owned Unix process group",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/providers.rs",
        boundary: "cli-host",
        responsibilities: &[
            "provider value contracts, immutable bootstrap policy and physical discovery composition",
        ],
        next_seams: &[
            "directory, retained caches, secret storage and exact instance construction stay independent",
        ],
    },
    Surface {
        path: "crates/cli/src/providers/directory.rs",
        boundary: "cli-host",
        responsibilities: &[
            "whole private captured catalog/health/deferred-selection owner",
            "validated exact selection and physical adapter construction",
        ],
        next_seams: &[
            "deferred physical work belongs to discovery; no frontend or writer authority",
        ],
    },
    Surface {
        path: "crates/cli/src/providers/catalog_cache.rs",
        boundary: "cli-host",
        responsibilities: &[
            "private retained credential-scoped catalog candidates and bounded validated lookup/update",
        ],
        next_seams: &["raw scope key and namespace publication stay behind storage ports"],
    },
    Surface {
        path: "crates/cli/src/providers/probe_cache.rs",
        boundary: "cli-host",
        responsibilities: &[
            "private retained account evidence and bounded positive-reuse/failure-backoff decision",
        ],
        next_seams: &["account availability never follows catalog visibility alone"],
    },
    Surface {
        path: "crates/cli/src/providers/cache_storage.rs",
        boundary: "cli-host",
        responsibilities: &[
            "installation-local scope key and checked private namespace atomic byte publication",
        ],
        next_seams: &["no formatting or serialization port for scope secret bytes"],
    },
    Surface {
        path: "crates/cli/src/providers/cache_writeback.rs",
        boundary: "cli-host",
        responsibilities: &[
            "consumed actual discovery snapshot/probe observation writeback lifetime",
        ],
        next_seams: &["best-effort cache refusal never changes provider execution truth"],
    },
    Surface {
        path: "crates/cli/src/providers/instance_factory.rs",
        boundary: "cli-host",
        responsibilities: &[
            "operator configuration to exact immutable provider routes and explicit model catalogs",
        ],
        next_seams: &["construction performs no physical discovery or validation request"],
    },
    Surface {
        path: "crates/cli/src/providers/selection_identity.rs",
        boundary: "cli-host",
        responsibilities: &[
            "pure identity over actual captured entry, selected model and admitted capability evidence",
        ],
        next_seams: &["no mutable directory, provider transport or filesystem authority"],
    },
    Surface {
        path: "crates/cli/src/tui/attachment_owner.rs",
        boundary: "cli-tui",
        responsibilities: &[
            "private attachment worker, cancellation generation, physical slot and progress",
        ],
        next_seams: &["immutable prepared attachment crosses existing composer admission"],
    },
    Surface {
        path: "crates/cli/src/tui/session_navigation.rs",
        boundary: "cli-tui",
        responsibilities: &[
            "private origin/generation and native inspection/adoption worker lifetime",
        ],
        next_seams: &[
            "trusted host factory replacement is still developing; no completed frontend parity claim",
        ],
    },
    Surface {
        path: "crates/cli/src/tui/picker_owner.rs",
        boundary: "cli-tui",
        responsibilities: &[
            "private picker query, tree, selection, cursor and page generation",
            "unique physical page worker and bounded row window with explicit omitted count",
        ],
        next_seams: &[
            "immutable view consumed by terminal renderer; stale worker cannot adopt a new scope",
        ],
    },
    Surface {
        path: "crates/tools/src/desktop/mod.rs",
        boundary: "tools-execution",
        responsibilities: &[
            "operator-selected native session, current view, quarantine and physical operation slot",
            "actual application source and main display screenshot with distinct desktop scope",
        ],
        next_seams: &[
            "native Mac2 platform gate remains separate from physical HTTP ownership fixtures",
        ],
    },
    Surface {
        path: "crates/cli/src/providers/discovery.rs",
        boundary: "cli-host",
        responsibilities: &[
            "dormant network work and the unique physical discovery task",
            "post-paint admission and typed immutable catalog settlement",
        ],
        next_seams: &[
            "directory cache and route catalog adapters remain distinct responsibilities",
        ],
    },
    Surface {
        path: "crates/cli/src/machine_projection.rs",
        boundary: "cli-output",
        responsibilities: &[
            "pure shared result/event schema and canonical v7 projection",
            "bounded secret scrubber state over immutable protocol facts",
        ],
        next_seams: &["physical CLI emitter and server/TUI adapters consume this owner directly"],
    },
    Surface {
        path: "crates/cli/src/tui/completion_owner.rs",
        boundary: "cli-tui",
        responsibilities: &[
            "unique physical completion worker, generation and debounce",
            "private completion menu with immutable render view",
        ],
        next_seams: &[
            "stale completion cannot reopen a dismissed menu or discard editor attachments",
        ],
    },
    Surface {
        path: "crates/cli/src/queue_policy.rs",
        boundary: "cli-host",
        responsibilities: &[
            "shared SQ/EQ capacities and bounded overflow contract",
            "immutable checkpoint policy decoded without a runtime dependency on frontend adapters",
        ],
        next_seams: &[
            "priority reservation still reads existing tunables; no broader frozen-field claim",
        ],
    },
    Surface {
        path: "crates/cli/src/tui/headless/connection.rs",
        boundary: "cli-tui",
        responsibilities: &[
            "physical socket and immutable authenticated client negotiation",
            "replay cursor, pending reply and independent bounded observation subscriptions",
        ],
        next_seams: &[
            "explicit source/read/write ports; final real TCP and cancellation evidence pending",
        ],
    },
    Surface {
        path: "crates/cli/src/tui/headless/commands.rs",
        boundary: "cli-tui",
        responsibilities: &[
            "run-local command receipts and bounded exact command replay",
            "captured dispatch-gate and SQ control signal adapter",
        ],
        next_seams: &[
            "count and actual retained-string capacities bound admission before SQ dispatch; final TCP evidence pending",
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
        boundary: "cli-tui",
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
        path: "crates/cli/src/app_server/client_export.rs",
        boundary: "cli-host",
        responsibilities: &[
            "strict operator transcript command and observed current run opaque port",
            "actual Activity read lease and one detached physical export slot",
        ],
        next_seams: &["same-candidate TCP/observer/adoption/cancellation evidence pending"],
    },
    Surface {
        path: "crates/cli/src/client_effects.rs",
        boundary: "cli-host",
        responsibilities: &[
            "shared native export custody independent of frontend observers",
            "separate file publication, process cleanup and private content cleanup facts",
        ],
        next_seams: &["native Mac/Windows publication and bounded helper drain source in progress"],
    },
];
