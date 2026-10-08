# State owner refactoring evidence

Generate the current source inventory with:

```sh
cargo run --locked -p iteron-xtask -- architecture inventory
```

Each row includes a source SHA-256, physical production/test line counts, responsibilities and
remaining seams. Counts include comments and blank lines. Rust AST spans exclude only explicitly
test-only items; `any(test, feature)` code remains production. This separates source inventory from
runtime or release acceptance.

## Baseline responsibilities

Public main `7ec48721747ab5067679518be9ccfe8455a293b4` has these physical counts:

| Module | Production | Test | Responsibilities to separate |
| --- | ---: | ---: | --- |
| CLI runtime | 7,881 | 837 | turn/control owner, provider/tool supervision, authorization, context, verification |
| App server | 4,814 | 2,777 | negotiation/transport, lifecycle handler, control handler, observers, assembly |
| Main | 4,997 | 817 | argument adapters, configuration/route binding, startup, composition |
| TUI | 5,694 | 76 | terminal, input, read-only projections, typed control adapter |
| CLI workflow | 1,907 | 1,622 | submission, supervisor, progress projection, child assembly |
| QuickJS bindings | 1,618 | 12 | script adapter, attempt dispatch, parallel group owner, ledger ports |

At that baseline all six exceed the 1,200 production-line target. Adding the live scheduler creates a new narrow
owner; it does not remove these existing responsibilities or close their refactoring work.

## Current integrated source checkpoint

The following source snapshot was captured on 2026-10-08 after the retained coding coordinator,
concrete execution sessions and context injection integration (`04a13705`). The existing inventory
binary supplied these AST counts; a rebuilt inventory and final same-candidate compilation,
native journeys and architecture checks remain pending.

| Original entry module | Production | Test |
| --- | ---: | ---: |
| CLI runtime | 1,165 | 620 |
| App server | 417 | 17 |
| Main | 1,124 | 828 |
| TUI | 689 | 53 |
| CLI workflow | 56 | 126 |
| QuickJS bindings | 901 | 0 |

All six original entry modules are below the production-line target in this source snapshot.
This does not establish the size of every workspace module, correctness of executable borrows,
or final architecture/release acceptance. The maintained inventory records current source
commitments and distinguishes production from explicit test-only code.

The ordinary coding loop now runs through private `CodingRunDriver`, `CodingRunCoordinator`,
`CodingProviderExecution` and `CodingResponsePhase` owners. The driver retains the actual working
transcript, physical provider/USD obligation and tool leases. The coordinator retains only its
undispatched native request, exact suspended hedge/kernel handoffs and completed action; a
consumed or failed stage cannot be used to dispatch it again. Trusted composition captures current
native, permission, financial and controller ports for each real IO boundary. Special kernel tools
use concrete Plan, child and workflow execution owners. A known tool terminal settles its retained
slot before an accounting-observation error stops the driver; absent accounting remains separately
pending and cannot grant a fresh finite-budget admission.

Context injection now owns historical reconstruction and pending live materialization through the
actual bounded ContextPort, frozen context/memory strategies and record journal. Legacy upgrades
and newly selected context require their actual writer receipt before cached bytes are installed.
The existing host source observation, UI/SDK phase projection, taint, historical frontend evidence
and optional memory behavior remain separate ports. Actual hook gates execute through the same
physical hook/effect owner; no mandatory verifier was added.

The immutable compiled policy bundle owns all nine strategy objects and boot evidence as one
generation. Agent and child composition hold that generation rather than writable strategy
mirrors. Request-cycle, provider-response and complete tool-round owners consume real phases
through concrete journal, control, permission and execution ports. Startup history, retained
workflow restart inventory and native transcript export have host owners; frontend projections
carry no filesystem/provider construction authority. Their native parity, cancellation and
restart fixtures are source candidates until executed on the final integrated revision.

## Executable architecture guard

`boundaries check` now also verifies the complete workspace normal dependency graph is acyclic,
domain crates do not depend on the CLI composition root, and agent/kernel/protocol/context owners
do not depend directly on a concrete provider or frontend. The new scheduler modules additionally
reject concrete controller/provider/frontend imports, hidden I/O aliases, wildcard imports,
`include!` source slicing and production modules above the target.

These are specific executable guards. They supplement review and typed ports; source checks do
not prove all possible runtime behavior or complete product decoupling.

When `ticket-investigation` is declared by the CLI, defaults must remain empty and the original
ticket strategy module must be absent from ordinary production on both Unix and Windows. A test
cohort may compile the strategy, and an explicit ticket profile must enable it. Candidate
workspace integrity and configured verification remain independent core responsibilities.

## Remaining product evidence

The live scheduler owns plan revisions, dependency readiness, attempt attribution and lifetime
reservations. Agent identity/mailbox and process execution are separate state owners accessed
through versioned ports. Concrete host ports now supply CLI/TUI/API assembly. Actual parity,
controller/process cancellation, provider journeys and Windows restart/fault evidence still require
final execution. Final architecture and release receipts must describe the same immutable candidate; this inventory is not a production
readiness claim.

## Workflow and script owner boundaries

The CLI workflow facade now assembles explicit independent contracts and owners. The detached
supervisor retains all live handles, cancellation/settlement and bounded summary state in
`workflow/supervisor.rs`; callers observe immutable run info or issue owner actions. Progress
retention belongs to `workflow/progress.rs`, filesystem sidecars and restart inventory to
`workflow/run_store.rs`, the directional launch contract to `workflow/launch.rs`, and pure evidence
formatting to `workflow/summary.rs`. Production code imports explicit ports and types. Existing
integration tests continue through the facade; their eviction fixture asks the owner to perform
an action instead of reaching through its mutex.

QuickJS bindings keep wire conversion, journal attribution and schema orchestration. Per-run
admission/counters/phases live in `bindings/run_state.rs`; physical child execution, bounded cleanup
and durable attempt settlement in `bindings/attempt_executor.rs`, which imports no JS interpreter.
The bindings facade and CLI supervisor retain their actual interpreter/run and task-lifetime
responsibilities. Their source sizes and explicit dependency edges supplement ownership review;
adding module count does not prove physical cleanup or product correctness.
The maintained inventory reports their source digests and remaining seams.

`script-workflows` is an explicit build profile. Default builds compile the generic live scheduler
and controller ports without QuickJS, the script compiler/cache, host bindings or script executor;
the writer catalog omits the Workflow schema. Public legacy execution entries return the typed
`ScriptWorkflowsUnavailable` before directory creation or child dispatch. Enabled builds retain
the existing script graph identity and journal semantics. CLI features must forward both the
workflow engine and tool catalog features together. Default and enabled profiles require final
same-candidate integration evidence; source guards and physical line counts alone do not accept
provider cleanup, recovery or end-user journeys.
