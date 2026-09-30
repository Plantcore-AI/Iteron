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

All six exceed the 1,200 production-line target. Adding the live scheduler creates a new narrow
owner; it does not remove these existing responsibilities or close their refactoring work.

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
through versioned ports. Product assembly still needs real CLI/TUI/API parity, controller/process
cancellation, provider journeys and Windows restart/fault evidence. Final architecture and
release receipts must describe the same immutable candidate; this inventory is not a production
readiness claim.
