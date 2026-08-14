# Runtime service and optimization-module graph

Iteron publishes two deliberately different inventories. `ModuleId::ALL` is the set of 28
independently trainable agent-behavior stages. The runtime service graph also lists the typed
production ports that consume those decisions, operational service boundaries, and the host
invariants that no optimizer or plugin may replace.

The distinction prevents misleading node-count comparisons. A credential store, evidence journal,
or cancellation owner can be an architectural service without becoming a training dimension.

## Machine contract

`iteron_tunables::runtime_service_graph()` returns schema v2. The same graph is embedded in the
schema-v3 `tunables surface` document. Every node declares:

- a stable identity and layer;
- `trainable`, `replaceable_only`, `host_fixed_non_optimization`, or
  `immutable_host_invariant` disposition;
- current implementation status: external process, external protocol, compiled interface, or
  host-fixed;
- versioned provider and consumer contracts;
- exact owning boundary and dependencies;
- an optional optimization module and production port.

A host-fixed platform service also declares a bounded `non_optimization_reason`, its typed
`delegated_modules`, and/or its `closed_host_invariants`. The validator requires those typed entries
to agree exactly with the service's dependency edges. Across the host-fixed platform layer, the
delegated module evidence is total over all 28 `ModuleId` values.

The graph currently contains 66 classified nodes. That is an architectural inventory, not a claim
of 66 pluggable modules:

- 28 optimization modules, each retaining a distinct `external_process` identity;
- nine host-fixed typed production consumers;
- 22 platform services: six `replaceable_only + external_protocol` services and 16
  `host_fixed_non_optimization + host_fixed` services;
- seven immutable host invariants.

A source-manifest test compares the platform layer to the workspace member list, so adding a
production crate without classifying it fails CI. Multiple ordered module stages may feed one typed
consumer without losing their individual implementation identity, lifecycle, state, or consumption
evidence.

The six externally replaceable platform services are the optimizer runtime, LSP transport, MCP
transport, observation export, provider adapters, and tunables registry. The validator pins this
allowlist: compiled Rust is never relabeled as an external protocol. `compiled_interface` remains a
wire-level status for compatibility, but schema-v2 platform validation rejects it, and the current
graph contains zero compiled-interface rows. A new service may be advertised as replaceable only
after a real language-neutral protocol exists and the allowlist is deliberately revised.

Validation fails closed if a platform row is neither an allowlisted external protocol nor explicit
host-fixed non-optimization infrastructure; if a host-fixed row lacks a reason or typed evidence;
if evidence and dependency edges differ; if the host-fixed services fail to cover every trainable
module; or if any of the 28 module nodes loses its external-process identity.

## Host invariant envelope

The following remain outside every candidate and implementation:

- activation and promotion;
- capability and permission authority;
- hard budgets and deadlines;
- cancellation and process reaping;
- evidence durability;
- replay and identity;
- trust and secret handling.

External implementations can return decisions and observations. They cannot activate themselves,
widen authority, edit the evidence ledger, or turn a hard ceiling into a learned preference.
