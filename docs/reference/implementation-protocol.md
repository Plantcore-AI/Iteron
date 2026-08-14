# Replaceable implementation protocol

`iteron-implementation/1` is the language-neutral JSON contract between Iteron's host and an
admitted process implementation. It complements the content-addressed marketplace manifest: the
manifest decides what bytes and capability ceiling may be considered, while this protocol carries
only bounded lifecycle requests, correlated responses, and schema-identified observations.

Every one of the 28 optimization modules has an entry in the versioned capability seam graph. Each
entry names distinct definition, provider, consumer, load/start/cancel/stop, and observation
contracts, plus its dependency order, failure semantics, and the seven host invariants that a
provider cannot replace. A request is rejected unless all contract references exactly match the
selected module's graph entry.

The closed request operations are:

- `load`: binds the verified artifact digest, all module contract identities, and the already
  intersected capability set;
- `start`: binds a run and candidate digest to the module's consumer schema, a bounded JSON input,
  and a nonzero deadline;
- `cancel`: addresses one run through the module's cancellation contract;
- `stop`: asks the provider process to stop through the module's stop contract.

Responses repeat `protocol`, request, implementation, and module identity. The only successful
results are `loaded`, `started`, `cancelled`, and `stopped`; a bounded `failed` result carries no
fallback, quarantine, activation, or promotion authority. Observation envelopes repeat the run and
must use the module's exact observation schema. The host process owner separately enforces sequence
monotonicity, deadlines, output limits, cancellation escalation, evidence durability, and reaping.

The marketplace registry verifies actual artifact bytes before it can emit a shell-free launch
plan. That plan clears ambient environment and carries only the host-intersected capability set.
Creating a plan or exchanging protocol messages does not activate an implementation or allow it to
select itself; composition records a candidate selection and the host retains admission and
activation authority.

## External activation document

`ImplementationActivationDocument` schema version 1 is the bounded handoff from composition to
the process owner. It carries one prefixed candidate SHA-256 and at most one source per optimization
module. Each source names `module`, `implementation_id`, absolute `catalog_path`, absolute
`artifact_root`, and prefixed canonical-manifest and artifact SHA-256 values. Unknown fields,
duplicate JSON object keys at any nesting depth, duplicate modules, duplicate implementation IDs,
oversized documents or catalogs, relative paths, symlinks, and non-canonical paths fail closed.

Activation reads each catalog with a fixed upper bound and applies the catalog registry's normal
dependency and capability-ceiling admission. The selected manifest must match the source ID and
module. Its manifest digest is SHA-256 over the stable `serde_json` encoding of the selected
`ImplementationManifest`; its declared artifact digest must match the source. The executable is a
canonical regular file under the canonical artifact-root directory and is hashed through a fixed
64-KiB streaming buffer. Only that verified digest can be passed back to the registry to mint a
`ProcessLaunchPlan`.

The resulting `ImplementationActivation` exposes plans in deterministic `ModuleId` order and
retains a non-forgeable verified identity for immutable receipts, including the exact manifest and
artifact digests and canonical source paths. It does not spawn, load, start, cancel, stop, activate,
promote, approve permission, or allocate budget. Taking a plan transfers only the already
intersected capability ceiling carried by the registry-minted value.

## Host process runtime

`ImplementationRuntime` is the host-owned direct-process implementation of this contract. It
accepts only a registry-minted `ProcessLaunchPlan` rather than command text. The plan's fields are
private and bind implementation identity, module, verified artifact digest, absolute executable,
arguments, admitted capabilities, deadlines, and evidence limits in one value. The runtime hashes
the regular executable against that bound digest immediately before and after `spawn`. It invokes
the executable directly (never through a command shell), rejects a plan that does not clear the
environment, and supplies no ambient environment variables.

Requests and provider messages use newline-delimited JSON. The runtime serializes and validates
every request envelope before writing it and accepts a response only when its protocol, request,
implementation, module, operation, run, and contract identities match exactly. Observations are
accepted only for the active run and exact graph schema, with strictly increasing sequence numbers.
Provider messages are bounded both per frame and cumulatively; stdin, stdout, stderr, observation
bytes, and observation count all have finite host-enforced limits.

The manifest runtime deadline bounds the whole child lifetime. A `start` deadline can only narrow
that limit, while cancel and stop use the bounded cancellation deadline. Timeout, malformed or
mis-correlated protocol, output overflow, invalid observation, or provider failure closes the
input, kills the provider process group (including ordinary descendants), and waits for the direct
child to be reaped. A successful stop also waits for clean exit and escalates to group kill-and-reap
if the provider does not exit by its deadline. Dropping the runtime has the same guarantee.

The runtime returns typed responses and observations only. It deliberately exposes no method to
activate or promote an implementation, widen admitted capabilities, approve permissions, allocate
budget, choose fallback or quarantine policy, or make evidence durable; those decisions remain in
their host-owned composition and policy boundaries.
