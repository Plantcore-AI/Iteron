# External harness adapter

`iteron-eval` exposes a public, serde-serializable adapter contract for harnesses that want to
evaluate an Iteron tunables profile without running `iteron-evolve`. The current contract admits
exactly `terminal-bench` version `2.1`; a missing, newer, older, or differently formatted version
is refused.

## Lifecycle

1. Export Iteron's optimization surface and construct a valid profile outside the adapter.
2. Create a bounded `TerminalBenchRequest` with exact task/trial identity, profile and registry
   digests, Iteron revision, absolute artifact paths, and time/turn/output/evidence/memory ceilings.
3. Call `TerminalBenchRequest::command()`. Execute the returned program and argv with its cleared,
   fixed public environment. Credential **names** may be inherited directly by the launcher from
   the six built-in provider variables; values never enter the request, command document, or
   evidence envelope.
4. Bound stdout/stderr and wall time exactly as specified. Save stdout at `stdout_path`, retain the
   emitted effective profile, and retrieve the run record named by Iteron's machine result.
5. Hash those bytes, have the external verifier write its score evidence, then serialize an
   `ExternalHarnessResult`. `parse_external_harness_result` rejects duplicate keys, oversized
   input, identity drift, invalid digests/paths, and evidence or timing beyond the request bounds.

The command uses Iteron's ordinary `--tunables-profile` plus
`--tunables-profile-digest` path. `--emit-tunables-profile` provides the exact effective-profile
artifact, while JSON stdout supplies the terminal result and run id. The adapter has no dependency
on `iteron-evolve`, cannot select a winner, and has no authority to promote a candidate.

Path validation is lexical and must occur before execution. The launcher is additionally
responsible for opening/canonicalizing inputs and artifacts without following an unsafe symlink,
and for verifying every recorded byte count and SHA-256 against the file it actually retained.

Passing contract tests or running a one-task smoke establishes adapter/surface acceptance only. It
is not a Terminal-Bench campaign, qualification, leaderboard submission, or score claim. Those
claims require the pinned upstream dataset, its prescribed trials/resources, external verifier
evidence, and complete failed/timeout accounting.

## Research implementation activation

The CLI also has a separate, operator-owned process-implementation path. It is intentionally
hidden from ordinary help and requires both
`--implementation-candidate <PATH> --implementation-candidate-digest <64-lowercase-hex>` with
`--harness-profile research`. The file is read once as a bounded regular file without symlinks and
is verified directly through the marketplace activation registry. This research path does not
consult `HOME`, `ITERON_CONFIG_HOME`, the installed plugin store, or composition winners. Every
source still has an absolute canonical catalog and artifact root, exact manifest and executable
digests, a regular executable, and capabilities intersected with the explicit CLI host ceiling.
Project configuration cannot name or activate an implementation.

Activation is atomic and every source resolves through the marketplace's verified launch-plan API.
For research, the paired hidden CLI arguments are the process-execution authorization; declared
decision authority is still intersected with the explicit host and caller ceilings. The ordinary
installed-plugin path remains separate: an implementation there must retain `code_executing`,
equal a composition-winning binding, and remain inside the winning plugin's fixed catalog/artifact
layout. All 28 optimization modules have an independent public module identity, lifecycle, and
consumption-evidence row. Nine typed production consumers execute these as deterministic ordered
module-stage chains; sharing a consumer does not merge implementation identity or permit one
implementation to stand in for a sibling module.

Each module stage launches a bounded direct child, loads it, starts one correlated run, consumes a
terminal schema-checked decision, then stops and reaps it. A stage can return a typed decision or
explicitly inherit the prior stage (the compiled baseline for the first stage). The decision's
authority is intersected with the registry-minted plan, every prior stage, and the caller ceiling.
Any lifecycle, protocol, schema, deadline, receipt, or identity failure returns the port's typed
unknown/refusal decision; it never silently skips the failed stage.

Fresh genesis records the exact implementation, manifest, artifact, candidate, and activation
identity in the immutable bundle receipt. Resume requires the same candidate and reconstructs the
same receipt byte-for-byte; omission or drift is refused. Children inherit the same compiled slot
objects. Actual process consumption is reported at
`<runs_dir>/.iteron-implementation-<bare-activation-sha256>-consumption.json` with schema
`iteron-implementation-consumption/1`, the prefixed candidate digest, bare activation digest, CLI
run id, and ordered per-module `loaded/started/terminal/stopped` truth flags. Flags start false and
change only after the corresponding operation succeeds.

Neither path is a trainer or promotion protocol. They do not define reward, trajectory, checkpoint
exchange, or authorize a candidate to select itself.
