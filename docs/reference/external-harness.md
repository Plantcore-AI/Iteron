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

This adapter is also not a universal plugin or trainer protocol. It transports an already-built
Iteron profile through one exact benchmark contract; it does not register arbitrary runtime module
implementations, enumerate caller-injected defaults, define reward/trajectory/checkpoint exchange,
or make the native tuner cover every profile artifact. The tracked completion gaps are documented
in `docs/development/deepseek-harness-gap-audit.md`.
