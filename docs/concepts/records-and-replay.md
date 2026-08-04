# Records and replay

The record subsystem gives a run a durable, append-only history rather than
treating terminal output as the source of truth.

## Hash-chained rollout

Each durable entry is linked to the previous entry. Resume validates and rebuilds
the transcript from that chain. Forking records the parent and its tail hash so a
later change to the shared prefix can be detected.

The design supports:

- listing and continuing repository-local sessions;
- explicit resume by run id;
- shared-past, divergent-future forks;
- checkpoints around reversible local effects;
- recording provider, tool, usage, workflow, and terminal outcome evidence;
- marking an external effect unknown when dispatch was observed but authoritative
  completion was not.

## Immutable tunables genesis evidence

The record API can project an atomically successful `ResolvedTunableSet` into a bounded
`tunables_snapshot` companion immediately after `run_start` (physical seq 1, before any provider or
tool effect). The v1 snapshot commits the resolver, registry, and family schema versions; registry
revision and digest; frozen-input, effective-set, full-resolution, and optional-profile digests;
and all 160 ordered family identities and states. It deliberately does not carry per-family value
hashes: low-entropy booleans, paths, provider/model ids, and profile choices would be recoverable by
offline dictionary enumeration. Exact comparison instead uses the aggregate resolver commitments.
A canonical self-digest is recomputed at every record read and write boundary rather than trusted.
Those unkeyed aggregate digests can reveal equality of whole resolved sets; they are compatibility
commitments, not confidentiality or evidence authentication.
The companion API, not a caller-supplied payload sequence, owns physical placement; the ordinary
append placeholder remains `seq = 0`, and checked readers compare against the hash-chain sequence.

Checked resume and replay compare the complete snapshot with the caller's current resolved set.
Checked fork performs that comparison before creating a child, copies the exact parent snapshot,
and binds the child event to the parent run and parent snapshot digest. Logical fork loading
rechecks that binding against the direct parent's unique physical seq-1 snapshot on every ancestry
edge, including a fork pinned at parent seq 0; nested forks therefore cannot hide replacement of an
ancestor snapshot behind an otherwise valid seq-0 parent hash. Missing, malformed, duplicated,
late, or mismatched evidence fails with a typed error. A caller may explicitly choose
`AllowUnpinned` only when a structurally valid historical `run_start` lacks the snapshot. Empty
journals, a different event at physical seq 0, and partial or invalid fork triples fail under both
legacy policies. An admitted historical record returns `LegacyUnpinned`, never `Exact`; no
automatic migration or new authority is fabricated.

This is an evidence and compatibility boundary, not runtime admission by itself. The provider-free
`core tunables` command remains a simulation, and a composition root must deliberately call the
resolved-set genesis/check APIs before it can claim a run is pinned. The snapshot authenticates no
external evidence, binds no policy to an executor, and makes no family trainable.

## Replay boundary

Reproducibility does not mean calling a model again and hoping for the same text.
Recorded model output and nondeterministic choices should be consumed from the
record where the replay contract covers them.

The current implementation has meaningful record, checkpoint, resume, and fork
primitives, but a complete pure-reducer replay runtime and full crash
reconciliation remain target work.

## Security and privacy

The record is tamper-evident, not encrypted. Redaction is applied at several
output boundaries, but users must still treat run files as private because they
can contain source excerpts, paths, prompts, model output, diffs, and tool
evidence.

Do not commit `.core/runs`, paste a real record into a public issue, or mistake a
same-disk record for a backup.
