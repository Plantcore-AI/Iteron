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
