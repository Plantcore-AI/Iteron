# Sessions, resume, and fork

Each run writes an append-only, hash-chained local record beneath the configured
runs directory. The default is `.core/runs` in the target repository.

## List and continue

```sh
core --sessions -C /path/to/repository
core --continue -C /path/to/repository
```

`--sessions` lists local run metadata. `--continue` selects the most recent valid
session for that repository and continues from its durable tail.

Core maintains a bounded `.meta.json` sidecar per run and one compact
`sessions.index`. The record writer refreshes these rebuildable projections at
turn and terminal boundaries, so covered sessions can be listed or selected
without replaying their historical rollout. Each projection is bound to the
current record length, subsecond modification time, and hash-chain tail. Fork
projections also carry bounded receipts for the exact ancestor prefixes they
consumed; later parent appends do
not invalidate a child, while a changed or truncated pinned prefix does.

The cache never becomes session truth. Missing, stale, oversized, or malformed
cache files are ignored and rebuilt from the bounded, hash-verified record. Run
`core reindex` to repair all local projections explicitly. Exact `Zero` and
`Known` cost states are also replayed instead of being trusted from mutable cache
bytes; only an honest unknown-cost projection may take the no-replay read path.

## Resume a known run

```sh
core --resume RUN_ID -C /path/to/repository \
  "Continue with this follow-up instruction"
```

The follow-up task is optional in the TUI. Runtime routing recorded by the session
is restored unless an explicit CLI or environment override takes precedence.
The existing rollout is locked before route and message reconstruction, so a
second writer cannot append between resume replay and continuation.

This durable session operation is unrelated to the headless transport's
`resume_from` cursor. The latter only replays missed live EQ frames from an App
Server process that is already running; if its bounded ring no longer reaches the
cursor, the server sends durable Rollout evidence under distinct `rollout_seq`
fields and then resumes the live cursor. Neither form can be passed where the
other is expected.

## Fork a session

```sh
core --fork RUN_ID -C /path/to/repository
```

A fork creates a new run with a shared past and divergent future. Its genesis pins
the parent chain hash at the fork point so later parent-prefix modification is
detectable. In the TUI, `/fork` and `/rewind` provide related branch-from-here
operations.

## What the record does and does not prove

- The hash chain makes later modification detectable when the chain is checked.
- It supports transcript reconstruction and explicit unknown-effect handling.
- It is not encryption, a remote backup, or proof that an external side effect did
  not occur.
- If a process ended after dispatching an external effect but before recording an
  authoritative terminal result, Core Code records the outcome as unknown and
  does not automatically retry it.

Run records can contain prompts, model output, paths, diffs, and tool evidence.
Keep `.core/` private and never publish a real session as a bug fixture.
