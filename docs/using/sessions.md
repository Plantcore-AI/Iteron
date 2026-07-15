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

## Resume a known run

```sh
core --resume RUN_ID -C /path/to/repository \
  "Continue with this follow-up instruction"
```

The follow-up task is optional in the TUI. Runtime routing recorded by the session
is restored unless an explicit CLI or environment override takes precedence.

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
