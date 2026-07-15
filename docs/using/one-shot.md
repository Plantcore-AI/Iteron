# One-shot and automation

One-shot mode runs one task, streams or emits a machine-readable result, and
exits.

```sh
core -p -C /path/to/repository \
  "Find the smallest cause of the failing test and report it"
```

`-p`/`--print` requires a task. A non-interactive invocation with a task also
selects one-shot operation, but explicit `-p` is clearer in automation.

## Output formats

```sh
core -p --output-format text "Explain the repository"
core -p --output-format json "Explain the repository"
core -p --output-format stream-json "Explain the repository"
```

| Format | Stdout contract |
| --- | --- |
| `text` | Human-readable assistant text streams to stdout |
| `json` | Exactly one final result object |
| `stream-json` | One JSON object per UI event, followed by the same final result object |

Diagnostics remain on stderr for machine formats. The current machine schema
version is `3`; consumers must inspect `schema_version` rather than Rust enum or
debug text.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | completed with `done` |
| `2` | harness error |
| `3` | budget exhausted |
| `4` | stuck |
| `130` | interrupted |

The final JSON object repeats the authoritative `exit_code` and includes outcome,
success, assistant text, run id, cost state, turns, and any terminal error. See
the [output-format reference](../reference/output-formats.md).

## Permissions in a non-interactive run

One-shot mode defaults to `acceptEdits`: reversible local edits can proceed behind
the checkpoint path, while code execution still asks unless explicitly granted.
Because there is no live answer channel, an unresolved `Ask` is denied.

Use `--allow-code` only in a repository you have reviewed. `--mode yolo` is not an
unbounded bypass: declared trust-mutating and irreversible external operations
still require approval and therefore cannot silently succeed in ordinary one-shot
operation.

## Bound the run

```sh
core -p \
  --max-turns 12 \
  --max-usd 2.50 \
  --effort high \
  "Run the requested investigation"
```

`max_usd` is enforceable only to the extent that the active provider route emits
trustworthy monetary evidence. Unknown accounting is not converted into a false
exact amount.
