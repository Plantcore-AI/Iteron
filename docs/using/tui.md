# Terminal UI

The TUI is Core Code's default frontend when stdin and stdout are attached to a
terminal. It owns presentation and input, while the current CLI process still
participates in runtime composition; it is not yet a client of a stable App
Server.

## Start the TUI

```sh
core -C /path/to/repository
```

Passing `--tui` forces the interactive intent, but a real terminal is still
required. A pipeline should use [one-shot mode](one-shot.md) instead.

## Interaction surfaces

- Enter natural-language tasks in the composer.
- Type `/` to browse slash-command completion.
- Type `@path` to complete repository paths where the composer supports it.
- Use ++shift+tab++ to cycle `default`, `acceptEdits`, `plan`, and `yolo`.
- Use `/model`, `/effort`, `/mode`, `/permissions`, and `/theme` for explicit
  pickers or session changes.
- Use `/diff`, `/status`, `/context`, `/cost`, and `/workflows` to inspect the
  evidence Core Code currently exposes.
- Leave with `/quit`, ++esc++, or ++ctrl+d++.

The transcript distinguishes user input, assistant output, thinking, tool
activity, approvals, notices, workflow activity, and completion state. Terminal
width and color capability affect rendering; the semantic event stream remains
the source for tests.

## Approval behavior

An approval prompt names the tool, declared capability, reason, arguments, and
workspace. The operator may approve or deny it; selected capability decisions can
be remembered for the session where policy permits.

Core Code never turns a missing interactive answer into permission. In one-shot
mode, an operation that still needs a human answer fails closed.

## Honest observability limits

`/context` and `/cost` show only the estimate or provider evidence available for
the active route. A status row is not proof of authoritative billing, cache, or
context-window truth. Unknown cost remains unknown instead of being inferred from
token counts without a trusted price source.

See [context, usage, and cost](../concepts/context-usage-cost.md).
