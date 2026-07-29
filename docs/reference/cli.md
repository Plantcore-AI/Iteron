# CLI reference

The executable name is `core`.

```text
core [OPTIONS] [TASK]
```

This page describes Core Code `0.0.1`. Run `core --help` for the exact build you
have installed.

## Operation

| Argument or option | Meaning |
| --- | --- |
| `[TASK]` | Optional task in the TUI; required with `--print` |
| `--tui` | Force interactive TUI intent |
| `-p`, `--print` | One-shot operation |
| `--image PATH` | Attach a sniffed, bounded PNG/JPEG/GIF/WebP to a one-shot task; repeatable up to eight |
| `--output-format text\|json\|stream-json` | One-shot stdout contract |
| `-C`, `--repo PATH` | Target repository; default `.` |

## Provider and model

| Option | Meaning |
| --- | --- |
| `--provider ID` | Provider instance; built-ins are `anthropic`, `openai`, `deepseek`, `glm`, `minimax`, and `fireworks` |
| `--model ID` | Model id, optionally provider-qualified |
| `--base-url URL` | Trusted one-run OpenAI-compatible API root including its version/path prefix |
| `--effort LEVEL` | `low`, `medium`, `high`, `xhigh`, `max`, or `ultracode` |

## Budgets and authority

| Option | Meaning |
| --- | --- |
| `--max-turns N` | Maximum model turns |
| `--max-usd USD` | Monetary ceiling when the route has usable cost evidence |
| `--allow-code` | Grant sandboxed code-execution capability |
| `--mode MODE` | `default`, `acceptEdits`, `plan`, or `yolo` |
| `--verify COMMAND` | Harness-owned completion command; requires `--allow-code` |

User config also supports a wall-clock ceiling; the current CLI has no
`--max-wall-secs` flag.

## Sessions

| Option | Meaning |
| --- | --- |
| `--runs-dir PATH` | Rollout directory; default `.core/runs` |
| `--sessions` | List sessions and exit |
| `-c`, `--continue` | Continue the most recent session in the repository |
| `--resume RUN_ID` | Resume a named run |
| `--fork RUN_ID` | Create a child run at the parent's durable tail and exit |

## Standard options

| Option | Meaning |
| --- | --- |
| `-h`, `--help` | Help |
| `-V`, `--version` | Version |

Local validation runs before a new rollout is opened, so malformed mode, effort,
verification, or TUI/one-shot combinations should fail without creating a
phantom session.
