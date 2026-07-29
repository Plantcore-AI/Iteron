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
| `serve --listen ADDR` | Run the managed, authenticated App Server on a loopback TCP address; default `127.0.0.1:0` |

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

`core serve` is a managed/headless process. Before it binds, its parent must
write exactly one fresh 32-byte bearer capability as 64 lowercase hexadecimal
bytes to the child's inherited stdin and close the pipe. The token is not an
argument, environment setting, stdout value, stderr value, or field in the
structured ready metadata. A direct caller can use the same contract by writing
the token to a pipe connected to stdin and closing that pipe.

Every first client frame must be a `hello` carrying `bearer_token`,
`protocol_version`, and an optional `resume_from`. Authentication happens before
version negotiation, replay, or submission. Loopback binding excludes remote
hosts; the bearer capability excludes unrelated local processes. This does not
protect against a compromised managing parent or a process that can read Core's
memory.

The transport uses bounded newline-delimited JSON frames and refuses
non-loopback addresses. The unauthenticated first `hello` frame is capped at
4 KiB; after authentication, the submission bound is derived from the maximum
legal task and aggregate image envelope. Physical server frames remain at most
1 MiB. A larger bounded logical event, result, or Rollout projection is sent as
ordered `frame_chunk` frames with its stream, logical type, logical byte count,
chunk index/count, live `seq` or durable `rollout_seq`, and `base64_json_utf8`
data. Clients concatenate and decode all chunks before parsing the original
JSON frame.
Replay-ring entries are retained and evicted atomically by logical frame. If a
cursor predates an evicted terminal result, the server returns `cursor_expired`
instead of pretending that durable Rollout events can reconstruct the exact
result-v5 projection.

The server admits at most 32 connections, closes excess sockets without
spawning rejection tasks, expires an authenticated connection after five
minutes without inbound or outbound activity, and bounds every socket write and
whole Rollout fallback. Its bound address and lifecycle diagnostics are
non-secret JSON objects on stderr; it does not require or write to a terminal.
