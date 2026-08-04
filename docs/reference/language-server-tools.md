# Language-server tools

On Linux, Core's coding-agent registry includes one lazy `lsp_query` tool with a typed `query`
selector for `definition`, `references`, or `hover`. It is registered as
**Effecting / CodeExecuting**, not pure reads. A third-party language-server executable can write
inside its workspace even when the request itself is observational, so the normal code-execution
permission gate applies. Platforms without the required confinement backend do not advertise a
tool that is guaranteed to refuse.

The built-in adapter map is intentionally closed and does not accept a model-supplied command:

| Source suffix | Server command | LSP language ID |
| --- | --- | --- |
| `.rs` | `rust-analyzer` | `rust` |
| `.ts` | `typescript-language-server --stdio` | `typescript` |
| `.tsx` | `typescript-language-server --stdio` | `typescriptreact` |
| `.js` | `typescript-language-server --stdio` | `javascript` |
| `.jsx` | `typescript-language-server --stdio` | `javascriptreact` |
| `.py`, `.pyi` | `pyright-langserver --stdio` | `python` |

Each call starts the adapter only after admission. The workspace is retained as a descriptor and
mounted with bubblewrap's native `--bind-fd`; path replacement after admission cannot redirect the
server. The process runs under Core's egress-off Linux bubblewrap PID namespace, uses bounded stdio
framing, completes initialize/open/query/shutdown/exit, and is joined before a natural result is
returned. If persistent confinement is unavailable, Core refuses before starting an unconfined
server.

The input must be a control-free relative workspace path to a UTF-8 source file of at most 2 MiB.
Line and character use zero-based LSP positions; character offsets are UTF-16 code units. One frame
is limited by the `core-lsp` 16 MiB ceiling, at most 64 interleaved messages and 32 MiB aggregate
JSON are inspected, locations retain at most 200 entries, hover text retains at most 64 KiB, and
rendered tool output is capped at 1 MiB. The target file's identity and bytes are rechecked after
the reply. Server-produced content is labelled untrusted. Locations are projected to
workspace-relative paths; external/virtual locations are counted but not rendered. Known workspace
paths and peer-fabricated absolute POSIX, home, Windows, UNC, and file-URI paths are removed from
hover text, including quoted paths containing spaces; ordinary documentation URLs are retained.

The operation has a 70-second user-visible async budget: 67 seconds are available to admission,
spawn, protocol work, and projection, with three seconds reserved for forced process and stderr
cleanup, which run concurrently. The supervisor awaits that owned lifecycle task through the
absolute 70-second deadline. If terminal cleanup has not been confirmed then, Core returns an
Unknown outcome and detaches rather than aborting the runtime-owned cleanup task; that task
continues to own the process lifecycle, spends the process-group capability before any
direct-child reap, and completes the bounded reap and stderr-retirement attempts. Caller
cancellation uses the same ownership transfer. A kernel-stalled filesystem operation cannot be
interrupted portably; this
remains a host/filesystem availability boundary, not a claimed hard deadline for an unresponsive
FUSE or network mount.

This first live slice deliberately does not claim a persistent server pool or batched multi-query
session, restart/reconnect,
workspace-wide dependency freshness, configurable server selection, target-platform process
qualification, context chips, or run-genesis tunable binding. The output says
`dependency_freshness: server_observed_not_attested` and `run_genesis_bound: false` so callers
cannot mistake a target-file freshness check for a complete compilation snapshot.
