# Language-server tools

Core's coding-agent registry includes three lazy language-server queries:
`lsp_definition`, `lsp_references`, and `lsp_hover`. They are registered as
**Effecting / CodeExecuting**, not pure reads. A third-party language-server executable can write
inside its workspace even when the request itself is observational, so the normal code-execution
permission gate applies.

The built-in adapter map is intentionally closed and does not accept a model-supplied command:

| Source suffix | Server command | LSP language ID |
| --- | --- | --- |
| `.rs` | `rust-analyzer` | `rust` |
| `.ts`, `.tsx`, `.js`, `.jsx` | `typescript-language-server --stdio` | `typescript` |
| `.py`, `.pyi` | `pyright-langserver --stdio` | `python` |

Each call starts the adapter only after admission. The process runs under Core's egress-off Linux
bubblewrap PID namespace, uses bounded stdio framing, completes initialize/open/query/shutdown/exit,
and is joined before the result is returned. If that persistent confinement is unavailable, Core
refuses before starting an unconfined server. This means the live tools currently refuse on macOS
and Windows.

The input must be a control-free relative workspace path to a UTF-8 source file of at most 2 MiB.
Line and character use zero-based LSP positions; character offsets are UTF-16 code units. One frame
is limited by the `core-lsp` 16 MiB ceiling, at most 64 interleaved messages and 32 MiB aggregate
JSON are inspected, locations retain at most 200 entries, hover text retains at most 64 KiB, and
rendered tool output is capped at 1 MiB. The target file's identity and bytes are rechecked after
the reply. Server-produced content is labelled untrusted. Locations are projected to
workspace-relative paths; external/virtual locations are counted but not rendered, and the known
workspace root is redacted from hover text.

This first live slice deliberately does not claim a persistent server pool, restart/reconnect,
workspace-wide dependency freshness, configurable server selection, target-platform process
qualification, context chips, or run-genesis tunable binding. The output says
`dependency_freshness: server_observed_not_attested` and `run_genesis_bound: false` so callers
cannot mistake a target-file freshness check for a complete compilation snapshot.
