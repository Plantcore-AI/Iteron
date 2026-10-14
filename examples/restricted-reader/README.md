# A caller-selected read-only child

Run from the Iteron source checkout with an installed binary and an already configured provider.
This creates a separate synthetic workspace and performs provider calls; it uses the operator's
normal provider configuration. No credentials belong in this example.

```sh
ITERON_READER_EXAMPLE="$(mktemp -d "${TMPDIR:-/tmp}/iteron-reader.XXXXXX")"
mkdir -p "$ITERON_READER_EXAMPLE/.iteron/agents"
cp examples/restricted-reader/file-reader.md "$ITERON_READER_EXAMPLE/.iteron/agents/"
cp examples/restricted-reader/evidence.txt "$ITERON_READER_EXAMPLE/"
iteron --repo "$ITERON_READER_EXAMPLE" --runs-dir "$ITERON_READER_EXAMPLE/runs" \
  --max-turns 6 --max-wall-secs 60 -p \
  'Use dispatch_agent with agent_type="file-reader" for a read-only investigation of evidence.txt. The child must read that exact file and return its actual content. Return its evidence; report any failure.'
```

The parent sees `file-reader` in `dispatch_agent.agent_type` metadata (or in the tool returned by
`tool_search`). The runtime applies `tools: [read_file]` when building that child. The generic
profile remains available to other children; one child's profile never changes another registry.
A tool allowlist is not a file-path ACL: operator hooks and workspace/path policy own path access.

The prompt is a caller selection example, not evidence that a particular model obeyed it. Inspect
the parent `SubagentFinishedV2` and child `EffectIntent`/successful `ToolDone` before crediting a read.
The source regression uses this same profile and a deterministic provider that selects the
advertised name, requests an actual file read, and checks the recorded terminal. A second regression
holds two provider requests concurrently and proves the broader sibling cannot widen the reader.
Neither fixture certifies every model or an external application's pinned runtime.
