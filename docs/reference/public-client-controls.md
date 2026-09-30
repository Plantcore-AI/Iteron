# Resident public client controls

The authenticated headless transport and interactive TUI address the same resident control
owners. A control reply is a result from that owner; an SQ submission receipt remains a queue
receipt and does not prove an authorized effect. This document does not change TurnStart retry
or durable admission semantics.

## Compatibility and authority

The kernel SQ/EQ version gate remains exact. A current client can request ordinary controls.
An N-1 client can connect only with `"observation_only": true` in its authenticated Hello.
The accepted Hello then includes `"client_access": "observe"`. Observation authority is fixed
for that connection: sending a current-version Submit or mutation frame cannot upgrade it.
Versions older than N-1 and future versions are refused. Bearer authorization runs before
version diagnostics and capabilities are disclosed.

Observers may request Product V1 reads, resident artifact reads, thread history reads/exports,
job inventory/output pages, workflow inventory, MCP status, operator status and the turn-budget
read. All mutation commands remain unavailable. Observers must ignore unknown event tags; an
unknown control tag or field fails strict decoding. Control frames carry the version used in
the authenticated Hello. Outbound frames advertise the server version.

## Resident controls

The existing effort, mode, capability-rule, compact and turn-budget controls are joined by:

| Control tag | Resident owner |
| --- | --- |
| `set_tool_rule` | durable permission-policy transition |
| `operator_status` | live provider/process/LSP/MCP/workflow owners and settled budget |
| `workflows_list`, `workflows_cancel`, `workflows_resume` | session workflow supervisor |
| `mcp_status`, `mcp_cancel`, `mcp_restart`, `mcp_stop` | attached MCP supervisors |
| `memory_add`, `memory_update`, `memory_delete` | runtime memory Gate Hooks and effect owner |
| `jobs_list`, `jobs_attach`, `jobs_write`, `jobs_stop`, `jobs_clean` | process supervisor |

`set_tool_rule` takes a literal `tool` and `verdict` (`auto`, `ask`, `deny`). Names are 1–128
ASCII bytes from `[A-Za-z0-9_.:-]`; a session retains at most 128 named rules. Operation names
such as `bash:external` are exact names. Rules remain subject to Plan mode, capability ceilings
and the runtime gate. The TUI uses `/permissions allow|ask|deny tool:NAME`; existing capability
syntax remains available. Inventory is returned in the state reply's `permission_rules`.

## History lifecycle V1

Send `{"type":"thread_lifecycle_v1","command":{...}}`. Commands are `list`, `read`, `rename`,
`pin`, `archive`, `export` and `delete`, with an exact `run_id` for per-thread operations. `list` takes a bounded opaque cursor and a page size
of 1–100 (default 25); it reports an unavailable index or stale cursor explicitly. Requests never supply record
store paths. The resident owner verifies the target's recorded tenant and canonical workspace
before reading or changing presentation state. Another workspace or tenant is unavailable.
Rename/pin/archive use the same presentation owner as the TUI session picker.

Archive is reversible with `archived: false` and retains the journal. Permanent delete requires
`confirm_permanent_erasure: true`, refuses the resident thread, active writers and retained fork
ancestry/derivatives, and returns the existing durable erasure receipt. Permanent erasure has no
undo. Its receipt supports crash recovery; recovery does not restore erased conversation bytes.
Use archive when a session may need to be restored.

Export returns verified, scrubbed JSON for one physical journal. Fork ancestry remains explicit
in the genesis references. It refuses active writers, physical journals over 8 MiB, and export content
over 1 MiB. This does not claim a recursively flattened fork export. TUI history mutations use
the same controls: `/sessions rename RUN TITLE`, `archive RUN`, `unarchive RUN`, `pin RUN`,
`unpin RUN`, `read RUN`, `export RUN`, and `delete RUN permanently`.

## Client artifacts V1

Send `{"type":"artifacts_v1","command":{"type":"list","thread_id":"..."}}` or a
`read` command with the same thread ID, an `artifact_id`, `offset` and `max_bytes`. Read chunks
are base64 encoded and bounded to 64 KiB. `next_offset` and `eof` support paged download. A client
cannot supply a filesystem path or follow an artifact locator.

The resident catalog publishes scrubbed finalized answers, tool logs and structured file diffs from the public
event boundary. IDs are SHA-256 hashes of the retained bytes. Each descriptor declares the schema,
MIME type, retained byte count, ReadOnly requirement, source event and `complete` status. A
descriptor with `complete: false` is an explicitly truncated product; it is not a full log spill.
The catalog retains at most 128 entries and 4 MiB, with 256 KiB per entry. Eviction is counted,
missing handles are refused, and adoption clears the previous thread's handles. Retention is
resident-thread lifetime; this version does not promise restart recovery for these bytes.

The TUI's `/artifacts` lists this catalog with stable 12-character hash prefixes; `/artifacts HASH_PREFIX` opens the first 32 KiB with
terminal-safe text rendering. The same API supports the remaining download pages. Durable spill
downloads, external locator-backed screenshots/documents and general binary preview require
their respective private-content owners and remain separate work.
