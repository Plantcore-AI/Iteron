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

## Answer and finalization observations V1

Send `{"type":"turn_publications_v1","command":{"type":"read","thread_id":"..."}}`.
The reply contains a current-run snapshot of up to 256 recent content-free facts. Recovery is
labelled `verified_record`, `unavailable` or `live_only`; the snapshot is bounded recent history.
An exact authenticated thread mismatch is refused. The TUI reads this same snapshot through
`/finalization`.

`answer_available` names the earlier committed assistant Message after an actual final non-tool
EndTurn. It does not claim the terminal succeeded, that every streamed byte was delivered, or
that background maintenance finished. `turn_finalized` names the existing committed Done
sequence and carries the closed runtime outcome and optional budget limit. Runtime turn IDs
start at zero and are distinct from user-facing Product turn IDs. Their `source_seq` values are
record sequences, independent of the transport replay cursor.

Use `"type":"subscribe"` in that same command to opt into separate `turn_publication_v1`
frames. The Subscribe reply is the recovery snapshot; deduplicate overlap by current run and
record source sequence. The optional stream uses a 64-entry queue. A `turn_publication_gap`
requires another Read to reconcile; it is never treated as successful delivery. These frames
do not change the frozen legacy event/result cursor, and clients receive them only after an
explicit subscription. RunEnded/result remains the separate resident input-readiness boundary.

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

## Persistent agent controls V1

Send `{"type":"agents_v1","command":{...}}`. `enable` requests bounded capabilities, budgets,
agent/mailbox capacities and parallelism. It contains no workspace path, actor identity or recovery
evidence. The host derives its scope from the actual recorded owner and validates the requested
envelope against immutable authority and current parent budgets. Ordinary sessions allocate no
persistent controller until this explicit idle-boundary operation succeeds.

`command` carries an exact `request_id` and the existing typed Spawn/SendMessage/FollowupTask/
Steer/Interrupt/Close vocabulary. Other commands are `list`, `inspect`, `message_receipt` and
`wait` (1–60,000 ms). The server binds authenticated ordinary control requests to Operator;
model tools bind their own host AgentId. JSON cannot supply either authority. At most eight
public controller operations are pending at once. Reads and controls remain usable while the
parent turn is running; a bounded wait does not pause that parent turn. Observers can issue
only the read commands.

Acceptance receipts, mailbox delivery and provider request inclusion remain separate. `consumed`
means the host included a message in a provider request, without claiming model comprehension.
Steer/Interrupt target an exact incarnation/turn epoch; stale epochs are refused. Only host effect
reconciliation can release RecoveryRequired executions.

The TUI keeps `/agents` and `/agents definitions` for the pinned definition catalog. Live commands
use `/agents live`, `enable TURNS TOKENS USD WALL_SECONDS`, `spawn PARENT TASK`, `inspect ID`,
`send ID TEXT`, `followup ID TEXT`, `steer ID TEXT`, `interrupt ID`, `close ID [tree]`, `receipt ID`
and `wait [REVISION] [MS]`. Spawn defaults to one read-only investigator turn inside the observed
parent envelope; the host may refuse exhausted reservations. Inspect shows actual state and the
latest bounded summary. Steering and interruption use the latest epoch observed in that view.

## Captured inventory and model selection V1

`inventory_v1` accepts a bounded query with `kind`, optional model `provider_id`, `offset` and
`limit` (1–100). Kinds cover overview, providers, models, verified plugins, installed tools,
hook event counts, pinned agents, captured skill metadata, effective checkpoint and permissions.
Responses declare provenance, availability, total and next offset. Missing skill metadata before
the context owner captures it, legacy V1 value reconstruction, and missing bootstrap evidence
remain explicitly unavailable. Reads do not discover mutable configuration, skill or package files.

Provider/model records come from the immutable bootstrap catalog and declare stale/unavailable
evidence and actual captured capability limits. Plugin identity is the verified parsed manifest's
serde JSON SHA-256 (`parsed_manifest_serde_json_sha256_v1`), with version and surfaces actually
materialized; this digest does not claim to hash raw package bytes. Hook commands, credentials,
provider endpoints, package paths, prompts and skill bodies are excluded from these inventories.
Effective config pages project the real sealed runtime checkpoint. Tool declared gates are
informative: actual dispatch also intersects the task envelope and operation requirements.

`select_model_v1` requires provider/model and exact inventory, catalog and capability digests.
The trusted captured owner resolves the actual provider handle and applies the shared durable
model-selection transaction. Stale, absent or mismatched routes are refused. Observation-only
connections may read inventory but cannot select a model. The TUI's `/config KIND [OFFSET]`
and `/skills` use this same projection; `/model` sends typed identities to the host.

## Live workflow V1

The `live_workflow_v1` control carries a strict `command` tagged request: `open`, `read`,
`replan`, `pump`, `interrupt` or `reconcile`. Each request names a bounded `workflow_id`;
replan also carries `request_id` and the typed `WorkflowReplanV1` plan. Interrupt and reconcile
name the actual node ID. Only read is available to observation-only connections. Requests cannot
carry host paths, budgets, actors, terminal claims or completion/recovery evidence.

The real session owner mints graph ceilings from verified persistent-agent host limits and uses
a private rollout scope, retained scheduler journal, actual controller leases and host completion
proofs. Enable persistent agents first. After restart an operator must open the graph before
observers read it; a read cannot create state, repair a journal or start the driver. Responses
carry an immutable view with graph revision, sequence, nodes, ready IDs, reservations, deadline,
driver error and an optional durable plan receipt. Eight public dispatch permits bound concurrent
requests. Admitted owner operations finish if a transport connection stops waiting.

Use `/workflows live open|read|pump ID`, `interrupt|reconcile ID NODE`, or
`replan ID REQUEST_ID JSON`. The TUI renders actual typed graph state and driver failure without
changing the snapshot. `/workflows` retains the existing supervised-workflow inventory.

## Client artifacts V1

Send `{"type":"artifacts_v1","command":{"type":"list","thread_id":"..."}}` or a
`read` command with the same thread ID, an `artifact_id`, `offset` and `max_bytes`. Read chunks
are base64 encoded and bounded to 64 KiB. `next_offset` and `eof` support paged download. A client
cannot supply a filesystem path or follow an artifact locator.

Trusted runtime producers can publish complete text to the retained owner manifest before preview
truncation. Publication scrubs the full text, hashes the bytes actually served, and registers real
private-content source lineage. The index is scoped to the recorded tenant/run and canonical
workspace. Downloads reopen and verify the content graph, so source revocation and session
erasure revoke these artifacts as well. Each item is at most 8 MiB; one owner retains at most
256 entries and 64 MiB. Eviction first durably removes the catalog entry, then releases the exact
content reference. Prepared publications and release intents recover on the next trusted producer
call; incomplete publications are never listed. Publication errors can report an unknown outcome.
The same ID and byte offsets support downloads after a server restart when that recorded owner
is adopted again. Windows manifest publication uses the private local NTFS adapter; unsupported
filesystems are refused.

The compatibility resident catalog publishes scrubbed finalized answers, tool logs and structured file diffs from the public
event boundary. IDs are SHA-256 hashes of the retained bytes. Each descriptor declares the schema,
MIME type, retained byte count, ReadOnly requirement, source event and `complete` status. A
descriptor with `complete: false` is an explicitly truncated product; it is not a full log spill.
The catalog retains at most 128 entries and 4 MiB, with 256 KiB per entry. Eviction is counted,
missing handles are refused, and adoption clears the previous thread's handles. Retention is
resident-thread lifetime. These fallback bytes do not survive server restart.

The shared public list merges both owners and returns `resident_artifact_ids` for fallback entries.
Read replies identify `retained_owner_manifest` or `resident_public_event` provenance. Retained
complete bytes take priority over a resident preview with the same ID. Session erasure returns
any pending presentation/index cleanup separately from its verified content-erasure receipt.

The TUI's `/artifacts` lists this catalog with stable 12-character hash prefixes; `/artifacts HASH_PREFIX` opens the first 32 KiB with
terminal-safe text rendering. The same API supports the remaining download pages. General
binary publication and external screenshots/documents require typed safe producer ownership;
clients cannot turn an external locator into a retained public artifact.
