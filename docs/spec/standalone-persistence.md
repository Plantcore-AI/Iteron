# Standalone persistence contract

This is the current standalone persistence contract as of 2026-10-18. It overrides the older per-event `fsync`, provider-turn synchronization, and mandatory pre-dispatch request-archive wording in the [microkernel specification](microkernel.md) and [typed ABI specification](abi.md). It describes acknowledgement and recovery semantics; performance acceptance remains subject to measurement.

## Acknowledgement and recovery

The effect broker still admits a stable effect identity and appends its `EffectIntent` before invoking the executor. A successful ordinary append means the complete framed record was written to the operating system and the writer advanced its sequence/hash head. It does not mean the device cache was flushed. A queued write without that acknowledgement does not authorize execution.

| Operation | Current acknowledgement |
|---|---|
| Ordinary journal event, including effect intent/terminal and provider `TurnEnd` | Complete OS write; no per-event forced disk synchronization. |
| Authoritative append following buffered observations | The observation prefix and authoritative event are written in order before the authoritative receipt returns. Merely accepting an observation into memory provides no committed sequence. |
| Final `EventKind::Done` | Complete journal append followed by `File::sync_data` on that journal. |
| Immutable encrypted content/key publication | Complete private temporary-file write and rename; ordinary publication does not force a device flush for each object. |
| Content reference/lineage metadata update | Complete checksummed compact-log frame written before its in-memory index advances. |
| Optional advisory job journal and route/token cache publication on Unix | Complete private OS writes and pinned atomic rename; no per-transition forced synchronization. Exact journal revisions, checksums, pending/unknown state, bounded close, and ordinary process-crash recovery still apply. Windows retains its existing snapshot-store behavior. |
| Explicit revocation, erasure, and durable maintenance operations | Retain their own existing authorization, locking, and synchronization requirements. The ordinary append policy does not relax them. |

An ordinary process crash leaves OS-managed writes available for recovery while the operating system and storage remain healthy. Reopen verifies the journal chain and its scoped content references; only an incomplete trailing record/frame may be discarded. A complete malformed record, checksum mismatch, unresolved required content, or invalid scope is an error. A failed write poisons the active journal writer until close and verified reopen establish its actual head.

Power failure, kernel failure, or storage failure can lose recently acknowledged journal or content writes. There is no per-event power-loss durability promise. `Done` synchronizes the journal; it does **not** synchronize every referenced content blob, key, metadata log, directory entry, cache, or diagnostic artifact as one atomic checkpoint. A readable `Done` record alone therefore does not establish whole-store recoverability after power loss.

Recovered effects whose execution outcome is unknown remain unknown and must not be replayed automatically. Missing records after an unsupported power-loss scenario do not prove that an external request or tool never executed. The recovery path must report the available evidence and any unresolved state.

The frozen event/ABI shapes and journal hash verification remain in force. Existing names containing `durable` refer to acknowledgement under the applicable persistence contract; they do not add an implicit per-event device-flush guarantee.

Ordinary append writes execute on the owning caller without a per-event thread round trip. Final journal synchronization uses the bounded writer worker. The private mutable write operation returns only after its receipt, so later direct writes cannot overtake queued synchronization. Both paths share the same descriptor, length validation, and poisoned state; close joins the worker and releases the writer lock before another owner may resume.

## Compact content metadata and compatibility

Content ciphertext, encryption keys, and revocation state retain their separate owners. Encryption keys are never copied into the append metadata log: retaining historical keys there would undermine erasure.

Reference and lineage changes use a tenant-scoped `metadata-v2.log`. Each frame contains the `ITMETA02` marker, a bounded payload length, a SHA-256 checksum, and path-scoped mutations. Complete frames are authoritative. An incomplete final frame is ignored by readers and truncated by an admitted writer before further append; a corrupt complete frame is rejected.

The in-memory index is a bounded projection of this log. Access remains covered by the actual content-store ownership locks. Readers refresh against the on-disk log before trusting cached state. Legacy reference/lineage JSON files are merged into the current view; logged replacements and deletion markers take precedence. Cache eviction and process restart must yield the same effective metadata.

Within one exclusive store lease, a pinned index can reuse its validated log descriptor and append cursor. The descriptor is closed before the lease releases its OS lock; subsequent acquisitions validate the physical log again. Compaction invalidates the descriptor. Missing cache-stamp information forces a fresh log replay, while optional post-write cache bookkeeping cannot turn a completed metadata commit into a reported uncommitted write.

Current hard limits are 16 MiB per frame, 512 MiB per log, 64 MiB per decoded index, and 500,000 index entries. At most four store indexes are retained in the process cache. Additional active stores can use a bounded temporary index rather than fail merely because the cache is full. Existing per-owner, reference, lineage, and content quotas still apply.

Each cached tenant index may additionally retain 128 scalar reference counts across run and content-digest directories. Counts track committed membership changes and are rebuilt after a legacy-directory change, log replacement, compaction, or eviction. Quota checks do not enumerate the growing reference history on each append. An exclusive metadata lease may retain bounded facts about absent physical legacy directories; these facts expire with that lease and are cleared by compaction. They never suppress a later lease's physical validation or the actual content/key authentication. Events without any private-content fields use the same envelope validation but do not open the content store merely to append or hydrate control/accounting state.

Before admitting compact metadata mutations, an exclusive store acquisition writes `metadata_format: 2` into the separate revocation state using its existing durable replacement path. Current readers accept an absent field for legacy stores and reject unsupported format values. Older implementations with a strict revocation-state decoder reject the additional field at that gate. A process crash between fencing and the first compact mutation may leave a fenced store containing only legacy metadata; the current reader still handles it.

This is forward read compatibility plus an explicit migration fence, not a supported downgrade path. Mixed old/new processes must not operate the same store. The fence covers operations that pass through the revocation-state gate; it is not a claim that every historical direct-cleanup API checks it. Do not remove the fence, delete the compact log, or run an older cleanup tool to make a migrated store appear compatible.

Compaction runs under the existing exclusive store lease. It writes a private snapshot in bounded frames, closes the complete write, and atomically replaces the log. Ordinary process interruption before replacement leaves the old log authoritative; interruption after replacement exposes the complete new snapshot. This replacement retains the same buffered power-loss limitations as ordinary compact metadata writes.

The snapshot keeps live entries and deletion markers still needed to suppress physical legacy files. It can discard deleted entries whose legacy files are absent and prune direct lookup entries whose corresponding reverse references are absent. Snapshot frames target at most 1 MiB. Reclaim is considered when the log reaches 8 MiB and exceeds four times the accounted index size, when at least 4,096 deleted entries occupy more than half the index, or before an append would exceed an index/log bound. An append that still exceeds the hard limits after compaction is rejected. These thresholds bound storage growth without requiring a whole-log rewrite on each update.

## Rebuildable projections

Session metadata, discovery indexes, statistics, and live-context views are projections of owned state. A missing, stale, malformed, or over-limit cache must not become authoritative merely because it is faster to read. Cache readers retain their bounded validation and replay/rebuild behavior.

The record owner maintains the current session projection incrementally. Its explicit refresh APIs can schedule or perform a bounded publication; pending discovery markers allow interrupted publication to be repaired. Publication coordination and OS leases retain their ownership rules. The continuation path does not require a fresh full-history replay solely to obtain session statistics.

An active writer retains the publication scope registered for its canonical directory and tenant. Nested activity windows reuse that registration while retaining the same foreground/publication exclusion. Provider-round continuation updates owned state without preparing or publishing a new session index on every round; invocation completion, terminal boundaries, and explicit refresh/read repair retain their publication responsibilities.

For an admitted live product turn, terminal effect status is a constant-size projection of actual effect-admission and settlement receipts, bound to its tenant, run, and starting sequence. Failed record writes or unmatched recovery state remain unavailable/unknown. Adoption resets this projection; callers without a matching live scope retain verified replay. One-shot command execution holds publication admission through the final policy record, then releases it before the record owner's close barrier. This coalesces terminal publications without delaying the ordinary resident AppServer's idle-session publication boundary.

Live context inspection uses the runtime's current captured state. Inspection availability and freshness must be reported honestly; a cached view cannot assert that an unobserved request included particular material. Actual serialized request inclusion remains a separate provider-boundary check.

Lifecycle diagnostics retain their bounded queues, event ordering, and explicit loss counters. Subscriber wakeups are coalesced when a queue becomes nonempty; already queued events do not require another producer wakeup. Multiple waiting consumers must still be woken correctly. Diagnostic subscribers do not acquire execution authority.

## Optional request archives

Standalone execution does not create complete diagnostic request archives by default. The effect journal retains the request's admitted effect/route identity and outcome. It does not retain an inspectable copy of every complete wire body. Enabling archives later cannot reconstruct bodies that were never captured.

Use `--archive-requests` when complete scrubbed request/material artifacts are needed for subsequent requests. Embedded hosts can use `Agent::set_request_archiving(true)`, inspect `Agent::request_archive_status()`, and call `Agent::flush_request_archive()` at a quiescent completion or inspection boundary.

Provider preparation still verifies the admitted output-token ceiling and observer ordering. Mailbox acknowledgement and memory/context inclusion use the actual serialized native request fields. They do not depend on successful diagnostic publication and do not claim socket delivery or remote model consumption. An adapter that cannot expose the required actual-body evidence cannot fabricate a mailbox inclusion acknowledgement.

Enabled archives reserve space in a per-agent deferred queue, capped at **64 requests and 64 MiB** of accounted body/scope data. The bound includes prepared captures awaiting dispatch, queued work, and the current publication. Queue admission never waits for artifact IO. A cancelled request prepared before cancellation may retain preparation evidence; no dispatch record is invented for it.

The archive is published sequentially at task completion, explicit flush, disable, or normal owner destruction. No archive worker publishes alongside active tool execution, because archive and tool artifacts can share content-store locks. The drain checks a 30-second budget before each bounded request job. An individual filesystem operation follows the store's IO behavior; the budget does not interrupt a system call already in progress. No detached archive worker survives a returned drain.

Queue saturation, contention, scope errors, publication errors, and drain-budget exhaustion leave diagnostic status incomplete. They do not turn an observed successful provider/tool effect into a failed effect. The explicit flush returns an error; task completion reports an archive notice; owner destruction has a fallback error report. Diagnostic status remains available through the live artifact-list response's `request_archive` field when an owner is bound.

| Status field/value | Meaning |
|---|---|
| `enabled` / `mode` | Whether capture is currently enabled; `compact_effect_journal` or `deferred_diagnostic`. |
| `availability: not_captured` | No diagnostic request has been submitted. |
| `availability: pending` | Captures await completion/publication. |
| `availability: drained` | Submitted diagnostic work has completed without a recorded archive error. |
| `availability: incomplete` | At least one diagnostic failure was recorded; retained successful artifacts may still be readable. |
| `submitted_requests`, `completed_requests`, `pending_requests`, `pending_bytes` | Bounded capture/publication progress. |
| `failed_captures`, `first_error_code` | Failure count and a closed, content-free diagnostic code. |

Previously retained request/body/material artifact schemas and reads remain supported. Newly retained bodies and source materials pass the existing scrubbers; raw endpoints are represented by commitments and authorization headers are excluded. Absence of a full archive is a capture-availability fact, not evidence that no request was sent.

## Boundaries and invariants

Affected boundary IDs: `record-core`, `record-sessions`, `context-core`, `provider-core`, `cli-host`, `observability`, `architecture-roadmap`, `documentation-site`, and `project-governance`.

Affected invariant overlays: `governance-enforcement`, `public-compatibility`, `tcb-authority`, `durability-replay`, `secrets-redaction`, `boundedness`, `provider-routing`, `frontend-contract`, `cost-accounting`, `eval-ground-truth`, `evolution-promotion`, `release-supply`, and `public-truth`.

The persistence change must preserve effect admission ordering, exclusive owner leases, tenant/run scoping, secret redaction, revocation checks, bounded work/memory, and conservative unknown-effect recovery. Optional diagnostics may be incomplete; they must not drop or acknowledge user mailbox input without actual inclusion evidence. Public inspection must distinguish missing capture, pending work, completed publication, and failure.

## Acceptance evidence

The latency target is no worse than Pi for the same host, physical disk, protocol, request/tool trace, and task outcome. Measurements must include complete process exit and any required drain. Inter-request gaps are useful diagnostics but are not a substitute for total elapsed time. Default and explicitly archived executions must be identified separately.

Acceptance also requires focused evidence for ordinary process restart, normal shutdown, cancellation, failed/torn writes, complete-frame corruption, old-store reads, the format fence, compaction, actual tool results, mailbox inclusion, and archive failure reporting. This document does not assert benchmark parity, test completion, power-loss survival, or support for an unverified platform.

Implementation anchors: [journal acknowledgement](../../crates/record/src/lib.rs), [append actor](../../crates/record/src/append_actor.rs), [content metadata](../../crates/record/src/content_store/metadata.rs), [content storage and format gate](../../crates/record/src/content_store/storage.rs), [metadata compaction](../../crates/record/src/content_store/metadata/snapshot.rs), [session projections](../../crates/record/src/session_maintenance.rs), [request observation](../../crates/cli/src/runtime/request_manifest.rs), [deferred archive](../../crates/cli/src/runtime/request_manifest/archive.rs), and [archive host API](../../crates/cli/src/runtime/request_manifest_runtime.rs).
