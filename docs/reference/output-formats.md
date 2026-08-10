# Output formats

Machine output is available for one-shot runs and the bounded session operations below.

The current default is schema v5. A client that pins the retained v4 contract passes
`--output-schema-version 4` together with `--output-format json` or `stream-json`. On one-shot
task, continue, and resume operations this projects every stdout record onto the frozen v4 shape;
in particular, the v5-only `kernel_tax` terminal field and `input_attachment` stream record are
not emitted. Unsupported selectors fail before a rollout is opened.

`iteron --machine-contract` is a provider-free capability query. Its JSON reports
`cli_stream_versions`, `default_cli_stream_version`, and `resident_protocol_version` as distinct
values; a launcher must not infer the CLI stream version from the resident SQ/EQ protocol.

## Session operations

Schema-selected session operations use direct argv and emit one typed object:

- `--sessions [--session-limit N] [--session-cursor TOKEN] [--agent-definition-tag TAG]` emits
  `session_list_page { sessions, next_cursor }`;
- `--transcript RUN_ID [--transcript-cursor TOKEN]` emits
  `session_transcript_page { run_id, events, older_cursor }`;
- `--fork RUN_ID` emits
  `session_fork_result { parent_run_id, child_run_id, fork_point, status: "created" }`.

Cursors are opaque and bounded. List cursors are tied to their tenant and tag filter; transcript
cursors are tied to their run. A transcript is read newest-page first while events within each
page remain chronological. A stale, modified, or cross-query cursor is rejected rather than
returning a page with silent gaps or duplicates.

`--agent-definition-tag` is immutable grouping metadata: at most 128 UTF-8 bytes, non-blank,
control-free, and rejected when it resembles a credential. A fresh run records it, resume may
only repeat the recorded value, forks inherit it, and legacy untagged sessions remain readable.

## Final result

Both `json` and `stream-json` end with an authoritative result object:

```json
{
  "schema_version": 5,
  "type": "result",
  "outcome": "done",
  "reason": null,
  "success": true,
  "assistant_text": "...",
  "run_id": "...",
  "cost_usd": null,
  "cost_status": "...",
  "cost_reason": null,
  "turns": 1,
  "kernel_tax": {
    "admission_latency_us": 0,
    "broker_latency_us": 0,
    "record_fsync_latency_us": 0,
    "estimated_tokens": 0,
    "failed_runs": 0
  },
  "exit_code": 0,
  "error": null
}
```

The example shows shape, not guaranteed values. `cost_usd` can be null or unknown
when no authoritative price evidence exists. Schema v5 requires the typed
`kernel_tax` object; its latency values are measured in microseconds and all five
fields are non-negative integers.

Schema v4 introduced the terminal `outcome` value `drained`, which schema v5
retains: it means the runtime stopped cleanly after quiescing admitted work and
durably checkpointing the workspace. It has `success: true` and exit code `0`,
but remains distinct from ordinary `done`.

## Stream event vocabulary

`stream-json` may emit:

- `assistant_text` and `thinking` deltas;
- `input_attachment` metadata before a multimodal SQ submission;
- `phase` and `turn_end` lifecycle events;
- `tool_start`, `tool_end`, and `approval_request`;
- `notice`, `steer_applied`, and `run_done`;
- `workflow_start`, `workflow_plan`, `workflow_phase`;
- `workflow_agent_start`, `workflow_agent_activity`, `workflow_agent_end`;
- `workflow_end`;
- the terminal `result`.

Every event carries `schema_version`. Consumers should ignore unknown event types
they do not need and use the final result as the authoritative terminal outcome.
`input_attachment` carries only `ordinal`, `media_type`, and `encoded_bytes`; it
never carries image bytes, a filename, or a path. Historical v4 event fixtures
and their terminal result remain unchanged; consumers should skip this v5 tag
when they do not need attachment metadata.

## Run-declared artifacts

A run can declare a product it made: a report, a table, a diff. Before this
existed the only way to learn that a run had produced something was to parse the
assistant's prose, so every consumer invented its own convention and none of
them could be verified.

The declaration is a handle, never inline content, because the evolution
registry has to be able to verify what it holds. The handle carries everything a
consumer needs to store, list and reopen the product later:

| what | where it comes from |
|------|---------------------|
| the ref and its content address | `artifact.hash` |
| its kind | `artifact.schema` |
| its producing turn | the enclosing event's `turn` |
| the tool or effect that made it | `artifact.producer`, `artifact.provenance.effect_id` |
| where it lives | `artifact.locator` |

Two rules the producer path enforces rather than documents.

**The content lands before the event does.** Admission takes a durability
witness and refuses without one, so a handle never names content that is not yet
readable. An event that preceded its write would hand a consumer a handle to
nothing.

**Exceeding the per-run ceiling is counted, never silently dropped.** A run may
declare at most 256 artifacts; beyond that a declaration is refused *and*
tallied, because a product stream that quietly stops is indistinguishable from a
run that stopped producing. A duplicate content address is refused the same way,
so a product gets exactly one event.

On the durable record this is `artifact_produced`, appended under abi.md
§4.3(b)2: every byte already on disk decodes unchanged, so `PROTOCOL_VERSION`
does not bump for it. The content address is preserved through redaction —
masking it would make the product unfindable — while the locator, being a path,
is scrubbed.

## Stdout and stderr

For machine formats, stdout remains JSON or JSONL; diagnostics are written to
stderr. Do not merge the two streams before parsing.

Model and tool text passes through output-boundary redaction. Streaming deltas use
a stateful scrubber so a credential-shaped token split across transport chunks is
not exposed merely because each chunk looked incomplete. This is defense in depth,
not permission to send secrets to a model or tool.
