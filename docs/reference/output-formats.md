# Output formats

Machine output is available only in one-shot operation.

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
