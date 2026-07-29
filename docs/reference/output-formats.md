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

## Stdout and stderr

For machine formats, stdout remains JSON or JSONL; diagnostics are written to
stderr. Do not merge the two streams before parsing.

Model and tool text passes through output-boundary redaction. Streaming deltas use
a stateful scrubber so a credential-shaped token split across transport chunks is
not exposed merely because each chunk looked incomplete. This is defense in depth,
not permission to send secrets to a model or tool.
