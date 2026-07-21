# Output formats

Machine output is available only in one-shot operation.

## Final result

Both `json` and `stream-json` end with an authoritative result object:

```json
{
  "schema_version": 4,
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
  "exit_code": 0,
  "error": null
}
```

The example shows shape, not guaranteed values. `cost_usd` can be null or unknown
when no authoritative price evidence exists.

Schema v4 adds the terminal `outcome` value `drained`: it means the runtime stopped
cleanly after quiescing admitted work and durably checkpointing the workspace. It
has `success: true` and exit code `0`, but remains distinct from ordinary `done`.

## Stream event vocabulary

`stream-json` may emit:

- `assistant_text` and `thinking` deltas;
- `phase` and `turn_end` lifecycle events;
- `tool_start`, `tool_end`, and `approval_request`;
- `notice`, `steer_applied`, and `run_done`;
- `workflow_start`, `workflow_plan`, `workflow_phase`;
- `workflow_agent_start`, `workflow_agent_activity`, `workflow_agent_end`;
- `workflow_end`;
- the terminal `result`.

Every event carries `schema_version`. Consumers should ignore unknown event types
they do not need and use the final result as the authoritative terminal outcome.

## Stdout and stderr

For machine formats, stdout remains JSON or JSONL; diagnostics are written to
stderr. Do not merge the two streams before parsing.

Model and tool text passes through output-boundary redaction. Streaming deltas use
a stateful scrubber so a credential-shaped token split across transport chunks is
not exposed merely because each chunk looked incomplete. This is defense in depth,
not permission to send secrets to a model or tool.
