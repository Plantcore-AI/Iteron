# PlantCore contract inputs

These artifacts are public, deterministic implementation inputs for the PlantCore resident bridge.
They contain no credentials, session data, or deployment state.

The G1 v7 implementation is reviewed against `Plantcore-AI/plantcore-platform` commit
`df0ef637549ce4d69fab14379188785a72599ccb`. The content digests below identify the exact
implementation inputs without depending on that repository remaining at the same checkout:

| Upstream path | Raw file SHA-256 |
| --- | --- |
| `contracts/proto/plantcore/control/worker/v1/worker_control.proto` | `7655fab84407333a0b3b28d912b902690cf9ade1598a674bba8006e41f138b0d` |
| `contracts/worker-control-v1-semantics.md` | `030155b1ad3a0ad23e2b505f24a868f801a29bd07cfdcf481eb05be5c6b6122c` |
| `contracts/iteron-app-server-bridge-v1.md` | `a38fe151e997c2c91fd423372905c83a615b3028a0fd8991daf141850dd6c33b` |
| `contracts/schema/iteron-output-v7/target.schema.json` | `72e7188e425999f55367646d68f1a75b7c96f052ddeeb66feaaabe6f5a3a9d8a` |
| `contracts/schema/iteron-output-v7/README.md` | `44a9fe3d966efee65a7971e3eaa7f274f7fefc1d343e92e045339b854c72e62f` |
| `contracts/run-io-v1.md` | `fca7971a13078895c8da99aee49d56d90d5a0d2956a6b56f9ae02e3d69901737` |
| `contracts/run-pod-v1.md` | `33a86cdaca66e66b625ae714f88563f05ff09cdd0bccc57c5409297868febc74` |
| `e2e/recording/g1-v7/README.md` | `a3307b6431cad3b1dd52275ec5b5842ea5511bf9436064c2533923e3b052b77d` |
| `e2e/recording/g1-v7/scenarios.json` | `0584605abcceddd6ba6e7e3be1b41cd16e33a226318b6d925a52bd2891423b73` |
| `e2e/recording/g1-v7/recipes.json` | `43b5f6c7b83c64f6146622e076719ec4d02816b12b57ae845da2b870c477f66d` |
| `e2e/recording/g1-v7/actions.json` | `949300ac381ae0d1b28810377d97fd294b5210e9861fc8db1596b3678e85a7f7` |
| `e2e/recording/g1-v7/check.py` | `7eb2a3315317718c4654f6c166ad7c3d8e9dc036cc7e8acb29b5c4eb83711104` |
| `e2e/recording/g1-v7/fake-provider/scripts.json` | `1cefaef441ddd5fdfe9d360e37f59bb0d8cf9282efed529233e19d30448496e0` |
| `e2e/recording/g1-v7/fake-gateway/gateway-simulator` | `0361717045d84e9526b8c520c1840373be902a43719b01eb08f5b5f5582a62eb` |
| `e2e/vectors/portable-canonical-json-v1.json` | `7ce7683acb86d9c4b8248eab42c4b1b4d569a2ec64dc6b4f9072035234083bf4` |

The copied v7 schema has portable-canonical-JSON SHA-256
`83ef558efc9c72b375d9f981a73285831b1936ae1e547cef0a67d9ce1d6c30bc`. This parsed canonical
digest is the value used for output-schema admission. Release provenance separately hashes the raw
machine-contract sidecar bytes; the two digests are not interchangeable.

The machine contract declares the PlantCore capabilities implemented by this source tree. The G1
runtime capability set is supported on Linux. That declaration is implementation evidence, not release evidence: multi-architecture binaries, SBOM,
signature, provenance, Platform recording suites, Qwen smoke, and Worker-driven Cloud evidence
remain valid only after their external release workflows have actually produced and verified those
artifacts.

The reversible dispatch gate is resident-session-local. Iteron accepts
`pause_dispatch_after_safe_point` only after every already-issued Provider or MCP call reaches its
normal accounting boundary, and `resume_dispatch` only while that same session remains live and
paused. Control reconnect, the fixed 30-second window, durable outbox/ACK reconciliation, and the
timeout-triggered `drain` request remain Cloud Worker responsibilities.

`request_user_input` ends the source Run. A later answer starts a newly scheduled Run and Pod;
process-local agent state is not restored, repeated context may cost more, and work absent from the
durable conversation or declared artifacts can be lost. This is the accepted G1 limitation pending
a durable pause/resume contract.

The fixed workspace Hook enforces path policy for model-visible Iteron tools. Process-level
isolation remains a later hardening stage.

### Recording-only App Server fault ABI

Worker parser recordings may arm exactly one fixed malformed App Server sequence. The Cloud
recording harness creates one regular marker containing the exact bytes `enabled\n`:

`/run/plantcore/bridge/iteron.app-server-fault.<value>.enabled`

It then launches the otherwise normal resident process with `CONTROL_BRIDGE=1`,
`serve --plantcore`, `--recording-provider-ca-file <absolute PEM>`, and the hidden pair
`--recording-app-server-fault <value>`. The closed values are `raw-v7-at-limit`, `raw-v7-over-limit`,
`frame-chunk-missing`, `frame-chunk-out-of-order`, and `frame-chunk-conflict`. Iteron opens the
fixed marker without following symlinks, requires its exact eight-byte content, and removes it
before binding the listener. A missing gate, marker, or mismatched value fails startup.

After the authenticated hello, accepted PlantCore Run bootstrap, and parsed initial submission,
the selected fault is emitted once and that connection closes. `raw-v7-at-limit` sends one fixed
schema-valid 65,536-byte `recording_frame_boundary` event, an empty completed assistant stream, and
one successful terminal result. For `raw-v7-over-limit`, Iteron independently asserts that the
production canonicalizer rejects the fixed 65,537-byte counterpart, then the restricted fault seam
deliberately sends that same malformed object so the Worker boundary can reject it. The three chunk
faults start from one fixed rollout whose nested `ServerFrame::Rollout.event` compact JSON is exactly
1,048,577 bytes; its outer logical frame is naturally larger than 1 MiB. They use the production 512
KiB source-chunk framing: missing replaces the next chunk with a complete frame, out-of-order sends
ordinal 2 after ordinal 0, and conflict repeats ordinal 0 with different bytes. The Worker must reject
each malformed sequence as `APP_SERVER_PROTOCOL_ERROR`; these sequences are not successful engine
evidence. No arbitrary bytes, sizes, ordinals, paths, or repeated fault injection are accepted.

Staging-path recording remains on the model-visible tool path: the scripted Provider requests
`read_file` for the action's `relative_path`, and the real fixed workspace Hook returns the denied
tool result. No recording marker or App Server reply stands in for that Hook observation.

## Affected boundaries and invariant overlays

Affected boundary IDs: `protocol-compat`, `provider-core`, `cli-host`, `cli-tui`, `cli-output`,
`kernel-hooks`, `kernel-effects`, `tools-core`, `record-core`, `record-sessions`, `observability`,
`mcp-interop`, `language-server-lifecycle`, `workflow-engine`, `tunability-registry`,
`documentation-site`, `build-release`, and `project-governance`.

Invariant overlays retained: `governance-enforcement`, `public-compatibility`, `tcb-authority`,
`durability-replay`, `secrets-redaction`, `boundedness`, `provider-routing`, `frontend-contract`,
`cost-accounting`, `release-supply`, `eval-ground-truth`, `evolution-promotion`, and `public-truth`.
