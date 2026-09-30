# Frontend owners and directions

Frontends receive an attached client, queue endpoints and immutable session facts. They do not
receive the runtime Agent or manufacture durable completion from terminal cells. This map records
actual source responsibilities; final compile, semantic rendering, TCP and native terminal evidence
remain required.

| Source | Actual state owner | Inputs and outputs |
| --- | --- | --- |
| `machine_projection.rs` and its `v7` child | Actual shared schema compatibility and streaming scrubber state | Immutable runtime facts → scrubbed bounded machine values; no CLI format/options, physical IO, server or TUI dependency |
| `output.rs` | One-shot CLI stdout format and physical emitter | Shared machine values → selected stdout framing/flush and bounded stderr notices |
| `app_server/session_host.rs` | Resident Agent and idle/running session lifetime | Authenticated typed commands → actual runtime operation; immutable events/replies leave the owner |
| `app_server/session_services.rs` | Captured actual controller/workflow/process/MCP/verifier/read ports | Same real owner handles refresh at adoption; shared activity scope leases prevent stale mutation |
| `app_server/turn_pump.rs` | Borrowed turn future and disjoint frontend channels | Fair runtime/control/event polling; no mutable Agent aggregate |
| `app_server/presentation.rs` and product/publication readers | Shared bounded immutable projection | Actual source events/receipts → snapshots; views do not grant permissions |
| `tui/session_client.rs` | Client handle, negotiated version and immutable current session facts | Public typed controls and queue submissions; no runtime ownership |
| `tui/driver.rs` | Terminal/input/event loop and bounded worker coordination | Client events + terminal input → view changes or typed client commands |
| `tui/input_lanes.rs` | Single private after-turn/steer queue and exact local submission ownership | Owned inputs preserve words/chips; read-only lane views; exact receipt reconciliation never resubmits another identified client |
| `tui/input_dispatch.rs` | Borrowed editor/view/key routing context | Input events → explicit local effects or shared client controls |
| `tui/terminal_lifecycle.rs` and `terminal_input.rs` | Physical terminal mode restoration and bounded input producer | Native terminal IO → input events; restoration on actual shutdown |
| `tui/transcript_effect.rs` | Independent local shell/clipboard/export effect lifetime | Explicit request → bounded state/result; never model admission or parent terminal truth |
| `tui/frame_render.rs`, `composer_render.rs`, `status_render.rs` | Effect-free rendered view | Immutable TUI state → terminal cells; no record, provider or runtime queries during paint |
| `tui/headless.rs` | Loopback listener, aggregate quotas, dense presentation ring and source event pump | Actual EQ → bounded encoded retained frames; independent observations keep their own source revisions |
| `tui/headless/connection.rs` | One actual socket, immutable negotiated authority, replay cursor, pending reply and subscriptions | Disjoint authenticated source/frame ports → physical connection delivery; fair live selection and bounded publication drain |
| `tui/headless/commands.rs` | Run-local bounded recording command map and captured gate/SQ ports | Exact command identity → cached receipt; reply delivery precedes actual resume activation |
| `tui/headless/input.rs`, `auth.rs`, `framing.rs` | Input bytes/permits, bearer zeroization and bounded encoding/replay leases | Untrusted physical frames → parsed commands only after handshake; byte permits follow actual work |

The connection owner cannot access the listener's mutable aggregate. Its source references are
explicit borrowed ports to the same queues, ring, client and command owner. Incoming parse work
retains the frame permit until SQ admission or refusal. Negotiated observer access never upgrades
when a later frame uses a newer version. Subscribe captures before the current-source snapshot;
publications and maintenance cannot create holes in the frozen legacy replay cursor.

## Remaining TUI architecture work

The `App` aggregate still owns transcript geometry, live assistant reduction, editor state, modal/worker state and activity views. Existing `impl App` child files are implementation
fragments and are not evidence of independent domain ownership. The event/input driver coordinates
these frontend-only domains and never holds the runtime Agent, but narrowing their private state and
mutation ports remains part of the architecture work. Production wildcard imports in older TUI
fragments also need explicit assembly boundaries. File length alone does not close these gaps.

The final candidate must execute ordinary input/steer/queue/approval, actual server terminal
reconciliation, session adoption, rendering, native terminal cleanup and independent-client
reconnect/backpressure journeys. A physical scripted W3C fixture verifies browser protocol IO and
actual screenshot correlation; it is not native ChromeDriver or OS desktop evidence.
