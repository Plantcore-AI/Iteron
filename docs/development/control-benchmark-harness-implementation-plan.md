# Control, benchmark, tunables, and trainable-harness implementation plan

Status: proposed implementation plan
Execution order: plan 1 of 2
Companion: [Hooks, OpenTelemetry, memory, and context observability implementation plan](observability-memory-context-implementation-plan.md)

## 1. Outcome

Implement an Iteron runtime whose interactive control path is as deterministic and responsive as the
Codex control model, whose effective prompt/context/memory/budget settings come from one runtime
truth, and whose SWE-bench Pro and Terminal-Bench 2.1 results can support a defensible trainable
harness paper.

This plan is complete when all of the following are true:

1. Every submitted prompt has a stable identity and an acknowledged state transition.
2. First `Ctrl-C` cancels the active turn immediately; a bounded second action force-cancels it.
3. Turn cancellation, draining the session, cleaning background terminals, and quitting are four
   different operations.
4. Foreground commands and all of their descendants are reaped after cancellation; background
   terminals survive until the operator explicitly stops them.
5. Runtime-effective tunables, their provenance, and their immutable run snapshot are generated
   from one typed source of truth.
6. Interactive, benchmark, and research profiles have different, explicit defaults.
7. Prompt, context, memory, and tool-catalog choices are bounded and attributable.
8. Iteron can run the pinned SWE-bench Pro corpus and Terminal-Bench 2.1 through real scoring paths,
   not only adapter fixtures.
9. Benchmark tasks cannot share memory, workspace state, credentials, or learned policy state.
10. The trainable harness optimizes a small typed policy over a byte-identical frozen safety
    kernel; safety, authority, durability, and effect semantics remain non-trainable.

## 2. Scope and boundary declaration

The implementation affects these registered boundaries:

| Boundary | Risk | Why it changes |
| --- | --- | --- |
| `protocol-compat` | critical | submission identity, control operations, acknowledgements, lifecycle evidence |
| `kernel-reduction` | critical | pure turn/control state transitions |
| `kernel-runtime` | critical | task ownership, cancellation tokens, safe terminal outcomes |
| `kernel-effects` | critical | cancellation of admitted effects without unsafe retry |
| `cli-host` | critical | app-server actor, trusted configuration, runtime profiles |
| `cli-tui` | elevated | composer, queue, `Ctrl-C`, `Esc`, drain, job UX |
| `tools-execution` | critical | process-group termination and confirmed reap |
| `provider-core` / `provider-adapters` | elevated | provider cancellation, usage and tokenizer truth |
| `scheduler` | elevated | retries, concurrency, deadlines |
| `context-core` | elevated | assembly, compaction, context budgets |
| `context-knowledge` | elevated | memory scope, recall and benchmark isolation |
| `record-core` / `record-sessions` | critical/elevated | command acknowledgements, immutable run snapshots, replay |
| `tunability-registry` | elevated | live/fixed/missing classifications and generated runtime bindings |
| `workflow-engine` / `agent-orchestration` | elevated | bounded fan-out and cancellation propagation |
| `evaluation` | elevated | benchmark execution and evidence bundles |
| `evolution-control` | critical | offline training and promotion only |
| `observability` | elevated | usage/cost/control measurements consumed by evaluation |

Invariant overlays that must remain true:

- `append-only-record`
- `hash-chain`
- `intent-execute-terminal`
- `unknown-effect-block`
- `bounded-queues`
- `bounded-run`
- `single-writer`
- `trusted-config-precedence`
- `bounded-retry`
- `bounded-concurrency`
- `memory-provenance`
- `bounded-recall`
- `compaction-policy`
- `fixed-model-comparison`
- `honest-quality-claim`
- `no-runtime-activation`
- `fixed-invariant-nontrainability`

Any PR crossing more than one critical boundary must name the human maintainers responsible for
those boundaries before implementation begins.

## 3. Current facts and hypotheses

### 3.1 Benchmark state

- The repository pins a schema-v2 SWE-bench Pro OS corpus under
  `crates/eval/corpora/swe-bench-pro-os-ca10a60-slice-v2.json`.
- The Harbor adapter pins Terminal-Bench 2.1, 89 tasks, at least five attempts per task, and a
  sample `max_turns: 250`, `max_wall_secs: 12000` profile.
- The Terminal-Bench adapter explicitly says fixture success is not a benchmark score.
- Shell egress is currently disabled even though the pinned Terminal-Bench tasks permit internet
  access.
- Provider sampling seed is not controlled.
- The production CLI has no live policy-bundle selection matching the adapter's intended trained
  arm.
- An older, separate evaluation harness recorded SWE-bench Pro `0/4` and Terminal-Bench `8/24`.
  Those are warnings and priors, not Iteron benchmark results.

Engineering priors to replace with measurements:

| Configuration | SWE-bench Pro solve-rate prior | Terminal-Bench 2.1 solve-rate prior |
| --- | ---: | ---: |
| current open/default-model path | 0-5% | 10-25% |
| strong reference model with adapter fixes | 5-15% | 20-40% |

These ranges are not release claims. The first full evidence bundle with confidence intervals
supersedes them.

### 3.2 Runtime/default drift

The semantic registry contains 160 families:

- provider 18
- reasoning 7
- budget 5
- context 24
- memory 6
- tooling 24
- verification 17
- orchestration 32
- runtime 6
- extensibility 13
- observability 1
- governance 7

Registry status is 30 `full`, 51 `partial`, 26 `missing`, and 53 `fixed_hidden`. The registry is a
pure resolver and does not currently bind the runtime. Therefore 160 families do not mean 160
effective knobs.

Known contradictions:

| Setting | Registry/documented default | Runtime default or behavior |
| --- | ---: | ---: |
| `max_turns` | 40 | 600 |
| `max_wall_secs` | 1,800 | 14,400 |
| `memory_enable` | false | workspace memory is wired unconditionally |
| `max_usd` | optional | none |
| `max_tokens` | optional | none unless supplied on CLI |
| consecutive tool errors | not a first-class visible default | 25 |

The operator-facing configuration currently exposes approximately 20 top-level functional fields
plus CLI-only `max_tokens`: model/provider/routing, turn/time/cost ceilings, code/egress authority,
compaction, retry, notifications, prompt history, keymap/editor, effort, rate cards, policy bundle,
MCP and hooks. Nested provider, retry, MCP and keymap structures add fields, but they are not a
5-10x larger live control surface than Codex or Claude Code.

### 3.3 Context and memory state

- A measured nine-token task paid 3,671 prompt tokens; 2,730 were tool schemas.
- Tool schemas are filtered primarily by permission, not by relevance to the current task.
- The fallback compaction trigger is 120k estimated tokens; the normal recent tail is 25% of
  model-usable context, clamped to 2k..15k tokens rather than a fixed six messages.
- With provider metadata, the hard trigger is the usable context boundary; proactive end-of-turn
  compaction can therefore start near 60% of usable context.
- Token estimation uses a byte heuristic, not the provider tokenizer.
- Default memory component budgets are 25k index bytes, 16k recall bytes, 8k instruction bytes and
  a nominal 49k total.
- Same-session memory becomes visible on the next exact boundary notification, which is the right
  cache-stable direction and must be preserved.
- Benchmark workers must not use persistent cross-task memory.

### 3.4 Control-path state

- Plain text during a turn can steer; structured attachment submissions cannot steer and are
  queued.
- SQ admission is treated as user-visible acceptance without a stable submitted/received/applied
  identity.
- First `Ctrl-C` sets cooperative interruption; second `Ctrl-C` escalates to `Drain`.
- `Drain` requires a Git worktree even when the user only wants work to stop.
- Interrupt and drain are checked at bounded safe points, but a hanging provider/tool/hook can
  still make the TUI appear frozen.
- Direct shell execution already uses process groups in important paths. The missing part is one
  consistent ownership and reap contract across foreground jobs, background terminals, MCP,
  hooks, providers and workflows.

### 3.5 Codex behavior to adopt

Use the locally installed Codex 0.146.1 tag `rust-v0.146.1` as the pinned behavioral reference:

- each `Submission` has a unique `id`, optional client message ID and W3C trace carrier;
- `Interrupt` aborts the active task without killing background terminals;
- `CleanBackgroundTerminals` is separate;
- active-turn steering preserves structured pending input;
- task cancellation uses a cancellation token, waits 100 ms for cooperative completion and then
  aborts the task;
- foreground process cancellation sends `SIGTERM` to the process group, waits 50 ms, then sends
  `SIGKILL` and reaps;
- rejected or interrupted queued text is restored to the composer/queue.

Pinned references:

- `codex-rs/protocol/src/protocol.rs`
- `codex-rs/core/src/tasks/mod.rs`
- `codex-rs/core/src/exec.rs`
- `codex-rs/tui/src/chatwidget.rs`

Copy the state-machine idea and terminal semantics. Do not copy source text or internal names
blindly; Iteron's durable record and effect ledger remain authoritative.

## 4. Target architecture

```text
TUI / headless / app client
        |
        | SubmissionEnvelope(id, client_message_id, trace, op)
        v
bounded data SQ -----------------------+
                                       |
priority control lane ---------------->| SessionActor
                                       |   owns resident Agent
                                       |   owns active TurnTask handle
                                       |   owns pending structured inputs
                                       +----------+
                                                  |
                                             TurnTask
                                       CancellationToken tree
                                    provider/tool/workflow children
                                                  |
                                    foreground ProcessGroupOwner
                                                  |
                              TERM -> bounded grace -> KILL -> reap

Durable record: command admission, state decisions, terminal outcomes
EQ: acknowledged live projection keyed by submission id
OTel/hooks: projections from lifecycle evidence, never control-path authority
```

### 4.1 New protocol concepts

Add these versioned protocol types, keeping historical `Op` tags readable:

```rust
struct SubmissionEnvelope {
    protocol_version: u32,
    submission_id: ClientSubmissionId,
    client_message_id: Option<String>,
    trace: Option<W3cTraceContext>,
    op: Op,
}

enum ControlOp {
    CancelTurn { expected_turn: Option<TurnId> },
    ForceCancelTurn { expected_turn: Option<TurnId> },
    DrainSession { checkpoint: CheckpointPreference },
    CleanBackgroundTerminals,
    QuitFrontend,
}

enum SubmissionState {
    Received,
    Admitted { turn: Option<TurnId> },
    Applied { turn: TurnId, durable_seq: Seq },
    Requeued { reason: RequeueReason },
    Rejected { reason: SubmissionRejectionReason },
}
```

`ClientSubmissionId` must be globally unique per client process and opaque on the wire. Do not
reuse durable numeric `SubmissionId`, which already identifies approvals/effect decisions.

### 4.2 Turn ownership

`SessionActor` owns the mutable resident `Agent`. Starting a turn creates a separately owned
`TurnTask` with:

- immutable turn input;
- `TurnId` and initiating submission ID;
- root cancellation token;
- child tokens for provider, tools, workflow and verification;
- pending structured steer queue;
- foreground effect/process ownership;
- terminal oneshot returning `TurnTerminal`.

The app server must not hold `&mut Agent` across the entire turn. It continues servicing control,
job and queue requests while the turn task runs.

### 4.3 Cancellation contract

1. First `Ctrl-C` or active-run `Esc` sends `CancelTurn` on the priority lane.
2. The TUI immediately renders `cancelling…` without claiming completion.
3. `SessionActor` cancels the root token and acknowledges `Received`.
4. Provider streams, tool futures, workflow children and verifier loops observe the token.
5. Foreground process owner sends process-group `SIGTERM`.
6. After a 50 ms process grace, still-running groups receive `SIGKILL` and are reaped.
7. The turn task gets up to 100 ms to produce a cooperative terminal.
8. After that, the actor aborts the task handle and writes an `Interrupted` terminal record.
9. Unapplied structured steer/input is requeued by submission ID.
10. Background terminals remain alive.

A second `Ctrl-C` while state is `Cancelling` sends `ForceCancelTurn`. It never means drain.

### 4.4 Drain contract

`DrainSession` means:

- stop admitting new turns immediately;
- cancel the active turn using the same bounded cancellation contract;
- close or requeue unadmitted submissions with explicit acknowledgements;
- sync the durable journal;
- attempt a workspace checkpoint if supported and requested;
- return `Drained` even when no Git checkpoint exists;
- report checkpoint success/failure separately from stopping work.

If product still needs “finish current safe operation and checkpoint”, name it
`CheckpointAndStop`; do not overload `DrainSession`.

## 5. Executable work breakdown

Each slice below should be one reviewable PR unless the boundary owners explicitly combine it.

### A0. Freeze the baseline and add characterization tests

Files:

- `crates/cli/tests/tui_pty.rs`
- `crates/cli/src/tui/tests.rs`
- `crates/cli/src/runtime/tests.rs`
- `crates/tools/src/process/tests.rs`
- `crates/eval/harbor/README.md`

Tasks:

1. Add PTY tests that record current first/second `Ctrl-C`, active `Esc`, `Ctrl-D`, SQ-full and
   non-Git drain behavior.
2. Add a hanging provider fixture that never yields after request admission.
3. Add a shell fixture that ignores `SIGTERM` and spawns a descendant that also ignores it.
4. Add hanging MCP and hanging hook fixtures.
5. Add tests for text steer, image/file steer, slash command queue and post-interrupt queue restore.
6. Record current key-to-terminal latency distributions as diagnostic evidence, not acceptance.

Exit evidence:

- every known bad behavior has a deterministic red characterization test;
- no test depends on wall-clock sleeps longer than the bounded cancellation windows;
- fixtures clean all descendants after themselves.

### A1. Add submission identity and acknowledgements

Files:

- split `Op`/envelopes from `crates/protocol/src/lib.rs` into
  `crates/protocol/src/submission.rs`;
- add `crates/protocol/src/control.rs` and `crates/protocol/src/ack.rs`;
- `crates/protocol/src/wire.rs`;
- `crates/cli/src/app_server.rs` and `crates/cli/src/app_server/*`;
- `crates/cli/src/tui/submission.rs`;
- `crates/cli/src/tui/app_input_state.rs`.

Tasks:

1. Introduce `ClientSubmissionId` without changing existing approval `SubmissionId` semantics.
2. Wrap every SQ operation in `SubmissionEnvelope`.
3. Add EQ acknowledgements for received/admitted/applied/requeued/rejected.
4. Store TUI optimistic rows keyed by submission ID rather than by queue count.
5. Clear the composer only after `Received`; mark the user transcript durable only after
   `Applied`.
6. Preserve image/file/tag/chip payloads in pending and requeued submissions.
7. Add compatibility tests for legacy wire `Op` decoding and new-reader/old-reader degradation.
8. Add bounded retention for completed acknowledgement state.

Acceptance:

- no submitted input can disappear without one terminal acknowledgement;
- duplicate acknowledgements are idempotent;
- reconnect/replay cannot confuse EQ sequence with durable record sequence;
- queue-full never renders an accepted user transcript row.

### A2. Introduce the session actor and priority control lane

Files:

- add `crates/cli/src/app_server/session_actor.rs`;
- add `crates/cli/src/app_server/control_lane.rs`;
- add `crates/cli/src/app_server/turn_task.rs`;
- refactor `crates/cli/src/app_server.rs` and `app_server/control.rs`;
- add pure state transitions under `crates/kernel/src/turn_control.rs` and tests.

Tasks:

1. Define pure `Idle`, `Running`, `Cancelling`, `Draining`, `Stopped` actor states.
2. Move long-running turn execution out of the resident-agent mutable borrow.
3. Keep data SQ bounded; create a separate bounded priority control lane.
4. Retain atomic cancellation as an emergency wake-up, but require every action to acquire a
   typed control epoch and eventually write evidence.
5. Reject stale control operations using expected turn ID/control epoch.
6. Service job inventory/stop, workflow cancel and turn cancel during provider/tool awaits.
7. Ensure a full data SQ cannot delay control traffic.

Acceptance:

- the app-server remains responsive while provider, tool or compaction work is pending;
- there is exactly one state transition function for each control operation;
- stale cancel cannot cancel a later turn;
- all queues remain bounded and have explicit overflow behavior.

### A3. Implement cancellation-token propagation

Files:

- add `crates/cli/src/runtime/cancellation.rs`;
- refactor `runtime/inbound_control.rs`, `runtime/tool_interrupt.rs`,
  `runtime/subagent_control.rs`;
- provider adapters and workflow/verification call boundaries;
- `crates/sched` retry loops.

Tasks:

1. Create one root token per turn and child tokens per admitted operation.
2. Make provider streaming select directly on cancellation rather than 25 ms polling.
3. Make pure tool concurrency, effecting tools, subagents, planner, compaction and verification
   observe child tokens.
4. Cancellation must stop future retry attempts immediately.
5. For an admitted effect with unknown terminal state, append `EffectUnknown`; never retry it.
6. Convert cooperative cancellations to a stable typed terminal, not provider/tool failure.
7. Preserve already streamed assistant output as interrupted durable evidence.

Acceptance:

- cancellation reaches every async child without relying only on periodic polling;
- no post-cancel provider retry starts;
- no unknown effect is replayed;
- interrupted partial output resumes/retries from honest transcript state.

### A4. Unify foreground process termination and background job ownership

Files:

- `crates/tools/src/process/actor.rs`;
- `crates/tools/src/process/supervisor.rs`;
- `crates/tools/src/process/types.rs`;
- `crates/tools/src/shell.rs`;
- `crates/cli/src/runtime/tool_interrupt.rs`.

Tasks:

1. Introduce `ProcessGroupOwner` with explicit foreground/background ownership.
2. Foreground cancellation performs TERM -> 50 ms -> KILL -> confirmed reap.
3. Descendants must be in the same process group before executable dispatch.
4. Background jobs detach from the turn token and remain owned by `ProcessControl`.
5. Add explicit `CleanBackgroundTerminals` and per-job stop operations.
6. Record whether termination was cooperative, forced, timed out or unknown.
7. Prevent actor drop from silently abandoning a child process.

Acceptance:

- the TERM-ignoring parent-and-child fixture is gone after cancellation;
- interrupting a turn does not kill a deliberately backgrounded terminal;
- quitting/draining performs the documented background-job policy;
- every process has exactly one reaper.

### A5. Replace TUI interrupt/drain semantics

Files:

- `crates/cli/src/tui/control_submission.rs`;
- `crates/cli/src/tui/event_actions.rs`;
- `crates/cli/src/tui/app_input_state.rs`;
- `crates/cli/src/tui/submission.rs`;
- `crates/cli/src/tui/terminal_lifecycle.rs`;
- `crates/cli/tests/tui_pty.rs`.

Tasks:

1. First active-run `Ctrl-C`/`Esc` -> `CancelTurn`.
2. Second `Ctrl-C` during bounded cancellation -> `ForceCancelTurn`.
3. Idle `Ctrl-C` follows a separately documented clear/quit behavior.
4. `Ctrl-D` or `/drain` invokes `DrainSession`; no Git precondition.
5. Add `/jobs`, job stop and explicit background-terminal cleanup affordances.
6. Keep draft and queued structured input visible during cancellation.
7. Render command state from acknowledgement events: queued, steering, received, applying,
   requeued, rejected.
8. Do not set `running=false` until the authoritative turn terminal arrives.

Acceptance SLOs:

- key-to-cancel-received p99 <= 50 ms under a full data SQ;
- foreground descendant processes are gone p99 <= 250 ms on supported Unix hosts;
- the composer is usable immediately after the turn terminal;
- no queued prompt is popped before admission;
- terminal alternate-screen, mouse and selection state is restored after every exit path.

### A6. Establish one runtime-effective tunables source

Decision: runtime Rust types are authoritative; documentation/JSON and simulation metadata are
generated from those typed specifications. The runtime must not interpret generated prose or a
second JSON default catalog.

Files:

- `crates/tunables/src/families.rs` and a new `runtime_binding.rs`;
- `crates/cli/src/config.rs` and `crates/cli/src/config/*`;
- `crates/cli/src/tunables.rs`;
- `crates/protocol/src/bundle.rs` and run-genesis tunables types;
- `crates/record/src/tunables.rs`;
- `xtask` tunables generation/checks;
- generated `docs/reference/tunables.md` and JSON.

Tasks:

1. Add a required execution classification to every family:
   `runtime_live`, `policy_bundle`, `experimental`, `fixed_invariant`, or `unimplemented`.
2. Add typed default, validator, composition rule, runtime getter and provenance source to every
   `runtime_live` family.
3. Generate CLI/config schema/docs/snapshot code from the typed family definition.
4. Fail CI if a `full` family has no runtime getter or if runtime has an unregistered knob.
5. Resolve effective config once at run start and store a canonical digest plus redacted values in
   `TunablesSnapshot`.
6. Persist per-turn overrides as versioned durable events.
7. Expose `iteron config explain --effective` with value, source, ceiling and inactive reason.
8. Remove or reclassify the current false `memory_enable`, `max_turns` and `max_wall_secs`
   metadata.
9. Keep repository config tighten-only and incapable of granting authority, hooks, provider or MCP
   execution.

Acceptance:

- registry, CLI help, config schema, runtime getter and run snapshot agree byte-for-byte;
- `iteron-xtask tunables check` proves there are no orphan live knobs;
- fixed security/effect fields cannot appear in training search spaces;
- replay uses the run snapshot rather than current machine defaults.

### A7. Define explicit runtime profiles and repair defaults

Add three named profiles. Numbers below are initial governed defaults to validate with the
benchmark ladder, not learned values.

| Setting | Interactive | Benchmark | Research/exploration |
| --- | ---: | ---: | ---: |
| max turns | 120 | manifest-owned | manifest-owned |
| max wall time | 1,800 s | task manifest | experiment manifest |
| consecutive tool errors | 5 | 8 | explicit |
| provider attempts | 3 | 6 | explicit |
| retry max delay | 8 s | 30 s | explicit |
| pure tool concurrency | 6 | 8 | explicit |
| effecting concurrency | fixed 1 | fixed 1 | fixed 1 |
| workflow fan-out | 4 | 8 | max 16 with manifest |
| active subagents | 4 | 8 | max 16 with manifest |
| memory | bounded on | isolated/off unless arm enables | experiment-owned |
| memory facts | 8 | 0 or arm-owned | <=32 |
| memory total bytes | 16 KiB | 0 or arm-owned | <=49 KiB |
| compaction threshold | 78% usable window | profile-owned | explicit |
| proactive compaction | 90% of threshold | profile-owned | explicit |

Tasks:

1. Make profile identity and digest visible in status/output/evidence.
2. Show `cost unbounded` when no signed rate card and no enforceable dollar ceiling exists.
3. Require benchmark manifests to specify turn, wall, token and attempt limits.
4. Keep effecting concurrency and unknown-effect policy fixed.
5. Emit warnings when operator overrides combine bursty fan-out with low provider quota.
6. Add rate-limit-aware adaptive admission that lowers concurrency but never raises it above the
   profile ceiling.

### A8. Rebuild prompt/context engineering around stable segments

Files:

- `crates/ctx/src/context_assembly.rs`;
- `crates/ctx/src/context_strategy.rs`;
- `crates/ctx/src/instructions.rs`;
- `crates/cli/src/runtime/context_runtime.rs`;
- provider request builders;
- companion plan's `ContextLedger` instrumentation.

Tasks:

1. Divide request context into immutable kernel prefix, governed operator/project instructions,
   task-local context, memory, transcript, attachments and tool schemas.
2. Hash each stable segment and preserve prefix order across turns.
3. Select tool schemas by permission and task relevance; denied tools remain absent.
4. Add a bounded fallback tool-discovery mechanism so lazy schemas do not make tools unreachable.
5. Enforce per-source token/byte ceilings before serialization.
6. Use provider tokenizer/usage when available; retain heuristic only as a conservative fallback.
7. Move proactive compaction later than the current effective 60% point.
8. Verify compaction preserves unresolved user requests, effect outcomes, file/image anchors,
   workflow state and memory visibility notifications.
9. Measure cache-read/cache-write/uncached tokens by segment through the companion observability
   plan.

Acceptance:

- the nine-token characterization task's fixed schema overhead drops by at least 50% without
  reducing reachable allowed tools;
- repeated stable prompts produce stable segment digests;
- compaction decisions are reproducible from recorded inputs;
- no source can exceed its declared budget silently.

### A9. Make memory semantics explicit and benchmark-safe

Files:

- `crates/ctx/src/memory.rs`;
- `crates/ctx/src/context_port.rs`;
- `crates/cli/src/runtime/context_runtime.rs`;
- memory tools under `crates/tools/src/mem.rs`;
- benchmark provisioner/runner.

Tasks:

1. Enforce the total memory budget, not only component budgets.
2. Version `MemoryScope`: user, workspace, session and benchmark-task.
3. Preserve same-session add visibility at the next turn boundary and record that boundary.
4. Add explicit supersede/delete/expiry semantics and contradiction detection.
5. Prevent project memory from overriding kernel/operator facts.
6. For benchmarks, allocate an empty per-attempt memory root and destroy it after evidence
   collection.
7. Training arms that evaluate memory must receive only training-split memory artifacts.
8. Record memory manifest digest in the attempt attestation.
9. Add contamination tests that seed a canary fact in one attempt and prove it is absent in every
   other attempt.

### A10. Complete benchmark execution and scoring

Files:

- `crates/eval/harbor/*`;
- `crates/eval/src/runner.rs`, `attempts.rs`, `measurement.rs`, `report.rs`, `statistics.rs`;
- `crates/eval/src/evidence_bundle*`;
- SWE-bench corpus and provisioner code;
- CLI bundle/profile plumbing.

Tasks:

1. Treat the current Terminal request as Terminal-Bench 2.1, the pinned repository dataset. Add a
   separate manifest only if Terminal-Bench 2.0 is deliberately required.
2. Reproduce benchmark-authorized network conditions without granting broader egress.
3. Implement live policy-bundle selection and attest its digest.
4. Emit the benchmark's real task score and aggregate, not an Iteron proxy metric.
5. Persist model/provider/version, profile, kernel hash, prompt/context/memory digests, tool catalog,
   workspace image and evaluator version.
6. If provider seed is unavailable, record that fact and rely on the required repeated attempts.
7. Classify every failure: provision, provider, harness, timeout, agent terminal, grader or
   infrastructure.
8. Produce confidence intervals and paired comparisons for every arm.
9. Refuse leaderboard language unless all pinned tasks and required attempts completed under the
   official contract.

Execution ladder:

1. contract smoke: 1 task x 1 attempt;
2. diagnostic: 5 diverse tasks x 1 attempt;
3. reliability: same 5 tasks x 5 attempts;
4. pilot: 20 tasks x 5 attempts;
5. full Terminal-Bench: 89 tasks x 5 attempts;
6. SWE-bench Pro diagnostic slice;
7. SWE-bench Pro held-out evaluation at the scale allowed by budget and storage.

Do not advance a rung until harness failure rate is below 2% and no unresolved contamination,
scoring or process-leak defect remains.

### A11. Build the trainable harness data and policy path

Train only 15-25 high-leverage strategy fields:

- context: source budgets, tool-schema selection, compaction threshold/retention;
- memory: enablement, scope, retrieval `k`, score threshold, budget;
- reasoning: effort and bounded thinking/output budget;
- tools: pure concurrency, timeout, retry and output retention;
- orchestration: fan-out, active agents, planner budget, writer reserve;
- verification: test selection and repair-loop ceiling.

Never train:

- permission or authority grants;
- effecting concurrency;
- egress policy;
- sandbox/file boundaries;
- record/hash/checkpoint behavior;
- retry of unknown effects;
- secret handling;
- evaluator or held-out split selection.

Files:

- `crates/eval/src/tuner.rs` and `tuner/*`;
- `crates/eval/src/pareto.rs`;
- `crates/evolve/src/training.rs`, `gate.rs`, `promotion.rs`, `held_out.rs`;
- run-genesis tunables and companion lifecycle evidence.

Tasks:

1. Define `HarnessAction` as a typed subset of runtime-live tunables.
2. At every decision opportunity, record eligible actions, selected action, policy identity and
   selection probability/score.
3. Optimize a Pareto objective: solve rate first, then cost, wall time, tokens and harness errors;
   safety violations are hard rejection, not a weighted penalty.
4. Keep training, validation and private held-out task identities cryptographically separated.
5. Bind promoted policies by immutable digest; runtime cannot load mutable policy bodies.
6. Require transfer evaluation on at least two model families.
7. Compare learned policy against static default, manually tuned profile and equal-budget search.
8. Store failed and negative trajectories; do not train only on successes.

### A12. Paper scope and experiment contract

Working title:

> Trainable Harnesses: Offline Optimization of Typed Agent Control Policies over a Frozen Safety
> Kernel

Primary claim:

> A bounded typed harness policy, trained offline while the safety/effect kernel remains
> byte-identical, improves the held-out solve-cost Pareto frontier and transfers across at least two
> model families and two task families.

Research questions:

1. Does learned harness control improve held-out task resolution at equal model and budget?
2. Which context, memory, tool and orchestration decisions causally contribute?
3. Does a learned policy transfer across models and between repository and terminal tasks?
4. What solve/cost/latency trade-off is lost when the policy is constrained by the frozen kernel?

Experiment matrix:

- two benchmarks: SWE-bench Pro and Terminal-Bench 2.1;
- at least two model families, preferably one strong proprietary/reference model and one open
  model;
- static default, manual profile, learned policy and equal-budget search baselines;
- ablations: context, memory, tool policy, orchestration and verification;
- five repeated attempts where the benchmark requires them;
- paired bootstrap confidence intervals and effect sizes;
- explicit harness/infrastructure failure accounting;
- frozen kernel binary/config digest reported for every arm.

The paper does not claim that more Hook names improve performance. Hooks/OTel are the measurement
and intervention substrate defined in the companion plan. TUI appearance and product breadth are
outside the paper except where control reliability affects valid experiments.

## 6. Test matrix

| Scenario | Unit | Integration | PTY/process | Evidence requirement |
| --- | --- | --- | --- | --- |
| SQ full | envelope/ack reducer | app server | TUI visible refusal | no lost input |
| cancel idle/running/stale | state reducer | turn actor | first/second Ctrl-C | bounded terminal |
| hanging provider | token propagation | provider adapter | active TUI | no later retry |
| TERM-ignoring shell tree | process owner | shell tool | descendant probe | confirmed reap |
| background terminal | ownership reducer | process supervisor | interrupt then attach | remains usable |
| non-Git drain | drain reducer | record sync | TUI `/drain` | stopped + checkpoint result |
| image/file steer | structured pending queue | provider input | tag/chip restoration | no omission |
| memory add in session | visibility reducer | next turn | TUI evidence | exact first-visible turn |
| benchmark isolation | scope policy | provisioner | canary task pair | zero leakage |
| tunable drift | generated binding | CLI run | config explain | snapshot equals effective |
| compaction | deterministic plan | long run | context status | preserved obligations |
| full benchmark | statistics | adapter/evaluator | process cleanup | signed evidence bundle |

## 7. Required checks per implementation PR

Run the narrow checks first, then the repository gates before completion:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo run --locked -p iteron-xtask -- boundaries check
cargo run --locked -p iteron-xtask -- tunables check
```

Additional boundary-specific checks:

- `cargo test -p iteron-protocol --locked`
- `cargo test -p iteron-kernel --locked`
- `cargo test -p iteron-tools process --locked`
- `cargo test -p iteron-cli tui --locked`
- `cargo test -p iteron-cli --test tui_pty --locked`
- `cargo test -p iteron-ctx --locked`
- `cargo test -p iteron-record --locked`
- `cargo check -p iteron-eval --all-targets --locked`
- `cargo test -p iteron-evolve --locked`

## 8. Recommended PR sequence

1. Characterization tests only.
2. Protocol submission identity and acknowledgement vocabulary.
3. Pure kernel control reducer.
4. Session actor and priority control lane.
5. Cancellation-token propagation.
6. Foreground process-group ownership and reap.
7. TUI `Ctrl-C`/`Esc`/drain/job semantics.
8. Tunables typed runtime binding and drift checks.
9. Interactive/benchmark/research profiles.
10. Prompt/tool-schema selection and compaction repair.
11. Memory scope and benchmark isolation.
12. Terminal-Bench execution/scoring evidence.
13. SWE-bench Pro execution/scoring evidence.
14. Trainable action logging and offline tuner.
15. Promotion/held-out gates and paper experiment runner.

Do not combine steps 2-7 into a single refactor. Each slice must preserve legacy protocol replay
and keep production modules below the repository's size targets.

## 9. Definition of done

- All outcome statements in section 1 have automated evidence.
- Current red characterization tests from A0 are green under the new semantics.
- No foreground process or workflow child survives turn cancellation accidentally.
- Background terminals survive ordinary turn cancellation and are explicitly controllable.
- Every prompt has a stable submission ID and terminal acknowledgement.
- Effective runtime config and the tunables registry cannot drift in CI.
- Benchmark evidence includes real grader output, complete provenance and confidence intervals.
- Benchmark memory/workspace isolation passes canary tests.
- The frozen-kernel digest is identical across learned/static benchmark arms.
- The paper's trainable action set contains only governed strategy fields.
- No implementation PR is pushed, merged or released without explicit user direction.
