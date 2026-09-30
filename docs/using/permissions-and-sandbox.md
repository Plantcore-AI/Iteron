# Permissions and sandbox

Iteron classifies tools by capability, then applies a permission mode plus
session rules. The model cannot grant itself a capability.

The host also checks the actual operation. Every required capability must pass;
an execution grant cannot stand in for an external or trust-changing grant.

## Capability classes

These mode/rule decisions describe **gated** sessions (`--ask-permissions`). The
fresh-session dangerous bypass below auto-approves otherwise-asking decisions;
explicit denies, Plan and authority ceilings are not bypassed.

| Capability | Examples | Gated posture |
| --- | --- | --- |
| `read_only` | workspace reads, search, repository inspection | automatic |
| `reversible_local` | tracked workspace edits behind recovery state | asks in `default`; automatic in `acceptEdits` and `yolo` |
| `code_executing` | shell, build, test | automatic under the trusted initial grant, sandboxed |
| `trust_mutating` | declared writes to Git/CI/instruction/trust surfaces | always asks or denies |
| `irreversible_external` | push, publish, send, external MCP effects | always asks or denies |

### Operation requirements

Structured edits retain local-write authority and additionally require
`trust_mutating` when they target Git, CI, instruction, skill or agent-config
surfaces, including `.agents` and `.codex`. Resolved symlink targets are checked
again before dispatch. Targets beyond the bounded classifier are treated as
potential trust changes.

Arbitrary shell programs, scripts, substitutions and terminal input can have
unknown effects. They require execution, local-write, trust-change and external
authority. A small literal builtin command without expansion or redirection can
use only execution authority when the actual interpreter is `/bin/bash` or
`/bin/sh`. A custom interpreter retains the unknown classification. Use the
structured observation tools for repository inspection.

A blanket `bash` allow does not approve its extra effect classes. Their host
rules are `bash:trust_mutating` and `bash:external`; process launch/input use the
corresponding `process_start` and `process_write` prefixes. Dynamic trust writes
use rules such as `write_file:trust_mutating`. Explicit operation-class denies
also apply under dangerous bypass. Plan and immutable ceilings remain binding.

Shell startup scripts, imported functions and dynamic-loader injection from
ambient or configured child environment are removed. An explicit script launch
is still evaluated as part of the visible command.

## Permission modes

| Mode | Behavior |
| --- | --- |
| `default` | reads automatic; edits ask; trusted code rule remains automatic |
| `acceptEdits` | reversible edits and trusted code rule automatic |
| `plan` | hard read-only overlay; everything above read-only is denied |
| `yolo` | reads, reversible edits, and granted code execution automatic; the two highest classes still ask |

Set a mode with `--mode` or `/mode`. Use `/permissions allow|ask|deny CAPABILITY`
for session rules where policy permits. Read-only cannot be disabled, and the two
highest capability classes cannot be changed to automatic.

## New sessions and historical checkpoints

Fresh ordinary TUI and one-shot sessions default to `acceptEdits` with dangerous
permission bypass **on** and execution **unconfined**. Tools can act without an
approval prompt, including declared external effects, within the kernel's
authority ceiling. This is not a sandbox or a safety guarantee. A visible
startup warning and status notice identify this posture before execution.

- `--ask-permissions` disables bypass for a fresh session, enables confinement,
  and selects `default` mode unless an explicit `--mode` was supplied. It does
  not remove the trusted code-execution grant. One-shot (`-p`) has no approval
  channel, so an "ask" becomes a refusal.
- `--confine` retains bypass but requests the workspace execution boundary.
- Explicit `--mode default` or `--mode acceptEdits` also restores approval gates
  and confinement, unless `--dangerously-bypass-permissions` is explicitly given.
- Fresh `--mode yolo` retains the broad bypass default. Combined with
  `--ask-permissions`, it uses the gated `yolo` table above instead.
- `--mode plan` is confined read-only and denies effects, even alongside
  `--dangerously-bypass-permissions`.
- `--dangerously-bypass-permissions` remains accepted for existing invocations;
  ordinary fresh sessions no longer need the flag. Explicit deny rules and the
  kernel capability ceiling still apply.

Resume uses the checkpoint's recorded bypass, not today's fresh-session
default. An older gated run remains gated; a bypassed run retains its bypass.
An explicit `--ask-permissions`, gated `--mode default`/`--mode acceptEdits`, or
`--dangerously-bypass-permissions` that conflicts with the recorded bypass is
rejected: omit that override to retain the checkpoint or start a new session
with the desired authority. `--mode yolo` alone does not upgrade a recorded
gated bypass; it changes only the mode overlay. Explicit
`--mode plan` can tighten the durable mode overlay without rewriting bypass.
`--confine` is an invocation-level tightening; repeat it on resume if required.

## Budget defaults and explicit limits

Ordinary defaults have no turn-count, USD or aggregate-token ceiling, with a
finite **86,400-second (24-hour) ceiling per submission** and **50 consecutive
tool errors** before stopping a stuck loop. This is generous, not infinite:
individual tool, output, retry and concurrency bounds still apply. Absence of a
USD cap is not a spending guarantee.

Explicit CLI caps and tighter repository limits remain exact. For example, a
run configured with `max_turns: 20` and `max_wall_secs: 180` still stops at those
limits; changing defaults does not remove them or rewrite a resumed checkpoint.

## Enable code execution

`bash`, builds, tests, and `--verify` are enabled by default. `--allow-code` is
retained and still grants the `code_executing` capability explicitly; an operator
removes that automatic code rule with `"allow_code": false` in
`~/.iteron/config.json` or the same key in a project `.iteron/config.json`.
That rule alone does not override dangerous bypass: use `--ask-permissions` for
approval gates, an explicit deny for refusal, or `--mode plan` for read-only.

## Sandbox contract

On macOS/Linux, `--confine`, a gated session, or `--mode plan` requests
confinement. Fresh ordinary bypass does **not** confine executed code. The
requested boundary is intended to:

- network egress denied;
- writes confined to the workspace plus a capability-private scratch directory;
- ambient HOME credential paths denied;
- macOS uses the system Seatbelt interface;
- Linux requires a usable bubblewrap/user-namespace boundary and fails closed if
  it cannot establish one.

Windows has no equivalent code-execution sandbox. The built-in file-edit tools
have a separate workspace write guard when confined or gated, while read-only tools
may inspect outside paths where the authority ceiling permits it. A shell
sandbox alone does not prove file writes are contained.

The current file guard is **not yet an adversarial filesystem boundary**. A
concurrent parent-directory symlink swap can race path validation and staging;
do not run Iteron against a hostile local process or on sensitive repositories
on the assumption that this race is closed. Dangerous bypass grants
host-path write authority unless a narrower authority ceiling applies.

!!! danger "Not a confidentiality boundary"
    Do not run hostile code or secrets on the assumption that the pre-alpha
    sandbox has completed production adversarial validation. Declared tool-level
    classification cannot prove every nested effect of arbitrary code.

For an unfamiliar repository, use `--mode plan` or do not run it unattended.
