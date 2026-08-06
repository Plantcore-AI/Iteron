# Permissions and sandbox

Core Code classifies tools by capability, then applies a permission mode plus
session rules. The model cannot grant itself a capability.

## Capability classes

| Capability | Examples | Default posture |
| --- | --- | --- |
| `read_only` | workspace reads, search, repository inspection | automatic |
| `reversible_local` | tracked workspace edits behind recovery state | asks in `default`; automatic in `acceptEdits` and `yolo` |
| `code_executing` | shell, build, test | asks except in `yolo`; unavailable without the code-execution grant |
| `trust_mutating` | declared writes to Git/CI/instruction/trust surfaces | always asks or denies |
| `irreversible_external` | push, publish, send, external MCP effects | always asks or denies |

## Permission modes

| Mode | Behavior |
| --- | --- |
| `default` | reads automatic; edits and code ask |
| `acceptEdits` | reversible edits automatic; code asks |
| `plan` | hard read-only overlay; everything above read-only is denied |
| `yolo` | reads, reversible edits, and granted code execution automatic; the two highest classes still ask |

Set a mode with `--mode` or `/mode`. Use `/permissions allow|ask|deny CAPABILITY`
for session rules where policy permits. Read-only cannot be disabled, and the two
highest capability classes cannot be changed to automatic.

## The gate is bypassed by default

**Owner decision, 2026-08-05: on a default run, none of the two tables above
decides anything.** The capability gate is replaced by blanket auto-approval, so
every tool runs without prompting — including `trust_mutating` and
`irreversible_external`, the two classes the first table calls "always asks or
denies" and which even `yolo` still stops at. `yolo` is a bounded mode; this is
not one.

Three things still apply, and they are the whole of what is left:

- `--mode plan` hard-denies everything above read-only. Bypass never punches
  through Plan.
- An explicit `/permissions deny` on a tool or a capability is still honored.
- The kernel's **capability ceiling** still holds: the task authority ceiling
  intersected with the immutable policy capability set is not part of the
  permission gate and is not bypassed with it. A task that never held a capability
  cannot use it in any posture.

**Owner decision, 2026-08-06 — two of those were narrowed further.** The kernel's
**trust conjunct** no longer applies to an operator-authority session: a turn that
has read untrusted content may still call an egress tool. It never covered `bash`
(classified `code_executing`, so a `curl` inside it was never held by it), so the
conjunct was a boundary on one path and not the other. And **delegated sub-agents
now inherit the session posture** rather than running gated: a child has no
approval channel, so a gate it cannot answer is a refusal wearing a question's
clothes, and a bypassed session was delegating work its own children could not do.
What bounds a child is its ceiling and its tool filter, both still intersected
downward — a read-only definition stays read-only.

`--ask-permissions` and `--mode plan` restore the gate AND the trust conjunct.

`--ask-permissions` restores the gate, and then the modes above mean exactly what
they say. In one-shot (`-p`) there is no approval channel, so an "ask" resolves as
a refusal — pair `--ask-permissions` with `--mode acceptEdits` or an explicit
allow rule rather than expecting a prompt.

A bypassed session says so in three places, deliberately: a stderr banner at
startup, the `mode` row in `/status`, and the first row of `/permissions`.

## Enable code execution

`bash`, builds, tests, and `--verify` are enabled by default. `--allow-code` is
retained and still grants the `code_executing` capability explicitly; an operator
removes the grant with `"allow_code": false` in `~/.core/config.json`, with the
same key in a project `.core/config.json`, or with `--mode plan`.

## Sandbox contract

**The default posture is unconfined (owner decision, 2026-08-05).** A `bash`
command runs with the authority of the account that started `core`: it reaches the
network, reads any file that account can read — `~/.ssh`, `~/.aws`, the keychain
paths — and writes anywhere on the host. The file tools resolve paths the same
way, so `read_file` and `write_file` address the whole filesystem, not the
workspace.

Two ceilings survive that change, because they are liveness bounds rather than
security ones: a per-command wall clock and a per-stream retained-output bound.

`--confine` selects the confined posture instead. Nothing about it was weakened;
it is the same contract this document has always described:

- network egress denied;
- writes confined to the workspace plus a capability-private scratch directory;
- ambient HOME credential paths denied;
- macOS uses the system Seatbelt interface;
- Linux requires a usable bubblewrap/user-namespace boundary and fails closed if
  it cannot establish one.

### Why the default changed

The confined posture was not wrong, it was silently fatal to the tool. With no
network, `git push`, `gh`, `curl`, and every package install failed, and they
failed as ordinary command errors rather than as a visible policy denial. With
workspace-only paths, the absolute path the model naturally emits was refused,
and three such refusals in a row tripped the consecutive-error floor and ended
runs that had nothing wrong with them.

### What to use when

| Situation | Posture |
| --- | --- |
| Your own repository, your own machine | the default |
| A repository you have not read | `--confine`, or `--mode plan` |
| Anything you would not hand your shell to | do not run it |

!!! danger "Not a confidentiality boundary"
    Do not run hostile code or secrets on the assumption that the pre-alpha
    sandbox has completed production adversarial validation. A repository can
    contain code that writes trust-sensitive paths from inside an allowed shell
    command. Declared tool-level classification cannot parse and prove every
    nested effect of arbitrary code.

`yolo` is therefore a deliberate operator tradeoff, not a bypass-permissions
mode. Prefer `default` or `plan` for an unfamiliar repository.
