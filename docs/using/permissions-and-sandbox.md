# Permissions and sandbox

Iteron classifies tools by capability, then applies a permission mode plus
session rules. The model cannot grant itself a capability.

## Capability classes

| Capability | Examples | Default posture |
| --- | --- | --- |
| `read_only` | workspace reads, search, repository inspection | automatic |
| `reversible_local` | tracked workspace edits behind recovery state | asks in `default`; automatic in `acceptEdits` and `yolo` |
| `code_executing` | shell, build, test | automatic under the trusted initial grant, sandboxed |
| `trust_mutating` | declared writes to Git/CI/instruction/trust surfaces | always asks or denies |
| `irreversible_external` | push, publish, send, external MCP effects | always asks or denies |

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

New sessions default to `acceptEdits` with the permission bypass **off**. Edits
and the trusted initial code-execution rule run without prompting; trust changes
and declared external effects still ask or deny. In one-shot (`-p`) there is no
approval channel, so an "ask" becomes a refusal. `--ask-permissions` selects the
stricter `default` mode when no explicit `--mode` was given; it does not remove
the trusted code grant. `--mode plan` denies all effects.

`--dangerously-bypass-permissions` is an explicit opt-in to broad auto-approval.
Plan mode, explicit deny rules, and the kernel capability ceiling still apply. A
historical checkpoint that records bypass is not silently migrated: resume
requires a matching explicit dangerous opt-in. Conversely, the flag cannot
silently disable confinement when resuming a gated checkpoint. A bypassed
session displays a startup banner and status/permissions notice.

## Enable code execution

`bash`, builds, tests, and `--verify` are enabled by default. `--allow-code` is
retained and still grants the `code_executing` capability explicitly; an operator
removes the grant with `"allow_code": false` in `~/.iteron/config.json`, with the
same key in a project `.iteron/config.json`, or with `--mode plan`.

## Sandbox contract

The ordinary macOS/Linux posture confines executed code; `--confine` also
requests confinement in an explicitly bypassed session. It is intended to:

- network egress denied;
- writes confined to the workspace plus a capability-private scratch directory;
- ambient HOME credential paths denied;
- macOS uses the system Seatbelt interface;
- Linux requires a usable bubblewrap/user-namespace boundary and fails closed if
  it cannot establish one.

Windows has no equivalent code-execution sandbox. The built-in file-edit tools
have a separate workspace write guard in ordinary mode, while read-only tools
may inspect outside paths where the authority ceiling permits it. A shell
sandbox alone does not prove file writes are contained.

The current file guard is **not yet an adversarial filesystem boundary**. A
concurrent parent-directory symlink swap can race path validation and staging;
do not run Iteron against a hostile local process or on sensitive repositories
on the assumption that this race is closed. Explicit dangerous bypass restores
host-path write authority unless a narrower authority ceiling applies.

!!! danger "Not a confidentiality boundary"
    Do not run hostile code or secrets on the assumption that the pre-alpha
    sandbox has completed production adversarial validation. Declared tool-level
    classification cannot prove every nested effect of arbitrary code.

For an unfamiliar repository, use `--mode plan` or do not run it unattended.
