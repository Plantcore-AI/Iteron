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

## Enable code execution

`bash`, builds, tests, and `--verify` need the code-execution grant:

```sh
core --allow-code -C /path/to/repository
```

This is equivalent to allowing the `code_executing` capability for the session;
it does not grant external network authority.

## Sandbox contract

The current shell path is intended to run with network egress denied and writes
confined to the workspace:

- macOS uses the system Seatbelt interface;
- Linux requires a usable bubblewrap/user-namespace boundary and fails closed if
  it cannot establish one.

!!! danger "Not a confidentiality boundary"
    Do not run hostile code or secrets on the assumption that the pre-alpha
    sandbox has completed production adversarial validation. A repository can
    contain code that writes trust-sensitive paths from inside an allowed shell
    command. Declared tool-level classification cannot parse and prove every
    nested effect of arbitrary code.

`yolo` is therefore a deliberate operator tradeoff, not a bypass-permissions
mode. Prefer `default` or `plan` for an unfamiliar repository.
