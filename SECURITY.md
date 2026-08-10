# Security policy

## Current support level

Iteron is pre-alpha. Only the current `main` branch receives security fixes. There
are no supported stable releases yet.

Do not run Iteron unattended on sensitive repositories or treat its sandbox as a
confidentiality boundary.

Since 2026-08-05 the shipped default is **unconfined and ungated**: the capability
gate is replaced by blanket auto-approval, so no tool prompts — including the
`trust_mutating` and `irreversible_external` classes that the permission tables
describe as always asking. Code execution is enabled, `bash` runs with the invoking
user's own authority (network reachable, whole filesystem readable and writable),
and the file tools resolve any path that user can reach, including `~/.ssh`. This
is an owner decision recorded in `docs/using/permissions-and-sandbox.md`, not an
oversight. `--ask-permissions` restores the gate, `--confine` puts executed code
back inside the Seatbelt/bubblewrap sandbox, and `--mode plan` disables effects
entirely. `--mode plan` and an explicit `/permissions deny` are honored even under
the bypass; so is the kernel's capability ceiling (`task_ceiling ∩
policy_capabilities`), which is not part of the permission gate and is why a
read-only sub-agent stays read-only in every posture.

Since 2026-08-06 the default also clears the **trust-egress conjunct**: a turn that
has read untrusted content may still call an egress tool. That conjunct was the last
automatic barrier between a prompt-injection payload and the network, and it never
covered `bash` — that tool is classified `code_executing`, so `curl` inside it was
never held by it. `--ask-permissions` and `--mode plan` put the conjunct back.
Delegated sub-agents now inherit the session's posture instead of running gated with
nobody to ask; their capability ceiling is unchanged and still intersected downward.
Treat a prompt-injection payload in an untrusted repository as
having the authority of the account running `iteron`, and choose the posture
accordingly. A sandbox never made hostile code safe; its absence makes the blast
radius your home directory.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** / private security advisory flow for
this repository. Do not open a public issue for a suspected vulnerability and do
not include real credentials, customer data, or weaponized exploit data in public
comments.

Include, where possible:

- the affected commit and platform;
- a minimal reproduction using synthetic data;
- the expected and observed security boundary;
- impact and any known workaround.

The maintainers will acknowledge a complete report, triage severity, coordinate a
fix and disclosure, and credit the reporter if requested.
