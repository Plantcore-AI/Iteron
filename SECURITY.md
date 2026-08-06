# Security policy

## Current support level

Core Code is pre-alpha. Only the current `main` branch receives security fixes. There
are no supported stable releases yet.

Do not run Core Code unattended on sensitive repositories or treat its sandbox as a
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
the bypass; so is the kernel's own admission layer, which is not part of the
permission gate. Treat a prompt-injection payload in an untrusted repository as
having the authority of the account running `core`, and choose the posture
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
