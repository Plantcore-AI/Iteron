# Security policy

## Current support level

Iteron is pre-alpha. Only the current `main` branch receives security fixes. There
are no supported stable releases yet.

Do not run Iteron unattended on sensitive repositories or treat its sandbox as a
confidentiality boundary.

The ordinary new-session default now has the permission bypass **off** and the
macOS/Linux execution sandbox **on**. Reversible workspace edits and trusted
sandboxed code execution run automatically; trust-changing and declared external
effects require approval. One-shot operation refuses decisions that need an
interactive answer. `--mode plan` disables effects entirely.

`--dangerously-bypass-permissions` explicitly opts into broad auto-approval and,
without `--confine`, host-authority execution. A historical checkpoint recording
the old bypass requires matching explicit opt-in to resume; a gated checkpoint
cannot silently lose confinement. Plan mode, explicit denies, and the kernel's
capability ceiling (`task_ceiling ∩ policy_capabilities`) remain in force.

**Workspace file-write containment is not yet adversarially proven.** The
current path guard can race a concurrent symlink swap between validation and
staging/commit. Do not run against a hostile local process or unattended on
sensitive repositories. The pre-alpha sandbox is not a confidentiality
guarantee. Windows has no equivalent code-execution sandbox.

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

The human Project Owner monitors this private queue and is accountable for
triage, fix coordination, disclosure, and reporter credit when requested. This
pre-alpha project provides best-effort handling and no guaranteed acknowledgement
or resolution time. If that ownership or service level changes, this policy must
change before the repository promises a different response.
