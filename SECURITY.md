# Security policy

## Current support level

Iteron is pre-alpha. Only the current `main` branch receives security fixes. There
are no supported stable releases yet.

Do not run Iteron unattended on sensitive repositories or treat its sandbox as a
confidentiality boundary.

Ordinary fresh TUI, one-shot and standalone serve sessions default to `yolo`,
permission bypass **on**, code execution **on**, and execution **unconfined**.
Within the admitted authority ceiling, tools can edit, execute code and perform
declared external effects without approval prompts. This includes host-authority
execution; `--dangerously-bypass-permissions` is not required for this default.

`--ask-permissions` restores approval gates and confinement. Explicit
`--mode default` or `--mode acceptEdits` also restores them unless the dangerous
flag is supplied. `--confine` requests confinement while retaining bypass, and
`--mode plan` is always read-only. One-shot operation refuses decisions that need
an interactive answer. Plan mode, explicit denies, configured code restrictions,
and the kernel's capability ceiling (`task_ceiling ∩ policy_capabilities`) remain
binding.

Resume retains the checkpoint's recorded bypass authority. A gated checkpoint
stays gated and a bypassed checkpoint stays bypassed; conflicting explicit
overrides are rejected. Selecting a mode within a session changes its overlay,
not its recorded bypass. See the [permission contract](docs/using/permissions-and-sandbox.md).

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
