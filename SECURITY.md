# Security policy

## Current support level

Core is pre-alpha. Only the current `main` branch receives security fixes. There
are no supported stable releases yet.

Do not run Core unattended on sensitive repositories or treat its sandbox as a
confidentiality boundary. Code execution is disabled by default; enabling it does
not make hostile code safe.

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
