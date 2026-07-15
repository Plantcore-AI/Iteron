# Security

Core Code executes model-proposed operations against source trees, so permission,
sandbox, provider routing, records, extensions, and release provenance are
security boundaries rather than optional polish.

## Current posture

- Pre-alpha; only current `main` receives security fixes.
- Code execution is disabled by default.
- The sandbox is not a confidentiality boundary and hostile-code safety is not
  claimed.
- A repository cannot grant itself provider routing, endpoints, hooks, MCP
  processes, effort, or code execution.
- Trust-mutating and irreversible external declared operations cannot be made
  automatic through a mode or session rule.
- Run records are tamper-evident, not encrypted.

Review the full
[SECURITY.md](https://github.com/Plantcore-AI/core/blob/main/SECURITY.md) before
using Core Code with valuable source.

## Report a vulnerability

Use GitHub's private
[Report a vulnerability](https://github.com/Plantcore-AI/core/security/advisories/new)
flow. Do not open a public issue and do not attach live credentials, customer
data, proprietary source, or weaponized exploit material.

The private reporting feature is repository configuration, not a Markdown file.
Maintainers must keep the remote intake enabled and test it from a non-maintainer
account; a documentation link alone does not prove the route works.

Provide the affected commit and platform, a synthetic reproduction, the expected
and observed boundary, impact, and any known workaround.
