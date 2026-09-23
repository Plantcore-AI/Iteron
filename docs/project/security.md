# Security

Iteron executes model-proposed operations against source trees, so permission,
sandbox, provider routing, records, extensions, and release provenance are
security boundaries rather than optional polish.

## Current posture

- Pre-alpha; only current `main` receives security fixes.
- Code execution is enabled by default and confined by the macOS/Linux sandbox.
  Use `--mode plan` to disable effects entirely. Windows has no equivalent
  code-execution sandbox.
- The sandbox is not a confidentiality boundary and hostile-code safety is not
  claimed.
- A repository cannot grant itself provider routing, endpoints, hooks, MCP
  processes, effort, or code execution.
- The shipped permission gate is enabled by default. Reversible workspace edits
  and trusted sandboxed code execution run automatically; trust-changing and
  declared external operations require approval. The file-write guard still has
  an unresolved symlink race, so workspace containment is not yet proven against
  a hostile concurrent local process.
- Run records are tamper-evident, not encrypted.

Review the full
[SECURITY.md](https://github.com/Plantcore-AI/Iteron/blob/main/SECURITY.md) before
using Iteron with valuable source.

## Report a vulnerability

Use GitHub's private
[Report a vulnerability](https://github.com/Plantcore-AI/Iteron/security/advisories/new)
flow. Do not open a public issue and do not attach live credentials, customer
data, proprietary source, or weaponized exploit material.

The private reporting feature is repository configuration, not a Markdown file.
Maintainers must keep the remote intake enabled and test it from a non-maintainer
account; a documentation link alone does not prove the route works.

Provide the affected commit and platform, a synthetic reproduction, the expected
and observed boundary, impact, and any known workaround.
