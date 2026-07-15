# Governance

Core Code has one human Owner/Project Lead and an open-ended group of human
maintainer/engineers. Maintainer count follows accountable work; it is not a fixed
set of seats.

The Owner holds final authority over roadmap, architecture, maintainer
appointment, merge, release, security, governance, and licensing. That override
authority cannot be delegated to an agent.

## Modular responsibility

`governance/boundaries.json` is the machine-readable source for path ownership,
human assignments, invariant-review overlays, and internal dependency baseline.
`OWNERSHIP.md` and `.github/CODEOWNERS` are generated views.

Every public path has one primary responsibility boundary. Cross-cutting overlays
add independent invariant review without creating ambiguous second ownership.

Community authors may contribute anywhere after agreeing scope. Ownership is
ongoing human accountability for contracts, review, incidents, and handoff; it is
not exclusive authorship.

## Human-agent boundary

A maintainer may bind one persistent coding agent to declared boundaries. The
agent may investigate, implement, test, and prepare evidence, but cannot approve,
merge, claim ownership, negotiate cross-boundary contracts, dispatch an agent
swarm, or exercise Owner override.

Read the canonical
[GOVERNANCE.md](https://github.com/Plantcore-AI/core/blob/main/GOVERNANCE.md),
[ownership registry](https://github.com/Plantcore-AI/core/blob/main/OWNERSHIP.md),
and [maintainer onboarding](../maintainer-onboarding.md).
