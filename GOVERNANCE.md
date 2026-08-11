# Iteron governance

Iteron has one human **Owner/Project Lead** and an open-ended group of human
**maintainer/engineers**. The number of maintainers is determined by the work and
the people who can own it; it is not a fixed set of seats. Project authority
belongs to humans, not to automation or coding agents.

## Owner / Project Lead

Iteron was created and is led by
[Jamal Cao (`@fr0m-scratch`)](https://github.com/fr0m-scratch), the project's
human Owner and Project Lead.

The Owner holds final authority over every project decision, including roadmap,
architecture, maintainer appointment or removal, merge, release, security policy,
governance, and licensing. The Owner may override any maintainer vote or normal
process.

Owner override is final, cannot be delegated to an agent, and should be recorded
with its decision, rationale, and affected scope so contributors can understand
the resulting contract. Recording an override documents it; it does not limit the
Owner's authority.

## Modular ownership

Maintainers choose coherent module or invariant boundaries they are prepared to
own. A boundary may be a crate, a small group of crates, a public interface, or a
cross-cutting invariant. The machine-readable source of truth is
[`governance/boundaries.json`](governance/boundaries.json); the detailed human view
in [`OWNERSHIP.md`](OWNERSHIP.md) and GitHub's `.github/CODEOWNERS` are generated
from it.

These are responsibility units, not an organization chart or a fixed number of
seats. They deliberately separate fine-grained areas such as runtime, effects,
hooks, provider adapters, context knowledge, tool execution, TUI rendering, and
release engineering. Boundaries may be split, merged, or added through review as
the architecture changes. A maintainer may own one or several coherent boundaries.
Every public path has exactly one primary boundary; cross-cutting invariant
overlays add independent review responsibility without creating ambiguous second
owners.

Ownership is accountability, not exclusive authorship. Community contributors may
work anywhere after agreeing scope with the responsible maintainer. Every critical
boundary should have a primary owner and an independent reviewer or backup; an
unowned boundary is surfaced as an open maintainership opportunity rather than
silently assigned. Before explicit public identities are recorded, the registry
remains in honest `bootstrap` mode. Bootstrap branch protection may require the
public Owner as the fallback code owner; module-specific registered-human review
becomes active only after the Owner appoints people, records their handles, and
enables the active protected-branch policy. The exact activation and canary
procedure is documented in
[`docs/repository-enforcement.md`](docs/repository-enforcement.md).

## One maintainer, one persistent agent

Each maintainer may bind one persistent coding agent to their currently declared
boundaries.

- The human maintainer owns design decisions, interface promises, reviews,
  incidents, and the result.
- The agent may investigate, reproduce, implement, test, and review diffs within
  the maintainer's declared worktree and path boundary.
- Agents do not dispatch work to one another, negotiate interfaces, approve pull
  requests, merge, change release gates, or accept risk.
- The Owner's override authority is never inherited by, proxied through, or
  exercised by an agent.
- Cross-boundary work is agreed by the responsible human maintainers before code
  changes begin.
- Agent memory is a cache. Contracts, decisions, tests, and runbooks must remain
  reconstructible from the repository.

This is deliberately not an agent-swarm development model.

## Decisions and merges

- A routine, backward-compatible change requires the responsible maintainer and
  green required checks. A maintainer may not be the sole reviewer of a
  substantial patch produced by their own agent.
- Runtime protocol, security boundary, durable record, permission, benchmark
  ground truth, or public API changes normally require every directly affected
  primary owner plus at least one independent qualified maintainer.
- License, governance, fixed security invariants, and stable release promotion are
  Owner decisions made after review by the relevant maintainers.
- Evaluation fixtures and scoring changes are reviewed separately from the feature
  expected to improve the score.
- An on-call maintainer may land a bounded emergency security mitigation with
  Owner approval. It requires independent human review and a follow-up incident
  record; temporary mitigations must have an expiry or removal issue.
- The Owner may override any of these thresholds, decisions, checks, or release
  outcomes and may merge or revert directly.

No maintainer may bypass required checks by merging through another account or an
automated agent. The repository review-policy check maps the base-plus-head diff
to registered primary and invariant-review groups and accepts only current-commit
GitHub approvals; the protected Ruleset remains the final merge authority.

## Community contribution path

1. Open an issue or discussion for substantial behavior or interface changes.
2. Agree the responsible maintainer, invariants, non-goals, and acceptance tests.
3. Land compatibility or regression tests before, or with, the implementation.
4. Keep the pull request reviewable and provide verification evidence.
5. The responsible human contributor answers review comments and supports the
   change after merge.

Small bug fixes, tests, and documentation corrections may go directly to a pull
request.

## Becoming a maintainer

The Owner appoints and removes maintainers. Candidates may propose the boundary
they want to own; existing maintainers advise based on sustained, high-quality
contributions, sound judgment, review participation, and demonstrated ownership
during failures. There is no maintainer quota. A departing maintainer helps
transfer context, updates the ownership registry, and leaves any uncovered
boundary explicitly open.

An appointment is activated by an Owner-confirmed ownership-claim issue followed
by a reviewed registry change. Critical active boundaries require a primary and a
different human reviewer. Repository checks reject unknown identities, ambiguous
registry IDs, malformed or duplicate individual handles, ambiguous path ownership,
stale generated ownership files, and silent internal Cargo dependency drift.
GitHub account existence, repository permission, and actual review identity are
verified during remote activation and canary testing, not inferred from strings.
