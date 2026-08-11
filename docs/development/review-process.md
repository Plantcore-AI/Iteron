# Review process

## Issue before implementation

Open an issue before changing a public protocol, security boundary, governance
contract, release process, or several responsibility boundaries. Record the
outcome, affected paths, acceptance evidence, non-goals, and rollback.

Small documentation fixes and isolated regressions may go directly to a pull
request when their scope is unambiguous.

## Compute responsibility

The registry is the source of truth:

```sh
cargo run --locked -p iteron-xtask -- boundaries explain path/to/file
cargo run --locked -p iteron-xtask -- boundaries affected --base origin/main
```

Copy the exact primary boundary and invariant-overlay identifiers into the pull
request template. Multi-boundary work links the issue where affected humans agreed
scope. Agents are not responsibility identities.

## Review sequence

1. Contributor self-review: scope, provenance, diff, tests, and rollback.
2. CI: boundary, format, check, clippy, tests, and area-specific gates.
3. Responsible human review: behavior and ongoing ownership.
4. Independent invariant review when the registry requires it.
5. Owner decision for bootstrap, governance, license, release, or override.

A new commit invalidates stale approval. A branch update must contain the current
base; the trusted validator comes from that exact base commit.

## Merge policy

The default branch accepts squash merges only. Force push and branch deletion are
blocked. Required checks are bound to the GitHub Actions application, and the
Owner's bypass applies only through a visible pull request.

An Owner override records its reason and scope. Recording makes the decision
auditable; it does not delegate or reduce Owner authority.

## After merge

The responsible human owns regressions, compatibility follow-up, documentation,
and removal of temporary mitigations. A green merge is not the end of ownership.
