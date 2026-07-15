# Contributing to Core Code

Thank you for helping build Core Code. The project welcomes focused contributions from
humans using any responsible development tools, including coding agents.

Unless a contributor explicitly states otherwise, an intentionally submitted
contribution is licensed under the repository's Apache-2.0 license as described in
Section 5 of [`LICENSE`](LICENSE). No CLA is required.

## Current bootstrap state

Contributions are welcome while the ownership registry is in `bootstrap` mode,
but remote responsibility and human-review enforcement are not active yet. During
bootstrap, the human Owner sponsors or assigns scope, selects the required human
reviewers, and makes the merge decision manually. Contributors do not need to claim
maintainership to submit a patch.

Boundary and review jobs inspect bootstrap pull requests and succeed with an
explicit non-enforcing result; they do not claim that registered-human review is
active.
Enforcement becomes active only after public identities, generated CODEOWNERS,
the protected Ruleset, and a non-bypass remote canary have all been verified.

## Before starting

- Search existing issues and pull requests.
- Find the primary responsibility unit for the paths you expect to change:

  ```sh
  cargo run --locked -p core-xtask -- boundaries explain path/to/file
  ```

- For a new subsystem, public protocol, security boundary, cross-boundary change,
  or behavior change, open an issue first and agree scope with the responsible
  human maintainer. If the boundary is open, the Owner may sponsor or assign the
  contribution without making the contributor a maintainer. Use an ownership-claim
  issue only when a human is volunteering for ongoing responsibility.
- Keep unrelated cleanup out of the same change.
- Never include credentials, private session data, proprietary source, or copied
  third-party implementation in an issue or pull request.

## Responsibility boundaries

[`governance/boundaries.json`](governance/boundaries.json) is the source of truth
for path ownership, human assignments, invariant-review overlays, and the exact
internal workspace dependency baseline. [`OWNERSHIP.md`](OWNERSHIP.md) and
`.github/CODEOWNERS` are generated views; do not edit them directly.

Responsibility units are not team seats. Any coherent unit may be claimed, one
person may own several, and a unit may be split or merged through a reviewed
registry change. Every public path must have exactly one primary boundary.
Cross-cutting overlays add review responsibility without creating a second path
owner.

To change assignments or boundaries:

1. Open an ownership-claim issue and name the human primary, reviewer or backup,
   affected contracts, adjacent owners, and handoff evidence.
2. Obtain Owner confirmation and, for cross-boundary work, agreement from the
   affected human maintainers.
3. Edit the registry, then regenerate and validate its views:

   ```sh
   cargo run --locked -p core-xtask -- boundaries generate
   cargo run --locked -p core-xtask -- boundaries check
   ```

The full human/agent pairing and handoff workflow is in
[`docs/maintainer-onboarding.md`](docs/maintainer-onboarding.md).

Active enforcement requires explicit public GitHub identities. Critical active
boundaries require an independent human reviewer; switching the global mode to
`active` also requires every critical boundary and independent overlay to be
assigned. Coding agents cannot be owners, reviewers, approvers, or substitutes
for a human identity.

Maintainers activating the public repository must also follow the
[repository-enforcement runbook](docs/repository-enforcement.md); generated
CODEOWNERS alone is not a branch protection policy.

## Development checks

```sh
cargo fmt --all -- --check
cargo run --locked -p core-xtask -- boundaries check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

Tests that require a real provider account or network access must be opt-in and
must not be required for the default local test suite.

## Change shape

- Target production Rust modules below 500 lines where practical.
- If a file is already around 800 lines, put new functionality behind a smaller
  module rather than extending the giant file.
- Keep complex pull requests below roughly 500 changed lines and mechanical ones
  below roughly 800. Split larger work into contract, implementation, and
  integration steps.
- Agent/runtime behavior changes need an integration or replay-level regression
  test, not only a unit test.
- TUI behavior changes need semantic state tests and, when rendering changes,
  terminal/snapshot evidence.

Existing large files are architecture debt, not precedent for adding more.

## Pull request checklist

- Explain the user-visible outcome and the failure mode being addressed.
- Fill the structured boundary fields in the pull request template. To preview
  the machine-computed impact against a committed local base revision, run:

  ```sh
  cargo run --locked -p core-xtask -- boundaries affected --base origin/main
  ```

- Before requesting responsibility review, update the branch so its head contains
  the current base commit. A base update or retarget requires a new head and fresh
  current-commit approvals.

- Identify affected invariant overlays, contracts, and public interfaces.
- Multi-boundary pull requests must link the agreement of the responsible humans;
  CI rejects declared boundary or overlay IDs that differ from the actual diff.
- `Responsible-Maintainers` names the effective registered maintainers (or the
  Owner fallback), not the community author or an agent. Issue fields use `#123`
  or the exact value `not-applicable`; multi-boundary agreement always needs an
  issue reference.
- The `review / required-humans` check reads current GitHub reviews and requires
  one eligible approval for every affected registered responsibility group. A new
  push or dismissed/changed review invalidates stale evidence.
- Include tests that fail before the change when feasible.
- Report the exact verification commands run.
- State compatibility, security, rollout, and rollback considerations.
- Keep generated output and formatting churn out of the diff.

AI-assisted contributions are welcome. The human author must understand the patch,
be able to explain it, and remain accountable for it. Do not add AI co-author or
generated-by trailers to commits.
