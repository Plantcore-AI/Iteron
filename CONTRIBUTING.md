# Contributing to Core Code

Thank you for helping build Core Code. Focused bug fixes, tests, documentation,
provider adapters, evaluation fixtures, and carefully scoped features are
welcome. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) before
participating.

Unless you explicitly state otherwise, an intentionally submitted contribution
is licensed under Apache-2.0 as described in Section 5 of [LICENSE](LICENSE). No
CLA is required.

## Find the right starting point

| Contribution | Start here |
| --- | --- |
| Reproducible bug | Search issues, then use the bug report form |
| Documentation correction | Open a focused issue or a small pull request |
| New behavior or public contract | Open a feature issue before implementation |
| Cross-module or security-sensitive change | Open an issue and agree scope with the affected humans |
| Vulnerability | Use the private route in [SECURITY.md](SECURITY.md), never a public issue |
| Ongoing module responsibility | Use the ownership-claim form; this is not required for ordinary contributions |

Issues labeled `good first issue` should be independently reproducible, bounded to
one responsibility area, and include acceptance evidence. `help wanted` may need
more design work. Ask setup and usage questions in
[GitHub Discussions](https://github.com/Plantcore-AI/core/discussions).

## Planned work runs through issues and milestones

Every piece of planned work on this repository is tracked as a GitHub issue that
carries **exactly one owner and exactly one milestone**. This is not a convention,
it is enforced:

- **One owner per issue.** Ownership is declared by a `role:` label naming the
  person (`role:jamal`, `role:xingyu`, `role:intern`) and restated in the issue's
  *Ownership & dependencies* block. Co-ownership is not allowed: if two people
  need to work on something, split it into two issues with one owner each.
- **No unowned issue in a milestone, and no milestone work outside an issue.**
  An issue with no owner or no milestone is not scheduled work; it is a note.
  Close it or give it both.
- **Dependencies are declared, not discovered.** Each issue states what hard-blocks
  it, what it blocks, and what it consumes through a stub without waiting. If you
  find yourself blocked by something the issue does not name, that is a plan defect
  worth raising, not a queue to wait in.
- **Milestones are targets, not gates.** Finishing early means starting the next
  milestone's work, not waiting for the date.

Before writing code, find your issue, confirm you are its owner, and check its
blocked-by list. If the work you are about to do has no issue, open one first.

## Local setup

Supported development hosts are macOS and Linux. You need:

- Git;
- Rust 1.90 or newer, installed with `rustup`;
- a C toolchain supported by Rust;
- on Linux, `bubblewrap` for the live sandbox boundary test.

Fork the repository in GitHub, then clone your fork:

```sh
git clone https://github.com/YOUR-ACCOUNT/core.git
cd core
git remote add upstream https://github.com/Plantcore-AI/core.git
cargo build --locked -p core-cli
cargo test --workspace --all-targets --locked
```

The default test suite does not require a provider credential or network access.
Real-provider and real-network tests must remain opt-in. Never place API keys in a
repository file, issue, test fixture, shell transcript, or pull request.

See [development setup](docs/development/setup.md) for platform details and
troubleshooting.

## Before changing code

1. Search open issues and pull requests.
2. Keep the work to one user-visible outcome.
3. Find the primary responsibility boundary for each path:

   ```sh
   cargo run --locked -p core-xtask -- boundaries explain path/to/file
   ```

4. For a new subsystem, public protocol, security boundary, cross-boundary
   change, or externally observable behavior, agree scope in an issue first.
5. Keep unrelated cleanup and formatting churn out of the change.

If a boundary is unassigned, the Owner can sponsor the contribution without
appointing the contributor as a maintainer.

## Development workflow

Create a descriptive branch from current `main`, make the smallest correct
change, add evidence that fails before the fix when feasible, and review your own
diff before pushing.

Run focused checks while iterating. Before requesting review, run the full gate:

```sh
cargo fmt --all -- --check
cargo run --locked -p core-xtask -- boundaries check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

The [testing guide](docs/development/testing.md) explains focused crate tests,
all-target tests, PTY evidence, sandbox tests, network opt-ins, and CI parity.

### Required checks run off GitHub Actions

Most gates no longer run on a GitHub-hosted runner. They need no property a
hosted runner provides, so they run on hardware the project already owns and
publish the same status contexts from there:

```sh
./release-tools/local_gate.sh macos   # rust / macos-15
./release-tools/local_gate.sh linux   # rust / ubuntu-24.04, boundary / validate,
                                      # supply / validate, docs / strict-build
```

A runner does not need a credential. If the machine running a lane is shared, or
has no `gh`, record the run there and publish it from a machine that is
authenticated — a `statuses: write` token on a shared box would let anyone on it
mint a green check for this repository:

```sh
runner$ ./release-tools/local_gate.sh linux --emit /tmp/gate.json
local$  scp runner:/tmp/gate.json . && ./release-tools/local_gate.sh --publish gate.json
```

The linux lane's `boundaries check-pr` reads the pull request body, so run that
lane **after** opening the pull request. Where `gh` is available the body is
fetched automatically; where it is not, hand it over explicitly:

```sh
local$  gh pr view --json body --jq .body > /tmp/body.txt
runner$ GATE_PR_BODY_FILE=/tmp/body.txt ./release-tools/local_gate.sh linux --emit /tmp/gate.json
```

The lane fails rather than skipping that check. `boundary / validate` is a
required context, and publishing it after quietly dropping one of its checks
would be exactly the silent downgrade this arrangement exists to prevent.

A branch ruleset matches a required check by context *name*, not by producer, so
the protection is unchanged. Two consequences you need to know about, because
neither is discoverable from a red pull request:

- **A pull request nobody gates stays blocked.** The contexts never appear, so
  the merge button stays disabled. That is the design, not a broken repository.
  If you do not have a machine that can run a lane, say so on the pull request
  and a maintainer will run it for you.
- **A published status is executor-attested, not machine-enforced.** Anyone with
  push access could post a green status without running anything. The status
  description records the host and the commit that was actually tested, so this
  is auditable after the fact, but it is weaker than a hosted runner and is
  accepted deliberately.

`review / required-humans` still runs on Actions: it reads the pull request's own
review state, which has no local equivalent. The Windows lane will run there too,
since Windows is the one platform this project cannot self-host.

`ci.yml` retains every lane behind `workflow_dispatch`. It is the reference
definition these local lanes mirror, and the fallback when hosted capacity is
available. Note that a manual dispatch skips the base-relative boundary steps,
which are guarded on `pull_request`/`merge_group`; `local_gate.sh linux`
reproduces those against `git merge-base origin/main HEAD`, including building
the validator from the base commit so a change cannot loosen the rule judging it.

### Evidence by change type

| Area | Minimum evidence |
| --- | --- |
| Runtime or protocol | Unit coverage plus integration, replay, or compatibility evidence |
| Durable records | Round-trip, recovery, corruption, and version behavior |
| Permissions, tools, or sandbox | Denial path, bounded failure, and a live boundary test where available |
| Provider adapter | Synthetic transport fixtures, redaction, discovery bounds, and missing-credential behavior |
| TUI | Semantic state tests; PTY/resize/terminal evidence for input or rendering changes |
| Documentation | Strict site build and link validation |
| Release engineering | Clean-runner build, package inspection, checksum, SBOM, provenance, and install canary |

Additional area guides cover [provider adapters](docs/development/provider-adapters.md)
and [TUI testing](docs/development/tui-testing.md).

## Change shape

- Prefer small modules and explicit interfaces. Do not extend an already large
  file merely because it exists.
- Keep complex pull requests near 500 changed lines when practical. Split larger
  work into contract, implementation, and integration stages.
- Preserve boundedness: queues, retries, output, memory, deadlines, and
  concurrency need explicit ceilings.
- Never weaken a test or policy only to make CI green. Explain platform-specific
  capability detection and fail closed.
- Do not introduce framework or supply-chain dependencies without documenting the
  trust and maintenance cost.
- Generated ownership files must be regenerated from their source; do not edit
  them directly.

Existing large files are architecture debt, not precedent.

## Pull requests

Use the pull request template and explain the outcome, failure mode, evidence,
compatibility impact, security impact, rollout, and rollback. To compute the exact
boundary contract for a committed branch:

```sh
cargo run --locked -p core-xtask -- boundaries affected --base origin/main
```

- Declare every affected primary boundary and invariant overlay exactly as CI
  reports it.
- Link an issue for multi-boundary agreement and public contract changes.
- `Responsible-Maintainers` names registered humans or the bootstrap Owner
  fallback, never an agent.
- Update the branch onto current `main` before review; a new head invalidates stale
  review evidence.
- Report exact commands and relevant remote canaries. “Tests pass” is not enough.
- Use clear commits without generated-by or AI co-author trailers.

The complete human review and protected-branch path is in
[review process](docs/development/review-process.md).

## Responsibility boundaries

[`governance/boundaries.json`](governance/boundaries.json) is the source of truth
for path ownership, human assignments, invariant overlays, and the internal Cargo
dependency baseline. [OWNERSHIP.md](OWNERSHIP.md) and `.github/CODEOWNERS` are
generated views.

Responsibility units are not fixed team seats. A human may own several coherent
units, and a unit may be split or merged through review. Coding agents cannot be
owners, reviewers, approvers, merge authorities, or substitutes for a human
identity. See [maintainer onboarding](docs/maintainer-onboarding.md) and the
[repository enforcement runbook](docs/repository-enforcement.md).

## Bootstrap state

The registry remains in `bootstrap` until explicit module maintainers and
independent reviewers are appointed. During bootstrap, CODEOWNERS falls back to
the human Owner and the custom registered-human review job reports a successful
but explicitly non-enforcing result. The protected GitHub ruleset remains the
merge authority.

No contributor needs to claim maintainership to submit a patch.

## AI-assisted contributions

AI-assisted contributions are welcome. The human author must understand the
change, be able to reproduce and explain its evidence, check its provenance, and
remain accountable after merge. Do not submit copied proprietary implementation,
private session data, credentials, or output whose license you cannot establish.

## Changelog and releases

User-visible changes should update [CHANGELOG.md](CHANGELOG.md) under
`Unreleased`. Maintainers follow the evidence-gated
[release process](docs/development/releasing.md); contributors must not create
release tags or upload binaries manually.
