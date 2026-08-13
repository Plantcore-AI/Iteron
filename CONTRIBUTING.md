# Contributing to Iteron

Thank you for helping build Iteron. Focused bug fixes, tests, documentation,
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
[GitHub Discussions](https://github.com/Plantcore-AI/Iteron/discussions).

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
git clone https://github.com/YOUR-ACCOUNT/Iteron.git
cd Iteron
git remote add upstream https://github.com/Plantcore-AI/Iteron.git
cargo build --locked -p iteron-cli
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
   cargo run --locked -p iteron-xtask -- boundaries explain path/to/file
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
cargo run --locked -p iteron-xtask -- boundaries check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

The [testing guide](docs/development/testing.md) explains focused crate tests,
all-target tests, PTY evidence, sandbox tests, network opt-ins, and CI parity.

### Required checks run on DGX Spark

The protected-base `ci.yml` workflow is the only pull-request CI entry point. It
classifies each change and runs only the required Linux lanes on the
repository-scoped DGX Spark:

- documentation-only: boundary, strict docs, and human-review policy;
- grouped dependency update: Linux check, dependency audit, supply validation,
  and human-review policy;
- workflow/release infrastructure: boundary, supply validation, relevant docs,
  and human-review policy;
- runtime: the full Linux Rust lane plus affected specialist gates.

`ci / required` always executes and verifies that every routed lane actually
completed successfully. Individual skipped jobs are not branch-protection
evidence. The protected ruleset also requires the emitted
`review / required-humans / review / required-humans` context. Its inner
`review / required-humans` job is called by the same protected-base entry
workflow and reads the pull request's current review records.

External fork code does not run on the persistent DGX. Such a pull request stays
blocked until a maintainer provides an isolated ephemeral runner; approving a
fork workflow on persistent company hardware is not an accepted workaround.

`local_gate.sh` remains a manual Linux parity/evidence tool:

```sh
./release-tools/local_gate.sh linux
```

If a shared runner should not hold a status-writing credential, record the run
there and publish it from a separately authenticated machine:

```sh
runner$ ./release-tools/local_gate.sh linux --emit /tmp/gate.json
local$  scp runner:/tmp/gate.json . && ./release-tools/local_gate.sh --publish gate.json
```

The manual lane's `boundaries check-pr` reads the pull request body, so run that
lane after opening the pull request. Where `gh` is unavailable, hand it over:

```sh
local$  gh pr view --json body --jq .body > /tmp/body.txt
runner$ GATE_PR_BODY_FILE=/tmp/body.txt ./release-tools/local_gate.sh linux --emit /tmp/gate.json
```

Manual results are executor-attested evidence, not a substitute for the
protected `ci / required` check. macOS and Windows PR runners are paused. Release
workflows remain separately protected and only run for explicit tag or manual
release events; platform support claims remain governed by the release evidence
matrix, not by PR CI.

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
cargo run --locked -p iteron-xtask -- boundaries affected --base origin/main
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
