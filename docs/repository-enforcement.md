# Repository enforcement

This runbook turns Iteron's local collaboration contract into GitHub merge
enforcement. The repository remains in `bootstrap` mode until the public human
identities and the protected `main` ruleset have both been verified.

## Required checks

Protect these stable check names:

- `boundary / validate`
- `docs / strict-build`
- `review / required-humans`
- `rust / ubuntu-24.04`
- `rust / macos-15`
- `supply / validate`

For pull requests, the boundary job builds the validator from the exact base
commit and uses that trusted binary to inspect the candidate tree as data. It
validates unique path ownership, generated ownership views, assignment shape,
registry-level invariant-review independence, the internal Cargo dependency
baseline, and base-plus-candidate impact. In `active` mode it also enforces the PR
body's exact responsibility contract and registered-human review groups. In
`bootstrap` mode those two gates succeed with a conspicuous non-enforcing result
so early contributions are not falsely rejected or represented as human-review
enforced.
An active base cannot be downgraded to bootstrap by a pull request. Delete and
rename impact is the union of base and candidate ownership. Cross-platform release
build jobs run after merge and are not merge requirements. Binary artifact upload
never occurs from the main-branch smoke build. Only an Owner-created version tag
can invoke the protected release workflow that packages the project license,
audited third-party notices, SBOMs, provenance, and installer canaries.

The review-policy workflow reads GitHub's current review records with a read-only
token. For every affected primary boundary, base and candidate boundary-reviewer
set, and per-boundary base and candidate invariant-overlay set, it requires a
registered human approval on the current head commit. Base and candidate sets are
separate AND-groups, so a newly named reviewer cannot replace the previous policy's
approval. Overlay candidates exclude the effective primary for that boundary. A
primary who authored the pull request is accountable by authorship and cannot
approve their own change; independent groups remain required.
Changes to the ownership registry additionally require the registered Owner's
approval, or the Owner's accountable authorship, from both base and candidate
policy where those identities exist. Review submission, edit, dismissal, and new
commits rerun the check.

The pull request head must contain the exact current base commit. A base update or
retarget therefore requires the contributor to update the branch, producing a new
head commit before responsibility review can pass; approvals tied to the old head
cannot be reused. The workflow also reruns on pull-request edits.

This custom check matches registered logins and review state. It does not prove
that an account exists, has repository write access, or is eligible under GitHub's
CODEOWNERS and protected-branch rules. The Ruleset remains the merge authority;
account permissions and code-owner eligibility must be verified during activation
and with a non-bypass canary.

Issue fields are repository evidence links, not API-backed attestations. The
validator checks their exact `#<number>` shape and requires an ownership-claim
reference for registry changes; the Owner and affected humans must still verify
that the linked issue exists and contains the required appointment or
cross-boundary agreement comments.

## Bootstrap main ruleset

Configure a repository ruleset targeting the default branch with:

- pull requests required;
- one approving human review;
- code-owner review required;
- stale approvals dismissed after a new commit;
- approval of the most recent reviewable push required;
- all review conversations resolved;
- the six status checks above required and up to date with the target branch;
- force pushes and branch deletion blocked.

In bootstrap, every CODEOWNERS pattern falls back to the public Owner. This permits
an external contributor's pull request to receive one accountable Owner approval
without pretending that module maintainers have already been appointed. The
`review / required-humans` check is still required, but reports its explicit
successful, non-enforcing bootstrap result.

Grant pull-request-only bypass to the individual human Owner/Project Lead. This
lets the Owner land an authored governance change through a visible pull request
without permitting direct protected-branch pushes. Using bypass is an Owner
override and should be recorded with rationale and scope. Do not grant bypass to
bots, coding agents, broad teams, or ordinary maintainers.

GitHub treats multiple eligible owners on one CODEOWNERS pattern as alternatives;
it does not require every listed person to approve. The trusted `review /
required-humans` check enforces one current approval from each registered
responsibility group once the registry is active. The Ruleset supplies a one-review
bootstrap floor and a two-review active floor. The Owner resolves any identity or
permission mismatch before merge.

The repository workflow is still editable source. Where the GitHub organization
supports required workflows, bind `boundary / validate` to the reviewed workflow
and `review / required-humans` to reviewed workflows on the protected base branch
or a dedicated policy repository. Otherwise,
CODEOWNERS and the configured human-review floor must protect workflow and
validator changes; a green check alone is not proof that an altered workflow
remained trustworthy.

## Active ownership upgrade

After public maintainers claim the critical boundaries and invariant overlays,
switch the registry to `active`, regenerate the ownership views, and raise the
Ruleset minimum to two approving humans. Run a second non-bypass canary proving
that the custom review groups, stale-review invalidation, and Owner-only bypass
work before describing active ownership enforcement as production-ready.

Trusted-base policy changes use a two-stage migration. First merge a
backward-compatible validator that understands both the existing and proposed
policy shape. Only after that validator is on the protected base may a second pull
request change the registry schema, generated views, or enforcement contract. Do
not weaken the base-policy check to make a one-pull-request migration pass.

Merge queue is not currently supported: `review / required-humans` is evaluated on
pull-request and review events, not on `merge_group` commits. Do not enable a merge
queue or require this check for merge-group SHAs until the review-policy workflow
has an explicit merge-group design and a queue canary proves all required
checks report on the queued commit.

## Activation sequence

1. Add each appointed person and explicit public GitHub handle to
   `governance/boundaries.json`.
2. Mark claimed boundaries and overlays `active`, with a primary and required
   reviewers. Critical boundaries and independent overlays cannot self-review.
3. Switch `enforcement.mode` to `active` and run:

   ```sh
   cargo run --locked -p iteron-xtask -- boundaries generate
   cargo run --locked -p iteron-xtask -- boundaries check
   ```

4. Merge the identity and assignment change, configure the `main` ruleset, and
   verify its required-check names against an actual pull request.
5. Open a canary pull request from a non-bypass account. Confirm that a wrong PR
   boundary declaration, a missing approval, a stale approval, and a failing check
   each block merge. Close the canary without merging if it contains no product
   change.

Local success, a local commit, and a same-disk copy are not proof that GitHub
enforcement works. Activation is complete only after the remote canary passes.
