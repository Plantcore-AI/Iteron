# Maintainer onboarding

Core maintainership is organized around claimable responsibility units, not fixed
seats. One person may own several coherent boundaries, and a boundary can be split
when its review or incident load becomes too large. The human Owner/Project Lead
retains final override authority.

## Choose a boundary

List the currently open responsibility units:

```sh
cargo run --locked -p core-xtask -- boundaries list --open
```

Inspect the exact owner and invariant reviewers for a path:

```sh
cargo run --locked -p core-xtask -- boundaries explain crates/provider/src/openai.rs
```

The complete contracts and checks are generated in
[`OWNERSHIP.md`](../OWNERSHIP.md). Choose a unit whose interfaces, tests, failure
modes, and post-merge support you can explain. Ownership is accountability; it
does not prevent community contributors from editing the same code through review.

Large units such as `kernel-runtime`, `cli-host`, `cli-tui`, and `provider-core`
are current architecture debt. A candidate may propose a mutually exclusive split
instead of accepting an overly broad unit. The registry checker requires every
public path to remain covered exactly once during that split.

Optional coherent bundles can reduce context switching during initial activation:

- runtime integrity: protocol, kernel, record, scheduler, and durability contracts;
- execution and interoperability: provider adapters, MCP, sandbox, and tools;
- product and quality: CLI/TUI, verification, evaluation, evolution, release, and
  public documentation.

These are examples, not roles or quotas. People may select individual units or a
different coherent combination. Invariant review must be assigned across bundles
so nobody is the only reviewer of their own primary responsibility.

## Claim responsibility

1. Open an ownership-claim issue using the repository form.
2. Name the exact boundary IDs, stable contracts, invariant overlays, adjacent
   maintainers, independent reviewer or backup, evidence, and handoff plan.
3. Obtain explicit Owner confirmation and affected-human agreement as comments on
   that ownership-claim issue. Link those comments from the registry pull request;
   an offline conversation or an agent summary is not appointment evidence.
4. The Owner grants the minimum GitHub repository or organization access required
   by the configured enforcement. A person listed directly in CODEOWNERS needs
   write access to be an eligible code owner. Do not grant an agent, bot, or shared
   account human review authority.
5. Add the human identity and assignments to
   `governance/boundaries.json`. Never add an agent or shared bot identity.
6. Regenerate and validate:

   ```sh
   cargo run --locked -p core-xtask -- boundaries generate
   cargo run --locked -p core-xtask -- boundaries check
   ```

7. Submit the registry and both generated views in one pull request. A registry
   change must reference its ownership-claim issue.

Before enabling the public Ruleset, obtain an exact readiness report:

```sh
cargo run --locked -p core-xtask -- boundaries readiness
```

Critical boundaries require an independent human reviewer. Active enforcement
also requires all mandatory invariant overlays to have reviewers independent from
every effective primary they cover.

Before treating the appointment as active, the Owner verifies the exact GitHub
login, repository access, generated CODEOWNERS entry, and an actual review request
or required-review result on a non-bypass canary pull request. The local readiness
command proves registry consistency; it does not prove GitHub account permissions
or remote Ruleset behavior.

## One human, one persistent agent

A maintainer may bind one persistent coding agent to their declared boundaries.
The pairing is operational state and is not recorded as GitHub authority.

- The human owns scope, design, public contracts, review, incidents, and handoff.
- The agent may inspect, implement, test, and prepare evidence inside that human's
  agreed worktree and boundary.
- The agent cannot approve, merge, claim ownership, negotiate cross-boundary
  contracts, dispatch another agent, or exercise Owner override.
- Cross-boundary work begins only after the responsible humans agree the issue and
  sequencing.
- Agent memory is disposable. Decisions, tests, contracts, and runbooks must be
  reconstructible from the repository.

Use a separate Git branch or worktree for each active change, not for each agent.
Keep one accountable human and one reviewable outcome per pull request. Stage
exact files and preserve unrelated dirty work.

## Handoff or absence

Before leaving a boundary, record open incidents, compatibility promises, known
debt, verification commands, and pending decisions. Transfer to a confirmed human
through an ownership-claim issue, or return the boundary to explicit `open` state.
Never leave a stale name that implies unavailable support.

After the handoff registry change is merged, the Owner removes obsolete repository
or organization access and CODEOWNERS eligibility. Retain only access still needed
for other declared boundaries, then verify with a canary or repository permission
check that the departed maintainer is no longer requested or accepted for the
vacated responsibility.

An open standard or elevated boundary falls back to the Owner for sponsorship.
Active mode does not permit a critical boundary or mandatory invariant overlay to
be silently open.
