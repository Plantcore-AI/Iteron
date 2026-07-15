# Core agent contract

This repository is public. Never add credentials, private sessions, machine state,
company/client material, proprietary source, or unredistributable research
snapshots.

## Human ownership

- The human Owner/Project Lead has final override authority over every project
  decision. That authority cannot be delegated to an agent.
- Every change has one accountable human author and one responsible human
  maintainer.
- Maintainer count is not fixed. Each maintainer may use one persistent agent
  across their declared boundaries in `OWNERSHIP.md`.
- Agents do not approve, merge, negotiate cross-subsystem contracts, or dispatch
  work to other agents.
- Cross-boundary changes require agreement between the responsible humans first.
- `governance/boundaries.json` is the ownership and dependency source of truth;
  `OWNERSHIP.md` and `.github/CODEOWNERS` are generated and must not be edited by
  hand.

## Engineering rules

- Read the nearest `AGENTS.md`; narrower instructions override this file.
- Preserve unrelated work and stage exact files only.
- Keep all loops, retries, queues, output, time, cost, and concurrency bounded.
- Security, permission, durability, replay, budget, and effect-ledger guarantees
  are not learnable strategy choices.
- Prefer small private modules and exhaustive typed protocols.
- Target production modules below 500 lines; add a module rather than extending a
  file already around 800 lines.
- Agent/runtime changes require integration evidence. TUI changes require semantic
  and terminal-render evidence.
- Every change must declare affected boundary IDs and invariant overlays. Run
  `cargo run --locked -p core-xtask -- boundaries check` before completion.
- Run formatting, all-target check, clippy with warnings denied, and all-target
  tests before claiming completion.
- Do not add AI co-author or generated-by commit trailers.
