# Changelog

All notable changes to Iteron are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). During `0.0.x`, public
interfaces may change between releases.

## [Unreleased]

## [0.0.9] - 2026-08-17

There is no 0.0.8. That tag was cut and its release validation failed, and release
tags are immutable by rule, so the version was retired rather than reused. It
names a commit that was never published.

### Fixed

- Streamed shell output is assembled on line boundaries and labelled once per run
  of a stream, so a chunk boundary no longer splits a line, or a UTF-8 sequence,
  across two transcript blocks.
- A notice now breaks on its own newlines. Row wrapping measured display width
  only, and a newline is zero cells wide, so every multi-line notice in the
  product rendered as one run-on line.
- Cancelling a turn no longer disables the session. A forced stop settled its
  effect as an unknown outcome, which set a process-lifetime gate that nothing
  cleared, and every later submission failed on it. The unknown terminal is still
  recorded and automatic retry is still forbidden; only the gate on the
  operator's own next turn is lifted.
- The per-turn workspace checkpoint no longer fails on every turn in a
  repository that ignores the runtime state directory by its directory name, and
  reuses its index across a run instead of rebuilding it.
- Compaction derives its trigger from the model's real context window and output
  reservation. The absolute fallback is now only for a window no catalog proves.
- The Anthropic wire accepts a turn that ends with complete tool calls, matching
  the OpenAI adapter. Fail-closed is retained for every other terminal.
- A route that never connected can fail over: the shipped rule set was missing
  the class it classifies.

### Changed

- Tool output collapses to a fixed five rows — two from the head, the elision
  line, two from the tail — instead of choosing its size from the terminal's
  width. Reasoning collapses to one line so the layout does not jump.
- A built-in provider with no credential is no longer offered. Every offered
  entry says whether it is built in or came from the operator's config, and
  entries are grouped by service.
- Startup posture collapses to one line; the bypass notice stays separate
  because a default that auto-approves everything has to announce itself.
- A prompt that asks for orchestration in the operator's own words opts that
  turn in, without touching the session's effort or thinking budget.
- Unknown languages are no longer guessed at by the highlighter, and word-level
  status colouring is gone: the renderer marks lexical shape, not English words.
- Operator-visible strings name the product Iteron.


## [0.0.7] - 2026-08-15

### Fixed

- Advanced the public schema chronology exactly once from the published
  `v0.0.5` base. The immutable `v0.0.6` tag failed this check before release or
  asset creation; `v0.0.7` is the first downloadable release carrying the
  changes listed below.

## [0.0.6] - 2026-08-15

### Release status

- This tag was not published and has no release assets because the release
  workflow rejected its unchanged public schema chronology before any release
  mutation.

### Added

- Candidate Graph v3, a language-neutral trainer bridge, and the repository-only
  `iteron-harness` research protocol for bounded external harness optimization.
- Independent external contracts for all 28 optimization modules, including
  content-addressed implementations, state migration, transactional hot swap,
  rollback, and exact consumption evidence.
- A bounded offline TPE/successive-halving tuner, signed evidence-bundle schema
  and fixture, an evidence-only scoreboard, and the TUI experiment lab.

### Changed

- Exposed 1,894 source-current runtime settings through typed external addresses
  with zero advertised-but-inert or unaddressed rows; retained 830 safety,
  authority, durability, identity, and protocol candidates as read-only pending
  owning-human review.
- Made workflow topology model-directed through the generic `Workflow` surface
  instead of a fixed Ultracode planner, lexical auto-trigger, or hard-coded fan.
- Kept the base model and safety kernel frozen: evolution labels describe harness
  artifact provenance and cannot authorize model-weight training.

### Fixed

- Made provider setup usable from a terminal and a pipe while keeping credential
  values outside repository and diagnostic output.
- Repaired the release verification and content-canary gates exposed after the
  immutable `v0.0.5` publication.

### Known limitations

- `iteron-harness` remains a source-only research executable and is deliberately
  absent from release archives and the installer.
- No real benchmark campaign or performance-superiority result is claimed by
  this release.

## [0.0.5] - 2026-08-14

### Added

- Offline evolution evidence, checkpoint algebra, recorded-run projection,
  parameterized signed transcripts, and cross-model transfer.
- `providers[].model_capabilities`, including an operator-declared per-model
  `context_window_tokens` with operator provenance.
- A complete, addressable tunables surface plus runtime binding and trainable
  harness acceptance evidence.
- A reproducible, redacted public-history audit with exact synthetic-fixture
  fingerprints instead of path-wide secret-scanner exceptions.

### Changed

- Reduced the declared kernel trusted base to its two actual crates, pinned the
  nine core slot bindings, and corrected the corresponding specification claims.
- Routed normal Linux CI and Pages work to the repository DGX runner while
  pausing regular macOS and Windows pull-request lanes.
- Made the human-review and aggregate CI contexts the exact protected-main
  requirements.

### Fixed

- Restored the release-manifest receipt guard to the release path and drove
  build-info generation through the real argument parser.
- Hardened persistent-runner worktree cleanup, release verification tooling, and
  unchanged-schema inheritance from the trusted base.
- Upgraded the terminal UI dependency chain to a patched LRU implementation.

## [0.0.4] - 2026-08-10

### Fixed

- Corrected the public installer to find and install the renamed `iteron` archive
  member and command. The immutable `v0.0.3` tag remains unchanged.

## [0.0.3] - 2026-08-10

### Changed

- Renamed Core Code, its command, packages, archives, and user-facing prose to
  Iteron.
- Separated runtime and workflow adapters and made active tool processes
  interruptible with observable lifecycle state.

### Known limitations

- The shipped installer still looked for the pre-rename `core` archive member;
  `v0.0.4` supersedes this tag for installation.
- The release was built locally for `aarch64-apple-darwin` only because hosted
  Actions capacity was unavailable.

## [0.0.2] - 2026-08-07

### Added

- Completed the pre-alpha product-parity and platform surfaces, including the
  current TUI/workflow control, memory, attachment, HEIC, MCP, and experiment
  paths.
- Bounded live workflow display, dropped-path chips, and corrected startup and
  confinement reporting.

### Changed

- Workflows detach by default. `Workflow({...})` returns a receipt while the
  conversation stays usable; `Workflow({collect: "<run-id>"})` reads the result,
  and `background: false` retains in-turn execution.
- Image and file chips composed during a run remain attached to the queued text
  and preserve their `[Image #N]` anchor order.
- The trust-egress conjunct no longer applies to an operator-authority session,
  and delegated agents inherit the session posture. `--ask-permissions` or
  `--mode plan` restores the conjunct; child capability ceilings remain
  intersection-only.
- Raised bounded turn, wall-clock, tool-error, command-timeout, retained-output,
  file-read, grep, and web-fetch ceilings for long-running work.

### Fixed

- Isolated release build-info arguments, admitted the locked MIT-0 dependency,
  and verified native tar directory entries.

### Known limitations

- The release was built locally for `aarch64-apple-darwin` only because hosted
  Actions capacity was unavailable.

## [0.0.1] - 2026-08-06

### Added

- Documentation source, contributor guides, support policy, Code of Conduct,
  governance, and an evidence-gated roadmap.
- Version-bound installer and deterministic release tooling for archives,
  checksums, license attribution, SBOM, provenance, and public installation
  canaries.
- Protected collaboration workflow and machine-validated ownership map.
- Terminal-native interactive UI and one-shot CLI with text, JSON, and JSONL
  output.
- Anthropic, OpenAI, DeepSeek, GLM, MiniMax, Fireworks, and operator-defined
  provider routing with bounded catalog discovery.
- Typed workspace tools, permissions, hooks, skills, MCP integration,
  verification gates, and macOS/Linux sandbox backends.
- Hash-chained sessions with resume, continue, fork, checkpoint, and replay
  contracts.
- Modular Rust workspace for protocol, kernel, scheduling, providers, context,
  tools, sandboxing, records, observability, verification, evaluation, and
  evolution strategies.

### Changed

- The shipped default became unconfined and ungated: code execution is enabled,
  shell and file tools use the invoking account's authority, `--confine` selects
  the Seatbelt/bubblewrap backend, and `--mode plan` disables effects.

### Known limitations

- The release was built locally for `aarch64-apple-darwin` only and has no GitHub
  OIDC attestation.

[Unreleased]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.6...HEAD
[0.0.6]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/Plantcore-AI/Iteron/releases/tag/v0.0.1
