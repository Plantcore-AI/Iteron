# Changelog

All notable changes to Iteron are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). During `0.0.x`, public
interfaces may change between releases.

## [Unreleased]

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

[Unreleased]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.5...HEAD
[0.0.5]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/Plantcore-AI/Iteron/releases/tag/v0.0.1
