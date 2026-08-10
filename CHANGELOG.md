# Changelog

All notable changes to Iteron are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). During `0.0.x`, public
interfaces may change between releases.

## [Unreleased]

### Changed

- **A workflow now detaches by default.** `Workflow({...})` returns a receipt and
  the conversation stays usable while the fan-out runs; the result is read with
  `Workflow({collect: "<run-id>"})`. `background: false` is the opt-out for a model
  that cannot continue without the result. Detaching still requires a session that
  owns runs — in one-shot there is none, so the run executes in-turn and the tool
  result says the request was not granted, as before.
- **Chips can be composed during a run, and travel with the text they were composed
  with.** Dropping an image while the agent works used to produce a line of path
  text: the paste lane skipped image parsing whenever a turn was in flight, so no
  chip appeared. A draft carrying chips is queued behind the turn rather than
  steered into it (`Op::Steer` is text and the protocol is frozen), and the queued
  submission is assembled by the same staging the composer uses, so its images,
  files and `[Image #N]` anchor order reach the wire. Ctrl-V bitmap capture is
  available during a run on the same terms.
- **(security posture) The trust-egress conjunct no longer applies to an
  operator-authority session, and sub-agents inherit the posture.** A turn that has
  read untrusted content may now call an egress tool; `--ask-permissions` and
  `--mode plan` restore the conjunct. Delegated and workflow children inherit the
  session's bypass instead of running gated with no approval channel to answer
  them — their capability ceiling is unchanged and still intersected downward, so a
  read-only definition stays read-only. See `SECURITY.md` for what this surrenders.

- **BREAKING (security posture): the default is now unconfined.** By owner
  decision on 2026-08-05, `core` ships with the operator's own authority instead
  of the sandbox. `bash` reaches the network and the whole filesystem; `read_file`
  and `write_file` resolve any absolute path, `..` climb, or symlink the invoking
  account can reach, including `~/.ssh`; code execution is enabled by default
  rather than requiring `--allow-code`. The Seatbelt and bubblewrap backends are
  unchanged and are selected by the new `--confine` flag, which governs executed
  code; filesystem tools address the host in either posture. `--mode plan` still
  disables effects entirely. See `docs/using/permissions-and-sandbox.md`.
- Ceilings raised, not removed (invariant #1 is that a ceiling exists, not that it
  is small): turns 40 → 600, wall clock 1800s → 14400s, consecutive tool errors
  3 → 25, `bash` timeout 120s → 3600s and retained output 256 KiB → 8 MiB per
  stream, `read_file` output 40 KB → 400 KB, `grep` 100 → 1000 matches and 64 KB →
  512 KB, `web_fetch` 100 KB/1500 lines → 1 MB/15000 lines and 15s → 60s.

### Added

- Offline evolution evidence, checkpoint algebra, recorded-run projection,
  parameterized signed transcripts, and cross-model transfer.
- `providers[].model_capabilities`, an operator-declared per-model
  `context_window_tokens`. Before this, only the built-in GLM route had a known
  context window, so every other provider fell back to the absolute compaction
  trigger and skipped the pre-flight context-admission check. A declaration is
  recorded with operator provenance and never outranks an official vendor snapshot.

## [0.0.1] - 2026-07-15

### Added

- Public documentation website, contributor development guides, support policy,
  Code of Conduct, governance, and an evidence-gated roadmap.
- Verified one-line installer, deterministic release archives, checksums, license
  attribution, SBOM, provenance, and public installation canaries.
- Protected public collaboration workflow and machine-validated ownership map.
- Terminal-native interactive UI and one-shot CLI with text, JSON, and
  stream-JSON output.
- Anthropic, OpenAI, DeepSeek, GLM, MiniMax, Fireworks, and operator-defined
  provider routing with bounded catalog discovery.
- Typed workspace tools, permissions, hooks, skills, MCP integration, verification
  gates, and macOS/Linux sandbox backends.
- Hash-chained sessions with resume, continue, fork, checkpoint, and replay
  contracts.
- Modular Rust workspace for protocol, kernel, scheduling, providers, context,
  tools, sandboxing, records, observability, verification, evaluation, and future
  evolution strategies.

[Unreleased]: https://github.com/Plantcore-AI/Iteron/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/Plantcore-AI/Iteron/releases/tag/v0.0.1
