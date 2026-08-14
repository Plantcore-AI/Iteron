# Iteron v0.0.5 evidence-bound claim sheet

This page is the public one-page claim boundary. A number is included only when
the repository contains the cited machine-readable or source evidence. Paths are
relative to the repository root.

| Current claim | Repository evidence | Scope |
| --- | --- | --- |
| The workspace version is `0.0.5`. | `Cargo.toml` workspace package version; matching Iteron package entries in `Cargo.lock`. | Source version, not proof that every release target is published. |
| The optimization census schema is version `4`. | `governance/optimization-census.json` field `schema_version`. | Census format only. |
| The census contains `2,724` independent candidate rows: `1,894` runtime-settable, runtime-applied, and externally addressed; `0` unaddressed; `0` binding-required; `830` invariant/read-only. | `governance/optimization-census.json` summary fields. | Addressability census, not performance or quality. |
| The audited harness surface describes `28` modules and `66` services. | `docs/development/deepseek-harness-gap-audit.md`. | Audit inventory under that document's definitions; not universal trainer completion. |
| The research bridge protocol is `iteron-research/1`. | `docs/reference/research-harness-protocol.md`. | Protocol identifier, not evidence of a completed campaign. |
| Model adapters and model weights are structurally refused by manifest validation. | `crates/evolve/src/lib.rs`, `PolicyManifest::validate`, plus its reserved-artifact tests and `xtask/src/conformance.rs`. | Iteron admits harness artifacts only. |

## Explicit non-claims

Iteron does **not** claim production readiness, confidentiality isolation,
complete microkernel conformance, autonomous live promotion, model training,
universal harness optimization, parity with another coding agent, or a completed
real research campaign. It makes **no performance, latency, cost, quality, or
benchmark-superiority claim**. Counts above describe repository structure and
contract coverage only; they are not empirical outcome measures.

Any future empirical claim must identify an immutable campaign manifest,
dataset/task definition, baseline, model identity, evaluator, raw retained
results, analysis code, uncertainty, and failure cases. Until those artifacts
exist and are reviewable, result cells remain `PENDING`.
