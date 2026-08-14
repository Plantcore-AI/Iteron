# Installed cross-harness qualification

T49 qualification is a fail-closed evidence check over one exact installed Iteron binary. It is
functional acceptance only. It does not compare scores, select a winner, promote a candidate, or
claim superiority.

The runner is a Python standard-library client. It actively:

1. opens a pinned, absolute, executable `iteron` regular file without following a symlink and
   rechecks its byte count and SHA-256;
2. checks exact `iteron --version` output and the raw SHA-256 plus closed JSON shape of
   `iteron --machine-contract`;
3. independently pins `iteron-harness`, calls its `iteron-research/1` `surface` operation from
   Python, and verifies response correlation;
4. requires the adapter registry to be exactly `iteron-cli/1`, `iteron-native-adapter/2`, and
   `terminal-bench/2.1`; and
5. requires the installed surface to return the exact ordered 28-module registry.

It then validates every externally supplied proof described below. Missing, duplicated, stale,
oversized, symlinked, cross-binary, wrong-adapter, non-passing, or unknown evidence fails the whole
bundle. No partial qualification result is emitted.

## Run

Use absolute paths. The output path must not already exist:

```sh
python3 scripts/cross_harness_qualification.py \
  --manifest /absolute/path/to/t49-qualification.json \
  --output /absolute/path/to/t49-qualified-bundle.json
```

Omit `--output` to write one bounded JSON result to stdout. Success exits `0` with schema
`iteron-cross-harness-qualification-result/1`. Refusal exits `2` with a bounded machine-readable
failure object. The runner launches no shell and forwards no credentials.

Focused contract test:

```sh
python3 -m unittest scripts/test_cross_harness_qualification.py
```

## Qualification manifest

The manifest schema is `iteron-cross-harness-qualification/1`. Unknown and duplicate JSON keys are
rejected. Its top-level keys are exactly:

- `schema_id` and a non-empty `qualification_id`;
- `iteron_binary`: `path`, `bytes`, `sha256`, exact `version_output`, and raw
  `machine_contract_sha256`;
- `harness_binary`: `path`, `bytes`, and `sha256`;
- `terminal_bench`: exact `benchmark_id: terminal-bench`, `benchmark_version: "2.1"`, and one
  campaign `proof`;
- `module_matrix`: exactly 56 rows, one `ablation` and one `swap` for each ordered module returned
  by the installed surface;
- `optimizer_families`: at least five distinct declarations from the closed `EvolutionMethod`
  vocabulary;
- `stateful`: migration, committed happy path, deterministic replay, and ordered fault/rollback
  proofs for `verify`, `shadow_load`, `quiesce`, `snapshot`, `migrate`, `restore`, `readiness`,
  `atomic_switch`, and `drain`; and
- `claims`: exactly `{"score_superiority": false, "scope": "functional_acceptance_only"}`.

Every evidence reference has exactly `path`, `bytes`, and bare lowercase `sha256`. Paths must be
absolute, regular, non-symlink files. Each acceptance cell must use independent proof bytes and a
unique proof id. Individual proofs are capped at 2 MiB, their total at 128 MiB, process output at
32 MiB, and the final result at 2 MiB.

## Proof document

Every reference resolves to strict JSON schema `iteron-cross-harness-proof/1` with exactly these
fields:

```json
{
  "schema_id": "iteron-cross-harness-proof/1",
  "proof_id": "operator-unique-id",
  "proof_kind": "module_swap",
  "subject_id": "context.assembly/swap",
  "status": "passed",
  "iteron_binary_sha256": "64 lowercase hex characters",
  "harness_binary_sha256": "64 lowercase hex characters",
  "adapter": {
    "benchmark_id": "iteron-cli",
    "benchmark_version": "1"
  },
  "input_sha256": "64 lowercase hex characters",
  "output_sha256": "64 lowercase hex characters",
  "evidence_sha256": "64 lowercase hex characters",
  "score_micros": null,
  "claim_scope": "functional_acceptance_only"
}
```

Closed `proof_kind` values are `terminal_bench_campaign`, `module_ablation`, `module_swap`,
`optimizer_family`, `state_migration`, `fault_injection`, `rollback`, `deterministic_replay`, and
`hotswap_commit`. Module and state proofs use `iteron-cli/1`; the Terminal-Bench proof uses exact
`terminal-bench/2.1`. A Terminal-Bench proof may retain one bounded `score_micros`, but the runner
does not compare it and the result always records `score_superiority_claimed: false`.

## Operator campaign command

`iteron-harness campaign` is the bounded operator entry point for T52. It clears child-process
environments and uses no shell or credential value. Its local executable phase:

- launches one registry-minted external provider process for every independent module swap and
  ablation, requires a correlated terminal observation, and stops and reaps all 56 children;
- negotiates five distinct closed `EvolutionMethod` families through the public trainer bridge;
- commits one state migration through the public transactional HotSwap coordinator;
- injects a fault at each of the nine HotSwap phases and observes rollback to the old generation;
  and
- replays the durable hash-chained ledger twice and requires byte-identical records and the same
  active generation.

Run the credential-free executable coverage and request a structured prerequisite receipt:

```sh
/absolute/path/to/iteron-harness campaign \
  --qualification-id operator-chosen-id
```

The current audited installation has no official Harbor executable, no checked-out pinned TB2.1
dataset, and no sandbox/provider authorization. In that state the command exits `2` with schema
`iteron-cross-harness-campaign-receipt/1`. The receipt separates real locally observed runtime
coverage from external prerequisites and sets `manifest_path` to `null`. It is not a proof document
and the validator cannot consume it as one.

The exact external pin is Harbor `0.20.0` at commit
`5342956db1433368dd0b9b54286129ae415beebc`, Terminal-Bench repository commit
`5c8eadf1f393183288fa08b8f73ca9a469cc5e00`, tasks tree
`2f0f5fdc68f0befd9b4745386eb8698264b00d8a`, dataset
`terminal-bench/terminal-bench-2-1`, 89 tasks, and at least five trials per task. The checked-in
Harbor adapter remains the execution bridge. Provider and sandbox authorization must be arranged
outside this credential-free command; neither credential names nor values enter its receipt.

The 56 local child lifecycles establish the marketplace external-process boundary only. The
installed Iteron CLI does not have a credential-free public operation that runs a model turn and
consumes those implementations. The refusal names this separately as
`installed_iteron_consumption_unavailable`; the campaign does not relabel process-lifecycle
coverage as installed-binary task evidence.

Before the runner can pass, the external campaign must still supply:

- an independently verified complete Terminal-Bench 2.1 campaign proof, including failed and
  timed-out trials rather than only successful scores;
- 56 independent installed-binary run proofs covering every single-module swap and ablation;
- declarations and run evidence for at least five optimizer families;
- a committed state migration plus deterministic replay proof; and
- fault injection and observed rollback evidence at every pre-commit HotSwap phase.

The campaign and runner never substitute dry-run plans, unit tests, catalog declarations,
protocol negotiation, or agent-authored claims for these inputs. Only after the official run has
been independently correlated may the command write the existing
`iteron-cross-harness-qualification/1` manifest and proof files for the validator. Until those
external prerequisites exist, T49 remains blocked rather than being reported as superior or
complete.
