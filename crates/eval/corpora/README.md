# Pinned evaluation corpora

## Governed train/held-out split

[`core-eval-governed-2026-07-v1.json`](./core-eval-governed-2026-07-v1.json)
is the promotion-facing corpus snapshot. Its immutable identity is:

- `corpus_version`: `core-eval-governed-2026-07-v1`
- canonical `tasks` SHA-256:
  `4b08f1178b7c363186b0e4e324179b9c1823cbe06d531632611e566d3d4f3aed`

The internal partition is deliberately derived from separate upstream splits:

- `tune` selects only `marshmallow-code__marshmallow-1359`, copied from the
  pinned official SWE-bench Lite development split and declared `train`.
- `score` selects only `astropy__astropy-12907`, copied from the pinned official
  SWE-bench Lite test split and declared `held_out`.

`CorpusManifest::tasks_for` maps an evaluation purpose to exactly one partition,
and `CorpusManifest::task_for` returns a contamination error when a caller asks
for a task through the other purpose. The runner records both `corpus_version`
and `dataset_digest` in its result artifact. To add or replace tasks, create a
new manifest version and update its digest; no Rust source change is required.
Existing versioned manifests are immutable snapshots.

The train task is pinned to the official
[development parquet](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Lite/blob/6ec7bb89b9342f664a54a6e0a6ea6501d3437cc2/data/dev-00000-of-00001.parquet),
repository base
[`b40a0f4e33823e6d0f341f7e8684e359a99060d1`](https://github.com/marshmallow-code/marshmallow/commit/b40a0f4e33823e6d0f341f7e8684e359a99060d1),
and upstream [regression patch](https://github.com/marshmallow-code/marshmallow/pull/1359/files).
Its decoded prompt SHA-256 is
`6337f0b11fe9f200042e794046cec187e26d851f41c58c24e88500071e5d805e`,
and its decoded test-patch SHA-256 is
`09a4155999db5313084f78e1e0017e5637f30ab8e4ebf18b31eae3fdca86de3e`.

### Recorded held-out benchmark outcome

[`records/swe-bench-lite-gold-astropy-12907.json`](./records/swe-bench-lite-gold-astropy-12907.json)
binds the governed corpus version and digest to a completed boolean result for
the held-out task. It is an explicitly labeled import of the official
[SWE-bench Lite gold-patch validation report](https://github.com/SWE-bench/experiments/blob/2f15350cd32becc4569e0d826361048555b605c0/validation/lite_20240627/astropy__astropy-12907/report.json),
pinned to experiments revision
`2f15350cd32becc4569e0d826361048555b605c0`. The upstream report records that
the patch applied and both fail-to-pass tests succeeded, so the imported
`resolved` value is `true`. This receipt is benchmark-loader evidence, not a
claim that Core or a model produced the gold patch.

### Governed split integrity check

```sh
jq -j '.tasks[0].prompt' crates/eval/corpora/core-eval-governed-2026-07-v1.json | shasum -a 256
jq -j '.tasks[0].benchmark.test_patch' crates/eval/corpora/core-eval-governed-2026-07-v1.json | shasum -a 256
jq -cj '.tasks' crates/eval/corpora/core-eval-governed-2026-07-v1.json | shasum -a 256
```

## SWE-bench Lite: `astropy__astropy-12907`

[`swe-bench-lite-astropy-12907.json`](./swe-bench-lite-astropy-12907.json)
contains one held-out task copied from the official SWE-bench Lite test split.
Both `prompt` and `benchmark.test_patch` preserve the upstream row byte for
byte after JSON decoding; the solution patch is deliberately not included.

Pinned upstream material:

- Dataset revision:
  [`6ec7bb89b9342f664a54a6e0a6ea6501d3437cc2`](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Lite/tree/6ec7bb89b9342f664a54a6e0a6ea6501d3437cc2)
- Source row:
  [official test parquet](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Lite/blob/6ec7bb89b9342f664a54a6e0a6ea6501d3437cc2/data/test-00000-of-00001.parquet)
- Repository base commit:
  [`d16bfe05a744909de4b27f5875fe0d4ed41ce607`](https://github.com/astropy/astropy/commit/d16bfe05a744909de4b27f5875fe0d4ed41ce607)
- SWE-bench harness reference:
  [`f7bbbb2ccdf479001d6467c9e34af59e44a840f9`](https://github.com/SWE-bench/SWE-bench/tree/f7bbbb2ccdf479001d6467c9e34af59e44a840f9)

The pre-patch `verify_command` runs only the test file selected by the official
harness directive. The runner applies `test_patch` after capturing the
candidate diff. The `ground_truth_command` then narrows that file to the two
official `FAIL_TO_PASS` node IDs:

- `test_separable[compound_model6-result6]`
- `test_separable[compound_model9-result9]`

The upstream harness constructs its command from the repository/version
`test_cmd` plus test files extracted from `test_patch`; for Astropy 4.3 that
base command is `pytest -rA`. See
[`get_test_directives` and command construction](https://github.com/SWE-bench/SWE-bench/blob/f7bbbb2ccdf479001d6467c9e34af59e44a840f9/swebench/harness/test_spec/python.py)
and the
[`astropy/astropy` 4.3 environment spec](https://github.com/SWE-bench/SWE-bench/blob/f7bbbb2ccdf479001d6467c9e34af59e44a840f9/swebench/harness/constants/python.py).

### Integrity and environment boundary

- Decoded prompt SHA-256:
  `c01334ec1b21a089c650cf2e7b96ab974469076bf1260d23885799e1f0a7551f`
- Decoded test-patch SHA-256:
  `5ef90b640ffce4590bb61ef2ea0e3256416dddf41b45bf4f2c3610a6e8c53718`
- Canonical `tasks` SHA-256:
  `7cc073cc962954bab0bd6c440e55a554124fa9cfbdf694459aeed03c13ef7e79`

`environment_image` is `null` because the pinned dataset row does not
declare an exact image reference. The manifest records the row's
`environment_setup_commit`, but `core-eval` does not provision the official
Docker environment from that metadata. Callers must provide a compatible
Astropy 4.3/SWE-bench environment before running these commands. Likewise,
`provenance.license` is `null` because the pinned dataset card declares no
license value; this does not make any claim about the upstream Astropy
repository's separate license.

### Read-only integrity check

```sh
jq -j '.tasks[0].prompt' crates/eval/corpora/swe-bench-lite-astropy-12907.json | shasum -a 256
jq -j '.tasks[0].benchmark.test_patch' crates/eval/corpora/swe-bench-lite-astropy-12907.json | shasum -a 256
jq -cj '.tasks' crates/eval/corpora/swe-bench-lite-astropy-12907.json | shasum -a 256
```
