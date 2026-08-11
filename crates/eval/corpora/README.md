# Pinned evaluation corpora

## SWE-bench Pro OS schema-v2 slice

[`swe-bench-pro-os-ca10a60-slice-v2.json`](./swe-bench-pro-os-ca10a60-slice-v2.json)
is a native schema-v2 slice imported from the official MIT-licensed
[`scaleapi/SWE-bench_Pro-os`](https://github.com/scaleapi/SWE-bench_Pro-os)
repository at revision
[`ca10a60a5fcae51e6948ffe1485d4153d421e6c5`](https://github.com/scaleapi/SWE-bench_Pro-os/tree/ca10a60a5fcae51e6948ffe1485d4153d421e6c5).
The source JSONL is additionally pinned by SHA-256
`b5b2462bfbf5aeb2cb7ba7d215778a1768b85f9d7ad7f748546c7f80a0ad1510`.
The checked-in slice has:

- corpus version
  `swe-bench-pro-os-ca10a60a5fcae51e6948ffe1485d4153d421e6c5-slice-v2`;
- canonical task digest
  `a97b67f804b06bc3e546fc714de6eabdce2d4f75b26144482bfc774c9ce05d7a`;
- one OpenLibrary train task with two Python F2P tests;
- one Ansible held-out task with one F2P and 22 P2P tests; and
- one Teleport held-out task with a Go `test_cmd`, proving the manifest is not
  Python-only.

The importer copies each prompt, hidden test patch, repository commit, and test
set from the pinned row. It deliberately never writes the upstream solution
patch into the corpus. Docker Hub references are derived by the upstream
[`helper_code/image_uri.py`](https://github.com/scaleapi/SWE-bench_Pro-os/blob/ca10a60a5fcae51e6948ffe1485d4153d421e6c5/helper_code/image_uri.py)
algorithm and stored as full `jefzda/sweap-images:<tag>` references.

`local_no_daemon` is an explicitly lower-fidelity fixture path, not an invented
environment build. An `environment_setup_commit` hash alone does not specify a
setup repository or build recipe. Image-less fixtures therefore run their
`test_cmd` on the pinned host toolchain under `Confinement::egress_off`. If a
real task declares an image and that image cannot be prepared, the same host
command may run as a bounded diagnostic, but its receipt is forced to
`InfrastructureFailed` and is censored from benchmark resolution.

Reproduce and verify the slice:

```sh
python3 crates/eval/corpora/import_swe_bench_pro.py --check
jq -cj '.tasks' crates/eval/corpora/swe-bench-pro-os-ca10a60-slice-v2.json | shasum -a 256
```

For a live gold-patch witness, extract the withheld upstream patch outside the
repository, then use the bounded validator. The validator writes a completed
receipt only when the Core two-sided oracle resolves through the Docker backend
with egress disabled:

```sh
TASK=instance_ansible__ansible-be59caa59bf47ca78a4760eb7ff38568372a8260-v1055803c3a812189a1133297f7f5468579283f86
python3 crates/eval/corpora/import_swe_bench_pro.py \
  --extract-gold "$TASK" --gold-output /tmp/iteron-eval-ansible-gold.patch
cargo run --locked -p iteron-eval --example validate_pro_gold -- \
  --corpus crates/eval/corpora/swe-bench-pro-os-ca10a60-slice-v2.json \
  --task "$TASK" \
  --gold-patch /tmp/iteron-eval-ansible-gold.patch \
  --oracle-workspace /tmp/iteron-eval-ansible-gold-oracle \
  --output /tmp/iteron-eval-ansible-gold-receipt.json \
  --source https://raw.githubusercontent.com/scaleapi/SWE-bench_Pro-os/ca10a60a5fcae51e6948ffe1485d4153d421e6c5/helper_code/sweap_eval_full_v2.jsonl \
  --source-revision ca10a60a5fcae51e6948ffe1485d4153d421e6c5 \
  --recorded-at 2026-07-30 --executor dgx-spark
```

The checked-in
[`records/swe-bench-pro-gold-ansible-iptables.json`](./records/swe-bench-pro-gold-ansible-iptables.json)
is the resulting live DGX Spark receipt. It records the held-out Ansible F2P
test failing before the gold patch and passing after it, with all 22 P2P tests
passing on both sides. Every command ran through the Docker backend with
egress disabled. Its canonical sorted-JSON SHA-256 is
`3903ca6223307aa55e83d24bf68272de9f5ba59fa9b0905ea83bc7c947276a73`;
verify it with:

```sh
jq -cS . crates/eval/corpora/records/swe-bench-pro-gold-ansible-iptables.json | shasum -a 256
```

## Fair-control and trained-bundle fixtures

[`reference-harnesses/swe-agent-3ea751c.json`](./reference-harnesses/swe-agent-3ea751c.json)
pins SWE-agent source revision
`3ea751c087f32b16e039a2233dd6eefecef325d5`. The adapter verifies the clean
checkout and origin, launches the pinned entrypoint, reads SWE-agent's real
strict `.pred` contract, and passes only `model_patch` to Core's F2P/P2P oracle.
SWE-agent's own outcome is not consulted. The trusted coordinator retains the
provider route needed to call frozen model M, while the repository execution
container is forced to `--network=none`; Core then scores the captured diff in
its independently egress-off oracle. This separates necessary provider egress
from untrusted repository code rather than granting the task container network
access or provider credentials.

[`records/untrained-vs-swe-agent-paired-fixture.json`](./records/untrained-vs-swe-agent-paired-fixture.json)
is the golden paired-bootstrap report for the real slice identity.
[`records/trained-bundle-heldout-fixture.json`](./records/trained-bundle-heldout-fixture.json)
is the golden trained-vs-untrained, cross-model portable-fraction, and isolated
kernel-tax report. Both use explicitly named fixture models and recorded
transcripts: they validate the deterministic measurement contract and are not
claims about live model performance.

## Parallel runner controls

The compatibility-guarded `iteron-eval` entry point keeps its frozen
schema-authority `main` and `run_cell` path. Its CLI now defaults to 250 turns;
`--max-turns 0` is the explicit uncapped mode. `run_evaluation` executes cells
through the bounded parallel engine with 50 workers and sorts the completed
cells by their stable key before aggregation.

Callers that need a different worker bound or an immutable trained bundle use
`ParallelEvalOptions` with `run_evaluation_parallel`. `workers` must be in
`1..=100`; `uncapped` deliberately omits Core's turn flag; and `bundle_path` is
copied once into the fresh run root, sealed read-only, hashed, and recorded in
the manifest before any worker starts. Each live cell still enters the frozen
machine-result parser exactly once, then its captured diff is scored in a fresh
oracle checkout. The four F2P/P2P pre/post receipts are serialized into
`oracle_detail`, while infrastructure failures remain typed and excluded from
the completed-cell denominator.

## Governed train/held-out split

[`iteron-eval-governed-2026-07-v1.json`](./iteron-eval-governed-2026-07-v1.json)
is the promotion-facing corpus snapshot. Its immutable identity is:

- `corpus_version`: `iteron-eval-governed-2026-07-v1`
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
jq -j '.tasks[0].prompt' crates/eval/corpora/iteron-eval-governed-2026-07-v1.json | shasum -a 256
jq -j '.tasks[0].benchmark.test_patch' crates/eval/corpora/iteron-eval-governed-2026-07-v1.json | shasum -a 256
jq -cj '.tasks' crates/eval/corpora/iteron-eval-governed-2026-07-v1.json | shasum -a 256
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
`environment_setup_commit`, but `iteron-eval` does not provision the official
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
