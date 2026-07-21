# Pinned evaluation corpora

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
