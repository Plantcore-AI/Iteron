# Research harness protocol

[中文版](research-harness-protocol.zh-CN.md)

`iteron-research/1` is the benchmark-neutral, language-neutral interface between an external
research harness and Iteron's optimization surface. It accepts the same universal
`TunerCandidate` used by the native tuner and constructs bounded run plans without importing
`iteron-evolve`, selecting winners, promoting candidates, or granting new runtime authority.

`iteron-harness` is a repository research executable, not a released Iteron command. It is not
included in release archives or installers, and release CI does not package or install it. Build it
explicitly from a reviewed checkout with `cargo build --locked -p iteron-eval --bin iteron-harness`. The source-controlled
[request schema](https://github.com/Plantcore-AI/Iteron/blob/main/crates/eval/schemas/iteron-research-1.schema.json),
stdlib-only [Python client](https://github.com/Plantcore-AI/Iteron/blob/main/crates/eval/harbor/iteron_research_client.py),
and credential-free [fixture optimizer](https://github.com/Plantcore-AI/Iteron/blob/main/crates/eval/harbor/fixture_optimizer.py) are the portable integration
surface; the Rust runtime validator remains authoritative.

Every request is one closed JSON object:

```json
{
  "protocol": "iteron-research/1",
  "request_id": "caller-unique-id",
  "payload": {
    "operation": "surface",
    "adapter": {
      "benchmark_id": "iteron-cli",
      "benchmark_version": "1"
    }
  }
}
```

Every response repeats the exact `protocol` and `request_id`. Decoders reject unknown fields,
duplicate object keys, unsupported protocols, malformed identifiers, unpinned adapter versions,
oversized documents, unbounded paths/budgets, and mismatched response correlation.

## Operations

- `surface` returns `iteron_tunables::surface_json()`, the adapter registry, and its digest.
- `candidate_validate` accepts `candidate_sha256` plus one complete `TunerCandidate` containing
  its schema-v3 graph. For a non-empty implementation set,
  `implementation_candidate_path` is a required absolute create-new output. Validation calls the
  marketplace activation parser, which re-reads each canonical catalog, hashes its canonical
  manifest and executable artifact, and mints registry plans before the harness writes the bounded,
  no-follow activation JSON. For non-empty direct-config or caller-input patch sets,
  `native_materialization_path` is likewise a required absolute create-new destination under the
  native adapter. The response returns graph, activation, native-materialization, byte, and patch
  identities.
- `run` requires a candidate previously accepted by the same persistent session, verifies its
  adapter, candidate digest, and profile digest, then validates one `iteron_cli` or exact
  `terminal_bench_2_1` run request and constructs a deterministic shell-free `AdapterCommand`.
- `cancel`, `result`, and `evidence` address the same adapter/run identity retained by one
  persistent server process. Every run-lifecycle request and response repeats candidate id,
  `candidate_sha256`, `profile_sha256`, and the optional bare activation digest, so a run cannot be
  rebound to another implementation set even when the rendered profiles are byte-identical.

`candidate_sha256` is the exact native tuner content identity (`sha256:` followed by 64 lowercase
hex characters) over the complete candidate. `profile_sha256` is the bare 64-character SHA-256
of its canonical rendered profile. The two are intentionally distinct.
Candidate implementation bindings accept stateless `iteron-implementation/1` and current
`iteron-implementation/2`; state migration requires v2. They bind module, implementation id,
absolute canonical catalog/artifact paths, and prefixed manifest/artifact digests into
`candidate_sha256`. A run must repeat the materialized activation path and bare digest
inside its adapter request. The Iteron adapter appends the exact argv pair
`--implementation-candidate PATH --implementation-candidate-digest DIGEST`; it never reconstructs
or substitutes an implementation source. Implementation runs also pin `--harness-profile
research`, as required by the CLI admission boundary.

The built-in registry has three exact entries:

- `iteron-cli` / `1`, the generic ordinary Iteron profile CLI adapter;
- `iteron-native-adapter` / `2`, an operator-pinned external process that consumes v3
  direct-config/caller-input patch materialization and emits per-address consumption evidence;
- `terminal-bench` / `2.1`, a registry wrapper around the separate exact Terminal-Bench 2.1
  contract. The registry does not loosen that contract or supply a default version.

Each entry publishes request/result schema identifiers, supported operations, and a digest over
that identity. Missing and wrong versions fail closed.

## CLI

One-shot calls read one request from stdin and write one response to stdout:

```sh
iteron-harness surface < request.json
iteron-harness candidate-validate < candidate-request.json
```

`iteron-harness serve` is persistent NDJSON: one bounded request per input line and one correlated
response per valid line. It remains dry-run by default. In that mode, responses say
`execution_mode: "dry_run"`: `run` returns `planned`, `cancel` changes it to `cancelled`, and
`result`/`evidence` return no terminal artifact.

Real execution is an explicit process-level operator choice, not a remotely selectable bit in an
untrusted run request:

```sh
iteron-harness serve --execute --iteron-cli /absolute/path/to/iteron
```

Native patches use a separately pinned adapter executable:

```sh
iteron-harness serve --execute --native-adapter /absolute/path/to/adapter
```

The harness writes a bounded create-new `iteron-candidate-materialization/2` document and invokes
the adapter directly with exact profile, candidate, materialization, experiment, topology, run,
result, and receipt arguments. Completion requires an
`iteron-candidate-materialization-consumption/2` receipt in the predeclared path. It must contain
one ordered row per production-plan node, implementation binding, and patch; repeat each exact
address and input/observed digest; and prove dependency, condition, lifecycle, load, apply, and
observation stages. Missing, stale, reordered, partial, duplicate-key, or digest-rebound evidence
converts an apparent process success into a failed run.

Execute mode materializes the previously validated candidate profile only when the requested
profile path is absent or already byte-identical. The process-level CLI path is canonicalized and
bound to its observed size and SHA-256 when the session opens, then reverified immediately before
every spawn. It then spawns the exact registry-produced program and argv directly, never through a
shell. The supervisor clears the ambient environment,
installs only the command's fixed public environment, and directly inherits values for exactly the
sorted credential names admitted by the run spec. Those values are never stored in session state,
argv, responses, result summaries, or evidence metadata.

The supervisor enforces independent wall, stdout, stderr, retained-evidence, and address-space
limits. On Unix it starts a dedicated process group and installs the address-space ceiling before
`exec`; cancel, timeout, output/evidence overflow, session EOF/drop, and natural leader exit all
kill residual descendants and reap the direct child. A platform without those primitives refuses
execute mode rather than weakening the bounds. States are truthful and monotonic for the observed
lifecycle: `running`, `awaiting_result`, `completed`, `failed`, `cancelled`, `timed_out`,
`stdout_limit`, `stderr_limit`, or `evidence_limit`. Address-space exhaustion is reported as a
bounded execution failure because the child cannot reliably distinguish allocator refusal from
another nonzero exit. `result` returns only a content-free parsed terminal summary; untrusted
stdout/stderr text is never copied into protocol JSON. `evidence` returns verified
path/byte/SHA-256 references, not file contents.

An implementation run is not `completed` merely because Iteron exited successfully. The CLI must
atomically emit
`<runs_dir>/.iteron-implementation-<activation_sha256>-consumption.json` using schema
`iteron-implementation-consumption/1`. It repeats the candidate, activation, and final CLI run
identities and contains the activation-ordered module/id list with truthful `loaded`, `started`,
`terminal`, and `stopped` evidence. Missing, duplicate-key, stale, partial, reordered, oversized,
or false evidence makes the run fail closed and clears the terminal result.

For `terminal-bench/2.1`, Iteron stdout remains the `result_path` named by the exact adapter. The
independent Terminal-Bench verifier writes its `ExternalHarnessResult` to the `adapter_result_path`
returned by `run`, currently:

```text
<runs_dir>/.iteron-research-<task_id>-<trial_id>-result.json
```

Until that independently produced sidecar exists, a reaped adapter process is
`awaiting_result`, not a fabricated benchmark success. `result`/`evidence` parse the exact
Terminal-Bench 2.1 schema, re-check benchmark/task/profile/revision identity, process exit and
stdout/stderr counts, and hash every referenced artifact before reporting `completed`.
The current Terminal-Bench 2.1 result contract has no standardized implementation-consumption
receipt. Its registry entry therefore advertises no implementation activation support and rejects
an implementation-bearing run with `unsupported_implementation_activation`; it never runs an
inert candidate.

The returned command itself remains inspectable in both modes: it clears ambient environment,
fixes public locale/time/color values, and names only allowlisted credential variables.

The stdlib-only client in `crates/eval/harbor/iteron_research_client.py` provides one-shot
`ResearchClient` plus persistent `ResearchSessionClient`. The latter exposes the full external
trainer sequence—candidate validation, run, cancel, result, and evidence—and makes execute mode an
explicit constructor choice. It resolves the harness executable to an absolute path, supplies a
fixed public subprocess environment, and optionally forwards only canonical allowlisted credential
names selected by the operator. Both clients reject duplicate response keys and enforce protocol,
request-id, operation, and candidate correlation.

From a clean checkout, an anonymous, credential-free compatibility probe can be run without a
provider or benchmark campaign:

```sh
cargo build --locked -p iteron-eval --bin iteron-harness
python3 crates/eval/harbor/fixture_optimizer.py \
  --harness "$(pwd)/target/debug/iteron-harness"
```

This exercises only the public surface handshake. Supplying `--candidate PATH` additionally
validates the exact Candidate Graph document; the fixture never executes, selects, promotes, or
claims performance.

Repository-only engineering fixtures use the same executable:

```sh
target/debug/iteron-harness scoreboard \
  crates/eval/fixtures/evidence-bundle-v1 \
  fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618
target/debug/iteron-harness hermetic-fixture --output /absolute/create-new-receipt.json
target/debug/iteron-harness synthetic-cycle \
  --authorization "$(pwd)/crates/eval/tests/fixtures/synthetic-cycle-authorization-v1.json" \
  --output /absolute/create-new-cycle-directory
```

`scoreboard` accepts only a verified signed Evidence Bundle v1 and derives its denominators,
terminal-outcome breakdown, and interval. The committed bundle is marked
`synthetic_fixture`, so its board says `publishable_measured_result: false`. `hermetic-fixture`
proves deterministic manifest and physical-attempt identity handling without a live score.
`synthetic-cycle` consumes a separate authorization artifact and exercises the frozen-model,
provider-free engineering path through exact rollback; its receipt likewise refuses a live-score
claim.

## Claim boundary

Dry-run proves protocol compatibility and the validation-time marketplace activation identity; it
does not start Iteron or an implementation. Execute mode proves one bounded, correlated process
run only when the CLI's exact consumption receipt is also verified. Neither mode compares
candidates, selects a winner, invokes `iteron-evolve`, promotes a candidate, runs a benchmark
campaign, or substantiates a leaderboard claim.
