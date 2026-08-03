# Core Code adapter for Terminal-Bench 2.1

This directory is the version-pinned bridge from Core Code to Harbor. It does
not reimplement the Terminal-Bench verifier and does not translate tasks into
the SWE-bench-shaped `core-eval` corpus. Harbor remains authoritative for task
images, resources, agent and verifier timeouts, artifact collection, rewards,
and retry/trial layout.

The audited upstream inputs are:

- Terminal-Bench 2.1 repository commit
  `5c8eadf1f393183288fa08b8f73ca9a469cc5e00`;
- its `tasks` Git tree `2f0f5fdc68f0befd9b4745386eb8698264b00d8a`;
- 89 task directories and 89 entries in `tasks/dataset.toml`;
- Harbor commit `5342956db1433368dd0b9b54286129ae415beebc`
  (`pyproject.toml` identifies this checkout as version 0.20.0); and
- the leaderboard requirement of at least five trials per task.

The sample configuration therefore fixes `n_attempts: 5`. Do not reduce it for
a leaderboard claim, change task timeouts/resources, or silently substitute a
newer dataset checkout. A new upstream revision requires a new evidence record
and a compatibility run.

## Binary boundary

Build one 64-bit little-endian Linux Core ELF binary for the target container
architecture. Set its absolute host path, lowercase SHA-256, and exact
`x86_64` or `aarch64` architecture in `terminal-bench-2-1.yaml`. The adapter
rejects relative paths, symlinks, non-ELF input, architecture mismatch, empty
or oversized binaries, and digest mismatch. It uploads those exact bytes to an
unpredictable path in each fresh Harbor environment, rejects destination
replacement, and verifies the digest before and after installation. It never
downloads `latest` and never reads or writes a credential file.

Provider credentials are passed by Harbor's `agent.env` configuration to the
installed agent process. Use a host template such as
`OPENAI_API_KEY: ${OPENAI_API_KEY}`; Harbor keeps the persisted form templated.
The adapter requires exactly the one canonical credential variable for a
built-in route, or exactly `key_env` for a custom `base_url`, and rejects every
additional environment key so `HOME`, Core configuration, proxies, or tuning
flags cannot silently perturb an arm. Never put a literal credential value in
YAML or an adapter kwarg.

Core's operator home/config, memory, hooks, MCP declarations, sessions, and
caches are rooted in unpredictable, fresh `/tmp/core-harbor-*` paths. Any
task-provided `/app/.core` path is refused because project configuration or an
agent catalog could perturb one experimental arm. The append-only Core runs,
unmixed JSONL stdout, and machine contract are written under `/logs/agent`, so
Harbor captures them with the trial record.

## Run

Clone the exact repositories and verify the pins:

```sh
python validate_upstream.py \
  --terminal-bench-root /path/to/terminal-bench-2-1 \
  --harbor-root /path/to/harbor \
  > tb21-upstream-attestation.json
```

Copy the sample YAML outside the source tree, fill only the absolute dataset
path, binary path, binary digest, model route, concurrency, and the selected
Harbor environment provider. Then run from a Harbor environment with this
directory on `PYTHONPATH`:

```sh
PYTHONPATH=/path/to/core/crates/eval/harbor \
  harbor jobs start --config /path/to/core-tb21.yaml --yes
```

Run `python -m py_compile core_code_agent.py validate_upstream.py` and the
checked-in adapter tests against the pinned Harbor checkout before a campaign.
A real qualification additionally requires one oracle smoke, one Core smoke,
all 89 tasks times five trials, and inspection of Harbor `lock.json`, task
rewards, Core final result records, and failed/timeout attempts. The adapter is
execution plumbing; checked-in fixture tests are not a benchmark score.

## Deliberate non-claims

- Core's `bash` tool remains egress-off even though every TB2.1 task currently
  declares `allow_internet = true`; first-party web tools are not equivalent to
  arbitrary shell network. This can lower Terminal-Bench score and must not be
  hidden by the adapter.
- The adapter does not make Core's provider sampling seed controllable. Harbor
  attempt identity and Core's own record must preserve that limitation.
- The current Core CLI exposes no production `--bundle` input. The adapter
  therefore runs the builtin/untrained arm only; it refuses to pretend the
  existing eval-side bundle fixture is a live runtime binding.
- `max_wall_secs: 12000` is the largest pinned TB2.1 agent timeout, while Harbor
  enforces every task's smaller exact timeout. It is not permission to change
  the dataset timeout.
- The sample config is not a live performance result, leaderboard submission,
  cross-platform qualification, or proof that B0/B1 are fully closed.
