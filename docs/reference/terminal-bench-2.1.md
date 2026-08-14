# Terminal-Bench 2.1 adapter contract

The Rust adapter in `iteron_eval::terminal_bench` is pinned to benchmark id `terminal-bench` and
version `2.1`. There is no default-version behavior: `2.0`, `2.1.0`, an absent version, or another
benchmark id fails closed.

The request binds:

- task id, trial id, and dataset revision;
- candidate profile SHA-256, family-registry SHA-256, and parameter-registry SHA-256;
- the full Iteron Git revision;
- absolute binary, workspace, profile, effective-profile, stdout-result, and run-record directory
  paths;
- bounded task text, wall time, turns, stdout, stderr, retained evidence, and peak memory; and
- allowlisted credential environment **names**, never their values.

`TerminalBenchRequest::command()` deterministically builds this normal Iteron invocation:

```text
iteron --print --output-format json --output-schema-version 5 \
  --repo WORKSPACE \
  --tunables-profile PROFILE --tunables-profile-digest PROFILE_SHA256 \
  --emit-tunables-profile EFFECTIVE_PROFILE --runs-dir RUNS \
  --harness-profile benchmark --benchmark-attempt-scope terminal-bench/2.1/TASK/TRIAL \
  --max-turns N --max-wall-secs N --allow-code --dangerously-bypass-permissions \
  -- TASK_PROMPT
```

The returned command clears the ambient environment, fixes locale/time/color values, and lists
only credential names the launcher may inherit directly. A harness must not resolve those values
into JSON, logs, argv, or evidence.

After execution, the harness retains and hashes the emitted effective profile, Iteron JSON result,
append-only run record, and optional external score evidence. The result envelope repeats the
benchmark, task, profile, registries, and Iteron revision; parsing verifies those identities against
the original request and enforces all declared bounds. Scores use integer millionths in
`0..=1_000_000`, avoiding floating-point ambiguity.

## Claim boundary

A successful adapter test or smoke proves only that a candidate profile can be accepted, invoked,
and tied to bounded evidence. It does not prove that Terminal-Bench tasks were completed, that the
full 2.1 campaign ran, or that any reported leaderboard score is valid. A score claim begins only
after the external Terminal-Bench verifier and campaign policy have supplied complete evidence.
