# Ultracode

Ultracode is Iteron's highest effort setting. It combines the maximum
provider-facing reasoning intent with a bounded internal investigation-and-write
workflow.

```sh
iteron --effort ultracode
```

## Current workflow

For a substantive task, the current policy may:

1. classify the task and decide that fan-out is not beneficial;
2. produce a bounded, normalized set of read-only investigation leaves;
3. run viable investigators under explicit turn and time reserves;
4. reduce their untrusted evidence in declaration order;
5. give one writer the original task plus the bounded evidence.

Investigators run bounded-concurrent: several are in flight at once, capped by a
permit pool, and the live tree renders one row per investigator. Iteron does
not claim a generic DAG scheduler or multiple concurrent writers. If
decomposition fails, yields no useful evidence, or would consume the writer
reserve, Iteron falls back to the single writer.

## Workflow scripts

The same engine also runs standalone workflow scripts — JavaScript files that
call `agent()`, `parallel()`, `pipeline()`, `phase()`, and `log()`. See
`iteron workflow` in the [CLI reference](../reference/cli.md) and the example
script at `crates/workflow/examples/repo-audit.js`.

## Authority remains fixed

Investigators are read-only. The writer still uses the same permission gate,
budgets, durable record, and verification path. Internal orchestration cannot
grant capabilities, relax ceilings, rewrite evidence, or promote a learned
strategy.

Ultracode is an experimental harness policy, not an autonomous software team and
not a claim of parity with another coding agent.
