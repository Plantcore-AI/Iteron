# Troubleshooting

## No interactive terminal detected

The TUI needs terminal stdin and stdout. In a pipeline, use one-shot mode:

```sh
core -p "Describe the failure"
```

## Provider or model is grey

Check `/model` and `/status`, then verify that the provider's credential variable
is present in the `core` process. Catalog presence does not prove account
entitlement. Use `/model retry MODEL_ID` only when you deliberately want to retry
one unavailable route.

Never paste a key into an issue or config file.

## Project config is ignored

Routing, endpoint, provider instances, effort, hooks, MCP processes, and grants of
code execution are operator authority. Put them in CLI/environment input or
`~/.core/config.json`. Repository config can name a bare model within the trusted
provider and tighten selected ceilings.

## Code execution is refused

Confirm that `--allow-code` or a trusted user grant is active, that the mode does
not deny it, and that the platform sandbox probe succeeds. On Linux, install and
enable a usable bubblewrap boundary. Core Code will not silently fall back to an
unconfined shell.

## `--verify` is rejected

Verification runs a command and therefore requires `--allow-code`:

```sh
core -p --allow-code --verify "cargo test --locked" "Fix the test"
```

## Resume reports an invalid record

Do not hand-edit the JSONL chain. Preserve the file for diagnosis and use another
valid run or a new session. A hash-chain failure is surfaced rather than ignored.

## Cost is unknown

The route has not provided sufficient trustworthy price evidence. Core Code does
not convert tokens to a guessed dollar value. Select a route with supported cost
evidence or treat the monetary ceiling as unavailable.

## Report a reproducible bug

Use a synthetic repository and include the Core Code version or commit, OS and
architecture, terminal, provider adapter, model id, exact command, expected
behavior, and observed behavior. Follow the [support guide](../project/support.md)
and report vulnerabilities privately.
