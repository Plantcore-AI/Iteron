# Troubleshooting

## No interactive terminal detected

The TUI needs terminal stdin and stdout. In a pipeline, use one-shot mode:

```sh
iteron -p "Describe the failure"
```

## Provider or model is grey

First follow [credential-free provider diagnosis](../getting-started/provider-diagnosis.md).
It separates executable resolution, configuration parsing, provider selection,
and network reachability from authentication. Only after those checks should you
load a credential into the `iteron` process. Catalog presence does not prove
account entitlement. Use `/model retry MODEL_ID` only when you deliberately want
to retry one unavailable route.

Never paste a key into an issue or config file.

## Project config is ignored

Routing, endpoint, provider instances, effort, hooks, MCP processes, and grants of
code execution are operator authority. Put them in CLI/environment input or
`~/.iteron/config.json`. Repository config can name a bare model within the trusted
provider and tighten selected ceilings.

## Code execution is refused

Code execution is granted by default. Confirm that trusted configuration has not
set `allow_code` to `false`, that `--mode plan` or an explicit deny rule is not
active, and use `--allow-code` to grant it explicitly if needed. When
`--confine` is selected on Linux, also install and enable a usable bubblewrap
boundary; the confined posture does not silently fall back to an unconfined
shell.

## `--verify` is rejected

Verification runs a command and therefore requires code execution to remain
enabled (the shipped default):

```sh
iteron -p --verify "cargo test --locked" "Fix the test"
```

## Resume reports an invalid record

Do not hand-edit the JSONL chain. Preserve the file for diagnosis and use another
valid run or a new session. A hash-chain failure is surfaced rather than ignored.

## Cost is unknown

The route has not provided sufficient trustworthy price evidence. Iteron does
not convert tokens to a guessed dollar value. Select a route with supported cost
evidence or treat the monetary ceiling as unavailable.

## Report a reproducible bug

Use a synthetic repository and include the Iteron version or commit, OS and
architecture, terminal, provider adapter, model id, exact command, expected
behavior, and observed behavior. Follow the [support guide](../project/support.md)
and report vulnerabilities privately.
