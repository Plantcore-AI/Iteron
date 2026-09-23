# Quickstart

Use a disposable Git repository for the first run. Iteron is pre-alpha; its
ordinary coding mode uses workspace-scoped execution and write boundaries, not a
guarantee of safety against hostile code or concurrent filesystem manipulation.

## 1. Build the executable

From the Iteron source tree:

```sh
cargo build --release --locked -p iteron-cli
```

The examples below use `/path/to/Iteron/target/release/iteron`. Replace it with
`iteron` if you installed the binary on `PATH`.

## 2. Set up a provider credential

With no provider selected, Iteron first reuses a validated last-success route;
otherwise it prefers locally credentialed `openai`, then another locally
credentialed provider. A catalog entry is not an account grant.
The supported BYOK wizard validates a key before writing it to a private
operator-owned file:

```sh
iteron setup --byok openai
```

Iteron never writes credential values into repository configuration. An
environment variable supplied by your shell or secret manager remains available
as an alternative and takes precedence over the stored file.

See [Setup and BYOK](setup-and-byok.md) for all six built-in providers,
credential rotation, and status checks. You can also declare a
[user-defined provider](providers.md).

## 3. Open the TUI

```sh
/path/to/Iteron/target/release/iteron -C /path/to/test-repository
```

When both stdin and stdout are terminals, the interactive TUI is the default. Ask
for a bounded, reviewable task, for example:

```text
Explain why the smallest test in this repository fails. Do not edit files.
```

Use `/status` to inspect the resolved model, effort, permission mode, cost state,
working directory, and run id. Use `/model`, `/effort`, or `/mode` to inspect or
change session settings.

## 4. Choose the authority posture deliberately

The shipped default uses `acceptEdits` with shell sandboxing and workspace file
write checks. Use `--ask-permissions` for stricter edit approvals, and
`--mode plan` for a read-only run. Only the explicit
`--dangerously-bypass-permissions` option grants the broad bypass. Review the
[permission and sandbox contract](../using/permissions-and-sandbox.md) before
opening an untrusted repository.

## 5. Run a one-shot task

```sh
/path/to/Iteron/target/release/iteron -p -C /path/to/test-repository \
  "Find the failing test, explain the cause, and stop without editing"
```

One-shot mode defaults to sandboxed `acceptEdits`, without a broad permission
bypass. It has no approval channel, so an operation that resolves to "ask"
fails closed; pass `--ask-permissions` only when that stricter refusal is intended.

For automation, use the stable machine-output modes described in
[one-shot and automation](../using/one-shot.md).
