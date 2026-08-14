# Quickstart

Use a disposable Git repository for the first run. Iteron is pre-alpha and, by
default, executes code with your account's own filesystem and network authority.

## 1. Build the executable

From the Iteron source tree:

```sh
cargo build --release --locked -p iteron-cli
```

The examples below use `/path/to/Iteron/target/release/iteron`. Replace it with
`iteron` if you installed the binary on `PATH`.

## 2. Set up a provider credential

With no provider selected, Iteron routes to the first built-in provider that has
a credential, so exporting one variable is enough to start. `glm` and its
`GLM_API_KEY` are the last-resort fallback, used only when nothing on the machine
can authenticate. The supported BYOK wizard validates a key before writing it to
a private operator-owned file:

```sh
iteron setup --byok glm
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

The shipped default bypasses permission prompts and runs unconfined. Use
`--ask-permissions` to restore the capability gate, `--confine` to confine shell
commands on macOS or Linux, and `--mode plan` for a read-only run. Review the
[permission and sandbox contract](../using/permissions-and-sandbox.md) before
opening an untrusted repository.

## 5. Run a one-shot task

```sh
/path/to/Iteron/target/release/iteron -p -C /path/to/test-repository \
  "Find the failing test, explain the cause, and stop without editing"
```

One-shot mode defaults to `acceptEdits` and inherits the shipped permission bypass,
so it does not prompt and code execution is already granted. Pass
`--ask-permissions` to restore the gate; because one-shot has no approval channel,
an operation that resolves to "ask" then fails closed.

For automation, use the stable machine-output modes described in
[one-shot and automation](../using/one-shot.md).
