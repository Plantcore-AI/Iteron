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

## 2. Provide a credential to the process

The built-in default provider is `glm`. Its credential environment variable is
`GLM_API_KEY`; Iteron never expects the credential value in repository
configuration. Make the variable available through your shell or secret manager
without committing it.

You can choose another [built-in or user-defined provider](providers.md).

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
