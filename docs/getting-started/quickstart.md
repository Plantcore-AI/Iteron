# Quickstart

Use a disposable Git repository for the first run. Core Code is pre-alpha and code
execution is intentionally disabled by default.

## 1. Build the executable

From the Core Code source tree:

```sh
cargo build --release --locked -p core-cli
```

The examples below use `/path/to/core/target/release/core`. Replace it with `core`
if you installed the binary on `PATH`.

## 2. Provide a credential to the process

The built-in default provider is `glm`. Its credential environment variable is
`GLM_API_KEY`; Core Code never expects the credential value in repository
configuration. Make the variable available through your shell or secret manager
without committing it.

You can choose another [built-in or user-defined provider](providers.md).

## 3. Open the TUI

```sh
/path/to/core/target/release/core -C /path/to/test-repository
```

When both stdin and stdout are terminals, the interactive TUI is the default. Ask
for a bounded, reviewable task, for example:

```text
Explain why the smallest test in this repository fails. Do not edit files.
```

Use `/status` to inspect the resolved model, effort, permission mode, cost state,
working directory, and run id. Use `/model`, `/effort`, or `/mode` to inspect or
change session settings.

## 4. Permit an edit deliberately

The interactive default mode automatically permits reads and asks before an edit
or command. Review the exact operation before approving it. Do not enable `yolo`
or code execution in an untrusted repository until you understand the
[permission and sandbox contract](../using/permissions-and-sandbox.md).

## 5. Run a one-shot task

```sh
/path/to/core/target/release/core -p -C /path/to/test-repository \
  "Find the failing test, explain the cause, and stop without editing"
```

One-shot mode defaults to `acceptEdits` because it has no interactive approval
channel. Code execution still requires `--allow-code`; an operation that needs an
unavailable approval fails closed.

For automation, use the stable machine-output modes described in
[one-shot and automation](../using/one-shot.md).
