# First session

## Start in a repository

```sh
core -C /path/to/repository
```

With an interactive terminal, Iteron opens the TUI even when no task argument
is supplied. With no terminal, pass `-p` and a task for one-shot operation.

## Orient before changing anything

Start with a read-only request and inspect the session:

```text
Map the smallest relevant part of this repository and explain the current behavior.
```

Useful commands:

- `/status` — resolved model, effort, mode, usage state, directory, and run id;
- `/tools` — registered tools and their capability classes;
- `/permissions` — session permission rules;
- `/diff` — current working-tree diff summary;
- `/context` and `/cost` — the estimates or measurements Iteron actually has;
- `/help` — the complete command list.

## Understand approval prompts

The default TUI mode automatically allows reads. Reversible edits and code
execution ask; plan mode denies every operation above read-only. Trust-mutating
and irreversible external operations always require approval, even in `yolo`.

An approval describes a declared tool operation. It cannot prove that arbitrary
shell code contains no nested side effect, so treat `bash` as code execution and
review the repository first.

## Leave and continue

Use `/quit`, ++esc++, or ++ctrl+d++ to leave. The local hash-chained run record
remains available:

```sh
core --sessions -C /path/to/repository
core --continue -C /path/to/repository
core --resume RUN_ID -C /path/to/repository
```

Continuation and resume rebuild the transcript from the durable record. They do
not make an interrupted external effect safe to retry automatically.

Next, read [sessions, resume, and fork](../using/sessions.md) and
[verification gates](../using/verification.md).
