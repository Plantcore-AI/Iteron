# Verification gates

`--verify` assigns a command to the harness rather than relying only on the
model's completion statement.

```sh
core -p --allow-code \
  --verify "cargo test --workspace --all-targets --locked" \
  "Fix the failing test and verify the change"
```

The option requires `--allow-code` because the verification command executes
repository-controlled code. If the command fails, Iteron refuses to accept a
successful completion and feeds the failure back into the bounded run.

## Choose a bounded command

A useful verification gate should:

- terminate without interactive input;
- exercise the behavior being changed;
- have bounded output and runtime;
- avoid network access unless that authority is explicitly part of the test;
- return non-zero on failure;
- avoid modifying unrelated files.

The sandbox and permission limitations still apply. A green command is evidence
for that command on that machine; it is not a general production-readiness claim.

Project contributors should also follow the repository's broader
[testing guide](../development/testing.md).
