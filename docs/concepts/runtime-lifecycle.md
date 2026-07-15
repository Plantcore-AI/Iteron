# Runtime lifecycle

Core Code currently runs as one CLI process that composes the frontend and runtime
dependencies. The intended App Server boundary does not exist yet.

## Current startup path

At a high level, the executable:

1. validates local CLI values before opening a run record;
2. loads repository and trusted user configuration under different authority
   rules;
3. registers built-in workspace, edit, shell, Git, memory, skill, and web-related
   tools;
4. starts operator-configured MCP stdio servers and registers their discovered
   tools;
5. resolves provider, model, effort, budgets, permission mode, and continuation;
6. opens or reconstructs the hash-chained rollout;
7. discovers bounded repository instructions, memory, skills, hooks, and agent
   definitions with their source trust;
8. starts the interactive TUI or one-shot event emitter;
9. runs bounded model/tool/verification turns until a terminal outcome.

The order matters. Routing-sensitive values never come from a cloned repository,
and invalid one-shot arguments are rejected before they can create an orphan run.

## Submissions and events

The protocol crate defines one id-correlated submission/event vocabulary. User
input, approval responses, steering, interrupt, and drain operations are explicit
submissions. Phases and tool or workflow activity are emitted as events for the
frontend and record path.

The current in-process use of that vocabulary is a useful extraction seam, not a
stable network or App Server API.

## Target extraction

The planned runtime boundary is:

1. versioned canonical command and event envelopes;
2. a pure reducer that requests actions rather than performing them;
3. one capability and effect broker;
4. injected provider, world, context, verification, and scheduler ports;
5. a long-lived session runtime with bounded queues and reconnect semantics;
6. a versioned App Server used by the TUI, CLI, and future clients.

Until those gates land, describe Core Code as a modular monolith rather than a
completed microkernel.
