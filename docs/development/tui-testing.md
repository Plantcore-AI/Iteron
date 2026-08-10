# TUI testing

The TUI is a terminal protocol, not a desktop canvas. Tests protect semantic
state, cell width, input ownership, terminal restoration, and human-readable
distinction between prompts, model output, tools, permissions, and status.

## Required evidence

- Reducer/state tests for every new interaction state.
- Rendering tests across narrow, standard, and wide terminal widths.
- Exact in-memory vt100 cell grids for Markdown tables/lists/fences, plus
  delimiter-split streaming and resize convergence against the single-shot grid.
- CJK, emoji, combining-mark, paste, and control-character coverage.
- One-enter acceptance and deterministic focus for pickers and permissions.
- Capable/incapable OSC 8 projections and single-writer notification prefix
  repair/poison behavior at every short-write boundary.
- Resize round trips without stale layout caches.
- PTY evidence for raw mode, alternate screen, signal handling, and exact terminal
  restoration.
- Bounded transcript, output, menu, and paste behavior.

Run:

```sh
cargo test -p iteron-cli --locked
cargo test -p iteron-cli --test tui_pty --locked -- --nocapture
```

## Visual changes

Use a real terminal with light, dark, and no-color modes. Verify 80x24 and a narrow
fallback. Decorative treatment must never remove authority, error, cost, context,
or progress truth. Color cannot be the only signal.

Snapshots or screenshots supplement semantic assertions; they do not replace
them. A visual pass on one font and terminal is not sufficient evidence.

## Interaction contract

Exactly one surface owns Enter at a time. Approval defaults to deny. A picker must
open on an actionable/current row and accept it with one Enter. Submitted prompts
remain visibly distinct from model output. The composer and bottom status line
must remain available without painting over transcript evidence.
