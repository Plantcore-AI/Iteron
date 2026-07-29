# Terminal UI

The TUI is Core Code's default frontend when stdin and stdout are attached to a
terminal. It owns presentation and input as a version-negotiated client of the
same resident App Server used by one-shot and headless operation. Runtime state
and the authoritative terminal result arrive over the event queue; the TUI never
reclaims or inspects the agent directly.

## Start the TUI

```sh
core -C /path/to/repository
```

Passing `--tui` forces the interactive intent, but a real terminal is still
required. A pipeline should use [one-shot mode](one-shot.md) instead.

## Interaction surfaces

- Enter natural-language tasks in the composer.
- Type `/` to browse slash-command completion.
- Type `@path.png` or `@image(path.png)` to attach a repository-relative image.
- Paste or terminal-drag a whole local image path to create an attachment chip.
  Press ++ctrl+v++ for bitmap clipboard capture when `pngpaste` (macOS),
  `wl-paste`/`xclip` (Linux), or PowerShell clipboard support (Windows) is
  available. Text paste remains ordinary composer text.
- Review the bounded attachment chips above the draft; ++alt+backspace++ removes
  the most recent chip. Image bytes and paths are never rendered in the preview.
- Scroll the transcript with the wheel or trackpad. A captured left click folds a
  card or places the composer cursor at the selected terminal cell, including
  wide CJK cells.
- Press ++ctrl+t++ to release mouse capture for terminal-native selection and
  copy; press it again to return scrolling and clicks to Core Code.
- Use ++shift+tab++ to cycle `default`, `acceptEdits`, `plan`, and `yolo`.
- Use `/model`, `/effort`, `/mode`, `/permissions`, and `/theme` for explicit
  pickers or session changes.
- Use `/diff`, `/status`, `/context`, `/cost`, and `/workflows` to inspect the
  evidence Core Code currently exposes.
- Leave with `/quit`, ++esc++, or ++ctrl+d++.

The transcript distinguishes user input, assistant output, thinking, tool
activity, approvals, notices, workflow activity, and completion state. Terminal
width and color capability affect rendering; the semantic event stream remains
the source for tests. Assistant Markdown supports CJK-aware tables, bounded
nested and task lists, ordered continuations, labeled fences, and width-neutral
links. Streaming and resize paths converge on the same terminal-cell rendering
as the completed document.

The composer accepts at most eight sniffed PNG/JPEG/GIF/WebP attachments, with
the same 6 MiB per-file and 24 MiB aggregate raw-byte ceilings as one-shot mode.
Images travel beside the prompt as neutral SQ content segments; the kernel does
not parse media. When the selected provider is text-only, the TUI shows one
degradation notice and the text task continues.

## Approval behavior

An approval prompt names the tool, declared capability, reason, arguments, and
workspace. The operator may approve or deny it; selected capability decisions can
be remembered for the session where policy permits.

Core Code never turns a missing interactive answer into permission. In one-shot
mode, an operation that still needs a human answer fails closed.

## Honest observability limits

`/context` and `/cost` show only the estimate or provider evidence available for
the active route. A status row is not proof of authoritative billing, cache, or
context-window truth. Unknown cost remains unknown instead of being inferred from
token counts without a trusted price source.

See [context, usage, and cost](../concepts/context-usage-cost.md).
