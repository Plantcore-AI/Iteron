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
  available. Both work while a run is in flight: the chip lands on the draft, and
  because a steer cannot carry an image, ++enter++ on a draft with chips queues it
  behind the running turn instead of steering it. The whole terminal drop must be
  one path — an interior line break is two references, not one — and the drop has
  to reach Core Code as a paste; a terminal that replays it as individual
  keystrokes leaves it as ordinary text.
- An attached image also gets an in-line anchor `[Image #N]` at the cursor, so a
  prompt can say *where* the picture belongs: "compare this screenshot
  `[Image #1]` with this log `[Pasted text #1 +200 lines]`". The images are sent
  in the order the sentence anchors them.
- A large text paste is held aside as one `[Pasted text #N +M lines]` tag instead
  of flooding the composer; the original bytes are put back in the tag's place at
  submission. Small pastes stay inline as ordinary text.
- ++backspace++ at the end of a tag or an anchor removes the whole thing in one
  press. Removing an image's anchor keeps the image attached — it is then sent
  after the anchored ones, as it was before anchors existed.
- Review the bounded attachment chips above the draft; ++alt+backspace++ removes
  the most recent chip, and an image's anchors go with it. The chip carries the
  `#N`, the file name and the byte count; image bytes, file text and pasted
  blocks are never rendered in the preview.
- Core starts as a complete alternate-screen TUI with application mouse mode enabled.
  The wheel or trackpad scrolls only the current session's transcript; it cannot fall
  through into shell output from before Core started and never navigates the composer's
  prompt history. Press ++ctrl+t++ to release mouse capture for native drag selection and
  copy without leaving the full-screen TUI; press it again to restore application
  scrolling. The status line reports `mouse:on · wheel:transcript` or `selection:on`
  truthfully. Page Up/Down and `/transcript` remain keyboard-accessible inspection paths.
- Use ++shift+tab++ to cycle `default`, `acceptEdits`, `plan`, and `yolo`.
- Use `/model`, `/effort`, `/mode`, `/permissions`, and `/theme` for explicit
  pickers or session changes.
- Use `/tunables [query]` to search the canonical 160-family control registry. Use
  `/tunables load <workspace-relative-request.json>` only to inspect an explicit
  frozen-request simulation; every value preview is redacted and the surface never
  claims to represent or modify the live runtime.
- Use `/lab` to inspect the local offline experiment queue and signed evidence.
  `/lab request <family> <json-value>` writes a content-addressed, train-only
  request without changing the active policy. `/lab compare <bundle-id>
  <trusted-public-key>` verifies the bundle signature and exact inputs, then
  recomputes its paired statistics and Pareto frontier before rendering them.
  `/lab promote` only shows the authority boundary: the TUI has no promotion key,
  activation credential, or rollback authority.
- Use `/diff`, `/status`, `/context`, `/cost`, and `/workflows` to inspect the
  evidence Core Code currently exposes. `/workflows` opens the run inspector:
  ++tab++ switches runs, arrows move through phases and agents, ++x++ stops the
  selected live run, ++r++ resumes an eligible persisted run, and ++n++ returns
  to a fresh prompt.
- Leave with `/quit`, ++esc++, or ++ctrl+d++.

The transcript distinguishes user input, assistant output, thinking, tool
activity, approvals, notices, workflow activity, and completion state. Terminal
width and color capability affect rendering; the semantic event stream remains
the source for tests. Assistant Markdown supports CJK-aware tables, bounded
nested and task lists, ordered continuations, labeled fences, and width-neutral
links. Streaming and resize paths converge on the same terminal-cell rendering
as the completed document.

## Visual grammar

The interface uses semantic color, not per-widget decoration. Ordinary prose
stays at the primary foreground; commands and active controls use the accent;
paths, counters, warnings, failures, and successful states retain stable roles
across the transcript, composer, status row, workflow inspector, notices, and
tool summaries. Structural connectors and ` · ` separators recede independently
so a long row remains scannable.

Unified diffs render additions and deletions as green/red sign gutters with
restrained full-row tints. The source text keeps its language syntax colors, so
change state does not flatten keywords, strings, comments, types, functions, or
numbers into one red or green foreground. Markdown fences use the same stateful
lexer, with a conservative generic fallback for unknown languages.

`NO_COLOR` preserves the same words, signs, gutters, spacing, bold/dim hierarchy,
and selection state without relying on hue. RGB palettes are projected once to
the detected 256- or 16-color terminal depth, so the semantic roles do not leak
unsupported color escapes.

The composer accepts at most eight sniffed PNG/JPEG/GIF/WebP attachments. On macOS, dropped or
mentioned HEIC/HEIF photos are privately resized when needed and normalized to JPEG before they
reach the provider. All formats retain
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

The tunables browser follows the same rule. Catalog mode shows implementation,
default, source, constraint, optimization, and benchmark-relevance metadata, while
requested/effective/adjustment rows say that no resolution is loaded. A loaded R2
report shows its atomic state and redacted provenance/adjustment explanation, but
remains `simulation=true` and `runtime_bound=false`. Editing is intentionally absent
until a runtime binding can prove which registry-declared families are safe to
persist and can record the admitted value at run genesis. Frozen-request loading uses
a retained, no-follow capability chain on Linux; platforms without equivalent
workspace confinement refuse `load` while retaining catalog browsing.

The experiment lab is similarly evidence-only. Opening it creates no files. New
requests are bounded, private workspace artifacts restricted to tuning on the
train partition. A comparison is shown only after verification against the
operator-supplied trusted public key, exact bundle file set, attested inputs,
paired report, and Pareto report. Promotion remains a separate human-authorized
operation even when the candidate wins the displayed comparison.

See [context, usage, and cost](../concepts/context-usage-cost.md).
