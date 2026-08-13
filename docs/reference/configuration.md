# Configuration

Iteron uses bounded JSON configuration and limits each file to 1 MiB. Unknown
top-level fields are retained, warned about, and ignored so a newer dotfile does
not brick an older binary; security- and spend-sensitive nested objects reject
unknown fields.

The current file schema is `schema_version: 2`. Configs written before the version field existed
are treated as v0; v1 configs are also migrated losslessly in memory. A config from a newer schema
is rejected with an upgrade-or-downgrade instruction before strict field decoding; Iteron never
guesses at future semantics.

## Locations and trust

| Location | Authority |
| --- | --- |
| `~/.iteron/config.json` | Operator-owned; may select providers, endpoints, signed rate cards, effort, MCP processes, hooks, and grants |
| `<repo>/.iteron/config.json` | Repository input; may select a bare model and tighten selected ceilings or grants, but cannot redirect provider traffic or spawn commands |

A repository config symlink is rejected. An operator may intentionally symlink
their own user config, but its contents are still bounded and strictly parsed.

## Top-level fields

| Field | Type | User config | Project config |
| --- | --- | --- | --- |
| `schema_version` | integer (`2`) | format discriminator | format discriminator |
| `model` | string | provider-qualified or bare default | bare id only, constrained to trusted provider |
| `provider` | string | provider instance default | ignored |
| `base_url` | string | trusted compatible endpoint | ignored |
| `max_turns` | positive integer | ceiling | may only tighten |
| `max_usd` | finite non-negative number | optional ceiling | may introduce or tighten |
| `max_wall_secs` | positive integer | default `1800` if absent | may only tighten |
| `allow_code` | boolean | may grant | `false` may tighten; `true` cannot grant |
| `effort` | string | allowed | ignored |
| `compaction_trigger_tokens` | positive integer | allowed | ignored |
| `retry` | object | operator-owned policy | parsed and ignored |
| `provider_governor` | object | bounded failover, circuit, hedge, request-control, and admission policy | parsed and ignored |
| `verification` | object | bounded incremental feedback, checkpoint, quorum, and rollback policy | parsed and ignored |
| `completion_notifications` | boolean | bounded run/approval/long-idle attention notifications; default `false` | parsed and ignored |
| `prompt_history` | `project`, `global`, or `disabled` | scrubbed, bounded TUI prompt history and text-draft retention; default `project` | parsed and ignored |
| `tui_keymap` | object | `standard` or `vim` input mode plus a closed, conflict-checked action map | parsed and ignored |
| `external_editor` | string array | direct executable argv used by Ctrl-G; no shell parsing | parsed and ignored |
| `providers` | array | allowed, maximum 64 | ignored |
| `rate_cards` | array | allowed, maximum 256 | ignored |
| `active_policy_bundle` | object | exact promoted policy-bundle identities and digests | parsed and ignored |
| `mcp_servers` | array | allowed | ignored |
| `hooks` | object of command arrays | allowed | ignored for execution |
| `egress_allow` | string array | schema field only | schema field only |

`provider_governor`, `verification`, and `active_policy_bundle` are consumed only
from the operator-owned user configuration. The provider governor admits bounded
fallback and request-control policy. Verification may add narrower feedback but
cannot replace the exact operator-owned `--verify` completion command.
`active_policy_bundle` carries validated identities and digests, never policy
bodies or credentials. A repository value for any of these fields is parsed so
errors remain visible, then ignored for authority.

!!! warning "No active egress-allow contract"
    `egress_allow` is accepted by the current schema but is not wired to a public
    runtime configuration path. Do not rely on it to grant or prove network
    access. Code execution runs unconfined unless `--confine` is passed; see the
    sandbox contract for what each posture means.

## Example user configuration

```json
{
  "schema_version": 2,
  "provider": "glm",
  "model": "glm-5.2",
  "max_turns": 40,
  "max_usd": 5.0,
  "max_wall_secs": 1800,
  "allow_code": false,
  "effort": "medium",
  "completion_notifications": false,
  "prompt_history": "project",
  "tui_keymap": {
    "mode": "standard",
    "bindings": {
      "external_editor": "ctrl+g",
      "reverse_search": "ctrl+r"
    }
  },
  "external_editor": ["/usr/bin/vi"],
  "compaction_trigger_tokens": 120000,
  "retry": {
    "base_ms": 500,
    "cap_ms": 30000,
    "max_attempts": 6
  }
}
```

The example contains no credential. Provider keys are always indirect environment
references.

`completion_notifications` is a TUI-only, operator-owned preference. It defaults to `false` and,
when enabled, emits one bounded attention notification for a completed run, a new approval request,
or a 30-second quiet period during live work. A positively identified terminal may select fixed OSC
9 / OSC 777 desktop-notification bytes only through the same single writer that owns retained TUI
frames; ordinary or nonterminal stdout falls back to one BEL byte. Repository configuration cannot
enable or disable notifications, and streamed or untrusted text is never copied into terminal
control output.

`prompt_history` controls the TUI's text-only history and draft restoration. `project` (the
default) hashes the canonical workspace identity and keeps unrelated repositories in separate
files; `global` intentionally shares one operator-wide history; `disabled` creates no history path
or writer. Files live below `~/.iteron/history/`, retain at most 200 entries, are scrubbed before
serialization, and use private directory/file permissions where the platform supports them. Image
attachments and their paths are never serialized. Ctrl-R searches newest-to-oldest; when an empty
composer has a failed turn, Ctrl-R retains retry compatibility and Ctrl-Shift-R explicitly starts an
empty-query history walk. Repository configuration cannot choose the operator's retention policy.

`tui_keymap` is operator-owned and reloads on the first key event after `~/.iteron/config.json`
changes. The only remappable actions are `external_editor`, `reverse_search`, `restore_draft`,
`toggle_fold`, and `transcript_viewer`; duplicate chords and unknown actions are refused. Ctrl-C,
Ctrl-D, Ctrl-J, Ctrl-T,
Ctrl-V, Enter, Esc, Tab, and Shift-Tab remain reserved for lifecycle, safety, terminal ownership,
submission, and permission-mode behavior. A malformed hot reload falls back to the built-in map and
shows a warning rather than leaving the session with a partially applied map. `mode: "vim"` adds a
small deterministic composer state machine: Esc enters normal mode; `i`, `a`, `A`, and `I` return
to insert mode; `h`/`l`, `0`/`$`, `b`/`w`, `x`, `j`/`k`, and `dd` provide bounded navigation,
history, deletion, and clear operations. The status line makes `keys:custom`, `vim:insert`, or
`vim:normal` visible.

Ctrl-F (or `/transcript [query]`) opens the fullscreen semantic transcript viewer. Its index is
incremental over stable block ids/revisions, evicts records with the retained transcript, and caps
the newest complete block projections at 16 MiB total and 2 MiB per block, a query at 512 bytes,
results at 512, and selected pretty/raw detail at 64 KiB. A block excluded by either search budget
is explicitly marked `search-unindexed`, and the header reports the incomplete block count; no
prefix-only result is presented as a complete search. MiB-scale block rendering, redaction, Unicode
folding, selected detail, and `Y` copy projection run on one persistent bounded background worker;
each interactive-loop turn only dispatches or collects one projection result, while result matching
advances one entry. The worker owns an exact cancellation token and join handle, delivers results
without blocking, and close/drop cancels and joins it after byte-capped cooperative work. Completion
explicitly wakes the event loop without polling. A superseded index keeps reusable
payload only for the newest 1200 authority IDs with exact matching revisions, so repeated live
cancellation cannot retain transcript history. The header exposes exact progress, and copy/export
wait until both transcript and query revisions are authoritative. `/` edits the filter while
indexing remains pending; `j`/`k` and `n`/`N`
navigate deterministically; canonical NFC/NFD-equivalent Unicode matches identically. `r` toggles
pretty/raw; `y` copies the selected block and `Y` the bounded matching-block projection through a
fixed direct-argv platform adapter; `e` exports the filtered ids and `E` exports all retained blocks
through the same writer as `/export`. Filtered export refuses when any block is search-unindexed or
the 512-result cap was reached, rather than publishing a partial result without a marker.

Copy and export run through one visible, single-flight background effect slot, so redraw, runtime
events, approvals, Ctrl-C, Ctrl-D, SIGTERM, and SIGHUP remain responsive. Copy repeats secret and
terminal-control scrubbing, admits only fixed root-owned, non-writable, non-symlink stock adapters,
and reports every post-dispatch write/shutdown/wait/exit/timeout failure as outcome-unknown without
trying a second adapter. Every failure before a successful wait explicitly kills and bounded-waits
the exact child handle; a nonzero exit has already been reaped. If the kernel does not confirm exit
inside the one-second async window plus the finite synchronous poll budget, cleanup is truthfully
outcome-unknown rather than falsely reported as joined. Export runs in a separately killable copy of the
current Iteron executable with a cleared environment and bounded stdin/stdout protocol. Its
five-second deadline, frontend shutdown, and every post-spawn error kill that helper, use a
one-second async reap window, and then make the same finite exact-handle cleanup attempt; every
normal and error return from the TUI crosses that cleanup scope before returning.
The shared process registry owns each real child handle behind a checked monotonic opaque ticket;
normal wait completion and emergency cleanup claim and remove that handle under one mutex, never by
a reusable numeric PID. Cleanup moves the exact child out under the mutex, releases the mutex before
all OS waits, and uses a finite condition-variable barrier for concurrent claimants. It sends no
later signal after dropping an unconfirmed handle, so PID reuse cannot redirect cleanup; both the
effect and reap result remain outcome-unknown. A timed-out publication is likewise reported as
outcome-unknown.

The interactive loop applies at most 64 ordered runtime events from the 1024-slot EQ per turn.
Lifecycle signals, one-shot effect completion, and terminal input have explicit priority before any
additional EQ receive, while repaint remains frame-coalesced. A continuously refilled runtime queue
therefore retains FIFO ordering and producer backpressure without starving control or draw phases.

On Linux, export opens the workspace and every parent with no-follow directory handles, writes and
fsyncs an anonymous `O_TMPFILE` inode, and exclusively publishes that held inode with `linkat` before
syncing the directory. The workspace is anchored at the filesystem root with a held capability for
every component of its absolute visible path; the complete chain is reopened and inode-compared
before and after publication. Renaming, unlinking, or replacing either the workspace or any ancestor
therefore cannot turn detached-inode publication into reported success. It creates no
temporary workspace pathname and never issues a cleanup unlink,
so an unlink/replace or symlink race cannot redirect publication or cause Iteron to remove an
attacker-owned replacement. Parent symlink swaps cannot redirect the write. Existing explicit
filenames are refused; default viewer and `/export` filenames allocate a bounded `-2`, `-3`, …
version instead of overwriting. Filesystems without anonymous-inode publication and non-Linux
platforms fail closed without creating a target. Authority revision notifications make stable
frames perform no index or result rebuild; every viewer key and effect first binds its result ids and
immutable block snapshot to that exact revision, including updates that arrived before a deferred
draw. Cached grapheme-aware row starts keep steady-frame work and allocation proportional to visible
rows. A bounded reflow runs only when the selected block or terminal width changes.

Ctrl-G invokes `external_editor` as an exact argv with the current repository as its working
directory. Iteron never shell-splits this array. If the field is absent, a single-token `VISUAL` or
`EDITOR` value is accepted; environment values containing arguments are refused. Iteron writes only
the text draft (never image attachments or paths) to a private, uniquely created file below
`~/.iteron/tmp`, temporarily restores the native terminal, strips provider/pricing names and ambient
secret-shaped variables from the child, and accepts at most 64 KiB of valid UTF-8 on a successful
exit. Spawn, timeout, exit,
read, type, or size failure preserves the original in-memory draft, and the temporary file is
removed on every ordinary return path. Repository configuration cannot select an executable or
take over terminal keys.

`retry` contains only bounded numeric policy: `base_ms` is `1..=30000`, `cap_ms` is between
`base_ms` and `60000`, and `max_attempts` (including the initial request) is `1..=10`. Numeric
environment overrides use `ITERON_RETRY_BASE_MS`, `ITERON_RETRY_CAP_MS`, and
`ITERON_RETRY_MAX_ATTEMPTS`, with environment taking precedence over user config. Repository retry
policy is always ignored because it can change paid-request timing and count.

!!! warning "Retry overrides are staged, not active"
    Iteron validates and resolves trusted retry policy, but does not yet install the transparent
    `RetryProvider` decorator in production. The kernel rejects opaque internal retries until each
    physical provider attempt can receive its own durable write-ahead intent. The CLI emits a
    warning when a trusted override is present; default production behavior remains one physical
    request per journaled attempt.

## Provider objects

Each user-defined provider requires:

- `id`: lowercase ASCII slug, at most 64 bytes;
- `adapter`: `anthropic_messages`, `openai_responses`, or `openai_chat`;
- `api_root`: HTTPS absolute root, except exact loopback HTTP;
- `key_env`: uppercase environment-variable name.

Optional fields are `display_name`, `error_profile`, `enabled`, `catalog`, a
bounded `models` manifest, and a bounded `model_capabilities` manifest. See
[configure a provider](../getting-started/providers.md).

### `model_capabilities`

A map from model id to facts no account-scoped API reports. At most 256 entries; each key follows
the same bound as a `models` id. Two fields are declarable:

- `context_window_tokens`: positive integer, at most 1000000000.
- `image_input`: boolean for this exact route/model pair.

Iteron cannot discover this. A `GET models` response is not capability evidence, and the
[static provider metadata](provider-metadata.md) document is a bounded set of official vendor
snapshots, so it can only speak for the vendors it ships. Declaring the window is what turns on
two behaviours that are otherwise silently unavailable: window-relative compaction, which triggers
at a share of the window instead of the absolute `compaction_trigger_tokens`, and the pre-flight
context-admission check, which rejects an over-large request before it is paid for.
Declaring `image_input: true` enables the adapter's multimodal wire encoding; absent capability
evidence remains unknown and an attachment submission fails before either text or images are sent.

An official vendor snapshot outranks a declaration for the same route. A declared value is
recorded with operator provenance rather than a vendor version, so it changes the route's
capability digest: a signed rate card bound to the previous digest stops matching, by design.

Prefer this over a 1M-sized `compaction_trigger_tokens`. That knob is global and fixed — setting
it replaces the window-relative rule for *every* provider, so a value sized for one large-window
model stops compaction from triggering for a smaller-window one and turns its long sessions into
a hard context-window rejection.

`max_output_tokens`, `tool_calling` and `semantic_effort` are deliberately not declarable. The
request path clamps the output reservation to 8192 regardless of any declaration, and the other
two gate a request feature rather than an arithmetic bound: an operator declaration is not an
entitlement.

## Signed rate cards

`rate_cards` is an operator-owned manifest of immutable, pre-signed pricing artifacts. Each entry
contains:

- `version` (`"v1"`), `provider_id`, `model_id`, `catalog_digest`, and
  `capability_digest` for the exact selected route;
- `provenance`, `issued_at_unix_secs`, and `expires_at_unix_secs`;
- `rates`, with fixed-point micro-USD-per-million-token values for `input`, `output`,
  `cache_creation`, `cache_read`, and `thinking` classes;
- `signer_id`, `rate_card_digest`, and `signature` (`hmac-sha256:...`);
- `key_env`, the uppercase environment-variable name containing the corresponding 32-byte key as
  64 hexadecimal characters.

Plaintext key fields are rejected by the strict schema. Iteron reads only the named environment
variable, authenticates the artifact before opening a rollout, and injects an opaque pricing port;
the kernel never receives key bytes or fetches a price. The artifact's full route must match the
catalog and capability digests recorded by `ModelSelected`, and its half-open validity interval must
be active. A positive `max_usd` with no exact active verified card is refused before a provider
request. Repository `rate_cards` are warned about and ignored.

The signing format is the canonical `iteron_obs::sign_rate_card` v1 format so operator pricing tools
can produce the public artifact offline. Durable projections retain the card digest and signed
projection timestamp; authenticated replay therefore does not consult a current price catalog.

## Precedence

Provider and endpoint routing use only:

```text
CLI > environment > trusted user config > built-in
```

Turn and monetary budgets allow project values only as a monotone tightening of
trusted settings. Inspect the resolved state with `/config` and `/status`.
