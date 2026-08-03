# Environment variables

Core Code reads environment variables from the process that starts `core`. Keep
credential values in a shell session or secret manager; never put them in the
repository or documentation.

## Runtime selection

| Variable | Meaning |
| --- | --- |
| `CORE_PROVIDER` | Trusted provider instance selection |
| `CORE_MODEL` | Model selection |
| `CORE_BASE_URL` | Trusted one-run compatible API root (requires `CORE_KEY_ENV` or `--key-env`) |
| `CORE_KEY_ENV` | Name of the variable holding the credential for `CORE_BASE_URL` |
| `CORE_CONFIG_HOME` | Config root, replacing `HOME` (for containers and CI runners with no `HOME`) |
| `CORE_EFFORT` | Effort level |
| `CORE_MAX_TURNS` | Turn ceiling |
| `CORE_MAX_USD` | Monetary ceiling when cost evidence is available |
| `CORE_RETRY_BASE_MS` | Trusted retry exponential base (staged; see configuration reference) |
| `CORE_RETRY_CAP_MS` | Trusted retry-delay cap (staged; see configuration reference) |
| `CORE_RETRY_MAX_ATTEMPTS` | Trusted total-attempt bound (staged; see configuration reference) |

CLI flags take precedence where a corresponding flag exists. Trusted user config follows these
values; retry policy currently has no CLI flag.

## Built-in credentials

| Variable | Provider |
| --- | --- |
| `GLM_API_KEY` | GLM / 智谱 |
| `ANTHROPIC_API_KEY` | Anthropic |
| `OPENAI_API_KEY` | OpenAI |
| `DEEPSEEK_API_KEY` | DeepSeek |
| `MINIMAX_API_KEY` | MiniMax |
| `FIREWORKS_API_KEY` | Fireworks |

A user-defined provider declares where its credential comes from through
`credential`, either `{"type": "env", "name": "..."}` or
`{"type": "file", "path": "..."}`. The deprecated `key_env` spelling is still
accepted and means the `env` form. Either way the config holds only the name of
the source, never the plaintext value.

An `env` credential is read once, when the process starts: a running process's
own environment is not a rotation channel. A `file` credential is re-read at
call time — always when it declares no expiry, and otherwise as soon as it is
within a minute of expiring — so a hosted subscription token can rotate without
restarting Core. The file must be a regular file at mode 0600 holding either one
token line or `{"token": "...", "expires_at_unix": N}`.

`core setup` writes that file for you; `core auth status` reports which source
is in use and when it expires.

A signed `rate_cards` entry also names its HMAC variable through `key_env`. Its
value is exactly 64 hexadecimal characters (32 bytes). Core authenticates the
configured artifact before opening a run, never persists or logs the key, and
removes the named variable from sandboxed shell and verification environments.

## Terminal and home

| Variable | Meaning |
| --- | --- |
| `CORE_THEME` | Explicit TUI theme selection where supported |
| `NO_COLOR` | Select monochrome rendering |
| `COLORFGBG` | Terminal light/dark hint when no explicit theme is set |
| `HOME` | Preferred operator home for `~/.core` config, skills, agents, and memory |
| `USERPROFILE` | Native Windows operator-home fallback when `HOME` is absent or not absolute |
| `HOMEDRIVE` + `HOMEPATH` | Final native Windows fallback when their combined path is absolute |

On Unix, an absent or non-absolute `HOME` means user-level sources are unavailable.
On Windows, Core next tries an absolute `USERPROFILE`, then an absolute path formed
from `HOMEDRIVE` and `HOMEPATH`. Repository operation can still use explicit CLI
settings when no operator home is available.

## Environment facts in the model context

For a fresh run, Core Code records and injects a facts-only snapshot capped at
4 KiB with the canonical workspace cwd, UTC capture time, target OS/architecture,
and a Git branch plus short status counts. It does not enumerate process environment
variables, credential names or values, Git filenames, commit text, remotes, or
raw Git errors. Git failure is represented only as `git: unavailable`.
Startup Git facts currently require Unix process-group teardown semantics; other
targets use the same explicit unavailable value rather than risk leaving a
cancelled descendant process alive.

The snapshot is durable. `--resume` and a resumed fork reuse the original durable
bytes from `ContextInjection`, or the crash-safe `RunStart` copy until the first
injection commits. They do not sample the clock or run Git to reconstruct these
facts. This keeps the system prefix reproducible even when the branch or working
tree changes between processes. Append, open, replay, and fork revalidate the same
4 KiB field bound; an oversized durable field is rejected rather than materialized
or replaced from live state.

### Clickable Markdown links

The TUI emits OSC 8 hyperlinks only when the inherited terminal environment gives
positive evidence for a supported terminal (for example iTerm2, WezTerm, Kitty,
Ghostty, VS Code, Windows Terminal, recent VTE, or recent Konsole). Unknown
terminals, `TERM=dumb`, tmux, and screen use the plain `text (url)` rendering; Core
does not assume passthrough support through a multiplexer.

Clickable targets are limited to bounded HTTP(S) URLs without embedded
credentials and existing local paths whose canonical location remains inside the
active repository. Unsupported schemes, path traversal, symlink escapes, control
characters, and oversized targets remain plain text and cannot inject terminal
escape sequences. The same policy covers Markdown (including table cells), typed
tool arguments and output documentation URLs, and file/diff paths. Link metadata
does not participate in wrapping, so clickable and fallback rows obey the same
display-width bounds.

### Attention notifications

Completion notifications are disabled unless the operator enables
`completion_notifications` in the user configuration. Terminal capability
evidence selects one of the bounded, fixed OSC 9 / OSC 777 desktop-notification
vocabularies. The live TUI admits those sequences only to its sole terminal
writer, which appends them after a complete retained frame. If a short write
accepts a prefix, the writer completes or repairs that prefix before it rejects
every later frame byte. Nonterminal or nonblocking stdout instead receives one
BEL byte, and ordinary test/output writers never receive an OSC prefix.

Notifications carry no model, tool, repository, or provider text. One run gets at
most one completion notification, repeated approval IDs are deduplicated, and a
live run gets at most one notification for each 30-second quiet period.
