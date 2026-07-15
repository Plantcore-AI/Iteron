# Environment variables

Core Code reads environment variables from the process that starts `core`. Keep
credential values in a shell session or secret manager; never put them in the
repository or documentation.

## Runtime selection

| Variable | Meaning |
| --- | --- |
| `CORE_PROVIDER` | Trusted provider instance selection |
| `CORE_MODEL` | Model selection |
| `CORE_BASE_URL` | Trusted one-run compatible API root |
| `CORE_EFFORT` | Effort level |
| `CORE_MAX_TURNS` | Turn ceiling |
| `CORE_MAX_USD` | Monetary ceiling when cost evidence is available |

CLI flags take precedence over these values. Trusted user config follows them.

## Built-in credentials

| Variable | Provider |
| --- | --- |
| `GLM_API_KEY` | GLM / 智谱 |
| `ANTHROPIC_API_KEY` | Anthropic |
| `OPENAI_API_KEY` | OpenAI |
| `DEEPSEEK_API_KEY` | DeepSeek |
| `MINIMAX_API_KEY` | MiniMax |
| `FIREWORKS_API_KEY` | Fireworks |

A user-defined provider names its own credential variable through `key_env`.
Core Code reads that variable at call time and does not persist the plaintext
value in config.

## Terminal and home

| Variable | Meaning |
| --- | --- |
| `CORE_THEME` | Explicit TUI theme selection where supported |
| `NO_COLOR` | Select monochrome rendering |
| `COLORFGBG` | Terminal light/dark hint when no explicit theme is set |
| `HOME` | Locates operator-owned `~/.core` config, skills, agents, and memory |

Unset `HOME` means user-level sources are unavailable; repository operation can
still use explicit CLI settings.
