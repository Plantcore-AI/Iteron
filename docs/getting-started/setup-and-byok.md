# Setup and BYOK

Iteron does not include model usage. Bring a provider credential for an account
you control, and your provider bills that account directly. The supported setup
path validates the credential before saving it and never writes a key into a
repository or `config.json`.

## 1. Choose a built-in provider

| Provider | Setup command | Environment alternative |
| --- | --- | --- |
| GLM / 智谱 | `iteron setup --byok glm` | `GLM_API_KEY` |
| Anthropic | `iteron setup --byok anthropic` | `ANTHROPIC_API_KEY` |
| OpenAI | `iteron setup --byok openai` | `OPENAI_API_KEY` |
| DeepSeek | `iteron setup --byok deepseek` | `DEEPSEEK_API_KEY` |
| MiniMax | `iteron setup --byok minimax` | `MINIMAX_API_KEY` |
| Fireworks | `iteron setup --byok fireworks` | `FIREWORKS_API_KEY` |

When you have not selected a provider, Iteron routes to the first one in this
table that has a credential, so setting a single environment variable is enough
to get a working first run. `glm` is only the last-resort fallback, used when
nothing on the machine can authenticate anywhere. An explicit choice, from
`--provider`, `ITERON_PROVIDER`, or `~/.iteron/config.json`, is never overridden
this way: your credential goes only where you named it.

A provider's presence in this table describes a wire adapter, not free usage,
account funding, regional availability, or access to every model in its catalog.

## 2. Run the setup wizard

For example, to use OpenAI:

```sh
iteron setup --byok openai
```

Paste the key at the hidden prompt. Setup then makes one minimal real inference
request with a 60-second total deadline and no transparent retry. The request
may incur the provider's minimum usage charge. Its purpose is to prove that the
key and selected route work before Iteron changes local state.

If the provider rejects the key, the endpoint is unreachable, or validation is
inconclusive, setup writes nothing and preserves any previous credential. On
success it:

- writes the credential to `~/.iteron/credentials/openai` with mode `0600`;
- records `openai` as the active provider in `~/.iteron/config.json` without
  putting the key in that JSON file;
- discovers the account-visible model catalog where the provider supports it;
- prints the resolved `provider:model` route for the next run.

Replace `openai` with any provider id in the table. Running plain `iteron setup`
opens the same wizard and asks which setup type and provider to use. BYOK is the
normal public setup path; select `--plan` only if an Iteron operator has issued
you a hosted-plan token.

On a Unix terminal the prompt turns echo off while you type, and says so. Where
that is not possible the prompt says the line will be visible instead, so you can
decide whether to paste a production key into a terminal that will remember it.

!!! warning "An exported key wins"
    For a built-in provider, its environment variable takes precedence over the
    credential file. Unset an old variable before setup if the new stored key
    should take effect. Iteron never prints either value.

## 2b. Setup without a terminal

A wizard cannot run in CI, in a container build, from a configuration management
run, or from an agent. `--stdin` takes the credential from standard input and
asks nothing:

```sh
printenv OPENAI_API_KEY | iteron setup --byok openai --stdin
```

Everything the wizard would have asked must be on the command line, and a run
that is missing one names the flag that supplies it. Validation, the refusal to
write a rejected key, and the `0600` credential file are identical to the
interactive path.

For a hosted-plan token, name the provider with `--provider` and pass the expiry
that the wizard would otherwise prompt for:

```sh
printenv ITERON_PLAN_TOKEN \
  | iteron setup --plan --provider glm --stdin --expires-at 1893456000
```

`--expires-at` is refused on a BYOK key, which does not expire.

!!! tip "Keep the credential off the command line"
    Pipe it, as above. An argument is visible in the process table to every user
    on the machine, and your shell writes it to its history file.

## 3. Verify the active route

Credential status is local and value-free:

```sh
iteron auth status openai
iteron config get provider
```

`auth status` reports the endpoint, credential source, presence, expiry, and a
local availability label. It does not contact every configured provider. The
setup request is the live validation evidence.

Then start in a disposable repository with an explicit safety posture:

```sh
iteron --provider openai --ask-permissions --confine \
  -C /path/to/disposable-repository
```

Omit `--provider openai` after setup if OpenAI should remain the persisted
default. `--ask-permissions` restores approval prompts. `--confine` places shell
commands inside the macOS/Linux sandbox; it does not turn that sandbox into a
confidentiality boundary. Read the
[permissions and sandbox guide](../using/permissions-and-sandbox.md) before
opening an untrusted repository.

## Environment-only setup

If a shell or secret manager already injects credentials, no setup file is
required. For example:

```sh
export OPENAI_API_KEY="$(your-secret-manager read openai-api-key)"
iteron --provider openai --model PROVIDER_MODEL_ID
```

Use the secret manager's real value-producing command in place of the
placeholder. Avoid literal keys in shell history, dotfiles, command arguments,
repository files, CI logs, and screenshots. Iteron removes configured provider
credential variables from agent-launched shell commands, but the parent process
still needs the variable to call the provider.

## Rotate or remove a stored key

Rerun setup to rotate a key. The existing file remains untouched unless the new
key passes validation:

```sh
iteron setup --byok openai
```

Remove the stored credential without deleting the provider route:

```sh
iteron auth logout openai
```

If `auth logout` says the credential comes from an environment variable, unset
that variable in the launching shell or secret-manager configuration as well.

## Custom OpenAI-compatible endpoints

The BYOK wizard accepts a custom provider only after its trusted route is
declared in the operator-owned `~/.iteron/config.json`. A cloned repository
cannot add a provider, change an API root, or redirect a key. Follow
[Configure a provider](providers.md) for persistent custom routes, or use the
paired `--base-url` and `--key-env` flags for a one-run endpoint override.

## Troubleshooting

- **`provider ... is not configured`** — use one of the six built-in ids, or
  declare the custom provider in user configuration first.
- **Authentication failed** — confirm that the key belongs to the selected
  provider and endpoint. A failed setup does not overwrite the previous key.
- **No selectable model** — specify an account-visible model with
  `--model provider:model-id`; custom endpoints may also need an operator-declared
  model list.
- **Stored key appears ignored** — unset the built-in provider's environment
  variable; the explicit per-process environment source wins by design.
- **Linux `--confine` fails closed** — install and configure bubblewrap as shown
  in [Supported platforms](../reference/platforms.md#linux-requirements).

For configuration precedence and provider capability details, continue to
[Models and providers](../using/models-and-providers.md), the
[configuration reference](../reference/configuration.md), and the
[provider matrix](../reference/providers.md).
