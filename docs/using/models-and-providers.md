# Models and providers

Provider routing, model selection, account availability, and model capability are
separate facts in Iteron. A model can appear in a catalog and still be disabled
because the provider is disabled, no credential is present, or account entitlement
is unknown.

## Resolve a route

Routing-sensitive provider precedence is:

1. CLI `--provider`;
2. `ITERON_PROVIDER`;
3. trusted user config `~/.iteron/config.json`;
4. built-in default `glm`.

Model selection accepts `--model`, `ITERON_MODEL`, trusted user config, and one
repository-safe exception: `.iteron/config.json` may name a **bare** model within the
already trusted provider. It cannot qualify another provider or redirect egress.

Use `provider:model` where qualification is needed and the provider id is known:

```sh
iteron --model anthropic:PROVIDER_MODEL_ID
```

## Inspect availability

In the TUI:

- `/model` shows the current selection and model picker;
- `/model retry MODEL_ID` explicitly retries one unavailable catalog path;
- grey or disabled entries are not selectable;
- `/status` reports the resolved route and effort application.

Iteron does not infer that a model is billable merely because its id is
documented. Provider errors and catalog evidence may change availability during a
session.

## Compatible endpoints

`--base-url` and `ITERON_BASE_URL` create a trusted one-run OpenAI-compatible Chat
endpoint override. Persistent endpoints belong in user configuration. The root
must include its full path/version prefix and use HTTPS except for an exact
loopback host.

OpenAI-compatible wire shape does not make provider business error codes
interchangeable. User-defined instances should use the correct `error_profile` or
the conservative `custom` profile.

See [configure a provider](../getting-started/providers.md) and the
[provider matrix](../reference/providers.md).
