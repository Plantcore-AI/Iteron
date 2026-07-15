# Effort levels

Effort is a session setting with two distinct effects:

1. a requested model reasoning level or thinking budget;
2. whether the built-in Ultracode orchestration policy is enabled.

| Level | Core Code intent |
| --- | --- |
| `low` | fastest; extended thinking disabled |
| `medium` | balanced default |
| `high` | larger thinking budget |
| `xhigh` | deeper thinking budget |
| `max` | maximum built-in thinking budget |
| `ultracode` | `max` reasoning intent plus bounded internal orchestration |

Set effort for one run:

```sh
core --effort high
```

Or use `/effort` in the TUI. Trusted user configuration and `CORE_EFFORT` can set
a default; repository configuration cannot raise or redirect effort authority.

## Provider enforcement is not uniform

Adapters may apply effort exactly, map it to a smaller enum, express it through a
token budget, expose only an on/off toggle, or mark it unsupported. Core Code
records the requested and sent form where available instead of claiming that all
providers implement the same semantics.

`ultracode` is not a provider model value. The provider-facing intent is `max`;
the extra behavior belongs to the harness. See [Ultracode](ultracode.md).
