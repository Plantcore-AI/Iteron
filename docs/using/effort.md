# Effort levels

Effort is a session setting with two effects:

1. a requested model reasoning level or thinking budget;
2. at `ultracode`, model-directed access to the bounded workflow tool.

| Level | Iteron intent |
| --- | --- |
| `low` | fastest; extended thinking disabled |
| `medium` | balanced default |
| `high` | larger thinking budget |
| `xhigh` | deeper thinking budget |
| `max` | maximum built-in thinking budget |
| `ultracode` | `max` reasoning intent plus optional model-directed workflows |

Set effort for one run:

```sh
iteron --effort high
```

Or use `/effort` in the TUI. Trusted user configuration and `ITERON_EFFORT` can set
a default; repository configuration cannot raise or redirect effort authority.

## Provider enforcement is not uniform

Adapters may apply effort exactly, map it to a smaller enum, express it through a
token budget, expose only an on/off toggle, or mark it unsupported. Iteron
records the requested and sent form where available instead of claiming that all
providers implement the same semantics.

`ultracode` is not a provider model value. The provider-facing intent is `max`; the model may use
the harness workflow tool when a task-specific graph adds value, but no workflow is launched merely
because this effort level is active. See [Ultracode](ultracode.md).
