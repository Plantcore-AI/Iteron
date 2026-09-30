# Ordinary extension SDK v1

Declare an ordinary contribution in a verified enabled marketplace package. Each `binding` is
compact JSON (the marketplace currently limits each detail to 4096 bytes). The package's admitted
capabilities are intersected with the resident task ceiling. No descriptor grants authority.

```json
{"kind":"tool","name":"sample__read_notes","binding":"{\"version\":1,\"name\":\"sample__read_notes\",\"description\":\"Read workspace notes\",\"primitive\":\"read_file\",\"fixed_arguments\":{\"path\":\"notes.md\"},\"write_paths\":[]}"}
```

The host advertises the native schema/purity/capability and a recipe commitment. Fixed arguments
cannot be changed by model input. Writers additionally require literal `write_paths`, intersected
with existing inherited scope at the physical native mutation boundary. The kernel applies both
alias and primitive named permission rules, sandbox checks and lifetime budgets. Native operations
retain their normal deadlines and cancellation. Unsupported primitives are refused. A native writer
receipt retains `tool_name()` as the physical primitive and `logical_tool_name()` as the alias.

Other contribution kinds use the same inert compact JSON binding:

- `provider`: `NativeProviderRegistrationV1` names a host-configured provider/model. It cannot
  declare a credential, API root, rate card or budget exemption. `resolve` returns the actual native
  IDs. An operator selects those IDs using existing model selection; signed pricing, serialized
  request limits and physical provider admission remain mandatory. Registration sends no request.
- `ui`: `UiStatusV1` chooses up to eight closed `StatusFactV1` facts with a bounded text label.
  The UI renders text, with no raw HTML, scripts or observer callbacks. Counters explicitly come
  from the last captured settlement/control boundary; admission slots are not socket dispatches.
- `event_subscription`: `EventSubscriptionV1` chooses up to sixteen active content-free lifecycle
  IDs and a queue of at most 256 events. `events` reads at most 64 rows and waits at most 60 seconds;
  it has a single nonblocking reader lease. This is lossy observation, not durable replay or model
  consumption. Rebinding the real host bus invalidates older in-flight reads.

`OrdinaryExtensionsReadPort` is safe to retain while the Agent runs. Its snapshot lists only actual
bound native routes, status projections and live subscriptions. Disabled packages and sessions
without ordinary contributions construct no SDK owner or schemas, subscribers, prompts or jobs.
Current-generation revocation applies at each tool, status, provider-resolution and event-read
boundary; the next startup uses the durable plugin registry configuration.

## Migration

Existing native tools and Provider implementations remain supported. Arbitrary `register_external`
Rust closures and custom `Provider` implementations are trusted host backend code; implementing
those APIs does not sandbox a plugin callback or attest its pricing. Move ordinary tools to native
recipes and ordinary providers to configured native route exports. Interpreter recipes retain all
actual classified effects, including unknown external/trust writes. SDK catalog identity commits
verified plugin/version/manifest, immutable recipes and actual native route metadata. A resumed run
refuses a changed binding catalog rather than replaying old tool calls through new fixed arguments.

## Conformance

Public SDK sample conformance exercises real lifecycle emission, bounded status selection,
revocation and rejected capability/HTML claims. Native recipe journeys exercise actual filesystem
reads, physical scoped writes, immutable arguments, cached-read revocation and effect projection.
CLI journeys exercise the actual Agent provider/tool path, durable reopen/mismatch refusal, signed
native provider budget refusal and same-bus rebind. These tests are source fixtures pending the
unified final gate; source presence is not an execution result.
