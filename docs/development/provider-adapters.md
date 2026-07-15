# Provider adapter development

Provider integration is split between transport compatibility, documented model
schema, credential-visible discovery, and account health. Do not collapse these
into a single “available” boolean.

## Adding or changing a provider

1. Define the exact API root and transport adapter.
2. Keep credentials indirect through a named environment variable.
3. Bound connection, request, page, model, byte, and wall-clock work.
4. Separate documented models from account-visible inventory.
5. Represent missing credentials, explicit unavailability, stale evidence, and
   unknown funding or entitlement distinctly.
6. Redact error bodies before they cross the provider boundary.
7. Add synthetic fixtures for normal streams, split UTF-8/SSE frames, in-band
   errors, retries, cancellation, and hostile error text.
8. Verify the TUI cannot select a disabled model and needs only one Enter for an
   enabled current model.

## Security rules

- Never place a credential in `Debug`, cache, record, event, output, or test log.
- A repository config cannot choose a credentialed egress destination.
- Catalog cache identity is installation-local and credential-bound without
  storing a naked credential hash.
- Provider output is untrusted data and cannot grant tools or change policy.
- HTTP is permitted only for an exact loopback development endpoint.

## Evidence

Run provider and CLI catalog tests plus the full workspace gate. A real account
probe is optional evidence and must not enter CI unless its credential, quota,
data retention, and failure ownership are explicitly governed.
