# Static provider metadata

Some provider facts cannot be discovered from an account-scoped API. Iteron ships a
bounded schema-v1 document for those facts: the official GLM standard Chat model
enum and exact model capabilities, plus the Anthropic semantic-effort beta header
and its explicit model allowlist. These are compatibility claims only. They do not
prove account entitlement, billing state, or availability.

The source-controlled default is
`crates/provider/static-provider-metadata-v1.json`.
At startup, Iteron uses `~/.iteron/provider-metadata.json` when that operator-owned file
exists; otherwise it uses the embedded default. Replacing this file is the refresh
path and does not require rebuilding Iteron.

Refresh the file only from provider documentation you reviewed, then replace it as
one complete document. The loader fails loudly on malformed, oversized, duplicate,
route-changing, or unversioned updates. A changed document must bump
`bundle_revision`; a changed GLM catalog, GLM capability, or Anthropic effort
snapshot must also bump that snapshot's `version`. Every revision has the form
`<human-label>+sha256:<canonical-content-digest>`; Iteron recomputes all snapshot and
bundle digests, so reusing a v2 label for different v2 bytes fails closed even when
there is no previous local file to compare. The public
`StaticProviderMetadata::stamp_content_versions` authoring helper recomputes these
suffixes after an offline editor changes the complete JSON value. The file is
limited to 256 KiB, the official API roots cannot be changed, and omitted
capabilities remain unknown.
In particular, listing a model never implicitly grants tool calling, token limits,
semantic effort, or image input. A provider catalog field dedicated to image support is retained
as model-level evidence; a generic model id is not.

For example, after preparing and reviewing a complete replacement:

```sh
mkdir -p ~/.iteron
install -m 600 /path/to/reviewed-provider-metadata.json ~/.iteron/provider-metadata.json
```

The final file itself must have one hard link and must not be a link. On Unix it
must be owned by the effective user with owner-only mode bits. On Windows Iteron
opens the named object without following reparse points, then verifies that the
authoritative handle is a single-link, non-reparse regular file. The current user
must own it, and its DACL must not grant mutation rights beyond that user,
LocalSystem, or Administrators. Iteron reads only through that validated,
size-bounded handle, so a later pathname swap cannot change the bytes read.

The first provider request in a run records and displays a bounded notice such as
`static provider metadata: catalog is 42 days old (stale)`. When active snapshot
versions differ from the embedded defaults, the same notice includes
`provider revision changed`. The notice is observational: it does not turn dated
metadata into fresh evidence, and it never authorizes a capability absent from the
active document. Once-only suppression is committed only after the notice reaches
the durable record, is scoped to the current physical run and exact recorded route,
and is reconstructed on resume. A fork or a genuinely different route therefore
records its own evidence, while returning to an already evidenced route does not
duplicate it. Iteron labels a snapshot stale after 30 complete days; a capture
timestamp more than five minutes ahead of the runtime clock is rejected before the
provider is built. A later clock rollback is still reported as invalid, never as
fresh. One-shot `text` and single-result `json` display scrubbed notices on stderr;
`stream-json` emits a typed `notice` object on stdout, and TUI renders the same UI
event. In every mode the notice is also durably recorded before `TurnStart`.
