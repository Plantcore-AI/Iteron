# File editing

Use a targeted edit for existing code. Whole-file replacement needs an explicit
preimage so a stale model view cannot silently overwrite a user's changes.

| Operation | Native path | Behavior |
| --- | --- | --- |
| Create a UTF-8 file | `write_file` with `path` and `content` | Creates only when the destination is missing; content is limited to 4 MiB. |
| Replace a whole UTF-8 file | `read_file` with `include_sha256: true`, then `write_file` with `expected_sha256` | Compares the full original raw-byte digest before staging and rechecks the retained snapshot before replacement. Preserve existing user changes in the supplied replacement. |
| Change a unique text anchor | `edit` with `old` and `new` | Preserves non-target text, supported BOM and newline conventions, and file mode. Ambiguous or missing anchors refuse. |
| Change several existing UTF-8 files | `apply_patch` with explicit file paths and hunks | Plans all members before replacement; rechecks each member. On partial failure, restores only unchanged transaction bytes. A later human edit stays in place and produces a rollback conflict. |
| Delete, move, modify binary or unsupported encodings, or exceed native text limits | Explicitly authorized shell/process tools | These are outside the native text-patch protocol. Use suitable byte-aware commands under the selected execution policy; inspect their actual result. Native read/edit/patch refuse unsupported text. |

`write_file` accepts UTF-8 replacement content. A caller with a legitimate raw
digest may deliberately replace an existing binary file with text; this is a
whole-file conversion, not binary patch support. `read_file` does not render or
return a replacement witness for an unsupported binary file.

The SHA-256 is computed over all bytes actually read, including the original BOM
and newlines. A paginated read can return that digest while showing only part of
the file; it does not mean the unseen content was reviewed. Read the remaining
content or use a targeted edit before forming a whole-file replacement.

For an existing destination, omitting `expected_sha256` returns
`preimage_required`. A stale digest, or a missing destination when an existing
preimage was supplied, returns `preimage_changed`. Re-read and reconcile the
user's changes. Creation inputs remain valid without a digest.

Replacement is atomic for one file. The identity check and filesystem rename
are separate operations; this is not an operating-system compare-and-swap or a
fully atomic multi-file transaction. Conflicts and unresolved rollback are
reported instead of being relabeled as success.
