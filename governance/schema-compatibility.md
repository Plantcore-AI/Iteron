# Public schema compatibility policy

`governance/schema-compatibility.json` is the source-controlled compatibility contract for SQ/EQ
envelopes and writable operations/events, durable rollout lines and their reachable tagged and
named object shapes, typed kernel diagnostics, and CLI JSON/JSONL machine output. `core-xtask
boundaries check` validates the current tree. Pull-request and merge-group jobs additionally
compare the candidate or prospective combined commit with its immediate trusted base and with the
last immutable published release.

The policy is intentionally stricter than tolerant JSON parsing:

1. Every fixture is pinned to a surface version. Once published, its path and bytes are immutable
   and remain in the corpus; a new version adds a new fixture. Current-version fixtures must have
   exactly the active field set, while every retained prior fixture must still pass the real typed
   parser or replay path in the current build. Contracts, source inputs, and fixtures must be real
   bounded regular files: symbolic links are rejected. The CLI golden directory is a flat,
   fail-closed inventory; nested or non-regular entries are not ignored.
2. A field, selector, deprecation marker, shim, or fixture-set change advances the affected
   surface's `current_version`. Protocol changes also remain subject to the independent SQ/EQ
   `PROTOCOL_VERSION` lockstep gate, and CLI result and stream surfaces remain bound to the single
   producer `SCHEMA_VERSION` constant. The immediate-base gate recalculates the global protocol
   bump for a merge-group commit, so two stale changes that both selected the same next version do
   not become valid merely because they were independently green.
3. `release_ordinal` counts published immutable full releases, not pull requests or schema edits.
   The first public release uses ordinal 1; every later release uses exactly the preceding
   published release's ordinal plus one, even when no schema changes. Ordinals seen only in pull
   requests are provisional and do not establish deprecation history. Each schema pull request is
   checked directly against the last published immutable release, so several changes targeting the
   same next ordinal can land during one release cycle without fabricating extra runway. If a
   provisional next-release branch becomes stale because a different release is published first,
   its provisional `introduced_release` and `deprecated_release` markers may move only strictly
   forward to the new candidate ordinal; they may never move backward or be cleared. The published
   anchor remains authoritative and rejects any rewrite of history that was actually released.
4. A tag release is checked against the highest lower strict `vX.Y.Z` stable release returned by
   GitHub. That release must be immutable, its local tag must be annotated, its commit must be an
   ancestor of the candidate, and `gh release verify` must succeed. The previous release's xtask
   binary—not candidate code—then validates the candidate contract and executes admitted
   migrators. A missing published contract fails closed. The one-time bootstrap path admits only
   ordinal 1, fields introduced in ordinal 1, no deprecations, and no shims.
5. An additive change is admitted only with a version bump and a new current fixture. A removal or
   rename additionally requires that the public name was already deprecated in the preceding
   published release and remained present for at least `minimum_deprecation_releases`. The removal
   keeps every old fixture, declares a live compatibility shim, names its replacement when
   applicable, and names a migrator already compiled into the previous published xtask. A bounded
   `fixtures` list must equal the complete set of retained fixture/source versions whose selected
   records contain the old field; the checker executes the migrator against every one. Candidate
   code cannot mint migration authority in the same breaking release. Because prior fixtures are
   permanent, an admitted shim has no expiry and cannot later be removed or weakened. Its target
   version, target field set, prior source-fixture entries, and migrator are frozen at the removal
   release. Its fixture list may only grow when a newly retained legacy fixture contains the old
   field, and current-tree validation must still prove exact exhaustive coverage. A later additive
   version therefore does not silently retarget or invalidate the historical migration. A surface
   with no published predecessor cannot claim shims or earlier field history. Registry admission
   is bound to the exact surface and source/target versions; a migrator name cannot be borrowed by
   another schema context.
6. A selector is an immutable part of a surface. Heterogeneous CLI JSONL is divided into one
   `type`-selected surface per record kind; every record in every selected fixture must match
   exactly one declared surface. A shim is applied only to the matching records and must preserve
   the selector, stamp its frozen target version, and produce exactly its frozen target field set.
   Removal/rename migrators are canonical: they preserve every unchanged value, move the old value
   unchanged to the declared replacement when one exists, remove the old name, and stamp the
   target version when the surface has a version field. The build-plane checker must equal each
   shim's frozen target. The runtime oracle composes every applicable rename/removal in ascending
   target-version order, advances the version field to the current surface version, rejects stale
   or undeclared keys, and requires every traceable migrated value to survive current typed
   serialization. Later additive/default fields may appear without weakening that preservation
   check.
7. Every writable SQ `Op` tag has one `protocol.op.*` direct-field surface selected by `op`, and
   the exhaustive typed operation corpus plus Rust-source inventory must agree exactly. Durable
   `EventKind` uses the same rule at its `kind` tag: every writable tag has a direct-field surface
   and occurs in the exhaustive record corpus. Tagged nested `Block`, `WorkflowEvent`, and
   `CostAttribution` variants likewise have direct-field surfaces and frozen corpora whose exact
   canonical values occur inside the event corpus. Every reachable named Serde object is also a
   `record.named.*` source-bound surface, including private-but-serialized fields; intentionally
   opaque `serde_json::Value` leaves are the recursion boundary. These versionless nested families
   (`record.named.*`, `record.block.*`, `record.workflow-event.*`, and
   `record.cost-attribution.*`) cannot declare local compatibility shims: there is no independent
   version marker or generic nested path at which such a migration could be applied safely. A
   nested additive field must be optional or have a Serde default and must land with the required
   protocol/surface version and a new golden. A nested rename or removal must instead use a new
   top-level event tag and a distinct new Rust type/surface while retaining the legacy tag and
   type, as `workflow_v2` and `subagent_finished_v2` do; it cannot silently change the established
   tag in place. This is a backward-reader guarantee—the current build replays every retained old
   rollout—not a claim that an old binary can read every future additive nested variant.
8. Protocol tests round-trip every SQ/EQ envelope and every manifest-registered writable operation
   fixture. Record tests enumerate every manifest-registered event-envelope and event-kind fixture,
   typed-decode it, require stable canonical serialization, tie every kind to an envelope, and tie
   every envelope to a hash-verified replayed rollout; every `record.rollout` fixture is replayed.
   The record projection corpus also equals the exact nested `Block`, `WorkflowEvent`, and
   `CostAttribution` values serialized by those event kinds; each named fixture typed-round-trips
   and is tied back to a value reachable from the event corpus. Shimmed independently-versioned
   record fixtures additionally compose frozen migrations and compare every traceable value with
   current typed output. Kernel tests typed-decode every diagnostic fixture. CLI source inventory
   binds every producer's literal top-level field set—not only its `type` tag—to the manifest and
   producer-generated goldens. Provider effort variants, emitted `enforcement` tags, the strict
   evaluation decoder, and the exhaustive golden must name the same set. The real evaluation
   consumer strictly decodes every retained CLI record and must admit precisely the frozen producer
   versions, including the current version. This strict corpus oracle is deliberately stronger
   than an ordinary streaming client, which may ignore an event type it does not consume and rely
   on the final result. These are compatibility checks only and do not execute an evaluation run.
9. Pull-request and merge-group CI rerun both published chronology validation and the immediate-base
   comparison from trusted policy code. The merge-group run checks the prospective combined commit,
   including a fresh boundary diff and global `PROTOCOL_VERSION` monotonicity check, closing
   stale-branch and independently-green-but-incompatible composition gaps before merge. Activating
   the external merge queue and protected ruleset is the separate D13-10 governance action and is
   not claimed by this compatibility implementation.

Changing this policy format requires an explicit policy-format migration. Reducing the
deprecation runway, deleting a public surface, weakening a shim, rewriting a frozen fixture, or
silently reusing a schema version is rejected.
