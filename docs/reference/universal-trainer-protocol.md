# Universal trainer bridge

`iteron-eval` schema v2 gives native and external optimizers one candidate model. A candidate
contains an ordinary digest-bound `ProfileDocument` for Tier-1 families, Tier-2 parameters,
prompts, and built-in tool descriptions, plus zero or more content-addressed implementation
bindings. The same rendered profile is accepted by Iteron's normal CLI; using the tuner or the
evolution crate is never required to run it.

`TunerCandidate.schema_version` is now exactly `2` for the universal path. Each
`CandidateImplementation` is an executable source locator, not an identity hint: it carries one
module, a unique marketplace implementation id, exact `iteron-implementation/1`, canonical
absolute `catalog_path` and `artifact_root`, and prefixed manifest/artifact SHA-256 values. The
canonical candidate digest covers every field, including both paths. Relative paths, duplicate
module/id bindings, unsupported protocols, and wrong catalog, manifest, or artifact content fail
before a run is admitted.

The method-neutral `TrainerBridgeSpec` pins distinct train and held-out datasets, reward
objectives, trajectory and checkpoint schemas, per-trial resource ceilings, and distributed lease
limits. `TrainerExchange` has four closed operations: `suggest`, `observe`, `checkpoint`, and
`resume`. Every exchange must repeat the bridge's exact experiment identity, and is bounded,
digest-addressed, and operation-shape checked; an exchange cannot be rebound across experiments.
Transcript content is not carried in trainer control messages.

External implementations use the same strict JSON records through `parse_trainer_bridge_spec` and
`parse_trainer_exchange`. Both parsers reject duplicate/unknown fields and messages over 1 MiB;
there is no Rust-only implicit default or unbounded side channel.

`TrainerExchange` still coordinates suggestions and observations; it does not carry the candidate
document itself. A language-neutral external trainer submits its schema-v2 `TunerCandidate` through
`iteron-research/1` `candidate_validate`, receives the correlated materialized activation identity,
then uses the same persistent session for run/result/evidence. This separation is the current T41
integration boundary, not an implicit candidate transport inside `TrainerExchange`.

Native `OfflineTuner` accepts legacy schema v1 family-only candidates for replay compatibility.
Schema v2 is the universal path: it requires the exact family, parameter, and tool-text registry
digests, a valid bridge contract, an externally runnable profile, and content-addressed
implementation identities. Mixing the legacy family map with the v2 profile is rejected rather
than merged by precedence.

The bridge has no runtime or promotion authority. It cannot loosen host resource ceilings, change
security or replay invariants, read held-out observations into tuning, select, evolve, or promote a
candidate. Marketplace validation and operator-selected research execute mode remain separate host
admissions with their own activation and consumption evidence.
