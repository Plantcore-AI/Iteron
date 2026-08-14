# Universal trainer bridge

`iteron-eval` schema v3 gives native and external optimizers one closed candidate graph. A graph
can contain unified-profile values, direct-config patches, caller-input patches, content-addressed
implementation bindings, conditional topology, sparse lineage, and a fully pinned experiment
identity. The same rendered profile remains accepted by Iteron's normal CLI; using the native
tuner or the evolution crate is never required to propose or inspect a candidate.

`TunerCandidate.schema_version = 3` selects `iteron-candidate/3`. Every dimension has a stable
language-neutral address (`kind`, selector, schema/protocol owner) and a typed value. Addresses are
unique and sorted; topology is acyclic and may contain exact-value conditions; lineage binds a
parent digest, generation, and sparse delta; experiment identity binds dataset, evaluator,
environment, resources, fidelity, and seed. Deterministic materialization produces exactly one
profile, direct-config patch set, caller-input patch set, implementation set, and topology, plus
separate materialization, experiment, and topology digests.

Each `CandidateImplementation` is an executable source locator, not an identity hint: it carries
one module, a unique marketplace implementation id, an exact supported implementation protocol,
canonical absolute `catalog_path` and `artifact_root`, and prefixed manifest/artifact SHA-256
values. The canonical candidate digest covers every field, including both paths. Relative paths,
duplicate module/id bindings, unsupported protocols, and wrong catalog, manifest, or artifact
content fail before a run is admitted. Protocol v2 is required for state migration; v1 remains a
stateless compatibility path.

The method-neutral `TrainerBridgeSpec` v2 pins distinct train and held-out datasets, reward
objectives, trajectory and checkpoint schemas, per-trial resource ceilings, and distributed lease
limits. It negotiates the exact intersection of host and optimizer capabilities: batch,
asynchronous, population, bandit, multi-objective, trajectory, checkpoint/resume, and opaque
artifact. `TrainerExchange` has four closed operations: `suggest`, `observe`, `checkpoint`, and
`resume`; schema v2 additionally binds optimizer/negotiation identity and correlated batch
suggestions. Every exchange must repeat the bridge's exact experiment identity, and is bounded,
digest-addressed, and operation-shape checked. Transcript content is not carried in trainer
control messages.

External implementations use the same strict JSON records through `parse_trainer_bridge_spec`,
`parse_trainer_exchange`, and `parse_negotiated_trainer_exchange`. Parsers reject duplicate or
unknown fields and messages over 1 MiB; there is no Rust-only implicit default or unbounded side
channel.

`TrainerExchange` coordinates suggestions and observations; it does not carry the candidate
document itself. A language-neutral external trainer submits its schema-v3 `TunerCandidate`
through `iteron-research/1` `candidate_validate`, receives the correlated graph and activation
identities, then uses the same persistent session for run/result/evidence.

Native `OfflineTuner` accepts legacy schema-v1 family-only tuner specifications and schema-v2
profile candidates for replay compatibility. Schema v3 is the universal graph path. Mixing legacy
maps/profile/implementation fields with its graph is rejected rather than merged by precedence.
An adapter must either consume every materialized address and return an exactly correlated receipt
or reject the candidate with a typed unsupported-materialization error; acceptance may never make
a dimension inert.

The bridge has no runtime or promotion authority. It cannot loosen host resource ceilings, change
security or replay invariants, read held-out observations into tuning, select, evolve, or promote a
candidate. Marketplace validation and operator-selected research execute mode remain separate host
admissions with their own activation and consumption evidence.
