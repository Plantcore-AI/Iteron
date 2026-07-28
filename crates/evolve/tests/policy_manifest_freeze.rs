//! The other half of the golden snapshot: the evolution documents, frozen at
//! `EVOLUTION_SCHEMA_VERSION` 3.
//!
//! Issue #14 acceptance criterion 7 names `core-protocol` **and** `PolicyManifest`.
//! `crates/protocol/tests/abi_freeze.rs` covers the first and says in its own words that it can
//! only cover half of the second: `PolicyManifest` lives here, in a crate that depends on
//! `core-protocol`, so reaching the type from there needs a dev-dependency cycle back into the
//! frozen crate's manifest. What that file freezes is the part `core-protocol` decides -
//! `BTreeSet<Capability>` ordering and the `policy_manifest` artifact tag. This file freezes the
//! document's own field set, from the only crate that can see it.
//!
//! # Why a field set with a JSON type, and not the serialised bytes
//!
//! Same reasoning as the protocol snapshot, and it is repeated here rather than cross-referenced
//! because the two files must stay independently readable. A byte-exact golden goes red whenever a
//! *value* moves - a digest, a locator, a slot name - and every one of those failures is cleared
//! by re-blessing the file. After the third re-bless nobody reads the diff, which is the exact
//! failure a freeze test exists to prevent. A field set fails only when the shape moves, and the
//! shape is what criterion 7 protects. Values are pinned separately, and only where the value *is*
//! the contract: the three tag vocabularies and the schema stamp each get their own assertion.
//!
//! A derived schema - `schemars`, or a proc macro over the types - was the other candidate. It
//! would add a dependency to a crate whose manifest is deliberately five lines long, and it would
//! freeze the *Rust* type rather than the wire form. `rename`, `transparent` and
//! `skip_serializing_if` all move the wire form without moving the Rust type at all, and the wire
//! form is what a peer and a document already on disk actually see.
//!
//! # Why now rather than when the first manifest is written
//!
//! A snapshot taken after six workstreams have started emitting manifests records their drift, not
//! the freeze. This is the freeze's own proof artifact, so it is taken in the freeze commit.
//!
//! # When this test fails
//!
//! A removal, a rename or a type change is a breaking diff, and the fix is to put the field back:
//! documents written before the change are on disk and cannot be migrated retroactively. An
//! addition is legal only if it survives the two additive checks below, and the snapshot row is
//! then updated in the same commit that adds the field. Editing a row to turn a red test green is
//! the one thing this file exists to make visible.
//!
//! A field genuinely appended after the freeze also needs `EVOLUTION_SCHEMA_VERSION` moved and an
//! N-1 migration written - see `crates/evolve/src/schema.rs`, which migrates exactly N-1 and
//! rejects everything else fail-closed (docs/spec/evolution.md §6.4).

use core_evolve::{
    ArtifactKind, BaseModelId, DataClass, DataGovernance, DatasetAuditKind, DeploymentStage,
    EVOLUTION_SCHEMA_VERSION, EvolutionMethod, PolicyBundle, PolicyManifest, PolicyRef,
    PromotionAssessment, PromotionAuditKind, PromotionOperation, PromotionRole, ProtocolRange,
    RewardVector, StrategyDecision, StrategySlot, TrainingConsent, TrajectoryEnvelope,
};
use core_protocol::{Capability, RunId, TenantId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

/// The JSON type behind one frozen field name.
///
/// Coarse on purpose. The snapshot catches a field changing kind - a scalar becoming an object, a
/// string becoming a number - not the Rust type, which the compiler already owns. Only the kinds
/// these documents emit are listed; adding an arm the day a field needs one is not itself a
/// change to the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Json {
    Number,
    String,
    Array,
    Object,
}

impl Json {
    fn of(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Json::Number => "number",
            Json::String => "string",
            Json::Array => "array",
            Json::Object => "object",
        }
    }
}

/// One row of the snapshot: a persisted evolution type.
struct Shape {
    /// How a failure names it.
    ty: &'static str,
    /// Where a reader goes to check the claim.
    module: &'static str,
    /// The field set this shape emitted at the freeze.
    fields: &'static [(&'static str, Json)],
    /// A fully populated value, as it serialises today.
    populated: fn() -> Value,
    /// Decode this shape from JSON and re-encode it. This is what makes the additive rule
    /// checkable: an appended field has to survive being deleted and must not come back.
    reencode: fn(Value) -> Result<Value, serde_json::Error>,
}

/// A row names its type twice - once for the label a failure prints, once for the decoder - and
/// writing both by hand buries the field lists, which are the part a reviewer actually reads. The
/// value argument is always a call, never a binding, so both closures stay non-capturing and
/// coerce to the fn pointers above.
macro_rules! shape {
    (
        $label:literal, $ty:ty, $module:literal, $value:expr,
        { $($field:literal : $json:ident),* $(,)? }
    ) => {
        Shape {
            ty: $label,
            module: $module,
            fields: &[$(($field, Json::$json)),*],
            populated: || serde_json::to_value($value).expect(concat!($label, " serialises")),
            reencode: |value| {
                serde_json::from_value::<$ty>(value).map(|decoded| {
                    serde_json::to_value(decoded).expect(concat!($label, " re-encodes"))
                })
            },
        }
    };
}

const D: &str = "9f2c1b4a5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f80";

fn base_model() -> BaseModelId {
    BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-opus-5".into(),
        model_digest: "b".repeat(64),
    }
}

fn policy_ref() -> PolicyRef {
    PolicyRef {
        slot: StrategySlot::router(),
        policy_id: "candidate-a".into(),
        version: "2.0.0".into(),
        digest: D.into(),
    }
}

fn parent_ref() -> PolicyRef {
    PolicyRef {
        slot: StrategySlot::router(),
        policy_id: "baseline-a".into(),
        version: "1.0.0".into(),
        digest: D.into(),
    }
}

fn protocol_range() -> ProtocolRange {
    ProtocolRange { min: 1, max: 1 }
}

/// Every optional field is populated, deliberately.
///
/// `parent` and `training_dataset_digest` are `Option` with no `skip_serializing_if`, so a `None`
/// emits `null` and the type check below would freeze them as the wrong kind - or, worse, a later
/// reader would conclude from a `null` row that they are absent from the wire. A snapshot built
/// from a half-populated value freezes less than it appears to.
fn policy_manifest() -> PolicyManifest {
    PolicyManifest {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        policy: policy_ref(),
        artifact_kind: ArtifactKind::Rules,
        artifact_locator: "registry://candidate-a@2.0.0".into(),
        parent: Some(parent_ref()),
        method: EvolutionMethod::Search,
        protocol: protocol_range(),
        required_capabilities: BTreeSet::from([Capability::ReadOnly]),
        training_dataset_digest: Some(D.into()),
        evaluation_suite_digest: D.into(),
        base_model: base_model(),
    }
}

fn policy_bundle() -> PolicyBundle {
    PolicyBundle {
        bundle_id: "bundle-a".into(),
        digest: D.into(),
        policies: vec![policy_ref()],
        rollback_to: Some("bundle-previous".into()),
    }
}

fn strategy_decision() -> StrategyDecision {
    StrategyDecision {
        decision_id: "decision-0".into(),
        ordinal: 0,
        policy: policy_ref(),
        observation_digest: D.into(),
        candidate_set_digest: D.into(),
        action: json!({ "route": "safe" }),
        action_digest: D.into(),
        propensity: Some(1.0),
    }
}

fn trajectory_envelope() -> TrajectoryEnvelope {
    TrajectoryEnvelope {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        run_id: RunId("run-a".into()),
        tenant_id: TenantId::default(),
        task_id: "task-a".into(),
        domain: "coding".into(),
        environment_digest: D.into(),
        bundle: policy_bundle(),
        decisions: vec![strategy_decision()],
        terminal_outcome: "completed".into(),
        reward: RewardVector {
            task_score: 1.0,
            correctness: 1.0,
            safety_violations: 0,
            policy_violations: 0,
            cost_usd: 0.01,
            wall_time_ms: 10,
            human_acceptance: Some(1.0),
            domain: BTreeMap::from([("tests_passing".to_owned(), 1.0)]),
        },
        governance: DataGovernance {
            class: DataClass::Public,
            consent: TrainingConsent::Allowed,
            content_license: Some("apache-2.0".into()),
            contains_secret_material: false,
            retention_policy: "training-v1".into(),
        },
    }
}

/// The snapshot: every document and embedded shape that reaches disk under a schema stamp.
fn frozen() -> Vec<Shape> {
    vec![
        shape!(
            "PolicyManifest", PolicyManifest, "crates/evolve/src/lib.rs", policy_manifest(),
            {
                "schema_version": Number,
                "policy": Object,
                "artifact_kind": String,
                "artifact_locator": String,
                "parent": Object,
                "method": String,
                "protocol": Object,
                "required_capabilities": Array,
                "training_dataset_digest": String,
                "evaluation_suite_digest": String,
                "base_model": Object,
            }
        ),
        shape!(
            "BaseModelId", BaseModelId, "crates/evolve/src/base_model.rs", base_model(),
            { "model_family": String, "model_id": String, "model_digest": String }
        ),
        shape!("PolicyRef", PolicyRef, "crates/evolve/src/lib.rs", policy_ref(), {
            "slot": String,
            "policy_id": String,
            "version": String,
            "digest": String,
        }),
        shape!(
            "ProtocolRange", ProtocolRange, "crates/evolve/src/lib.rs", protocol_range(),
            { "min": Number, "max": Number }
        ),
        shape!(
            "TrajectoryEnvelope", TrajectoryEnvelope, "crates/evolve/src/lib.rs",
            trajectory_envelope(),
            {
                "schema_version": Number,
                "run_id": String,
                "tenant_id": String,
                "task_id": String,
                "domain": String,
                "environment_digest": String,
                "bundle": Object,
                "decisions": Array,
                "terminal_outcome": String,
                "reward": Object,
                "governance": Object,
            }
        ),
    ]
}

fn emitted_object(shape: &Shape) -> serde_json::Map<String, Value> {
    match (shape.populated)() {
        Value::Object(fields) => fields,
        other => panic!(
            "`{}` no longer serialises as a JSON object but as a {}. The schema is frozen: a \
             document that stops being an object relocates every one of its fields at once, and \
             no migration can read what is already on disk. See {}.",
            shape.ty,
            Json::of(&other),
            shape.module
        ),
    }
}

#[test]
fn no_frozen_field_ever_leaves_the_wire_or_changes_its_type() {
    for shape in frozen() {
        let emitted = emitted_object(&shape);
        for (field, json) in shape.fields {
            let Some(value) = emitted.get(*field) else {
                panic!(
                    "`{}.{field}` is gone from the wire. The schema is frozen: a persisted field \
                     may be appended, never removed and never renamed. A rename shows here as \
                     this removal plus an addition, and the removal is the breaking half - every \
                     document already written stops parsing. Defined in {}; normative shape in \
                     docs/spec/evolution.md §6.1.",
                    shape.ty, shape.module
                );
            };
            let actual = Json::of(value);
            assert!(
                actual == json.name(),
                "`{}.{field}` changed type: the snapshot froze it as {}, it now emits {}. A type \
                 change is a breaking diff even when the name survives, because a reader decodes \
                 by type. New semantics take a new field and a schema bump with an N-1 migration \
                 (crates/evolve/src/schema.rs), never a reinterpreted field. See {}.",
                shape.ty,
                json.name(),
                actual,
                shape.module
            );
        }
    }
}

#[test]
fn a_field_appended_after_the_freeze_must_be_optional_and_absent_by_default() {
    for shape in frozen() {
        let emitted = emitted_object(&shape);
        let recorded: BTreeSet<&str> = shape.fields.iter().map(|(name, _)| *name).collect();
        for name in emitted.keys() {
            if recorded.contains(name.as_str()) {
                continue;
            }
            // Not in the snapshot, so it was appended after the freeze. Both halves of the
            // additive rule are observable from outside the type: a document written before the
            // field existed must still decode, and leaving it unset must leave the bytes exactly
            // as they were. A field that fails either half needed a schema bump, not an append.
            let mut without = emitted.clone();
            without.remove(name);
            let reencoded = (shape.reencode)(Value::Object(without)).unwrap_or_else(|error| {
                panic!(
                    "`{}.{name}` was appended after the freeze and is not optional: a document \
                     without it fails to decode ({error}). An appended field MUST be `Option` \
                     with `skip_serializing_if = \"Option::is_none\"` (docs/spec/abi.md \
                     §4.3(b)3), or it needed `EVOLUTION_SCHEMA_VERSION` moved and a migration \
                     written. See {}.",
                    shape.ty, shape.module
                )
            });
            assert!(
                reencoded.get(name).is_none(),
                "`{}.{name}` was appended after the freeze and is emitted even when unset, so it \
                 moves the bytes of every document written before it. An appended field MUST \
                 carry `skip_serializing_if = \"Option::is_none\"` so that unset stays \
                 byte-identical (docs/spec/abi.md §4.3(b)3). See {}.",
                shape.ty,
                shape.module
            );
        }
    }
}

#[test]
fn every_frozen_shape_decodes_its_own_snapshot_without_moving_it() {
    // The field-set checks are encode-side only. This is the decode side: a rename applied to one
    // half of a `#[serde(rename)]`, a stray `deny_unknown_fields`, or a `default` that overwrites
    // a decoded value all leave the emitted field set intact and still break the round trip - and
    // a document that does not survive its own wire form cannot be re-read after it is stored.
    for shape in frozen() {
        let emitted = (shape.populated)();
        let decoded = (shape.reencode)(emitted.clone()).unwrap_or_else(|error| {
            panic!(
                "`{}` cannot decode the wire form it just emitted ({error}). The schema is \
                 frozen, and a document that does not round-trip is not a contract. See {}.",
                shape.ty, shape.module
            )
        });
        assert!(
            decoded == emitted,
            "`{}` does not survive its own wire form: emitted {emitted}, read back {decoded}. The \
             schema is frozen. See {}.",
            shape.ty,
            shape.module
        );
    }
}

fn assert_tags_are_frozen<T>(ty: &str, members: &[(T, &str)])
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    for (member, tag) in members {
        let encoded = serde_json::to_value(member).expect("a vocabulary member serialises");
        assert!(
            encoded == *tag,
            "`{ty}::{member:?}` renders as {encoded}; the schema froze it as \"{tag}\". A tag is \
             the whole identity of a variant on the wire, so renaming one is indistinguishable \
             from deleting it and adding another."
        );
        let decoded: T = serde_json::from_value(Value::from(*tag)).unwrap_or_else(|error| {
            panic!("`{ty}` no longer decodes its frozen tag \"{tag}\": {error}")
        });
        assert!(
            decoded == *member,
            "`{ty}` decodes its frozen tag \"{tag}\" as {decoded:?} rather than {member:?}. A tag \
             may not be re-pointed at a different variant: every document already carrying it \
             would change meaning in place."
        );
    }
}

#[test]
fn the_persisted_vocabularies_keep_their_exact_tags_and_the_schema_stamp_holds() {
    // These three decide what a stored document *means*, so their tags are frozen by value while
    // the shapes above are frozen only by kind. Whether each degrades or hard-fails on an
    // unrecognised member is a separate property, argued and asserted where the enums are declared
    // (crates/evolve/src/lib.rs and the vocabulary tests in base_model.rs); the assertions below
    // are about the tags themselves, which are frozen either way. The one place that separation
    // does not hold is `DeploymentStage`, whose closure has no other register to be recorded in -
    // see the comment on its call.
    assert_tags_are_frozen(
        "ArtifactKind",
        &[
            (ArtifactKind::Rules, "rules"),
            (ArtifactKind::Prompt, "prompt"),
            (ArtifactKind::WasmComponent, "wasm_component"),
            (ArtifactKind::ModelAdapter, "model_adapter"),
            (ArtifactKind::ModelWeights, "model_weights"),
            (ArtifactKind::ExternalService, "external_service"),
            (ArtifactKind::Builtin, "builtin"),
            (ArtifactKind::Unknown, "unknown"),
        ],
    );
    assert_tags_are_frozen(
        "EvolutionMethod",
        &[
            (EvolutionMethod::HandAuthored, "hand_authored"),
            (EvolutionMethod::Search, "search"),
            (EvolutionMethod::ContextualBandit, "contextual_bandit"),
            (EvolutionMethod::SupervisedFineTune, "supervised_fine_tune"),
            (
                EvolutionMethod::PreferenceOptimization,
                "preference_optimization",
            ),
            (EvolutionMethod::Grpo, "grpo"),
            (EvolutionMethod::OfflineRl, "offline_rl"),
            (EvolutionMethod::OnlineRl, "online_rl"),
            (EvolutionMethod::GeneratedCode, "generated_code"),
            (EvolutionMethod::Unknown, "unknown"),
        ],
    );
    // `DeploymentStage` is a *closed* vocabulary under criterion 2. It cannot be registered beside
    // the `core-protocol` ones in
    // `crates/protocol/tests/abi_freeze.rs::the_closed_vocabularies_refuse_an_unrecognised_tag`,
    // because `core-protocol` cannot depend on `core-evolve` and the type is not nameable from that
    // file. Its entry in the register is therefore here.
    //
    // This comment used to claim `DeploymentStage` was "the only one that does not live in
    // `core-protocol`". That was false, and a review that enumerated the crate found it: this crate
    // has ten serde-derived enums and seven of them were in no register at all. They are registered
    // below, in `the_remaining_closed_vocabularies_are_recorded_and_refuse_an_unrecognised_tag`. A
    // register that asserts its own completeness in prose is worth less than one that enumerates,
    // because the prose stays confident while the crate grows.
    //
    // Closed deliberately, on the grounds argued at the declaration in crates/evolve/src/lib.rs:
    // the two vocabularies above describe what a *producer* made, and a newer peer is entitled to
    // invent a member of either, so they degrade to `Unknown` and are refused on use. A stage is
    // this build's own promotion state, written and read by the same authority, so an unrecognised
    // one is not forward compatibility - it is a corrupt or forged state record, and the correct
    // answer is a decode error rather than a sentinel. The enum also derives `Ord`, and `serde`
    // requires `#[serde(other)]` on the last variant, so an appended `Unknown` would sort above
    // `Active` - the same shape as the 2026-07-27e regression in Errors.md, where an appended
    // `Trust::Unknown` took the top discriminant and defeated `min()`.
    //
    // The refusal itself is asserted exactly once, by
    // `base_model::vocabulary_tests::deployment_stage_hard_fails_on_an_unrecognised_member_instead_of_degrading`
    // (crates/evolve/src/base_model.rs), which decodes an unrecognised tag and requires an error -
    // so it goes red the moment anyone gives this enum an `#[serde(other)]` arm. That is the whole
    // recording, and it is referenced rather than repeated: a second copy of the same assertion is
    // free to drift from the first, and a register whose two halves disagree tells a later reader
    // less than one that points at the single place the property is checked. What this call
    // freezes is the other half, the tags, which are frozen whether the vocabulary is open or not.
    assert_tags_are_frozen(
        "DeploymentStage",
        &[
            (DeploymentStage::Candidate, "candidate"),
            (DeploymentStage::Shadow, "shadow"),
            (DeploymentStage::Canary, "canary"),
            (DeploymentStage::Active, "active"),
            (DeploymentStage::Retired, "retired"),
            (DeploymentStage::RolledBack, "rolled_back"),
        ],
    );

    // The stamp every one of the shapes above carries. It is what tells the loader which of these
    // field sets a document on disk was written against, so moving it without moving this line
    // makes the snapshot describe a schema nothing writes.
    assert_eq!(
        EVOLUTION_SCHEMA_VERSION, 3,
        "this snapshot describes schema 3. Bumping the stamp means the field sets above changed, \
         and the bump belongs in the same commit as the new rows and the N-1 migration in \
         crates/evolve/src/schema.rs."
    );
}

/// The seven serde-derived vocabularies this crate had recorded nowhere.
///
/// A review enumerated every `#[derive(Deserialize)] enum` in `core-evolve` and found ten. Three
/// were registered — `ArtifactKind` and `EvolutionMethod` as open, `DeploymentStage` as closed. The
/// other seven were in neither register and had no test feeding them an unrecognised tag, so nothing
/// recorded whether their closure was a decision or an accident. `Errors.md` 2026-07-28c already
/// names that as the defect which lets a later contributor "helpfully" open a closed vocabulary; the
/// same gap had simply been reproduced one crate over.
///
/// All seven are **closed**, and each for the same reason `DeploymentStage` is: every one of them is
/// this build's own state or its own authorization vocabulary, written and read by the same code. An
/// unrecognised member is not a newer peer being forward-compatible — it is a corrupt or forged
/// record, and a sentinel would launder it into a value the rest of the code then has to handle.
///
/// `PromotionRole` deserves its own note. It derives `Ord` and lives in a `BTreeSet` on
/// `PromotionTrustAnchor`, which is exactly the shape of the `Trust::Unknown` regression recorded in
/// `Errors.md` 2026-07-27e: appending an `#[serde(other)] Unknown` arm would take the top
/// discriminant and silently reorder the set. This test is what goes red if anyone tries.
#[test]
fn the_remaining_closed_vocabularies_are_recorded_and_refuse_an_unrecognised_tag() {
    // --- unit-variant vocabularies: a bare string is the whole wire form ---
    assert_tags_are_frozen(
        "DataClass",
        &[
            (DataClass::Public, "public"),
            (DataClass::Internal, "internal"),
            (DataClass::CustomerConfidential, "customer_confidential"),
            (DataClass::Personal, "personal"),
            (DataClass::Secret, "secret"),
            (DataClass::Unknown, "unknown"),
        ],
    );
    // `DataClass` carries an `Unknown` variant WITHOUT `#[serde(other)]`, so it wears the shape of
    // an open vocabulary while behaving like a closed one: the literal tag "unknown" decodes, and a
    // genuinely new class fails the whole envelope. Both halves are fail-closed and the asymmetry is
    // deliberate — but it was undocumented, and a reader who saw the `Unknown` variant could
    // reasonably have "fixed" it by adding the attribute, turning a hard refusal into a silent
    // degrade with no test going red. This is that test.
    assert!(
        serde_json::from_value::<DataClass>(serde_json::json!("regulated_health")).is_err(),
        "DataClass has an Unknown variant but no #[serde(other)]: a new class must fail the decode, \
         not land in the sentinel"
    );
    assert_eq!(
        serde_json::from_value::<DataClass>(serde_json::json!("unknown")).expect("the literal tag"),
        DataClass::Unknown,
        "the literal tag `unknown` is a member of the vocabulary and still decodes"
    );

    assert_tags_are_frozen(
        "TrainingConsent",
        &[
            (TrainingConsent::Allowed, "allowed"),
            (TrainingConsent::EvaluationOnly, "evaluation_only"),
            (TrainingConsent::Denied, "denied"),
        ],
    );
    assert_tags_are_frozen(
        "PromotionRole",
        &[
            (PromotionRole::Bootstrap, "bootstrap"),
            (PromotionRole::AdmitCandidate, "admit_candidate"),
            (PromotionRole::AdvanceStage, "advance_stage"),
            (PromotionRole::Rollback, "rollback"),
        ],
    );
    assert_tags_are_frozen(
        "PromotionOperation",
        &[
            (PromotionOperation::Bootstrap, "bootstrap"),
            (PromotionOperation::AdmitCandidate, "admit_candidate"),
            (PromotionOperation::EnterShadow, "enter_shadow"),
            (PromotionOperation::CompleteShadow, "complete_shadow"),
            (PromotionOperation::CompleteCanary, "complete_canary"),
            (PromotionOperation::Rollback, "rollback"),
        ],
    );

    // Each of these is closed. If one of these assertions goes red because someone added
    // `#[serde(other)]`, read the note on this test before blessing it — for `PromotionRole` that
    // attribute also silently reorders the `BTreeSet` it lives in.
    assert!(
        serde_json::from_value::<TrainingConsent>(json!("revoked_pending_review")).is_err(),
        "TrainingConsent gates whether recorded data may be trained on; an unreadable consent value \
         must refuse, never default"
    );
    assert!(
        serde_json::from_value::<PromotionRole>(json!("superuser")).is_err(),
        "PromotionRole is an authorization vocabulary: an unrecognised role must not decode"
    );
    assert!(
        serde_json::from_value::<PromotionOperation>(json!("force_activate")).is_err(),
        "PromotionOperation is the operation field of an HMAC-authorized request; an unrecognised \
         operation must not decode"
    );

    // --- data-carrying vocabularies: swap ONLY the tag on a fully populated member ---
    //
    // A bare `{"kind":"whatever"}` would be refused for its missing body, so it would pass this test
    // for the wrong reason and keep passing the day someone adds an `#[serde(other)]` arm. Each
    // probe below therefore keeps a real body and changes nothing but the discriminant.
    let audit = serde_json::to_value(PromotionAuditKind::StageTransition {
        from: DeploymentStage::Candidate,
        to: DeploymentStage::Shadow,
        permit_digest: Some("a".repeat(64)),
    })
    .expect("serialises");
    assert_eq!(
        audit.get("kind").and_then(serde_json::Value::as_str),
        Some("stage_transition"),
        "PromotionAuditKind is internally tagged on `kind`"
    );
    let mut forged = audit.clone();
    forged["kind"] = serde_json::json!("stage_teleported");
    assert!(
        serde_json::from_value::<PromotionAuditKind>(forged).is_err(),
        "PromotionAuditKind is read back off a hash-chained journal; an unrecognised kind is a \
         corrupt or forged record, never a newer peer"
    );

    let dataset_audit = serde_json::to_value(DatasetAuditKind::ConsentRevoked {
        tenant_id: "acme".into(),
        run_id: "run-1".into(),
        reason: "subject request".into(),
    })
    .expect("serialises");
    assert!(
        dataset_audit.get("consent_revoked").is_some(),
        "DatasetAuditKind is externally tagged"
    );
    let body = dataset_audit
        .get("consent_revoked")
        .expect("the populated body")
        .clone();
    assert!(
        serde_json::from_value::<DatasetAuditKind>(
            serde_json::json!({ "consent_withdrawn": body })
        )
        .is_err(),
        "DatasetAuditKind is closed: an unrecognised member with a valid body must still fail"
    );

    let assessment = serde_json::to_value(PromotionAssessment::Reject {
        reasons: vec!["insufficient paired tasks".into()],
    })
    .expect("serialises");
    assert!(
        assessment.get("reject").is_some(),
        "PromotionAssessment is externally tagged"
    );
    let reject_body = assessment
        .get("reject")
        .expect("the populated body")
        .clone();
    assert!(
        serde_json::from_value::<PromotionAssessment>(serde_json::json!({ "defer": reject_body }))
            .is_err(),
        "PromotionAssessment is closed: this build's own assessor output, not a peer's"
    );
}
