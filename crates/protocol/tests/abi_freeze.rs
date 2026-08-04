//! The golden serde-shape snapshot: the five typed contracts, frozen at `PROTOCOL_VERSION` 1.
//!
//! Issue #14 acceptance criterion 7 asks for a CI check that asserts no breaking diff to the
//! frozen types. This is that check. It serialises a fully populated value of every shape the
//! five contracts put on the wire and compares the emitted field set - name by name, with the
//! JSON type behind each name - against the set recorded in [`frozen`].
//!
//! # Why the snapshot is a field set and not the bytes
//!
//! The obvious golden is the exact serialised bytes of each value. It was rejected. A byte-exact
//! golden fails whenever a *value* changes - a check id, a hash, a path - and every one of those
//! failures is resolved by re-blessing the file. After a few of them the test is a formality that
//! the next reader re-blesses without looking, which is the exact failure mode a freeze test
//! exists to prevent. A field set with a type behind each name fails only when the shape moves,
//! and the shape is what criterion 7 protects. Values are pinned where the value *is* the
//! contract rather than the payload: the tag vocabularies, the transparent identities and the
//! declared ceilings each get their own test below.
//!
//! The other alternative was to derive the shape, from a schema crate or a proc macro over the
//! types. Rejected on two grounds. It would add a dependency to a crate whose manifest admits
//! only `serde` and `serde_json`, and it would freeze the *Rust* type rather than the wire form.
//! A peer sees the wire form, and `rename`, `transparent` and `skip_serializing_if` all move it
//! without moving the Rust type at all.
//!
//! # The additive rule, observed from outside the type
//!
//! `docs/spec/abi.md` §4.3(b)3 requires an appended field to be `Option` with
//! `skip_serializing_if = "Option::is_none"`, so that a `None` is byte-identical to a producer
//! that never had the field. Rather than assert that about the source, this file observes it: a
//! field that appears and is not in the snapshot must survive being deleted from the JSON, and
//! re-encoding must not put it back. A field failing either half is not additive whatever its
//! declaration says.
//!
//! # What is only half here: `PolicyManifest`
//!
//! Criterion 7 names `core-protocol` **and** `PolicyManifest`. `PolicyManifest` lives in
//! `crates/evolve`, which depends on `core-protocol`; reaching it from here means a
//! dev-dependency cycle back into this crate's manifest, and #14 permits no change outside the
//! frozen modules. So this file freezes the half of the manifest that `core-protocol` owns, and
//! says plainly that it is a half. `PolicyManifest.required_capabilities` is a
//! `BTreeSet<Capability>`, so its persisted form is decided by this crate's `Capability` names
//! and their declaration order, and `ArtifactSchema::PolicyManifest` is the tag under which such
//! a document crosses the evolution boundary as an `ArtifactRef`. Both are pinned by
//! [`the_half_of_policy_manifest_this_crate_decides_is_frozen_here`].
//!
//! The document's own field set is frozen by the companion snapshot
//! `crates/evolve/tests/policy_manifest_freeze.rs`, which mirrors the `Json` / `Shape` / `shape!`
//! / `frozen()` pattern below from the one crate where the type is visible. Criterion 7 is met by
//! the pair, not by this file alone; neither half may be moved without the other.
//!
//! # Where this snapshot follows the code rather than the spec
//!
//! §4.2 of the spec is normative for the shape and this file promotes it. Most of what an earlier
//! draft of this list recorded as a departure is gone, because the spec was corrected rather than
//! quietly departed from: §4.2.1 now declares `input` / `trust` / `budget`, §4.2.3 declares
//! `proposed_by`, §4.2.4 names the effect id `id`, and every authority ceiling in the spec is a
//! `CapabilitySet` rather than a point on `Capability`'s declaration order.
//!
//! This module used to carry a prose list of three places where the spec and the code still
//! differed. That list was the whole problem: a comment is as far as an observation can travel, so
//! the spec kept rotting beside it and three issue bodies were written from the rotted version.
//! The comparison is now machine-checked by `core-xtask boundaries check`
//! (`xtask/src/spec_shapes.rs`), which parses every fenced Rust block under `docs/spec`, compares
//! it against `crates/protocol/src` at name-and-arity level, and fails on a divergence that is not
//! recorded in its `DIVERGENCES` allowlist with a reason. The allowlist is empty today, because the
//! three entries were resolved by correcting the spec rather than by recording them, and the gate
//! refuses an entry that is no longer live so it cannot rot the way this comment did.
//!
//! `TaskEnvelope` carries no `profile_ref`. That is not a departure: §4.2.1 comments the field out
//! and names it the one field in the section that may be appended losslessly under §4.3(b)3, so
//! its absence *is* the frozen shape.
//!
//! # Two vocabularies keep an unrecognised tag, and the rest throw it away
//!
//! `ContextSelector`, `InstructionScope` and `ContextSource` decode an unrecognised tag to a unit
//! `Unknown`, drop the payload beside it and re-emit `"unknown"`. They are replay-path values:
//! what matters is that one unreadable record cannot kill a replay, and a retained opaque string
//! there is an untyped field riding across the seam.
//!
//! `ArtifactSchema` and `Producer` are the evidence handle's two vocabularies, and §4.2.5 makes
//! that handle tamper-evident. A value that rewrote its own `schema` or its own `producer.kind` to
//! `"unknown"` on a decode/encode round trip would destroy the evidence it was minted to preserve,
//! so those two retain the producer's tag verbatim and re-encode byte for byte, while still
//! dropping every field beside the tag. Both behaviours are asserted below - by
//! [`assert_unknown_tag_degrades`] and [`assert_unknown_tag_is_retained_verbatim`] - because the
//! difference between them is exactly the sort of asymmetry a later reader "makes consistent".
//!
//! `Quantifier`, `Trust`, `Purity`, `Capability`, `Effort`, `Role`, `Phase`, `StopReason`,
//! `SubmissionRejectionReason`, `Block`, `WorkflowEvent` and `CostAttribution` carry no
//! `#[serde(other)]` arm at all, so an unrecognised member of any of them fails its enclosing
//! value's decode instead of degrading. That is recorded by
//! [`the_closed_vocabularies_refuse_an_unrecognised_tag`], not endorsed by it: `Trust` and
//! `Capability` are lattice and permission vocabularies this build must reason over completely,
//! and an `Unknown` member of either has no defensible ordering. Every one of the twelve is listed
//! so that adding `#[serde(other)]` to one turns a green test red rather than silently converting
//! a refusal into a downgrade - the regression `Errors.md` records for 2026-07-27e, where an
//! appended `Trust::Unknown` took discriminant 3 under derived `Ord`, sorted above `Trusted`, and
//! defeated `min()`.
//!
//! # When this test fails
//!
//! A removal, a rename or a type change is a breaking diff and the fix is to put the field back.
//! An addition is legal only if the two checks above pass, and the snapshot row is then updated in
//! the same commit that adds the field. Editing a row to make a red test green is the one thing
//! this file exists to make visible.

use core_protocol::artifact::{
    ARTIFACT_HASH_HEX_LEN, ArtifactRef, ArtifactSchema, MAX_ARTIFACT_LOCATOR_BYTES,
    MAX_ARTIFACT_PARENT_HASHES, MAX_ARTIFACT_TAG_BYTES, MAX_PRODUCER_NAME_BYTES, Producer,
    Provenance,
};
use core_protocol::capability_set::CapabilitySet;
use core_protocol::context::{
    ContextGrant, ContextRequest, ContextSegment, ContextSelector, ContextSource, InstructionScope,
    MAX_CONTEXT_GRANT_BYTES, MAX_CONTEXT_SEGMENTS, MAX_MEMORY_KEY_BYTES, MAX_MEMORY_KEYS,
    MAX_SELECTOR_ROOT_BYTES, MAX_SELECTORS, RequestId,
};
use core_protocol::effect::{
    EffectProposal, MAX_EFFECT_ARGUMENTS_BYTES, MAX_EFFECT_WORKSPACE_BYTES,
};
use core_protocol::input::{
    ContentSegment, ContentSegments, ImageBase64, ImageContent, ImageMediaType,
    MAX_IMAGE_BASE64_BYTES, MAX_INPUT_IMAGES, MAX_INPUT_SEGMENTS, MAX_TOTAL_IMAGE_BASE64_BYTES,
};
use core_protocol::intent::ToolIntent;
use core_protocol::slot::{MAX_SLOT_ID_BYTES, SlotId, SlotObservation, SlotOutcome};
use core_protocol::task::{
    Acceptance, AcceptanceCheck, MAX_ACCEPTANCE_CHECKS, MAX_TASK_TEXT_BYTES, Quantifier,
    TaskEnvelope, TaskInput,
};
use core_protocol::{
    Block, Budget, Capability, CostAttribution, EffectId, Effort, PROTOCOL_VERSION, Phase,
    ProviderState, ProviderStateFormat, Purity, Role, RunId, Seq, StopReason, SubmissionId,
    SubmissionRejectionReason, ToolResult, ToolUse, Trust, WorkflowChildOutcome, WorkflowEvent,
    WorkflowExecutionMode, WorkflowMetrics, WorkflowOutcome, WorkflowPhase, WorkflowTaskEvidence,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt::Debug;

/// The JSON type behind one frozen field name.
///
/// Coarse on purpose. The snapshot's job is to catch a field changing kind - a scalar becoming an
/// object, a string becoming a number - not to restate the Rust type, which the compiler already
/// owns. Only the kinds the five contracts actually emit are listed; a `Bool` arm is added the
/// day a contract field needs one, and adding it is not itself a change to the ABI.
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

/// One row of the snapshot: a contract type, or one variant of an internally tagged enum.
struct Shape {
    /// How a failure names it. `Type::Variant` where the row is one arm of a tagged enum.
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
/// writing both out by hand for two dozen shapes buries the field lists, which are the part a
/// reviewer actually reads. The constructor argument is always a call or a literal, never a
/// binding, so the two closures stay non-capturing and coerce to the fn pointers above.
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

const CONTENT_HASH: &str = "9f2c1b4a5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f80";

fn ceiling() -> CapabilitySet {
    CapabilitySet::from_iter_capabilities([Capability::ReadOnly, Capability::ReversibleLocal])
}

fn acceptance_check() -> AcceptanceCheck {
    AcceptanceCheck {
        id: "suite::regression".into(),
        quantifier: Quantifier::MustStayPassing,
    }
}

fn acceptance() -> Acceptance {
    Acceptance {
        checks: vec![acceptance_check()],
    }
}

fn task_input() -> TaskInput {
    TaskInput::Text {
        text: "fix the parser panic on empty input".into(),
    }
}

fn content_segments() -> ContentSegments {
    ContentSegments::new(vec![
        ContentSegment::Text {
            text: "describe the screenshot".into(),
        },
        ContentSegment::Image {
            image: ImageContent {
                media_type: ImageMediaType::Png,
                data: ImageBase64::new("iVBORw0KGgo=").expect("canonical base64"),
            },
        },
    ])
    .expect("valid multimodal content")
}

fn image_content() -> ImageContent {
    ImageContent {
        media_type: ImageMediaType::Png,
        data: ImageBase64::new("iVBORw0KGgo=").expect("canonical base64"),
    }
}

/// Fully populated on purpose. `max_usd` is part of the original shape; `max_tokens` is the legal
/// post-freeze optional append whose removal/re-encode behavior the generic append test exercises.
fn budget() -> Budget {
    Budget {
        max_turns: 60,
        max_usd: Some(5.0),
        max_tokens: Some(100_000),
        max_wall_secs: 900,
        max_consecutive_tool_errors: 3,
    }
}

fn task_envelope() -> TaskEnvelope {
    TaskEnvelope {
        task_id: SubmissionId(1),
        protocol_version: PROTOCOL_VERSION,
        input: task_input(),
        trust: Trust::Trusted,
        acceptance: acceptance(),
        budget: budget(),
        ceiling: ceiling(),
    }
}

fn context_request() -> ContextRequest {
    ContextRequest {
        request_id: RequestId(11),
        slot: SlotId("core/context".into()),
        selectors: vec![
            ContextSelector::RepoOutline {
                root: "crates/parser".into(),
                depth: 2,
            },
            ContextSelector::Instructions {
                scope: InstructionScope::Project,
            },
            ContextSelector::MemoryKeys {
                keys: vec!["parser/known-panics".into()],
            },
            ContextSelector::Transcript { last_n_turns: 4 },
            ContextSelector::EnvironmentFacts,
        ],
        max_bytes: 32_768,
        trust_ceiling: Trust::Workspace,
    }
}

fn context_segment() -> ContextSegment {
    ContextSegment {
        text: "crates/parser/src/lib.rs".into(),
        trust: Trust::Workspace,
        source: ContextSource::RepoOutline,
    }
}

fn context_grant() -> ContextGrant {
    ContextGrant {
        request_id: RequestId(11),
        segments: vec![context_segment()],
        bytes: 4_096,
    }
}

fn tool_use() -> ToolUse {
    ToolUse {
        id: "toolu_1".into(),
        name: "read_file".into(),
        input: json!({ "path": "crates/parser/src/lib.rs" }),
    }
}

fn tool_result() -> ToolResult {
    ToolResult {
        tool_use_id: "toolu_1".into(),
        content: "pub fn parse(input: &str) -> Result<Ast, Error>".into(),
        is_error: false,
        trust: Trust::Workspace,
        latency_ms: 12,
    }
}

fn provider_state() -> ProviderState {
    ProviderState {
        route_scope: "anthropic/messages".into(),
        format: ProviderStateFormat::AnthropicMessagesContentBlocksV1,
        payload: json!({ "signature": "opaque-adapter-private-continuation" }),
    }
}

fn tool_intent() -> ToolIntent {
    ToolIntent {
        proposed_by: SlotId("core/tool_policy".into()),
        call: tool_use(),
        purity: Purity::Pure,
        admitted: CapabilitySet::only(Capability::ReadOnly),
        argument_trust: Trust::Workspace,
    }
}

fn effect_proposal() -> EffectProposal {
    EffectProposal {
        id: EffectId("fx1-00000003-0001".into()),
        tool_use_id: "toolu_2".into(),
        tool: "edit_file".into(),
        admitted: CapabilitySet::only(Capability::ReversibleLocal),
        arguments: json!({ "path": "crates/parser/src/lib.rs" }),
        workspace: "/repo".into(),
    }
}

fn provenance() -> Provenance {
    Provenance {
        run_id: RunId("run-9".into()),
        parent_hashes: vec![CONTENT_HASH.into()],
        effect_id: Some(EffectId("fx1-00000003-0001".into())),
    }
}

fn artifact_ref() -> ArtifactRef {
    ArtifactRef {
        hash: CONTENT_HASH.into(),
        schema: ArtifactSchema::FileDiff,
        producer: Producer::Tool {
            tool: "edit_file".into(),
        },
        provenance: provenance(),
        permissions: CapabilitySet::only(Capability::ReadOnly),
        locator: "artifacts/9f2c.patch".into(),
    }
}

fn slot_observation() -> SlotObservation {
    SlotObservation {
        slot: SlotId("core/tool_policy".into()),
        ceiling: ceiling(),
        payload: json!({ "candidate": "edit_file" }),
    }
}

fn slot_outcome() -> SlotOutcome {
    SlotOutcome {
        admitted: CapabilitySet::only(Capability::ReversibleLocal),
        decision: json!({ "choice": "edit_file" }),
    }
}

/// The snapshot. Every shape the five contracts put on the wire as a JSON object.
///
/// `ToolUse` is here although `crates/protocol/tests/fixtures` already pins it: `ToolIntent.call`
/// embeds it, so a change to it is a change to contract 3 whether or not the fixtures notice.
/// `Budget` is here for the same reason on contract 1 - it is embedded by `TaskEnvelope` and
/// already durable behind `EventKind::ChildStarted`, so it has one shape, not two.
fn frozen() -> Vec<Shape> {
    vec![
        // Contract 1 - TaskEnvelope.
        shape!("TaskEnvelope", TaskEnvelope, "crates/protocol/src/task.rs", task_envelope(), {
            "task_id": Number,
            "protocol_version": Number,
            "input": Object,
            "trust": String,
            "acceptance": Object,
            "budget": Object,
            "ceiling": Array,
        }),
        shape!(
            "TaskInput::Text", TaskInput, "crates/protocol/src/task.rs",
            TaskInput::Text { text: "fix the parser panic on empty input".into() },
            { "kind": String, "text": String }
        ),
        shape!(
            "TaskInput::Unknown", TaskInput, "crates/protocol/src/task.rs", TaskInput::Unknown,
            { "kind": String }
        ),
        shape!(
            "TaskInput::ContentSegments", TaskInput, "crates/protocol/src/task.rs",
            TaskInput::ContentSegments { segments: content_segments() },
            { "kind": String, "segments": Array }
        ),
        shape!(
            "ContentSegment::Text", ContentSegment, "crates/protocol/src/lib.rs",
            ContentSegment::Text { text: "describe the screenshot".into() },
            { "type": String, "text": String }
        ),
        shape!(
            "ContentSegment::Image", ContentSegment, "crates/protocol/src/lib.rs",
            ContentSegment::Image { image: image_content() },
            { "type": String, "image": Object }
        ),
        shape!(
            "ContentSegment::Unknown", ContentSegment, "crates/protocol/src/lib.rs",
            ContentSegment::Unknown,
            { "type": String }
        ),
        shape!(
            "ImageContent", ImageContent, "crates/protocol/src/lib.rs", image_content(),
            { "media_type": String, "data": String }
        ),
        shape!("Budget", Budget, "crates/protocol/src/lib.rs", budget(), {
            "max_turns": Number,
            "max_usd": Number,
            "max_wall_secs": Number,
            "max_consecutive_tool_errors": Number,
        }),
        shape!("Acceptance", Acceptance, "crates/protocol/src/task.rs", acceptance(), {
            "checks": Array,
        }),
        shape!(
            "AcceptanceCheck", AcceptanceCheck, "crates/protocol/src/task.rs", acceptance_check(),
            { "id": String, "quantifier": String }
        ),
        // Contract 2 - ContextRequest, and the grant that answers it.
        shape!(
            "ContextRequest", ContextRequest, "crates/protocol/src/context.rs", context_request(),
            {
                "request_id": Number,
                "slot": String,
                "selectors": Array,
                "max_bytes": Number,
                "trust_ceiling": String,
            }
        ),
        shape!(
            "ContextSelector::RepoOutline", ContextSelector, "crates/protocol/src/context.rs",
            ContextSelector::RepoOutline { root: "crates/parser".into(), depth: 2 },
            { "kind": String, "root": String, "depth": Number }
        ),
        shape!(
            "ContextSelector::Instructions", ContextSelector, "crates/protocol/src/context.rs",
            ContextSelector::Instructions { scope: InstructionScope::Project },
            { "kind": String, "scope": String }
        ),
        shape!(
            "ContextSelector::MemoryKeys", ContextSelector, "crates/protocol/src/context.rs",
            ContextSelector::MemoryKeys { keys: vec!["parser/known-panics".into()] },
            { "kind": String, "keys": Array }
        ),
        shape!(
            "ContextSelector::Transcript", ContextSelector, "crates/protocol/src/context.rs",
            ContextSelector::Transcript { last_n_turns: 4 },
            { "kind": String, "last_n_turns": Number }
        ),
        shape!(
            "ContextSelector::EnvironmentFacts", ContextSelector,
            "crates/protocol/src/context.rs", ContextSelector::EnvironmentFacts,
            { "kind": String }
        ),
        shape!(
            "ContextSelector::Unknown", ContextSelector, "crates/protocol/src/context.rs",
            ContextSelector::Unknown, { "kind": String }
        ),
        shape!(
            "ContextSegment", ContextSegment, "crates/protocol/src/context.rs", context_segment(),
            { "text": String, "trust": String, "source": String }
        ),
        shape!(
            "ContextGrant", ContextGrant, "crates/protocol/src/context.rs", context_grant(),
            { "request_id": Number, "segments": Array, "bytes": Number }
        ),
        // Contract 3 - ToolIntent, over the model-emitted call it wraps.
        shape!("ToolIntent", ToolIntent, "crates/protocol/src/intent.rs", tool_intent(), {
            "proposed_by": String,
            "call": Object,
            "purity": String,
            "admitted": Array,
            "argument_trust": String,
        }),
        shape!("ToolUse", ToolUse, "crates/protocol/src/tool.rs", tool_use(), {
            "id": String,
            "name": String,
            "input": Object,
        }),
        // Contract 4 - EffectProposal.
        shape!("EffectProposal", EffectProposal, "crates/protocol/src/effect.rs", effect_proposal(), {
            "id": String,
            "tool_use_id": String,
            "tool": String,
            "admitted": Array,
            "arguments": Object,
            "workspace": String,
        }),
        // Contract 5 - ArtifactRef.
        shape!("ArtifactRef", ArtifactRef, "crates/protocol/src/artifact.rs", artifact_ref(), {
            "hash": String,
            "schema": String,
            "producer": Object,
            "provenance": Object,
            "permissions": Array,
            "locator": String,
        }),
        shape!("Provenance", Provenance, "crates/protocol/src/artifact.rs", provenance(), {
            "run_id": String,
            "parent_hashes": Array,
            "effect_id": String,
        }),
        shape!(
            "Producer::Slot", Producer, "crates/protocol/src/artifact.rs",
            Producer::Slot { slot: SlotId("core/tool_policy".into()) },
            { "kind": String, "slot": String }
        ),
        shape!(
            "Producer::Tool", Producer, "crates/protocol/src/artifact.rs",
            Producer::Tool { tool: "edit_file".into() }, { "kind": String, "tool": String }
        ),
        shape!(
            "Producer::Run", Producer, "crates/protocol/src/artifact.rs", Producer::Run,
            { "kind": String }
        ),
        // The retained arm carries the producer's own tag, so `kind` holds `wasm_component` rather
        // than `unknown`. The field *set* is the frozen thing here and it is unchanged: retention
        // is a value that survives, never an extra field.
        shape!(
            "Producer::Unknown", Producer, "crates/protocol/src/artifact.rs",
            Producer::Unknown("wasm_component".into()), { "kind": String }
        ),
        // The port the kernel calls a replaceable strategy through. Not one of the five, but the
        // seam all five are injected across, so its shape is frozen on the same terms.
        shape!(
            "SlotObservation", SlotObservation, "crates/protocol/src/slot.rs", slot_observation(),
            { "slot": String, "ceiling": Array, "payload": Object }
        ),
        shape!("SlotOutcome", SlotOutcome, "crates/protocol/src/slot.rs", slot_outcome(), {
            "admitted": Array,
            "decision": Object,
        }),
    ]
}

fn emitted_object(shape: &Shape) -> serde_json::Map<String, Value> {
    match (shape.populated)() {
        Value::Object(fields) => fields,
        other => panic!(
            "`{}` no longer serialises as a JSON object but as a {}. The ABI is frozen: a \
             contract that stops being an object relocates every one of its fields at once. See \
             {}.",
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
                    "`{}.{field}` is gone from the wire. The ABI is frozen: a contract field may \
                     be appended, never removed and never renamed. A rename shows here as this \
                     removal plus an addition, and the removal is the breaking half - a peer \
                     pinned to this shape stops finding the field. Defined in {}; normative shape \
                     in docs/spec/abi.md §4.2.",
                    shape.ty, shape.module
                );
            };
            let actual = Json::of(value);
            assert!(
                actual == json.name(),
                "`{}.{field}` changed type: the snapshot froze it as {}, it now emits {}. The ABI \
                 is frozen - a type change is a breaking diff even when the name survives, \
                 because a peer decodes by type. New semantics take a new field or a new top-level \
                 tag (docs/spec/abi.md §4.3(b)2), never a reinterpreted one. See {}.",
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
            // Not in the snapshot, so it was appended after the freeze. §4.3(b)3 allows that only
            // for an `Option` with `skip_serializing_if = "Option::is_none"`. Both halves of that
            // are visible from outside the type: a producer that never had the field must still
            // decode, and a `None` must leave the bytes exactly as they were.
            let mut without = emitted.clone();
            without.remove(name);
            let reencoded = (shape.reencode)(Value::Object(without)).unwrap_or_else(|error| {
                panic!(
                    "`{}.{name}` was appended after the freeze and is not optional: a value \
                     without it fails to decode ({error}). An appended field MUST be `Option` \
                     with `skip_serializing_if = \"Option::is_none\"` (docs/spec/abi.md \
                     §4.3(b)3), so that every producer shipped before it still parses. The ABI is \
                     frozen. See {}.",
                    shape.ty, shape.module
                )
            });
            assert!(
                reencoded.get(name).is_none(),
                "`{}.{name}` was appended after the freeze and is emitted even when unset, so it \
                 moves the bytes of every record an older producer wrote. An appended field MUST \
                 carry `skip_serializing_if = \"Option::is_none\"` so a `None` stays \
                 byte-identical (docs/spec/abi.md §4.3(b)3). The ABI is frozen. See {}.",
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
    // a decoded value all leave the emitted field set intact and break the round trip.
    for shape in frozen() {
        let emitted = (shape.populated)();
        let decoded = (shape.reencode)(emitted.clone()).unwrap_or_else(|error| {
            panic!(
                "`{}` cannot decode the wire form it just emitted ({error}). The ABI is frozen, \
                 and a contract that does not round-trip is not a contract. See {}.",
                shape.ty, shape.module
            )
        });
        assert!(
            decoded == emitted,
            "`{}` does not survive its own wire form: emitted {emitted}, read back {decoded}. The \
             ABI is frozen. See {}.",
            shape.ty,
            shape.module
        );
    }
}

#[test]
fn the_shapes_that_are_not_objects_keep_their_exact_wire_form() {
    // Each of these is embedded by name in one or more of the five contracts. A newtype that stops
    // being transparent, or a set that stops being an array, adds a JSON level inside every
    // contract that carries it - a breaking diff with no field name attached to point at.
    let pinned: [(&str, Value, Value); 6] = [
        (
            "SlotId",
            serde_json::to_value(SlotId("core/context".into())).expect("SlotId serialises"),
            json!("core/context"),
        ),
        (
            "RequestId",
            serde_json::to_value(RequestId(11)).expect("RequestId serialises"),
            json!(11),
        ),
        (
            "SubmissionId",
            serde_json::to_value(SubmissionId(1)).expect("SubmissionId serialises"),
            json!(1),
        ),
        (
            "EffectId",
            serde_json::to_value(EffectId("fx1-00000003-0001".into()))
                .expect("EffectId serialises"),
            json!("fx1-00000003-0001"),
        ),
        (
            "RunId",
            serde_json::to_value(RunId("run-9".into())).expect("RunId serialises"),
            json!("run-9"),
        ),
        (
            // Built out of declaration order and with a duplicate, because the canonical form is
            // part of what is frozen: two equal sets must serialise identically.
            "CapabilitySet",
            serde_json::to_value(CapabilitySet::from_iter_capabilities([
                Capability::IrreversibleExternal,
                Capability::ReadOnly,
                Capability::ReadOnly,
            ]))
            .expect("CapabilitySet serialises"),
            json!(["read_only", "irreversible_external"]),
        ),
    ];
    for (ty, actual, frozen) in pinned {
        assert!(
            actual == frozen,
            "`{ty}` now renders as {actual}; the ABI froze it as {frozen}. Every contract that \
             embeds it moves with it, so this is a breaking diff at five seams, not one."
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
            "`{ty}::{member:?}` renders as {encoded}; the ABI froze it as \"{tag}\". A tag is the \
             whole identity of a variant on the wire, so renaming one is indistinguishable from \
             deleting it and adding another."
        );
        let decoded: T = serde_json::from_value(Value::from(*tag)).unwrap_or_else(|error| {
            panic!("`{ty}` no longer decodes its frozen tag \"{tag}\": {error}")
        });
        assert!(
            decoded == *member,
            "`{ty}` decodes its frozen tag \"{tag}\" as {decoded:?} rather than {member:?}. The \
             ABI is frozen: a tag may not be re-pointed at a different variant."
        );
    }
}

/// The closed-vocabulary rule for an *internally tagged* enum, whose members are data-carrying and
/// therefore encode as an object rather than as a bare string.
///
/// This is a sibling of [`assert_tags_are_frozen`] rather than a generalisation of it, because the
/// two shapes make the same claim through different evidence and folding them together would cost
/// the second half of it. `assert_tags_are_frozen` compares the *whole* encoding to the tag and
/// decodes the tag standing alone; neither is possible here, where the tag is one field beside a
/// body. Worse, a refusal test written in that style would pass for the wrong reason: an
/// unrecognised tag with no body is rejected for the missing body as readily as for the tag, so it
/// would keep passing the day someone added `#[serde(other)]`. So this helper carries a fully
/// populated member through, asserts the frozen tag is the value of `tag_field`, asserts the value
/// survives its own wire form, and then swaps *only* the tag - body intact - and requires the
/// decode to fail. Weakening `assert_tags_are_frozen` to accept objects would delete exactly that
/// distinction, so it is left alone.
fn assert_tagged_variants_are_frozen<T>(
    ty: &str,
    tag_field: &str,
    unrecognised: &str,
    members: &[(T, &str)],
) where
    T: Serialize + DeserializeOwned + Debug,
{
    for (member, tag) in members {
        let encoded = serde_json::to_value(member).expect("a vocabulary member serialises");
        let Value::Object(fields) = encoded.clone() else {
            panic!(
                "`{ty}::{member:?}` no longer serialises as an internally tagged object but as a \
                 {}. The ABI is frozen: a variant that stops being an object relocates its tag and \
                 every field beside it at once.",
                Json::of(&encoded)
            );
        };
        let Some(emitted) = fields.get(tag_field) else {
            panic!(
                "`{ty}::{member:?}` emits no `{tag_field}` field. The tag field is how a peer tells \
                 the variants apart, so losing or renaming it deletes the whole vocabulary at once."
            );
        };
        assert!(
            emitted == &Value::from(*tag),
            "`{ty}::{member:?}` renders its `{tag_field}` as {emitted}; the ABI froze it as \
             \"{tag}\". A tag is the whole identity of a variant on the wire, so renaming one is \
             indistinguishable from deleting it and adding another."
        );
        let decoded: T = serde_json::from_value(encoded.clone()).unwrap_or_else(|error| {
            panic!("`{ty}` no longer decodes its frozen tag \"{tag}\": {error}")
        });
        let reencoded = serde_json::to_value(&decoded).expect("a vocabulary member re-serialises");
        assert!(
            reencoded == encoded,
            "`{ty}` decodes its frozen tag \"{tag}\" into something that re-emits {reencoded} \
             rather than {encoded}. The ABI is frozen: a tag may not be re-pointed at a different \
             variant."
        );

        // The closed half, asserted against a body this build accepts: the ONLY thing changed is
        // the tag, so a decode that succeeds succeeded on the tag alone.
        let mut widened = fields;
        widened.insert(tag_field.to_owned(), Value::from(unrecognised));
        assert!(
            serde_json::from_value::<T>(Value::Object(widened)).is_err(),
            "`{ty}` absorbed the unrecognised tag \"{unrecognised}\" carrying the body of \
             {member:?}. This vocabulary is deliberately closed: it has no `#[serde(other)]` arm, \
             and a peer must not be able to widen it by writing a string. If the arm is genuinely \
             wanted, adding it changes the failure mode of every enclosing value and this \
             assertion is what must be updated to say so."
        );
    }
}

/// The replay-path rule: an unrecognised tag decodes to a unit `Unknown` and re-emits `"unknown"`.
fn assert_unknown_tag_degrades<T>(ty: &str, unrecognised: &str, unknown: T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let decoded: T = serde_json::from_value(json!(unrecognised)).unwrap_or_else(|error| {
        panic!(
            "`{ty}` failed to decode the unrecognised tag \"{unrecognised}\" ({error}). A \
             cross-seam vocabulary MUST degrade to `Unknown` rather than fail its enclosing value, \
             or one member written by a newer producer kills a whole replay (docs/spec/abi.md \
             §4.3(b)1)."
        )
    });
    assert!(
        decoded == unknown,
        "`{ty}` decoded \"{unrecognised}\" as {decoded:?} rather than its `Unknown` arm."
    );
    let reencoded = serde_json::to_value(&decoded).expect("the Unknown arm re-serialises");
    assert!(
        reencoded == json!("unknown"),
        "`{ty}` re-emitted {reencoded} for an unrecognised tag. The producer's tag must be \
         dropped, not carried onward through this value into a record, a log or a UI."
    );
}

/// The evidence-handle rule: an unrecognised tag decodes to `Unknown(tag)` and re-emits the tag
/// byte for byte. This is the opposite requirement to [`assert_unknown_tag_degrades`], and both
/// are asserted so neither can be "corrected" into the other by a reader who saw only one.
fn assert_unknown_tag_is_retained_verbatim<T>(ty: &str, unrecognised: &str, retained: T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let decoded: T = serde_json::from_value(json!(unrecognised)).unwrap_or_else(|error| {
        panic!(
            "`{ty}` failed to decode the unrecognised tag \"{unrecognised}\" ({error}). A \
             cross-seam vocabulary MUST degrade rather than fail its enclosing value \
             (docs/spec/abi.md §4.3(b)1)."
        )
    });
    assert!(
        decoded == retained,
        "`{ty}` decoded \"{unrecognised}\" as {decoded:?} rather than {retained:?}."
    );
    let reencoded = serde_json::to_value(&decoded).expect("the retained arm re-serialises");
    assert!(
        reencoded == json!(unrecognised),
        "`{ty}` re-emitted {reencoded} for the unrecognised tag \"{unrecognised}\". The ABI is \
         frozen and §4.2.5 makes this handle tamper-evident: a content-addressed evidence handle \
         MUST re-encode byte for byte, so restating an unrecognised tag as anything else rewrites \
         the record it was minted to preserve."
    );
}

#[test]
fn every_open_vocabulary_keeps_its_tags_and_degrades_an_unrecognised_one() {
    assert_tags_are_frozen(
        "InstructionScope",
        &[
            (InstructionScope::User, "user"),
            (InstructionScope::Project, "project"),
            (InstructionScope::Directory, "directory"),
            (InstructionScope::Unknown, "unknown"),
        ],
    );
    assert_unknown_tag_degrades(
        "InstructionScope",
        "tenant_policy",
        InstructionScope::Unknown,
    );

    assert_tags_are_frozen(
        "ContextSource",
        &[
            (ContextSource::Instructions, "instructions"),
            (ContextSource::Memory, "memory"),
            (ContextSource::Skills, "skills"),
            (ContextSource::Environment, "environment"),
            (ContextSource::RepoOutline, "repo_outline"),
            (ContextSource::Transcript, "transcript"),
            (ContextSource::Unknown, "unknown"),
        ],
    );
    assert_unknown_tag_degrades("ContextSource", "vector_index", ContextSource::Unknown);
}

#[test]
fn the_evidence_handles_vocabulary_keeps_its_tags_and_retains_an_unrecognised_one() {
    assert_tags_are_frozen(
        "ArtifactSchema",
        &[
            (ArtifactSchema::FileDiff, "file_diff"),
            (ArtifactSchema::Checkpoint, "checkpoint"),
            (ArtifactSchema::PolicyManifest, "policy_manifest"),
            (ArtifactSchema::GovernedDataset, "governed_dataset"),
            (ArtifactSchema::VerticalProfile, "vertical_profile"),
            (ArtifactSchema::Trajectory, "trajectory"),
        ],
    );
    // A tag no build has heard of. Retaining it is what lets a new schema be appended later
    // without a reader shipped today rewriting the handle's own description of itself.
    assert_unknown_tag_is_retained_verbatim(
        "ArtifactSchema",
        "embedding_index",
        ArtifactSchema::Unknown("embedding_index".into()),
    );
    // Retention must not swallow a known tag: `Unknown` is reached only by exhausting the
    // vocabulary, never as a second spelling of a variant that already exists.
    assert!(
        serde_json::from_value::<ArtifactSchema>(json!("trajectory")).expect("a known tag decodes")
            != ArtifactSchema::Unknown("trajectory".into()),
        "`ArtifactSchema` decoded a known tag into its retained arm. The ABI is frozen: a tag that \
         names a variant must keep naming it, or two builds disagree about what the same handle \
         says."
    );
}

#[test]
fn an_unrecognised_tagged_variant_drops_its_payload_instead_of_carrying_it_across_the_seam() {
    const MARKER: &str = "opaque-payload-must-not-survive-the-abi-seam";

    let selector: ContextSelector = serde_json::from_value(json!({
        "kind": "embedding_search",
        "query": MARKER,
        "nested": { "credential": MARKER },
    }))
    .expect("an unknown selector kind must not fail the request around it");
    let input: TaskInput = serde_json::from_value(json!({
        "kind": "structured",
        "schema": MARKER,
        "body": { "credential": MARKER },
    }))
    .expect("an unknown payload kind must not fail the envelope around it");
    let producer: Producer = serde_json::from_value(json!({
        "kind": "wasm_component",
        "module": MARKER,
        "operator_note": MARKER,
    }))
    .expect("an unknown producer kind must not fail the handle around it");

    // The third column is what re-encoding must produce. `ContextSelector` and `TaskInput` are
    // replay-path values and drop the tag with the payload; `Producer` is half of the evidence
    // handle's attribution and keeps the tag - and only the tag.
    for (ty, debug, reencoded, expected) in [
        (
            "ContextSelector",
            format!("{selector:?}"),
            serde_json::to_value(&selector).expect("re-serialises"),
            json!({ "kind": "unknown" }),
        ),
        (
            "TaskInput",
            format!("{input:?}"),
            serde_json::to_value(&input).expect("re-serialises"),
            json!({ "kind": "unknown" }),
        ),
        (
            "Producer",
            format!("{producer:?}"),
            serde_json::to_value(&producer).expect("re-serialises"),
            json!({ "kind": "wasm_component" }),
        ),
    ] {
        assert!(
            !debug.contains(MARKER),
            "`{ty}::Unknown` retained the unrecognised variant's payload, so it reaches anything \
             that formats the value. The unknown arm MUST drop the payload, not buffer it."
        );
        assert!(
            reencoded == expected,
            "`{ty}::Unknown` re-emitted {reencoded}; the ABI froze it as {expected}. An \
             unrecognised variant must not smuggle fields across the seam under a tag this build \
             cannot interpret, and the one value it may keep - the tag itself, where the handle is \
             tamper-evident - must come back unchanged."
        );
        assert!(
            !reencoded.to_string().contains(MARKER),
            "`{ty}::Unknown` re-emitted the unrecognised variant's payload."
        );
    }
}

#[test]
fn the_closed_vocabularies_refuse_an_unrecognised_tag() {
    assert_tags_are_frozen(
        "Quantifier",
        &[
            (Quantifier::MustPass, "must_pass"),
            (Quantifier::MustFlipToPass, "must_flip_to_pass"),
            (Quantifier::MustStayPassing, "must_stay_passing"),
        ],
    );
    assert_tags_are_frozen(
        "Trust",
        &[
            (Trust::Untrusted, "untrusted"),
            (Trust::Workspace, "workspace"),
            (Trust::Trusted, "trusted"),
        ],
    );
    assert_tags_are_frozen(
        "Purity",
        &[(Purity::Pure, "pure"), (Purity::Effecting, "effecting")],
    );
    assert_tags_are_frozen(
        "Capability",
        &[
            (Capability::ReadOnly, "read_only"),
            (Capability::ReversibleLocal, "reversible_local"),
            (Capability::CodeExecuting, "code_executing"),
            (Capability::TrustMutating, "trust_mutating"),
            (Capability::IrreversibleExternal, "irreversible_external"),
        ],
    );

    // These four carry no unknown arm, so an unrecognised member fails the whole enclosing value
    // rather than degrading. Recorded here so the asymmetry with the open vocabularies is
    // deliberate and visible rather than an oversight someone later "fixes" in passing. `Trust`
    // and `Capability` are a lattice and a permission set that this build has to reason over
    // completely - an `Unknown` tier has no place in an ordering, and an `Unknown` permission
    // cannot be intersected against a ceiling - so failing closed is the correct reading for them.
    // `Quantifier` is the one where a future `#[serde(other)]` arm would be defensible: it is
    // producer vocabulary inside `TaskEnvelope`, and today an unrecognised quantifier costs the
    // entire envelope. Adding the arm is an additive change; nothing here blocks it, and this
    // assertion is what will have to be updated when it happens.
    assert!(
        serde_json::from_value::<Quantifier>(json!("must_flip_within_budget")).is_err(),
        "`Quantifier` has no `Unknown` arm today; if it gained one, the failure mode of a whole \
         `TaskEnvelope` changed and this snapshot must record that."
    );
    assert!(serde_json::from_value::<Trust>(json!("operator")).is_err());
    assert!(serde_json::from_value::<Purity>(json!("idempotent")).is_err());
    assert!(serde_json::from_value::<Capability>(json!("network_reading")).is_err());

    // The eight below were closed on the same terms and recorded nowhere until now, which left
    // nothing to fail if a later contributor "helpfully" added `#[serde(other)]` to one of them.
    // `Effort` is the clearest case: it is the session's orchestration authority, and an absorbed
    // `Unknown` tier would be a level a peer named by writing a string. The rest are durable
    // journal and transcript vocabularies whose whole purpose is that replay reads back exactly
    // what ran - a member this build cannot interpret must stop the record being trusted, not be
    // waved through as an `Unknown` that every later reader has to guess the meaning of.
    assert_tags_are_frozen(
        "Effort",
        &[
            (Effort::Low, "low"),
            (Effort::Medium, "medium"),
            (Effort::High, "high"),
            (Effort::XHigh, "x_high"),
            (Effort::Max, "max"),
            (Effort::Ultracode, "ultracode"),
        ],
    );
    assert!(serde_json::from_value::<Effort>(json!("ultrathink")).is_err());

    assert_tags_are_frozen(
        "Role",
        &[(Role::User, "user"), (Role::Assistant, "assistant")],
    );
    assert!(serde_json::from_value::<Role>(json!("system")).is_err());

    assert_tags_are_frozen(
        "Phase",
        &[
            (Phase::Context, "context"),
            (Phase::Model, "model"),
            (Phase::Tools, "tools"),
            (Phase::Verify, "verify"),
            (Phase::Idle, "idle"),
        ],
    );
    assert!(serde_json::from_value::<Phase>(json!("compacting")).is_err());

    assert_tags_are_frozen(
        "SubmissionRejectionReason",
        &[
            (
                SubmissionRejectionReason::UnsupportedOperation,
                "unsupported_operation",
            ),
            (
                SubmissionRejectionReason::ProtocolVersionMismatch,
                "protocol_version_mismatch",
            ),
        ],
    );
    assert!(
        serde_json::from_value::<SubmissionRejectionReason>(json!("rate_limited")).is_err(),
        "the rejection reason is the one field of a `SubmissionRejected` record, and the record \
         exists to describe client data this build refused. An arm that absorbed an unrecognised \
         reason would let the refusing record carry a reason string the refusing build chose not \
         to understand."
    );

    // `StopReason` is the one closed vocabulary here that HAS an `Unknown` arm, and it is closed
    // anyway: the arm carries a `StopReasonCode`, so serde cannot reach it from a bare tag - only
    // an adapter that parsed the provider's code against `MAX_STOP_REASON_CODE_BYTES` can build
    // one. That is the distinction being recorded. `#[serde(other)]` would collapse it, because
    // `other` applies to a unit variant and would make every unrecognised string decode to a
    // no-code `Unknown`, erasing the value the arm exists to retain.
    assert_tags_are_frozen(
        "StopReason",
        &[
            (StopReason::EndTurn, "end_turn"),
            (StopReason::ToolUse, "tool_use"),
            (StopReason::MaxTokens, "max_tokens"),
            (StopReason::StopSequence, "stop_sequence"),
            (StopReason::Refusal, "refusal"),
            (StopReason::PauseTurn, "pause_turn"),
        ],
    );
    assert!(serde_json::from_value::<StopReason>(json!("quota_exhausted")).is_err());
    assert!(
        serde_json::from_value::<StopReason>(json!("unknown")).is_err(),
        "even the literal spelling \"unknown\" is not a member of the wire vocabulary: the retained \
         arm is reachable only as a code an adapter bounded and parsed, never by a peer naming it."
    );

    // Three data-carrying vocabularies. See `assert_tagged_variants_are_frozen` for why they need
    // their own helper rather than a loosened `assert_tags_are_frozen`.
    assert_tagged_variants_are_frozen(
        "Block",
        "type",
        "audio",
        &[
            (
                Block::Text {
                    text: "the parser panics on empty input".into(),
                },
                "text",
            ),
            (
                Block::Thinking {
                    thinking: "check the empty-slice branch first".into(),
                },
                "thinking",
            ),
            (Block::ProviderState(provider_state()), "provider_state"),
            (Block::ToolUse(tool_use()), "tool_use"),
            (Block::ToolResult(tool_result()), "tool_result"),
        ],
    );

    assert_tagged_variants_are_frozen(
        "WorkflowEvent",
        "event",
        "child_paused",
        &[
            (
                WorkflowEvent::Started {
                    name: "investigate-parser-panic".into(),
                    class: "investigation".into(),
                },
                "started",
            ),
            (
                WorkflowEvent::Planned {
                    mode: WorkflowExecutionMode::ConcurrentFan,
                    tasks: vec![WorkflowTaskEvidence {
                        task_id: 1,
                        label: "read the parser".into(),
                        prompt_digest: CONTENT_HASH.into(),
                    }],
                    dropped: 0,
                    duplicates_removed: 0,
                    invalid_removed: 0,
                    fan_turn_budget: 12,
                    writer_turn_reserve: 4,
                    fan_wall_secs: 600,
                    writer_wall_reserve_secs: 300,
                },
                "planned",
            ),
            (
                WorkflowEvent::PhaseChanged {
                    phase: WorkflowPhase::Exploring,
                },
                "phase_changed",
            ),
            (
                WorkflowEvent::ChildStarted {
                    task_id: 1,
                    sub_run: "run-9.1".into(),
                    spawn_seq: Seq(17),
                    budget: budget(),
                },
                "child_started",
            ),
            (
                WorkflowEvent::ChildFinished {
                    task_id: 1,
                    sub_run: Some("run-9.1".into()),
                    outcome: WorkflowChildOutcome::Done,
                    metrics: WorkflowMetrics::default(),
                    error_code: None,
                    error_detail: None,
                    summary_digest: Some(CONTENT_HASH.into()),
                    evidence_bytes: 2_048,
                },
                "child_finished",
            ),
            (
                WorkflowEvent::Reduced {
                    evidence_message_seq: Some(Seq(23)),
                    done: 1,
                    failed: 0,
                    skipped: 0,
                    elapsed_ms: 4_200,
                },
                "reduced",
            ),
            (
                WorkflowEvent::Finished {
                    outcome: WorkflowOutcome::Done,
                    metrics: WorkflowMetrics::default(),
                    elapsed_ms: 5_100,
                    error_code: None,
                    error_detail: None,
                },
                "finished",
            ),
        ],
    );

    // The tag decides which parent terminal may aggregate a child's signed cost evidence. An
    // absorbed tag would be a monetary authority this build cannot name - the permission-widening
    // failure in its purest form, since the aggregation check is what the tag is for.
    assert_tagged_variants_are_frozen(
        "CostAttribution",
        "kind",
        "peer_run",
        &[
            (
                CostAttribution::DirectSubagent {
                    parent_run_id: "run-9".into(),
                    sub_run: "run-9.1".into(),
                },
                "direct_subagent",
            ),
            (
                CostAttribution::WorkflowChild {
                    parent_run_id: "run-9".into(),
                    workflow_id: "wf-3".into(),
                    task_id: 1,
                    sub_run: "run-9.1".into(),
                },
                "workflow_child",
            ),
        ],
    );
}

#[test]
fn the_half_of_policy_manifest_this_crate_decides_is_frozen_here() {
    // Criterion 7 names PolicyManifest, which lives in `crates/evolve` - a crate that depends on
    // this one, so it is not reachable from this test without a dev-dependency cycle. Its own
    // field set is frozen by `crates/evolve/tests/policy_manifest_freeze.rs`. What is decided HERE
    // is how the manifest persists: `required_capabilities` is a `BTreeSet<Capability>`, so its
    // wire form is this crate's `Capability` names emitted in this crate's declaration order.
    // Change either and every PolicyManifest already on disk reads differently.
    let required = BTreeSet::from([
        Capability::CodeExecuting,
        Capability::ReadOnly,
        Capability::IrreversibleExternal,
    ]);
    assert_eq!(
        serde_json::to_value(&required).expect("required_capabilities serialises"),
        json!(["read_only", "code_executing", "irreversible_external"]),
        "`PolicyManifest.required_capabilities` persists through this crate's `Capability` names \
         and their declaration order. The ABI is frozen: reordering the variants silently rewrites \
         every manifest already admitted."
    );
    assert_eq!(
        serde_json::to_value(ArtifactSchema::PolicyManifest).expect("schema serialises"),
        json!("policy_manifest"),
        "a manifest crosses the evolution boundary as an `ArtifactRef` under this tag; it is the \
         only thing an append-only registry has to recognise it by."
    );
}

#[test]
fn the_declared_ceilings_are_part_of_the_frozen_contract() {
    // Not serde shape, but frozen on the same terms and checked nowhere else. Every one of these
    // bounds the wire: lowering one refuses a value an older producer legally sent, and raising
    // one lets a newer producer emit a value an older reader refuses. Both are wire changes, so
    // the snapshot pins them exactly rather than one-sidedly.
    let pinned: [(&str, usize, usize); 21] = [
        ("PROTOCOL_VERSION", PROTOCOL_VERSION as usize, 1),
        ("MAX_TASK_TEXT_BYTES", MAX_TASK_TEXT_BYTES, 1_048_576),
        ("MAX_INPUT_SEGMENTS", MAX_INPUT_SEGMENTS, 9),
        ("MAX_INPUT_IMAGES", MAX_INPUT_IMAGES, 8),
        (
            "MAX_IMAGE_BASE64_BYTES",
            MAX_IMAGE_BASE64_BYTES,
            8 * 1024 * 1024,
        ),
        (
            "MAX_TOTAL_IMAGE_BASE64_BYTES",
            MAX_TOTAL_IMAGE_BASE64_BYTES,
            32 * 1024 * 1024,
        ),
        ("MAX_ACCEPTANCE_CHECKS", MAX_ACCEPTANCE_CHECKS, 256),
        ("MAX_SLOT_ID_BYTES", MAX_SLOT_ID_BYTES, 128),
        ("MAX_SELECTORS", MAX_SELECTORS, 32),
        ("MAX_SELECTOR_ROOT_BYTES", MAX_SELECTOR_ROOT_BYTES, 4_096),
        ("MAX_MEMORY_KEYS", MAX_MEMORY_KEYS, 64),
        ("MAX_MEMORY_KEY_BYTES", MAX_MEMORY_KEY_BYTES, 256),
        ("MAX_CONTEXT_SEGMENTS", MAX_CONTEXT_SEGMENTS, 64),
        (
            "MAX_CONTEXT_GRANT_BYTES",
            MAX_CONTEXT_GRANT_BYTES as usize,
            131_072,
        ),
        (
            "MAX_EFFECT_WORKSPACE_BYTES",
            MAX_EFFECT_WORKSPACE_BYTES,
            4_096,
        ),
        // Shared by `EffectProposal::validate` and `ToolIntent::validate` on purpose: the same
        // bytes travel from the intent into the proposal, so two different bounds would mean a
        // value one contract admits and the next refuses.
        (
            "MAX_EFFECT_ARGUMENTS_BYTES",
            MAX_EFFECT_ARGUMENTS_BYTES,
            1_048_576,
        ),
        ("ARTIFACT_HASH_HEX_LEN", ARTIFACT_HASH_HEX_LEN, 64),
        (
            "MAX_ARTIFACT_LOCATOR_BYTES",
            MAX_ARTIFACT_LOCATOR_BYTES,
            4_096,
        ),
        ("MAX_ARTIFACT_PARENT_HASHES", MAX_ARTIFACT_PARENT_HASHES, 64),
        ("MAX_PRODUCER_NAME_BYTES", MAX_PRODUCER_NAME_BYTES, 256),
        // The bound on a tag the evidence handle retains verbatim. It is the one place the Bounded
        // invariant is carried by the arm nobody reviews, so it is pinned with the rest.
        ("MAX_ARTIFACT_TAG_BYTES", MAX_ARTIFACT_TAG_BYTES, 128),
    ];
    for (name, actual, frozen) in pinned {
        assert!(
            actual == frozen,
            "`{name}` is {actual}; the ABI froze it at {frozen}. A bound is part of the contract \
             the five types declare (docs/spec/abi.md §4.2, the Bounded invariant), so moving it \
             changes what a peer may send or must accept. If the change is intended, move the \
             snapshot in the same commit and say which peers were re-checked."
        );
    }
}
