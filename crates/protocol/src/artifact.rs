//! `ArtifactRef` — the stable handle a produced artifact leaves the runtime through.
//!
//! # Why a handle rather than the content
//!
//! `docs/spec/abi.md` §4.2.5 makes this a MUST: every reusable product of a run - a patch, a
//! workspace checkpoint, a compiled vertical profile, a PolicyManifest, a governed dataset - is
//! referenced by a content address plus its provenance, never passed inline. The reason is the
//! evolution boundary. `crates/evolve` keeps append-only registries that are supposed to be able
//! to *verify* the evidence they hold, and that verification only exists if what they hold is a
//! hash. Inline content is evidence you can rewrite by re-sending it.
//!
//! # Why this wraps the two seeds instead of replacing them
//!
//! The spec names two seeds, and both are already frozen by something stronger than this module.
//!
//! `FileDiff` (`crates/protocol/src/diff.rs`) is `#[serde(deny_unknown_fields)]` at all three
//! nesting levels, and `d13_14_structured_diff_wire_is_strict_and_covers_every_tag` pins its exact
//! JSON. `EventKind::Checkpoint { at, tree_ref }` (`crates/protocol/src/event.rs`) is written into
//! the fsynced, hash-chained write-ahead log and read back by four match sites in
//! `crates/kernel/src/lib.rs` plus `crates/record/src/checkpoint.rs`.
//!
//! The alternative considered was reshaping the seeds - `Checkpoint { artifact: ArtifactRef }`,
//! `FileDiff` gaining a `hash` field. Both were rejected: the first adds a JSON level to a durable
//! record that replay already reads, the second moves bytes a frozen fixture asserts. So
//! `ArtifactRef` sits **beside** them and describes them. Neither seed changes; a caller that only
//! has a `FileDiff` still works, and a caller that needs to know where it came from and who may
//! read it asks the ref.
//!
//! # Two places the spec and the code disagree, stated rather than resolved silently
//!
//! **1. `hash` versus `Checkpoint.tree_ref`.** The spec says `ArtifactRef.hash` MUST be the
//! SHA-256 of the artifact's content. `tree_ref` is a git object id: `valid_object_id` in
//! `crates/record/src/checkpoint.rs` accepts 40 or 64 hex, so in practice it is SHA-1 today, and
//! even at 64 hex a git oid hashes git's own framed tree object rather than the artifact's bytes.
//! It is therefore not a value that can go into `hash` without making the content-address claim
//! false. This module keeps `hash` as the spec defines it and carries the git oid in the locator,
//! which is what a locator is for. Nothing here converts between them; a producer minting a
//! checkpoint ref computes the content hash itself.
//!
//! **2. `permissions` is a set, not a `Capability`.** The spec's code block types it as a single
//! `Capability`. `crates/protocol/src/capability_set.rs` documents why that is unsafe: `Capability`
//! derives `Ord` for `BTreeSet` storage, and any comparison against a single class reads that
//! declaration order as an authority order. `TaskEnvelope` already made the same substitution for
//! the spec's `capability_ceiling`. This module follows the code, and the divergence is recorded
//! here so the spec can be corrected rather than quietly departed from.
//!
//! # Why an unknown tag is kept here and dropped everywhere else
//!
//! The other open vocabularies in this crate - `ContextSelector`, `InstructionScope`,
//! `ContextSource`, `Op`, `EventKind` - decode an unrecognised tag to a unit `Unknown` and throw
//! the tag away with the payload. They are replay-path values: what matters is that one unreadable
//! record cannot kill a replay, and a retained opaque string there is just an untyped field riding
//! across the seam.
//!
//! This handle is not on that path. §4.2.5 calls it tamper-evident, and `crates/evolve` verifies
//! the evidence it holds by re-reading it. A value that rewrites its own `schema` and its own
//! `producer.kind` on a decode/encode round trip destroys the evidence it was minted to preserve:
//! the artifact still exists, but the record now attributes it to `unknown` and claims nobody can
//! say what it is. So [`ArtifactSchema::Unknown`] and [`Producer::Unknown`] carry the producer's
//! original tag verbatim, following `ProviderStateFormat::Unknown(String)`
//! (`crates/protocol/src/message.rs`), which solved the same problem for adapter-private state.
//!
//! Retained is not interpreted. A retained tag is bounded ([`MAX_ARTIFACT_TAG_BYTES`]) and
//! control-character-free, checked in [`ArtifactRef::validate`] and refused rather than
//! normalised, and nothing here ever matches on its contents. The bound is a mint-time gate, not a
//! parse-time one, for the reason `crates/protocol/src/effect.rs` states: refusing to decode an
//! oversized tag would destroy the evidence instead of flagging it.
//!
//! # No behaviour
//!
//! Types and serde only, per issue #14. [`ArtifactRef::validate`] is pure and has no call sites; it
//! exists because §4.2.5's MUSTs - content-addressed hash, bounded locator, deny-by-default
//! permissions - are otherwise assertions in prose that nothing can check.

use crate::capability_set::CapabilitySet;
use crate::ids::{EffectId, RunId};
use crate::slot::SlotId;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Length of a content address in lowercase hex. SHA-256, per §4.2.5.
pub const ARTIFACT_HASH_HEX_LEN: usize = 64;
/// Upper bound on the locator string, named by §4.2.5.
pub const MAX_ARTIFACT_LOCATOR_BYTES: usize = 4_096;
/// Upper bound on the lineage one artifact may declare.
pub const MAX_ARTIFACT_PARENT_HASHES: usize = 64;
/// Upper bound on a producer's tool name.
pub const MAX_PRODUCER_NAME_BYTES: usize = 256;
/// Upper bound on an unrecognised tag this handle retains verbatim.
///
/// §4.2 requires every value crossing the seam to be bounded, and retention is what makes that a
/// live question here: an unbounded `Unknown` payload would be a hole punched through the bound by
/// the one arm nobody reviews. 128 bytes is far above any plausible `snake_case` schema or
/// producer name and far below anything that could serve as a smuggled document.
pub const MAX_ARTIFACT_TAG_BYTES: usize = 128;

/// How the bytes behind a handle are to be interpreted.
///
/// The vocabulary belongs to the producer, not to this build, so a newer producer naming a schema
/// this build has never seen must degrade rather than fail: see [`ArtifactSchema::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArtifactSchema {
    /// A structured patch. Seed: [`crate::diff::FileDiff`].
    FileDiff,
    /// A workspace snapshot. Seed: `EventKind::Checkpoint`, whose `tree_ref` is a git object id
    /// and therefore belongs in the locator rather than the hash - see the module docs.
    Checkpoint,
    /// A harness checkpoint: one slot implementation plus the evidence admitted with it.
    PolicyManifest,
    /// A governed dataset on the evolution side of the boundary.
    GovernedDataset,
    /// A compiled vertical profile.
    VerticalProfile,
    /// One sampled run trajectory: the primary input of the evolution pipeline. Named by
    /// 4.2.5's normative boundary rule and by 4.3's schema-version table.
    Trajectory,
    /// A schema this build does not recognise, reached only by decoding a handle written by a
    /// newer producer. It keeps the producer's tag verbatim so the handle re-encodes byte for
    /// byte; see the module docs for why this evidence handle retains what the replay-path enums
    /// discard.
    ///
    /// Retaining is not understanding. A handle whose schema is `Unknown` names bytes nobody here
    /// can interpret, and interpreting them as the nearest known schema is the failure this arm
    /// exists to make impossible. Failing closed on that is the reader's job, not this arm's.
    Unknown(String),
}

impl ArtifactSchema {
    /// The wire tag, `snake_case` for the known schemas and the producer's own string otherwise.
    pub fn as_str(&self) -> &str {
        match self {
            Self::FileDiff => "file_diff",
            Self::Checkpoint => "checkpoint",
            Self::PolicyManifest => "policy_manifest",
            Self::GovernedDataset => "governed_dataset",
            Self::VerticalProfile => "vertical_profile",
            Self::Trajectory => "trajectory",
            Self::Unknown(raw) => raw,
        }
    }
}

impl From<&str> for ArtifactSchema {
    fn from(raw: &str) -> Self {
        match raw {
            "file_diff" => Self::FileDiff,
            "checkpoint" => Self::Checkpoint,
            "policy_manifest" => Self::PolicyManifest,
            "governed_dataset" => Self::GovernedDataset,
            "vertical_profile" => Self::VerticalProfile,
            "trajectory" => Self::Trajectory,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl From<String> for ArtifactSchema {
    fn from(raw: String) -> Self {
        match raw.as_str() {
            "file_diff" => Self::FileDiff,
            "checkpoint" => Self::Checkpoint,
            "policy_manifest" => Self::PolicyManifest,
            "governed_dataset" => Self::GovernedDataset,
            "vertical_profile" => Self::VerticalProfile,
            "trajectory" => Self::Trajectory,
            _ => Self::Unknown(raw),
        }
    }
}

/// Hand-written rather than `#[serde(other)]`, because that attribute can only reach a unit
/// variant and a unit variant is what re-encodes an unrecognised schema as `"unknown"`.
impl Serialize for ArtifactSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ArtifactSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// Who produced an artifact, for attribution and audit.
///
/// §4.2.5 names the type and gives its vocabulary as "slot / tool / run" without a body; the body
/// is supplied here. The three cases are alternatives rather than fields: a checkpoint has no slot
/// and no registry tool behind it, and a patch the edit tool produced was not decided by a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Producer {
    /// A replaceable strategy slot produced it. [`SlotId`] rather than a bare string, so
    /// attribution survives the two-types-called-strategy-slot collision `crate::slot` documents.
    Slot { slot: SlotId },
    /// A registry tool materialised it, under the effect [`Provenance::effect_id`] names.
    Tool { tool: String },
    /// The run itself produced it, with neither a slot nor a tool behind it - the checkpoint
    /// ledger's case.
    ///
    /// Deliberately carries no run id. [`Provenance::run_id`] already holds one, and a second copy
    /// here is a field that can disagree with it; a handle whose two run ids differ has no
    /// defensible reading.
    Run,
    /// A producer kind this build does not recognise, holding the original `kind` and nothing
    /// else. The distinction is the point: the *tag* is attribution and is preserved, while the
    /// fields beside it are an arbitrary payload an unrecognised producer must not be able to
    /// carry across the seam under the guise of attribution.
    Unknown(String),
}

impl Producer {
    /// The `kind` tag this producer writes on the wire.
    pub fn kind(&self) -> &str {
        match self {
            Self::Slot { .. } => "slot",
            Self::Tool { .. } => "tool",
            Self::Run => "run",
            Self::Unknown(raw) => raw,
        }
    }
}

/// Written out rather than derived, for the same reason as [`ArtifactSchema`]'s impls: an
/// internally tagged enum has no derived form in which the unrecognised arm both keeps its tag and
/// carries no fields.
impl Serialize for Producer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let fields = match self {
            Self::Slot { .. } | Self::Tool { .. } => 2,
            Self::Run | Self::Unknown(_) => 1,
        };
        let mut map = serializer.serialize_map(Some(fields))?;
        map.serialize_entry("kind", self.kind())?;
        match self {
            Self::Slot { slot } => map.serialize_entry("slot", slot)?,
            Self::Tool { tool } => map.serialize_entry("tool", tool)?,
            Self::Run | Self::Unknown(_) => {}
        }
        map.end()
    }
}

/// Decoding goes through `serde_json::Map` because the retained arm has to read the tag and then
/// deliberately drop every sibling key, which serde's derived internally-tagged decoder cannot
/// express. It costs the generality of a self-describing format; this contract is JSON, and
/// `docs/spec/abi.md` §4.3 pins it there.
///
/// A known `kind` whose payload is missing or malformed is still an error. Degrading is for tags
/// this build has never heard of, not for a producer that named a case it then failed to fill in.
impl<'de> Deserialize<'de> for Producer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut fields = serde_json::Map::deserialize(deserializer)?;
        let kind = match fields.remove("kind") {
            Some(serde_json::Value::String(kind)) => kind,
            Some(_) => return Err(serde::de::Error::custom("producer kind must be a string")),
            None => return Err(serde::de::Error::missing_field("kind")),
        };
        let mut take = |field: &'static str| {
            fields
                .remove(field)
                .ok_or_else(|| serde::de::Error::missing_field(field))
        };
        match kind.as_str() {
            "slot" => Ok(Self::Slot {
                slot: serde_json::from_value(take("slot")?).map_err(serde::de::Error::custom)?,
            }),
            "tool" => Ok(Self::Tool {
                tool: serde_json::from_value(take("tool")?).map_err(serde::de::Error::custom)?,
            }),
            "run" => Ok(Self::Run),
            _ => Ok(Self::Unknown(kind)),
        }
    }
}

/// Where an artifact came from. Hash-chained, so lineage is tamper-evident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The run the artifact was produced in.
    pub run_id: RunId,
    /// The content addresses this artifact was derived from. Empty for an original.
    pub parent_hashes: Vec<String>,
    /// The admitted effect that produced it, when one did.
    ///
    /// `#[serde(default)]` without `skip_serializing_if`, on purpose. This `Option` is part of the
    /// frozen shape rather than appended after it, so an explicit `null` is information: it says
    /// this build considered the question and there was no effect. The absent/`None`
    /// indistinguishability `skip_serializing_if` buys is reserved for fields appended after the
    /// freeze, where a `None` must stay byte-identical to a producer that never had the field.
    #[serde(default)]
    pub effect_id: Option<EffectId>,
}

/// A stable handle to one produced artifact.
///
/// Holding this grants nothing. §4.2.5 is explicit that `permissions` is read deny-by-default: a
/// reader must still hold the capability to open what the handle names. That is what makes the
/// handle safe to pass across the evolution boundary, which is not authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// SHA-256 of the artifact's content, lowercase hex. Content-addressed and immutable on the
    /// producer's side: one hash never names two different byte strings.
    pub hash: String,
    /// How to interpret the content.
    pub schema: ArtifactSchema,
    /// Who produced it.
    pub producer: Producer,
    /// What it was derived from.
    pub provenance: Provenance,
    /// The capability classes a reader must hold to read or act on it. A set, never a point on an
    /// order - `crate::capability_set` documents why. Empty is refused by [`ArtifactRef::validate`],
    /// because an empty requirement reads as "no capability needed", which inverts the
    /// deny-by-default rule this field carries.
    pub permissions: CapabilitySet,
    /// Where the bytes actually live: a path, a private git ref, a registry key. Bounded.
    ///
    /// This is the field that absorbs identifiers which are not content hashes, the git object id
    /// behind a `Checkpoint` being the case the module docs work through. A locator is a hint for
    /// finding bytes; only [`ArtifactRef::hash`] establishes which bytes they had to be.
    pub locator: String,
}

impl ArtifactRef {
    /// Check the §4.2.5 MUSTs that are mechanically checkable. Pure; no call sites.
    ///
    /// Uppercase hex is rejected rather than normalised, for the reason `SlotId::validate` gives
    /// about uppercase slot identities: normalising lets two handles that compare unequal here name
    /// the same content once persisted, which turns a content address into a near-address.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !is_content_hash(&self.hash) {
            return Err("artifact hash must be a lowercase 64-hex SHA-256 of the content");
        }
        if self.locator.len() > MAX_ARTIFACT_LOCATOR_BYTES {
            return Err("artifact locator exceeds its declared bound");
        }
        if self.permissions.is_empty() {
            return Err(
                "an artifact requiring no capability would be readable by anyone; permissions \
                 are read deny-by-default",
            );
        }
        if let Producer::Tool { tool } = &self.producer
            && (tool.is_empty() || tool.len() > MAX_PRODUCER_NAME_BYTES)
        {
            return Err("a tool producer must name its tool, within the name bound");
        }
        if let ArtifactSchema::Unknown(tag) = &self.schema
            && !is_retainable_tag(tag)
        {
            return Err("a retained schema tag must be bounded, non-blank and control-free");
        }
        if let Producer::Unknown(kind) = &self.producer
            && !is_retainable_tag(kind)
        {
            return Err("a retained producer kind must be bounded, non-blank and control-free");
        }
        self.provenance.validate()
    }
}

impl Provenance {
    /// Check that lineage is bounded and that every parent is a content address.
    ///
    /// A parent that is not a content address breaks the property the chain exists for: an
    /// append-only registry verifies lineage by re-hashing, and it cannot re-hash a path.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.run_id.0.is_empty() {
            return Err("provenance must name the run that produced the artifact");
        }
        if self.parent_hashes.len() > MAX_ARTIFACT_PARENT_HASHES {
            return Err("artifact lineage exceeds its declared bound");
        }
        if !self.parent_hashes.iter().all(|h| is_content_hash(h)) {
            return Err("every parent must itself be a lowercase 64-hex content address");
        }
        Ok(())
    }
}

/// May an unrecognised tag be minted into a handle as it stands?
///
/// Refusal rather than normalisation, on the same ground as the uppercase-hash rule: a tag that
/// gets trimmed or truncated on the way in no longer re-encodes to the bytes it arrived as, which
/// is the single property retention exists to give. Control characters are excluded because this
/// string is preserved precisely so it can be shown to a human in a log or an audit view.
fn is_retainable_tag(tag: &str) -> bool {
    !tag.trim().is_empty()
        && tag.len() <= MAX_ARTIFACT_TAG_BYTES
        && !tag.chars().any(char::is_control)
}

/// Is this a lowercase 64-hex SHA-256?
fn is_content_hash(value: &str) -> bool {
    value.len() == ARTIFACT_HASH_HEX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactRef, ArtifactSchema, MAX_ARTIFACT_PARENT_HASHES, MAX_ARTIFACT_TAG_BYTES, Producer,
        Provenance,
    };
    use crate::capability_set::CapabilitySet;
    use crate::diff::{DiffLine, DiffTag, FileDiff, Hunk};
    use crate::event::EventKind;
    use crate::ids::{EffectId, RunId, Seq};
    use crate::slot::SlotId;
    use crate::tool::Capability;
    use serde_json::json;

    const HASH: &str = "9f2c1b4a5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f80";
    /// The shape `crates/record` mints today: a 40-hex git object id.
    const TREE_OID: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d";

    fn patch_ref() -> ArtifactRef {
        ArtifactRef {
            hash: HASH.into(),
            schema: ArtifactSchema::FileDiff,
            producer: Producer::Tool {
                tool: "edit_file".into(),
            },
            provenance: Provenance {
                run_id: RunId("run-1".into()),
                parent_hashes: Vec::new(),
                effect_id: Some(EffectId("fx1-00000003-0001".into())),
            },
            permissions: CapabilitySet::only(Capability::ReadOnly),
            locator: "artifacts/9f2c.patch".into(),
        }
    }

    #[test]
    fn an_unknown_schema_degrades_without_rewriting_the_producers_tag() {
        // A tag no build has heard of. This arm is the mechanism that lets a new schema be appended
        // later without breaking a reader shipped now.
        let decoded: ArtifactSchema = serde_json::from_value(json!("embedding_index"))
            .expect("an unknown schema must not error");
        assert_eq!(decoded, ArtifactSchema::Unknown("embedding_index".into()));
        assert_eq!(
            serde_json::to_value(&decoded).expect("re-serialises"),
            json!("embedding_index"),
            "a tamper-evident handle must not restate its own schema as something else"
        );
    }

    #[test]
    fn an_unknown_producer_keeps_its_kind_and_drops_everything_beside_it() {
        const MARKER: &str = "opaque-payload-must-not-survive-producer-decoding";
        let decoded: Producer = serde_json::from_value(json!({
            "kind": "wasm_component",
            "module": MARKER,
            "operator_note": MARKER,
        }))
        .expect("an unknown producer must not error");
        assert_eq!(decoded, Producer::Unknown("wasm_component".into()));
        assert!(!format!("{decoded:?}").contains(MARKER));

        let reencoded = serde_json::to_value(&decoded).expect("re-serialises");
        assert_eq!(
            reencoded,
            json!({ "kind": "wasm_component" }),
            "attribution is the tag; the fields beside it are payload and must not cross the seam"
        );
        assert!(!reencoded.to_string().contains(MARKER));
    }

    #[test]
    fn a_retained_tag_is_bounded_at_mint_time_and_never_at_decode_time() {
        // Decoding stays permissive: refusing to read an oversized tag destroys the evidence
        // instead of flagging it, so the gate is where a handle is minted.
        let oversized = "x".repeat(MAX_ARTIFACT_TAG_BYTES + 1);
        let decoded: ArtifactSchema = serde_json::from_value(json!(oversized))
            .expect("an oversized tag must still decode, so the handle survives to be judged");
        assert_eq!(decoded, ArtifactSchema::Unknown(oversized.clone()));

        let handle = ArtifactRef {
            schema: decoded,
            ..patch_ref()
        };
        assert!(handle.validate().is_err());

        let controlled = ArtifactRef {
            producer: Producer::Unknown("wasm\u{0007}component".into()),
            ..patch_ref()
        };
        assert!(controlled.validate().is_err());

        let blank = ArtifactRef {
            producer: Producer::Unknown("   ".into()),
            ..patch_ref()
        };
        assert!(blank.validate().is_err());

        let plausible = ArtifactRef {
            schema: ArtifactSchema::Unknown("embedding_index".into()),
            producer: Producer::Unknown("wasm_component".into()),
            ..patch_ref()
        };
        assert!(plausible.validate().is_ok());
    }

    #[test]
    fn the_seeds_are_untouched_by_this_wrapper_existing() {
        let diff = FileDiff {
            path: "src/lib.rs".into(),
            adds: 1,
            dels: 0,
            hunks: vec![Hunk {
                header: "@@ -1,1 +1,2 @@".into(),
                lines: vec![DiffLine {
                    tag: DiffTag::Add,
                    text: "let x = 1;".into(),
                }],
            }],
        };
        let checkpoint = EventKind::Checkpoint {
            at: Seq(7),
            tree_ref: TREE_OID.into(),
        };
        let diff_before = serde_json::to_string(&diff).expect("FileDiff serialises");
        let checkpoint_before = serde_json::to_string(&checkpoint).expect("EventKind serialises");

        let _patch = patch_ref();
        let _snapshot = ArtifactRef {
            schema: ArtifactSchema::Checkpoint,
            producer: Producer::Run,
            locator: TREE_OID.into(),
            ..patch_ref()
        };

        // `FileDiff` is deny_unknown_fields and fixture-pinned; `Checkpoint` is in the fsynced,
        // hash-chained WAL. Describing them must not move either one's bytes.
        assert_eq!(
            serde_json::to_string(&diff).expect("re-serialises"),
            diff_before
        );
        assert_eq!(
            serde_json::to_string(&checkpoint).expect("re-serialises"),
            checkpoint_before
        );
    }

    #[test]
    fn a_git_object_id_is_a_locator_and_never_a_content_hash() {
        // §4.2.5 says `hash` is the SHA-256 of the content. `record`'s `valid_object_id` accepts 40
        // or 64 hex, so the checkpoint seed's identifier is a git oid over git's own framed tree
        // object. Accepting it as `hash` would make the content-address claim false.
        let mut snapshot = ArtifactRef {
            schema: ArtifactSchema::Checkpoint,
            producer: Producer::Run,
            locator: TREE_OID.into(),
            ..patch_ref()
        };
        assert!(snapshot.validate().is_ok());

        snapshot.hash = TREE_OID.into();
        assert!(
            snapshot.validate().is_err(),
            "a 40-hex git oid must not pass as a content address"
        );

        snapshot.hash = HASH.to_uppercase();
        assert!(
            snapshot.validate().is_err(),
            "uppercase is refused, not normalised: two spellings of one address is not an address"
        );
    }

    #[test]
    fn empty_permissions_are_refused_because_they_read_as_no_capability_required() {
        let mut handle = patch_ref();
        handle.permissions = CapabilitySet::none();
        assert!(handle.validate().is_err());

        // Holding the handle is still not authority: the field says what a reader must have, and
        // nothing in this type hands it to them.
        handle.permissions = CapabilitySet::only(Capability::ReadOnly);
        assert!(handle.validate().is_ok());
        assert!(!handle.permissions.contains(Capability::CodeExecuting));
    }

    #[test]
    fn lineage_must_be_bounded_and_re_hashable() {
        let mut handle = patch_ref();
        handle.provenance.parent_hashes = vec![HASH.into(), HASH.into()];
        assert!(handle.validate().is_ok());

        // A registry verifies lineage by re-hashing. It cannot re-hash a path.
        handle.provenance.parent_hashes = vec!["artifacts/parent.patch".into()];
        assert!(handle.validate().is_err());

        handle.provenance.parent_hashes = vec![HASH.into(); MAX_ARTIFACT_PARENT_HASHES + 1];
        assert!(handle.validate().is_err());

        handle.provenance.parent_hashes = Vec::new();
        handle.provenance.run_id = RunId(String::new());
        assert!(handle.validate().is_err());
    }

    #[test]
    fn the_wire_shape_is_frozen() {
        let frozen = json!({
            "hash": HASH,
            "schema": "file_diff",
            "producer": { "kind": "tool", "tool": "edit_file" },
            "provenance": {
                "run_id": "run-1",
                "parent_hashes": [],
                "effect_id": "fx1-00000003-0001",
            },
            "permissions": ["read_only"],
            "locator": "artifacts/9f2c.patch",
        });
        assert_eq!(
            serde_json::to_value(patch_ref()).expect("ArtifactRef serialises"),
            frozen
        );
        assert_eq!(
            serde_json::from_value::<ArtifactRef>(frozen).expect("round-trips"),
            patch_ref()
        );
    }

    #[test]
    fn the_wire_shape_is_the_one_the_spec_prints() {
        // Field for field the ArtifactRef in `docs/spec/abi.md` 4.4 step 5. If this test has to be
        // edited, the ABI moved and the spec is now wrong about what leaves the runtime.
        let spec = json!({
            "hash": "3b1f8e2c4a6d0b9f1e3c5a7d9b1f3e5c7a9d1b3f5e7c9a1d3b5f7e9c1a3d5b7f",
            "schema": "file_diff",
            "producer": { "kind": "slot", "slot": "iteron/tool_policy" },
            "provenance": { "run_id": "run-9", "parent_hashes": [], "effect_id": "eff-7" },
            "permissions": ["reversible_local"],
            "locator": "diff://run-9/eff-7"
        });
        let handle: ArtifactRef =
            serde_json::from_value(spec.clone()).expect("the spec's own JSON decodes");
        assert!(
            handle.validate().is_ok(),
            "the spec must not print an invalid handle"
        );
        assert_eq!(serde_json::to_value(&handle).expect("re-serialises"), spec);
    }

    #[test]
    fn a_slot_producer_carries_the_identity_that_crosses_to_the_evolve_side() {
        let handle = ArtifactRef {
            schema: ArtifactSchema::PolicyManifest,
            producer: Producer::Slot {
                slot: SlotId("iteron/tool_policy".into()),
            },
            provenance: Provenance {
                run_id: RunId("run-1".into()),
                parent_hashes: vec![HASH.into()],
                effect_id: None,
            },
            ..patch_ref()
        };
        assert!(handle.validate().is_ok());

        let wire = serde_json::to_value(&handle).expect("serialises");
        assert_eq!(
            wire["producer"],
            json!({ "kind": "slot", "slot": "iteron/tool_policy" }),
            "the slot identity must stay a bare string so it matches the evolve-side persisted form"
        );
        assert_eq!(
            wire["provenance"]["effect_id"],
            json!(null),
            "an Option that is part of the frozen shape stays visible on the wire"
        );
    }

    #[test]
    fn a_tool_producer_must_name_its_tool() {
        let handle = ArtifactRef {
            producer: Producer::Tool {
                tool: String::new(),
            },
            ..patch_ref()
        };
        assert!(handle.validate().is_err());
    }
}
