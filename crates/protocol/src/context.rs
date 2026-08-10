//! `ContextRequest` — a module's typed request for authorized context, and the grant it returns.
//!
//! # Why the request side has to exist at all
//!
//! Today there is no request. `crates/kernel/src/lib.rs::resolve_injection` decides what enters
//! context by itself: it builds the memory stores, calls `FileMemory::recall`, appends a skill
//! listing, and combines those with an instruction/environment prefix the frontend pushed in
//! through `set_instruction_context` / `set_environment_context`. The context strategy never
//! states what it wanted, so "what entered context, and why" is only recoverable by reading kernel
//! code, and an optimizer has nothing to search over.
//!
//! [`ContextRequest`] is the missing half: the slot declares *what* it wants, *how many bytes* it
//! will accept, and *how far* it is willing to trust what comes back. The kernel resolves that
//! into a [`ContextGrant`] and records it. This file freezes the shape only — nothing here reads a
//! file, and no call site changes.
//!
//! # Why the grant side is promoted rather than reused
//!
//! The grant already exists in pieces: `EventKind::ContextInjection { text, trust, instructions }`
//! plus `DurableInstructionContext`/`DurableEnvironmentContext` (`crates/protocol/src/event.rs`).
//! Those are one flat rendered string with one trust tier, plus one optional prefix that carries
//! its own tier so that combining cannot silently raise trust. That is a two-segment grant with
//! the segments hard-coded. [`ContextGrant`] is the same idea with the count unfixed, and it is a
//! separate type on purpose: `ContextInjection` is an fsynced, hash-chained durable record whose
//! bytes are pinned by fixtures, so reshaping it to hold a `Vec<ContextSegment>` would move the
//! record. The grant is what crosses the seam; the event stays exactly as it is.
//!
//! # Why the segment source is its own vocabulary
//!
//! `RuntimePolicySource` is the enum a reader is most likely to reach for here, and it cannot do
//! this job. It is the vocabulary of *runtime-policy transitions* — `Startup`, `Operator`,
//! `ApprovalRemember`, `Harness`, `Fork` — and it is written into three durable event kinds
//! (`UsdCeilingChanged`, `EffortChanged`, `PolicyChanged`). It cannot name a single thing the
//! grant side actually produces: memory tier, skill index, instruction file, environment facts.
//! The spec's own end-to-end walk-through in §4.4 labels the segments of a grant `repo outline`,
//! `instruction` and `environment`; none of those is `startup`/`operator`/`fork` either. Reusing
//! the enum would mean either mislabelling every segment or appending context vocabulary to an
//! enum whose readers are unrelated policy records — and it has no `#[serde(other)]` arm, which
//! every cross-seam enum here needs. Hence [`ContextSource`], which `docs/spec/abi.md` §4.2.2
//! specifies as a closed vocabulary and this module freezes.
//!
//! [`ContextSource`] is deliberately not a mirror of [`ContextSelector`]. The kernel injects a
//! skill listing that no selector asks for, so the grant can honestly report a source the request
//! could not have named. Forcing the two vocabularies into one enum would make that asymmetry
//! unspeakable, and it is real today.
//!
//! # Why there is no `purpose` field
//!
//! The audit anchor is `(request_id, slot)` plus the selector itself, which is what a recorded
//! request actually contains; `docs/spec/abi.md` §4.2.2 says exactly that, and the frozen shape
//! follows it. A per-request `purpose` can be appended later as an `Option` field under the
//! additive rule at zero wire cost; a per-*selector* purpose cannot, because an internally tagged
//! enum has no place for a field common to all variants. Anyone who wants it per selector has to
//! add it to each variant, and should know that before starting.

use crate::slot::SlotId;
use crate::trust::Trust;
use serde::{Deserialize, Serialize};

/// Upper bound on the selectors one request may name.
///
/// The vocabulary has five kinds. A request naming more than a few of each is not a selection, it
/// is a scrape, and the point of this contract is that context selection stays reviewable.
pub const MAX_SELECTORS: usize = 32;

/// Upper bound on a selector's root path. The same ceiling as `MAX_EFFECT_WORKSPACE_BYTES`
/// (`crates/protocol/src/effect.rs`), because it bounds the same thing: one filesystem path
/// crossing the seam.
pub const MAX_SELECTOR_ROOT_BYTES: usize = 4_096;

/// Upper bound on the keys a single `MemoryKeys` selector may name.
pub const MAX_MEMORY_KEYS: usize = 64;

/// Upper bound on one memory key.
///
/// This and [`MAX_MEMORY_KEYS`] together bound that selector at 16 KiB. It matters that the bound
/// is on the request value itself: a request is decoded before anyone decides whether to honour
/// it, so the ceiling has to hold on the untrusted value, not on what the kernel later grants.
pub const MAX_MEMORY_KEY_BYTES: usize = 256;

/// Upper bound on the segments one grant may carry.
pub const MAX_CONTEXT_SEGMENTS: usize = 64;

/// Hard ceiling on a grant's injected bytes, and therefore on any request's `max_bytes`.
///
/// The number is chosen against what the kernel already injects rather than picked for looks. The
/// four sources `resolve_injection` assembles today are individually capped at 49,000 (memory,
/// `MemBudget::default`), 32,768 (`MAX_MERGED_INSTRUCTION_BYTES`), 4,096
/// (`MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES`) and 2,000 (the skill listing) bytes: 87,864 together.
/// A ceiling below that would declare a bound the system's own assembly path already breaks. 128
/// KiB is the next power of two above it, leaving headroom for the sources a request can name but
/// the kernel does not yet produce.
pub const MAX_CONTEXT_GRANT_BYTES: u32 = 128 * 1024;

/// Correlates one request with the grant that answers it.
///
/// `docs/spec/abi.md` names this type and places it with the other identifiers, but `ids.rs` has
/// none today and this freeze touches no other module, so it is minted here. If a second contract
/// ever needs the same identity, moving it to `ids.rs` is a re-export change and not a wire
/// change: the representation is a bare integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub u64);

/// Which instruction files a request is asking for.
///
/// The three scopes are the three tiers `iteron_ctx::instructions::discover_hierarchy` actually
/// walks, in its own precedence order: the operator's `~/.iteron/instructions.md`, then the
/// repository-root candidates, then each directory from the root down to the active one. Naming a
/// scope selects a tier of that walk; it never grants authority, because every discovered
/// instruction file is data — `crates/ctx/src/instructions.rs` frames all of them as untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionScope {
    /// `~/.iteron/instructions.md`. Authored by the operator, which is why `MemTier::User` is the
    /// one tier `iteron_ctx` treats as first-party without a separate approval.
    User,
    /// The repository root's `AGENTS.md` / `CLAUDE.md` / `.iteron/instructions.md`.
    Project,
    /// The directory chain below the repository root, refining the project scope.
    Directory,
    /// A scope this build does not recognise, written by a newer producer. The tag and every
    /// field beside it are discarded on decode.
    #[serde(other)]
    Unknown,
}

/// One thing a module is asking for.
///
/// A selector is a declaration of intent. It carries no handle, no descriptor and no path the
/// kernel is obliged to open: `docs/spec/abi.md` §4.2.2 is explicit that a request must not read
/// files, walk the workspace or read the environment. Every variable-length field here has a
/// declared ceiling, and the two numeric fields are bounded by their own types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContextSelector {
    /// A structural outline of a subtree, to `depth` levels. `iteron_ctx::outline` is the seed.
    RepoOutline { root: String, depth: u8 },
    /// Instruction files at one tier of the discovery hierarchy.
    Instructions { scope: InstructionScope },
    /// Named read paths into the memory slot.
    MemoryKeys { keys: Vec<String> },
    /// The last `last_n_turns` turns of the transcript.
    Transcript { last_n_turns: u16 },
    /// Frontend-observed facts: cwd, git state. Data, never an instruction source.
    EnvironmentFacts,
    /// A selector kind this build does not recognise. Reached only by decoding a request written
    /// by a newer module. Degrading rather than failing keeps one unknown selector from killing a
    /// whole replay, and the payload is dropped so an opaque field cannot ride in through it —
    /// the discipline `Op::Unknown` is tested for in `crates/protocol/src/lib.rs`.
    #[serde(other)]
    Unknown,
}

/// Where a granted segment came from.
///
/// A closed vocabulary, not a free string: a module must not be able to invent a provenance label
/// for bytes it supplied. `Unknown` is here because the *kernel* is the producer on this side and
/// a newer kernel may name a source an older module has never heard of; the module degrades
/// instead of failing to decode its own grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSource {
    /// Discovered instruction files (`iteron_ctx::instructions`).
    Instructions,
    /// The memory slot's recalled segment (`iteron_ctx::memory`).
    Memory,
    /// The skill name/description index. No selector names this today: the kernel appends it
    /// unconditionally in `resolve_injection`, and the grant reports it rather than pretending it
    /// was asked for.
    Skills,
    /// Frontend-observed environment facts, matching `DurableEnvironmentContext`.
    Environment,
    /// A repository outline.
    RepoOutline,
    /// Prior transcript turns.
    Transcript,
    /// A source this build does not recognise, from a newer kernel. Payload dropped on decode.
    #[serde(other)]
    Unknown,
}

/// A module's typed request for authorized context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRequest {
    /// Correlates this request with its grant.
    pub request_id: RequestId,
    /// Who is asking. In this codebase the name `StrategySlot` belongs both to the trait the
    /// kernel calls and to a separate `iteron_evolve` newtype, so the identity that crosses between
    /// them is [`SlotId`] — see `crates/protocol/src/slot.rs`, which froze that distinction
    /// deliberately, and `docs/spec/abi.md` §4.2.2, which types this field as `SlotId` and fixes
    /// the subset direction against `iteron_evolve::StrategySlot`.
    pub slot: SlotId,
    /// What is being asked for. Bounded by [`MAX_SELECTORS`].
    pub selectors: Vec<ContextSelector>,
    /// The most bytes this request will accept back. Bounded by [`MAX_CONTEXT_GRANT_BYTES`].
    pub max_bytes: u32,
    /// The highest tier the requester is willing to treat as authoritative.
    ///
    /// A ceiling, so it can only lower the trust of what comes back. It does not ask for trust and
    /// cannot raise it: a segment's tier is decided by where its bytes came from, and
    /// `crates/protocol/src/trust.rs` keeps the governing tier a minimum for exactly that reason.
    pub trust_ceiling: Trust,
}

impl ContextRequest {
    /// Deny-by-default construction: nothing selected, nothing trusted above `Untrusted`.
    ///
    /// There is deliberately no constructor taking a trust tier and a selector list together. A
    /// request that intends to treat something as authoritative should have to say so on its own
    /// line, where a reviewer will see it.
    pub fn new(request_id: RequestId, slot: SlotId, max_bytes: u32) -> Self {
        Self {
            request_id,
            slot,
            selectors: Vec::new(),
            max_bytes,
            trust_ceiling: Trust::Untrusted,
        }
    }

    /// Add one selector.
    pub fn with_selector(mut self, selector: ContextSelector) -> Self {
        self.selectors.push(selector);
        self
    }

    /// Validate bounds and internal consistency. Pure.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.slot.validate()?;
        if self.selectors.len() > MAX_SELECTORS {
            return Err("too many context selectors");
        }
        if self.max_bytes > MAX_CONTEXT_GRANT_BYTES {
            return Err("requested context bytes exceed the protocol ceiling");
        }
        for selector in &self.selectors {
            match selector {
                ContextSelector::RepoOutline { root, .. } => {
                    if root.is_empty() || root.len() > MAX_SELECTOR_ROOT_BYTES {
                        return Err("selector root must be 1..=4096 bytes");
                    }
                }
                ContextSelector::MemoryKeys { keys } => {
                    if keys.len() > MAX_MEMORY_KEYS {
                        return Err("too many memory keys in one selector");
                    }
                    if keys
                        .iter()
                        .any(|key| key.is_empty() || key.len() > MAX_MEMORY_KEY_BYTES)
                    {
                        return Err("memory key must be 1..=256 bytes");
                    }
                }
                ContextSelector::Instructions { .. }
                | ContextSelector::Transcript { .. }
                | ContextSelector::EnvironmentFacts
                | ContextSelector::Unknown => {}
            }
        }
        Ok(())
    }
}

/// One rendered piece of granted context, with its own provenance.
///
/// Each segment keeps its own tier so that combining segments cannot raise trust — the property
/// `DurableInstructionContext.environment` already encodes by carrying a separate `trust` beside
/// the instruction bytes instead of folding both into one tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSegment {
    /// The exact bytes injected for this segment.
    pub text: String,
    /// The tier these bytes carry. Never derived from what the bytes say.
    pub trust: Trust,
    /// Where the bytes came from.
    pub source: ContextSource,
}

/// The kernel's answer: bounded, trust-tagged, and recordable as a `ContextInjection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextGrant {
    /// The request this answers.
    pub request_id: RequestId,
    /// The rendered segments, each with its own provenance. Bounded by [`MAX_CONTEXT_SEGMENTS`].
    pub segments: Vec<ContextSegment>,
    /// Bytes actually injected. This is the number the ceiling is enforced against, so
    /// [`ContextGrant::validate_for`] refuses a grant reporting fewer than its segments hold.
    pub bytes: u32,
}

impl ContextGrant {
    /// The tier this whole grant governs at, or `None` if it granted nothing.
    ///
    /// Delegates to [`Trust::governing`] — the minimum — and keeps its `Option`. An empty grant
    /// has the mathematical identity `Trusted`, and a security decision must not inherit that by
    /// accident; the caller has to say what "nothing was injected" means for it.
    pub fn governing_trust(&self) -> Option<Trust> {
        Trust::governing(self.segments.iter().map(|segment| segment.trust))
    }

    /// Check a grant against the request it claims to answer. Pure.
    ///
    /// The byte rule is `>=` the sum of the segment lengths rather than `==`, on purpose. The
    /// field's job is to be the honest number the ceiling is checked against: under-reporting it
    /// makes every bound in this contract decorative, while over-reporting only accounts for
    /// framing the kernel added around the segments. Freezing an exact accounting rule here would
    /// pin how the kernel is allowed to join segments, which is not this contract's business.
    pub fn validate_for(&self, request: &ContextRequest) -> Result<(), &'static str> {
        if self.request_id != request.request_id {
            return Err("grant does not answer this request");
        }
        if self.segments.len() > MAX_CONTEXT_SEGMENTS {
            return Err("too many context segments");
        }
        if self.bytes > MAX_CONTEXT_GRANT_BYTES {
            return Err("granted context bytes exceed the protocol ceiling");
        }
        if self.bytes > request.max_bytes {
            return Err("granted context bytes exceed the bound the request declared");
        }
        let rendered: usize = self.segments.iter().map(|segment| segment.text.len()).sum();
        if (self.bytes as usize) < rendered {
            return Err("granted bytes under-report the segments, so the bound is unenforceable");
        }
        if self
            .segments
            .iter()
            .any(|segment| segment.trust > request.trust_ceiling)
        {
            return Err("a segment exceeds the trust ceiling the request declared");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ContextGrant, ContextRequest, ContextSegment, ContextSelector, ContextSource,
        InstructionScope, MAX_CONTEXT_GRANT_BYTES, MAX_SELECTORS, RequestId,
    };
    use crate::slot::SlotId;
    use crate::trust::Trust;
    use serde_json::json;

    fn request() -> ContextRequest {
        ContextRequest {
            request_id: RequestId(11),
            slot: SlotId("iteron/context".into()),
            selectors: vec![
                ContextSelector::RepoOutline {
                    root: "crates/parser".into(),
                    depth: 2,
                },
                ContextSelector::Instructions {
                    scope: InstructionScope::Project,
                },
                ContextSelector::EnvironmentFacts,
            ],
            max_bytes: 32_768,
            trust_ceiling: Trust::Workspace,
        }
    }

    #[test]
    fn the_wire_shape_is_the_one_the_spec_prints() {
        // Field for field the request in `docs/spec/abi.md` §4.4 step 1. If this test has to be
        // edited, the ABI moved and the spec is now wrong about what a module sends.
        let spec = json!({
            "request_id": 11,
            "slot": "iteron/context",
            "selectors": [
                { "kind": "repo_outline", "root": "crates/parser", "depth": 2 },
                { "kind": "instructions", "scope": "project" },
                { "kind": "environment_facts" }
            ],
            "max_bytes": 32768,
            "trust_ceiling": "workspace"
        });
        assert_eq!(
            serde_json::to_value(request()).expect("request serialises"),
            spec
        );
        assert_eq!(
            serde_json::from_value::<ContextRequest>(spec).expect("the spec's own JSON decodes"),
            request()
        );
    }

    #[test]
    fn an_unknown_selector_degrades_and_drops_its_payload() {
        let marker = "opaque-payload-must-not-survive-selector-decoding";
        let decoded: ContextRequest = serde_json::from_value(json!({
            "request_id": 11,
            "slot": "iteron/context",
            "selectors": [
                { "kind": "embedding_search", "query": marker, "nested": { "key": marker } }
            ],
            "max_bytes": 1024,
            "trust_ceiling": "untrusted"
        }))
        .expect("an unknown selector kind must not fail the whole request");

        assert_eq!(decoded.selectors, vec![ContextSelector::Unknown]);
        assert!(!format!("{decoded:?}").contains(marker));
        let encoded = serde_json::to_value(&decoded).expect("re-serialises");
        assert!(!encoded.to_string().contains(marker));
        assert_eq!(encoded["selectors"], json!([{ "kind": "unknown" }]));
    }

    #[test]
    fn an_unknown_scope_or_source_degrades_rather_than_failing_its_enclosing_value() {
        let selector: ContextSelector =
            serde_json::from_value(json!({ "kind": "instructions", "scope": "tenant_policy" }))
                .expect("an unknown scope must not fail the selector around it");
        assert_eq!(
            selector,
            ContextSelector::Instructions {
                scope: InstructionScope::Unknown
            }
        );

        let segment: ContextSegment = serde_json::from_value(json!({
            "text": "x",
            "trust": "workspace",
            "source": "vector_index"
        }))
        .expect("an unknown source must not fail the segment around it");
        assert_eq!(segment.source, ContextSource::Unknown);
    }

    #[test]
    fn a_grant_may_not_exceed_the_bytes_or_the_trust_the_request_declared() {
        let request = request();

        let over_budget = ContextGrant {
            request_id: RequestId(11),
            segments: vec![ContextSegment {
                text: "x".repeat(40_000),
                trust: Trust::Workspace,
                source: ContextSource::Memory,
            }],
            bytes: 40_000,
        };
        assert!(over_budget.validate_for(&request).is_err());

        // The request was willing to treat what came back as Workspace at most. A grant may not
        // hand back operator-tier bytes against it: trust is not something a grant can raise.
        let over_trust = ContextGrant {
            request_id: RequestId(11),
            segments: vec![ContextSegment {
                text: "operator instruction".into(),
                trust: Trust::Trusted,
                source: ContextSource::Instructions,
            }],
            bytes: 20,
        };
        assert!(over_trust.validate_for(&request).is_err());

        let mismatched = ContextGrant {
            request_id: RequestId(12),
            segments: Vec::new(),
            bytes: 0,
        };
        assert!(mismatched.validate_for(&request).is_err());
    }

    #[test]
    fn a_grant_that_under_reports_its_bytes_is_refused() {
        // `bytes` is what the ceiling is checked against. If it may be smaller than the segments
        // it describes, every byte bound in this contract is decorative.
        let request = request();
        let lying = ContextGrant {
            request_id: RequestId(11),
            segments: vec![ContextSegment {
                text: "x".repeat(4_096),
                trust: Trust::Workspace,
                source: ContextSource::RepoOutline,
            }],
            bytes: 16,
        };
        assert!(lying.validate_for(&request).is_err());

        let honest = ContextGrant {
            bytes: 4_200,
            ..lying
        };
        assert!(
            honest.validate_for(&request).is_ok(),
            "over-reporting only accounts for framing the kernel added; that stays legal"
        );
    }

    #[test]
    fn merging_segments_governs_at_the_minimum_tier_and_never_the_maximum() {
        let grant = ContextGrant {
            request_id: RequestId(11),
            segments: vec![
                ContextSegment {
                    text: "env".into(),
                    trust: Trust::Workspace,
                    source: ContextSource::Environment,
                },
                ContextSegment {
                    text: "agents.md".into(),
                    trust: Trust::Untrusted,
                    source: ContextSource::Instructions,
                },
            ],
            bytes: 12,
        };
        assert_eq!(grant.governing_trust(), Some(Trust::Untrusted));

        let empty = ContextGrant {
            request_id: RequestId(11),
            segments: Vec::new(),
            bytes: 0,
        };
        assert_eq!(
            empty.governing_trust(),
            None,
            "an empty grant must not silently govern at Trusted"
        );
    }

    #[test]
    fn a_request_is_deny_by_default_and_bounded() {
        let fresh = ContextRequest::new(RequestId(1), SlotId("iteron/context".into()), 1_024);
        assert_eq!(fresh.trust_ceiling, Trust::Untrusted);
        assert!(fresh.selectors.is_empty());
        assert!(fresh.validate().is_ok());

        let too_many = (0..=MAX_SELECTORS).fold(fresh.clone(), |request, _| {
            request.with_selector(ContextSelector::EnvironmentFacts)
        });
        assert!(too_many.validate().is_err());

        let unbounded = ContextRequest {
            max_bytes: MAX_CONTEXT_GRANT_BYTES + 1,
            ..fresh.clone()
        };
        assert!(unbounded.validate().is_err());

        // An unnameable slot is refused here rather than downstream: a request whose origin no
        // policy bundle can name is the ungovernable hole `slot.rs` refuses to mint.
        let unnameable = ContextRequest {
            slot: SlotId("Core/Context".into()),
            ..fresh.clone()
        };
        assert!(unnameable.validate().is_err());

        let empty_key = fresh.with_selector(ContextSelector::MemoryKeys {
            keys: vec![String::new()],
        });
        assert!(empty_key.validate().is_err());
    }
}
