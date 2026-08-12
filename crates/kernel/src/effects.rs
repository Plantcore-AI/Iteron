//! The universal effect boundary: admission, durable intent ordering, terminal-or-unknown outcome.
//!
//! Every externally visible effect the kernel performs crosses this module — registry tool calls,
//! provider requests, lifecycle hooks, subagent spawns, verifier oracle runs, workspace checkpoints
//! and in-turn workflow launches. They share one fsynced `EffectIntent` write-ahead ordering, one
//! at-most-once admission ledger (`crate::effect_admission`) and one terminal vocabulary, so the
//! recovery story is a property of the boundary rather than a promise repeated at every call site.
//!
//! The identity vocabulary lives in `crate::effect_class` and the replay fold in
//! `crate::effect_journal`. The code here is constitutional mechanism, never a learnable/evolvable
//! strategy slot.

use crate::effect_admission::{EffectAdmissionError, EffectAdmissions};
use iteron_protocol::effect::EffectProposal;
use iteron_protocol::intent::ToolIntent;
use iteron_protocol::{Capability, EffectId, Event, EventKind, Seq, ToolResult, ToolUse, TurnId};
use std::collections::BTreeSet;
use std::future::Future;

pub const MAX_TOOL_CALLS_PER_TURN: usize = 128;
pub const MAX_TOOL_USE_ID_BYTES: usize = 512;
pub const MAX_TOOL_NAME_BYTES: usize = 256;
pub const MAX_TOOL_ARGUMENT_BYTES: usize = 1024 * 1024;

/// The tool port's observation of an execution. This kernel-owned value prevents the universal
/// broker from depending on a concrete registry crate. CLI adapters map their executor result into
/// this two-state proof vocabulary before crossing the port.
pub enum ToolExecution {
    Definite(ToolResult),
    Unknown(ToolResult),
}

impl From<ToolResult> for ToolExecution {
    fn from(result: ToolResult) -> Self {
        Self::Definite(result)
    }
}

impl ToolExecution {
    pub fn into_result(self) -> ToolResult {
        match self {
            Self::Definite(result) | Self::Unknown(result) => result,
        }
    }
}

/// Admission state for model-emitted tool calls in one provider turn. Validation happens before a
/// call crosses the UI, record, or registry boundary. The count ceiling is a hard resource guard,
/// not a scheduler policy.
#[derive(Debug, Default)]
pub struct ToolCallAdmission {
    ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ToolCallContractError {
    #[error("provider emitted more than the hard per-turn tool-call ceiling")]
    TooMany,
    #[error("provider emitted an empty or oversized tool-use id")]
    InvalidId,
    #[error("provider emitted a control/invisible character in tool identity")]
    UnsafeIdentity,
    #[error("provider emitted a secret-shaped tool identity")]
    SecretShapedIdentity,
    #[error("provider emitted a tool identity inside a harness-reserved namespace")]
    ReservedIdentity,
    #[error("provider emitted a duplicate tool-use id in one turn")]
    DuplicateId,
    #[error("provider emitted an empty or oversized tool name")]
    InvalidName,
    #[error("provider emitted tool arguments past the hard byte ceiling")]
    ArgumentsTooLarge,
}

impl ToolCallAdmission {
    pub fn admit(&mut self, tool: &ToolUse) -> Result<(), ToolCallContractError> {
        if self.ids.len() >= MAX_TOOL_CALLS_PER_TURN {
            return Err(ToolCallContractError::TooMany);
        }
        if tool.id.trim().is_empty() || tool.id.len() > MAX_TOOL_USE_ID_BYTES {
            return Err(ToolCallContractError::InvalidId);
        }
        if tool.name.trim().is_empty() || tool.name.len() > MAX_TOOL_NAME_BYTES {
            return Err(ToolCallContractError::InvalidName);
        }
        if unsafe_identity(&tool.id) || unsafe_identity(&tool.name) {
            return Err(ToolCallContractError::UnsafeIdentity);
        }
        // The id is asked the question the record path will answer. A structural correlation id
        // survives redaction verbatim, so admitting it cannot desynchronise the two sides; a
        // credential-shaped one would still be masked, so it stays refused (#74).
        if iteron_record::redact::scrub_correlation_identifier(&tool.id) != tool.id
            || iteron_record::redact::scrub(&tool.name) != tool.name
        {
            return Err(ToolCallContractError::SecretShapedIdentity);
        }
        // The harness mints two identity namespaces the model must never be able to enter: effect
        // ids (`fx1-`) and its own correlation ids (`hx1-`). Both are fully predictable, so without
        // this a provider could name a tool call after a checkpoint's audit record and have its
        // result correlate against an effect it never performed.
        if crate::effect_class::is_harness_effect_id(&tool.id)
            || crate::effect_class::is_harness_correlation_id(&tool.id)
        {
            return Err(ToolCallContractError::ReservedIdentity);
        }
        if !self.ids.insert(tool.id.clone()) {
            return Err(ToolCallContractError::DuplicateId);
        }
        if serde_json::to_vec(&tool.input)
            .map(|bytes| bytes.len() > MAX_TOOL_ARGUMENT_BYTES)
            .unwrap_or(true)
        {
            return Err(ToolCallContractError::ArgumentsTooLarge);
        }
        Ok(())
    }
}

/// The most artifacts one run may declare. A product stream is bounded like every other.
pub const MAX_ARTIFACTS_PER_RUN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactContractError {
    #[error("artifact ref is not admissible: {0}")]
    Invalid(&'static str),
    #[error("artifact content is not durable yet; the event may only follow the write")]
    ContentNotDurable,
    #[error("run declared more than the hard per-run artifact ceiling")]
    TooMany,
    #[error("run declared the same artifact hash twice")]
    Duplicate,
}

/// Admission for run-declared artifacts.
///
/// Two rules the type enforces rather than documents.
///
/// **The content lands before the event does.** An `ArtifactProduced` naming content that is not
/// yet readable is a promise, and a consumer that stores or reopens the product later would be
/// holding a handle to nothing. Admission takes a durability witness and refuses without it, so
/// "emit after the write" is a refusal rather than a convention someone remembers.
///
/// **Exceeding the ceiling is counted, never silently dropped.** A run that produces more than the
/// bound has its excess refused *and* tallied, because a product stream that quietly stops is
/// indistinguishable from a run that stopped producing.
#[derive(Debug, Default)]
pub struct ArtifactAdmission {
    hashes: BTreeSet<String>,
    refused: usize,
}

impl ArtifactAdmission {
    /// Admit one declared artifact. `durable` answers whether the content is already readable at
    /// the ref's locator; the caller owns that check because only it knows the store.
    pub fn admit(
        &mut self,
        artifact: &iteron_protocol::artifact::ArtifactRef,
        durable: impl FnOnce(&str) -> bool,
    ) -> Result<(), ArtifactContractError> {
        artifact
            .validate()
            .map_err(ArtifactContractError::Invalid)?;
        if self.hashes.len() >= MAX_ARTIFACTS_PER_RUN {
            self.refused = self.refused.saturating_add(1);
            return Err(ArtifactContractError::TooMany);
        }
        if !durable(&artifact.locator) {
            self.refused = self.refused.saturating_add(1);
            return Err(ArtifactContractError::ContentNotDurable);
        }
        if !self.hashes.insert(artifact.hash.clone()) {
            self.refused = self.refused.saturating_add(1);
            return Err(ArtifactContractError::Duplicate);
        }
        Ok(())
    }

    /// How many declarations were refused. Reported, so a truncated product stream is visible.
    pub fn refused(&self) -> usize {
        self.refused
    }

    pub fn admitted(&self) -> usize {
        self.hashes.len()
    }
}

fn unsafe_identity(value: &str) -> bool {
    value.chars().any(|character| {
        character.is_control()
            || matches!(
                character as u32,
                0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x00AD | 0xFEFF
            )
    })
}

/// Fully admitted registry call. Constructing this value does not grant authority; the caller must
/// already have completed the constitutional capability/taint/approval checks. The boundary owns
/// only the non-negotiable WAL ordering from this point onward.
pub struct AdmittedRegistryTool {
    pub turn: TurnId,
    pub effect_id: EffectId,
    pub intent: ToolIntent,
    pub capability: Capability,
    pub audit_arguments: serde_json::Value,
    pub workspace: String,
}

pub trait DurableEffectLog {
    fn append_effect(&mut self, event: &Event) -> Result<Seq, iteron_record::RecordError>;
}

impl DurableEffectLog for iteron_record::Rollout {
    fn append_effect(&mut self, event: &Event) -> Result<Seq, iteron_record::RecordError> {
        self.append(event)
    }
}

/// The universal effect-boundary descriptor. Registry tool calls are only one *kind* of effect that
/// must cross the single durable WAL boundary; provider requests, hooks, checkpoints, memory writes,
/// and subagents are others. Every one of them fills the same `EffectIntent`, so the boundary owns a
/// single, kind-agnostic ordering rule rather than a registry-only one. Constructing this value
/// grants no authority — the caller must already have completed the constitutional
/// capability/taint/approval checks; from here the boundary owns only the non-negotiable WAL order.
pub struct BrokeredEffect {
    pub turn: TurnId,
    pub effect_id: EffectId,
    /// Provider/model correlation for effects that originate from a model `tool_use` block.
    ///
    /// **Never empty.** An earlier draft of this field allowed empty for harness-internal effects,
    /// which `EffectProposal::validate` (crates/protocol/src/effect.rs) now refuses outright: empty
    /// is reserved for *reading* the first experimental WAL format, where a terminal is correlated
    /// by matching a `ToolResult`'s id against the effect id string. Classes with no model call
    /// behind them carry `crate::effect_class::harness_correlation_id` instead.
    pub tool_use_id: String,
    /// Stable, human-readable effect kind recorded in the intent and any terminal.
    pub kind: String,
    pub capability: Capability,
    pub audit_arguments: serde_json::Value,
    pub workspace: String,
    /// Content-free identity committed before a physical provider request may dispatch. The
    /// proposal gate requires this exactly for `kind == "provider"` and forbids it otherwise.
    pub provider_route_attempt: Option<iteron_protocol::ProviderRouteAttemptIdentity>,
}

impl BrokeredEffect {
    /// The frozen W1 value form of this admission.
    ///
    /// Going through `EffectProposal` rather than writing the six fields straight into the event is
    /// what makes the mint-time gate reachable: `validate` is the only place that knows empty
    /// correlation ids and multi-class admissions cannot be recorded.
    fn proposal(&self) -> EffectProposal {
        EffectProposal::from_event_fields(
            self.effect_id.clone(),
            self.tool_use_id.clone(),
            self.kind.clone(),
            self.capability,
            self.audit_arguments.clone(),
            self.workspace.clone(),
            self.provider_route_attempt.clone(),
        )
    }
}

/// Why the boundary refused, or how the durable log failed, on one dispatch.
///
/// The variants are kept apart because the caller owes them different things: `Record` means the
/// durable log is broken and the run must stop trusting it, while `Admission` and `Proposal` mean
/// the log is perfectly healthy and a *caller* asked for something the boundary will not record.
/// Collapsing them made a duplicate-id bug look like disk failure.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error(transparent)]
    Record(#[from] iteron_record::RecordError),
    #[error(transparent)]
    Admission(#[from] EffectAdmissionError),
    #[error("effect proposal refused before the write-ahead append: {0}")]
    Proposal(&'static str),
}

/// What an executor proves back to the boundary. `Definite` carries the exact durable terminal event
/// to append after a proven outcome; `Unknown` means the executor dispatched the operation but could
/// not observe an authoritative terminal, so the boundary journals `EffectUnknown` and never retries.
// `Definite` carries a whole `EventKind` (~384 bytes) while `Unknown` carries a String (~24), so
// clippy asks for a Box. Not taken: this type sits on the kernel-effects boundary (risk: critical)
// and inside the public-compatibility review overlay, so boxing it is an ABI change, not a lint fix
// — and issue #16 (universal effect broker) rewrites this file with the frozen `EffectProposal`
// contract anyway. Revisit the layout there rather than churning the contract twice.
#[allow(clippy::large_enum_variant)]
pub enum EffectDisposition<T> {
    Definite { terminal: EventKind, value: T },
    Unknown { reason: String, value: T },
}

/// The boundary's report to the caller: the same Definite/Unknown split, carrying the executor value
/// only after its terminal state is durable.
pub enum BrokeredOutcome<T> {
    Definite(T),
    Unknown(T),
}

impl<T> BrokeredOutcome<T> {
    pub fn into_value(self) -> T {
        match self {
            BrokeredOutcome::Definite(value) | BrokeredOutcome::Unknown(value) => value,
        }
    }
}

/// The one and only effect-dispatch sequence, for ANY effect kind: admission, durable intent,
/// exactly one executor invocation, durable terminal.
///
/// The order of the four steps is the whole contract:
///
/// 1. **Admit.** The identity is claimed in `admissions` first, so a repeat never reaches the log
///    and never reaches the executor. At-most-once is enforced *before* any side effect, not
///    reconstructed afterwards by [`EffectJournal`].
/// 2. **Validate.** The proposal crosses the frozen W1 mint-time gate. A proposal that cannot be
///    recorded honestly (empty correlation id, multi-class admission, oversized projection) is
///    refused here rather than written and reasoned about later.
/// 3. **Intend.** The fsynced write-ahead `EffectIntent`. A failed append means the executor is
///    never entered: no effect, no terminal, nothing to recover.
/// 4. **Terminate.** Exactly one of `ToolDone`/`EffectDone` (proven success), `EffectFailed`
///    (proven failure) or `EffectUnknown` (no terminal observable). A failed terminal append leaves
///    one recoverable pending intent rather than a silently lost effect.
///
/// It returns no outcome until the terminal append/fsync succeeds, keeping every downstream
/// projection strictly behind canonical state.
pub async fn broker_effect<L, Execute, ExecuteFuture, T>(
    log: &mut L,
    admissions: &mut EffectAdmissions,
    effect: BrokeredEffect,
    execute: Execute,
) -> Result<BrokeredOutcome<T>, BrokerError>
where
    L: DurableEffectLog,
    Execute: FnOnce() -> ExecuteFuture,
    ExecuteFuture: Future<Output = EffectDisposition<T>>,
{
    let ticket = open_effect(log, admissions, effect)?;
    let (settlement, outcome) = match execute().await {
        EffectDisposition::Definite { terminal, value } => (
            Settlement::Definite(terminal),
            BrokeredOutcome::Definite(value),
        ),
        EffectDisposition::Unknown { reason, value } => {
            (Settlement::Unknown(reason), BrokeredOutcome::Unknown(value))
        }
    };
    settle_effect(log, ticket, settlement)?;
    Ok(outcome)
}

/// An admitted effect whose write-ahead intent is durable and whose terminal is still owed.
///
/// The ticket exists so an executor that needs the whole agent — the provider turn, the verifier
/// poll loop, a subagent — can still cross the same boundary as a closure-shaped one. Both entry
/// points run the identical sequence; [`broker_effect`] is literally `open` + execute + `settle`.
///
/// # What happens if a ticket is dropped
///
/// Nothing unsafe, by construction. A dropped ticket leaves a durable intent with no terminal,
/// which is exactly the state recovery already understands: `EffectJournal::pending` reports it and
/// the run journals `EffectUnknown` for it, never a replay. Forgetting to settle is therefore
/// conservative, not fail-open — the boundary cannot be tricked into forgetting an effect happened.
#[must_use = "an opened effect owes the log a terminal; dropping the ticket makes recovery treat it as unknown"]
pub struct EffectTicket {
    turn: TurnId,
    effect_id: EffectId,
    kind: String,
    provider_route_attempt: Option<iteron_protocol::ProviderRouteAttemptIdentity>,
    /// When the write-ahead intent became durable. The ticket is the only object that already
    /// survives from admission to terminal, which makes it the correct — and only — carrier for a
    /// measurement of the whole admitted lifetime. Holding it here is what lets ONE seam measure
    /// all seven effect classes instead of seven hand-placed timers that would each drift.
    ///
    /// This is the effect boundary, not the reducer: the fold stays pure and still takes every
    /// clock reading as a command field. `Instant` (not `SystemTime`) because a duration must not
    /// be able to go backwards when the operator's wall clock is stepped.
    opened_at: std::time::Instant,
}

impl EffectTicket {
    /// The identity this ticket will settle. Callers that need to name the effect in their own
    /// terminal event (a registry `ToolDone`, say) read it from here rather than re-minting it.
    pub fn effect_id(&self) -> &EffectId {
        &self.effect_id
    }
}

/// Whole milliseconds, rounded UP and saturating.
///
/// Rounding up keeps a real sub-millisecond effect observable instead of indistinguishable from one
/// that never ran, and saturation means observational accounting can never wrap and report a fast
/// effect where a pathologically slow one happened. This mirrors `iteron_obs`'s phase conversion
/// deliberately: two different roundings would make the ledger and the record disagree by a
/// millisecond and cost somebody an afternoon.
fn duration_ms_ceil(duration: std::time::Duration) -> u64 {
    let nanos = duration.as_nanos();
    let millis = nanos.saturating_add(999_999) / 1_000_000;
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// How an opened effect ends.
// `Definite` carries an `EventKind` (~384 bytes) and `Unknown` a `String` (~24), so clippy asks for
// a Box. Not taken: a `Settlement` is constructed immediately before `settle_effect` consumes it and
// never crosses an await or a collection, so the boxing would buy nothing but an allocation on the
// durability path — the one path where an extra failure mode is least welcome.
#[allow(clippy::large_enum_variant)]
pub enum Settlement {
    /// The executor proved a terminal state and supplies the exact durable event.
    Definite(EventKind),
    /// The executor dispatched but could not observe an authoritative terminal.
    Unknown(String),
}

/// Validate the terminal against the exact ticket that authorised dispatch.
///
/// This is intentionally a mint-time rule. Historical JSON remains decodable, while every new
/// provider terminal must carry the same route digest and physical ordinal committed in its
/// pre-dispatch intent. Non-provider terminals cannot smuggle provider accounting onto another
/// effect class.
fn validate_terminal_for_ticket(
    terminal: &EventKind,
    expected_id: &EffectId,
    expected_kind: &str,
    expected_provider_attempt: Option<&iteron_protocol::ProviderRouteAttemptIdentity>,
) -> Result<(), &'static str> {
    let provider_accounting = match terminal {
        EventKind::EffectDone {
            id,
            tool,
            provider_route_attempt,
            ..
        }
        | EventKind::EffectFailed {
            id,
            tool,
            provider_route_attempt,
            ..
        }
        | EventKind::EffectUnknown {
            id,
            tool,
            provider_route_attempt,
            ..
        } => {
            if id != expected_id || tool != expected_kind {
                return Err("effect terminal identity does not match its durable intent ticket");
            }
            provider_route_attempt.as_ref()
        }
        EventKind::ToolDone {
            effect_id, tool, ..
        } => {
            if effect_id.as_ref() != Some(expected_id) || tool.as_deref() != Some(expected_kind) {
                return Err("tool terminal identity does not match its durable intent ticket");
            }
            None
        }
        _ => return Err("an effect ticket can only settle with an effect terminal"),
    };

    match (expected_provider_attempt, provider_accounting) {
        (Some(expected), Some(accounting)) if accounting.identity() == *expected => Ok(()),
        (Some(_), Some(_)) => {
            Err("provider terminal route identity does not match its pre-dispatch intent")
        }
        (Some(_), None) => Err("provider terminal omits its pre-dispatch route identity"),
        (None, Some(_)) => Err("non-provider terminal carries provider route accounting"),
        (None, None) => Ok(()),
    }
}

/// Phase one of the one and only dispatch sequence: admit the identity, validate the proposal,
/// fsync the write-ahead intent. The executor has NOT run when this returns.
pub fn open_effect<L>(
    log: &mut L,
    admissions: &mut EffectAdmissions,
    effect: BrokeredEffect,
) -> Result<EffectTicket, BrokerError>
where
    L: DurableEffectLog,
{
    // Admission and validation both happen before a single byte is appended, so neither can leave
    // a half-admitted effect on disk.
    admissions.admit(effect.turn, &effect.effect_id)?;
    effect
        .proposal()
        .validate()
        .map_err(BrokerError::Proposal)?;

    let BrokeredEffect {
        turn,
        effect_id,
        tool_use_id,
        kind,
        capability,
        audit_arguments,
        workspace,
        provider_route_attempt,
    } = effect;
    log.append_effect(&Event {
        seq: Seq::ZERO,
        turn,
        kind: EventKind::EffectIntent {
            id: effect_id.clone(),
            tool_use_id,
            tool: kind.clone(),
            capability,
            arguments: audit_arguments,
            workspace,
            provider_route_attempt: provider_route_attempt.clone(),
        },
    })?;
    Ok(EffectTicket {
        turn,
        effect_id,
        kind,
        provider_route_attempt,
        // Started AFTER the intent is durable, so the measurement covers the executor and not the
        // fsync that authorised it. A reader comparing effects across runs must not see one class
        // absorb the log's write latency because its intent happened to be larger.
        opened_at: std::time::Instant::now(),
    })
}

/// Phase two: append exactly one terminal for an opened effect. Consuming the ticket is what makes
/// "exactly one terminal" a type-level property rather than a review comment.
pub fn settle_effect<L>(
    log: &mut L,
    ticket: EffectTicket,
    settlement: Settlement,
) -> Result<(), BrokerError>
where
    L: DurableEffectLog,
{
    let EffectTicket {
        turn,
        effect_id,
        kind,
        provider_route_attempt,
        opened_at,
    } = ticket;
    let expected_id = effect_id.clone();
    let expected_kind = kind.clone();
    let elapsed_ms = duration_ms_ceil(opened_at.elapsed());
    let terminal = match settlement {
        // The executor supplies the terminal; the BOUNDARY supplies the measurement. Stamping it
        // here rather than at the nine dispatch sites is the whole point: one seam, seven classes,
        // one definition of "how long did it take". A caller that already measured is honoured —
        // `Some` is never overwritten — so a future executor with a better number (a provider that
        // can report server-side time, say) can still supply it.
        Settlement::Definite(EventKind::EffectDone {
            id,
            tool,
            duration_ms,
            provider_route_attempt,
        }) => EventKind::EffectDone {
            id,
            tool,
            duration_ms: duration_ms.or(Some(elapsed_ms)),
            provider_route_attempt,
        },
        Settlement::Definite(EventKind::EffectFailed {
            id,
            tool,
            reason,
            duration_ms,
            provider_route_attempt,
        }) => EventKind::EffectFailed {
            id,
            tool,
            reason,
            duration_ms: duration_ms.or(Some(elapsed_ms)),
            provider_route_attempt,
        },
        // A registry tool settles as `ToolDone`, whose `ToolResult` already carries `latency_ms`
        // measured at the registry. Stamping a second, differently-scoped number onto it would put
        // two disagreeing durations for one effect into the record, so this arm deliberately does
        // nothing. Every other `Definite` terminal is likewise passed through untouched.
        Settlement::Definite(terminal) => terminal,
        // No terminal was observed, so there is no honest duration to report. An `EffectUnknown`
        // that carried a number would be claiming knowledge the boundary just said it lacks.
        Settlement::Unknown(reason) => EventKind::EffectUnknown {
            id: effect_id,
            tool: kind,
            reason,
            provider_route_attempt: provider_route_attempt
                .clone()
                .map(iteron_protocol::ProviderRouteAttemptAccounting::outcome_unobservable),
        },
    };
    validate_terminal_for_ticket(
        &terminal,
        &expected_id,
        &expected_kind,
        provider_route_attempt.as_ref(),
    )
    .map_err(BrokerError::Proposal)?;
    log.append_effect(&Event {
        seq: Seq::ZERO,
        turn,
        kind: terminal,
    })?;
    Ok(())
}

/// The registry-effect dispatch sequence, expressed as one instance of the universal
/// [`broker_effect`] boundary: durable intent, exactly one executor invocation, durable terminal. It
/// returns no result until the terminal append/fsync succeeds, keeping every UI/transcript/ledger
/// projection downstream of canonical state. Sharing `broker_effect` is what keeps registry tools
/// and every other brokered effect on a single, non-diverging WAL ordering.
pub async fn execute_registry_tool<L, Execute, ExecuteFuture, Execution>(
    log: &mut L,
    admissions: &mut EffectAdmissions,
    admitted: AdmittedRegistryTool,
    execute: Execute,
) -> Result<ToolExecution, BrokerError>
where
    L: DurableEffectLog,
    Execute: FnOnce(ToolIntent) -> ExecuteFuture,
    ExecuteFuture: Future<Output = Execution>,
    Execution: Into<ToolExecution>,
{
    let AdmittedRegistryTool {
        turn,
        effect_id,
        intent,
        capability,
        audit_arguments,
        workspace,
    } = admitted;
    let provider_tool_use_id = intent.call.id.clone();
    // Carried into the terminal because the completion has to name its own tool (I-42): `effect`
    // is moved into the boundary and `intent` into the executor, so neither is readable there.
    let terminal_tool = intent.call.name.clone();
    let terminal_effect_id = effect_id.clone();
    let effect = BrokeredEffect {
        turn,
        effect_id,
        tool_use_id: provider_tool_use_id.clone(),
        kind: intent.call.name.clone(),
        capability,
        audit_arguments,
        workspace,
        provider_route_attempt: None,
    };
    let outcome = broker_effect(log, admissions, effect, move || async move {
        let mut outcome: ToolExecution = execute(intent).await.into();
        // Correlation identity belongs to the admitted call, never to plugin-returned data. Registry
        // already enforces this; repeating it here protects every executor behind the same boundary.
        {
            let result = match &mut outcome {
                ToolExecution::Definite(result) | ToolExecution::Unknown(result) => result,
            };
            result.tool_use_id = provider_tool_use_id;
        }
        match outcome {
            ToolExecution::Definite(result) => EffectDisposition::Definite {
                terminal: EventKind::ToolDone {
                    result: result.clone(),
                    effect_id: Some(terminal_effect_id),
                    tool: Some(terminal_tool),
                },
                value: ToolExecution::Definite(result),
            },
            ToolExecution::Unknown(result) => EffectDisposition::Unknown {
                reason: "executor dispatched the operation but did not observe an authoritative terminal outcome; automatic retry is forbidden".into(),
                value: ToolExecution::Unknown(result),
            },
        }
    })
    .await?;
    Ok(outcome.into_value())
}

/// The replay fold lives in its own module; it is re-exported here so every existing
/// `effects::EffectJournal` path keeps resolving.
pub use crate::effect_journal::{EffectJournal, EffectJournalError, PendingEffect};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect_class::{EffectClass, effect_id};
    use iteron_protocol::{Capability, Seq, ToolResult, Trust};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn intent(turn: u32, id: &str, tool_use_id: &str) -> Event {
        Event {
            seq: Seq::ZERO,
            turn: TurnId(turn),
            kind: EventKind::EffectIntent {
                id: EffectId(id.into()),
                tool_use_id: tool_use_id.into(),
                tool: "edit".into(),
                capability: Capability::ReversibleLocal,
                arguments: serde_json::json!({"path":"f"}),
                workspace: "/repo".into(),
                provider_route_attempt: None,
            },
        }
    }

    fn done(turn: u32, id: Option<&str>, tool_use_id: &str) -> Event {
        Event {
            seq: Seq::ZERO,
            turn: TurnId(turn),
            kind: EventKind::ToolDone {
                result: ToolResult {
                    tool_use_id: tool_use_id.into(),
                    content: "ok".into(),
                    is_error: false,
                    trust: Trust::Workspace,
                    latency_ms: 1,
                },
                effect_id: id.map(|value| EffectId(value.into())),
                tool: Some("edit".into()),
            },
        }
    }

    /// #74: a provider-minted tool-call id is high-entropy by construction, and the generic
    /// entropy rule masks any 32+ character mixed-case-with-digit run. Admission refused every
    /// such call, so tool use was unusable on any provider minting ids of this shape while an
    /// otherwise identical call with a shorter id succeeded.
    fn artifact(hash_seed: u8) -> iteron_protocol::artifact::ArtifactRef {
        use iteron_protocol::artifact::{ArtifactRef, ArtifactSchema, Producer, Provenance};
        ArtifactRef {
            hash: format!("{:064x}", hash_seed),
            schema: ArtifactSchema::FileDiff,
            producer: Producer::Tool {
                tool: "edit".into(),
            },
            provenance: Provenance {
                run_id: iteron_protocol::RunId("run-1".into()),
                parent_hashes: Vec::new(),
                effect_id: None,
            },
            // Read is deny-by-default: an artifact requiring no capability would be readable
            // by anyone, and `validate` refuses it.
            permissions: iteron_protocol::capability_set::CapabilitySet::only(Capability::ReadOnly),
            locator: "reports/summary.md".into(),
        }
    }

    /// The event may only follow the write. A handle to content that is not there yet is a promise.
    #[test]
    fn an_artifact_declared_before_its_content_is_durable_is_refused() {
        let mut admission = ArtifactAdmission::default();
        assert_eq!(
            admission.admit(&artifact(1), |_| false),
            Err(ArtifactContractError::ContentNotDurable)
        );
        assert_eq!(admission.admitted(), 0);
        assert_eq!(admission.refused(), 1, "a refusal is counted, not dropped");

        assert_eq!(admission.admit(&artifact(1), |_| true), Ok(()));
        assert_eq!(admission.admitted(), 1);
    }

    /// Exactly one event per product: the same hash twice is a duplicate, and it is counted.
    #[test]
    fn the_same_artifact_cannot_be_declared_twice() {
        let mut admission = ArtifactAdmission::default();
        assert_eq!(admission.admit(&artifact(7), |_| true), Ok(()));
        assert_eq!(
            admission.admit(&artifact(7), |_| true),
            Err(ArtifactContractError::Duplicate)
        );
        assert_eq!(admission.admitted(), 1);
        assert_eq!(admission.refused(), 1);
    }

    /// A product stream that quietly stops is indistinguishable from a run that stopped producing.
    #[test]
    fn exceeding_the_per_run_ceiling_is_counted_and_reported() {
        let mut admission = ArtifactAdmission::default();
        for index in 0..MAX_ARTIFACTS_PER_RUN {
            let mut ref_ = artifact(1);
            ref_.hash = format!("{index:064x}");
            assert_eq!(admission.admit(&ref_, |_| true), Ok(()));
        }
        let mut overflow = artifact(1);
        overflow.hash = format!("{:064x}", MAX_ARTIFACTS_PER_RUN + 1);
        assert_eq!(
            admission.admit(&overflow, |_| true),
            Err(ArtifactContractError::TooMany)
        );
        assert_eq!(admission.admitted(), MAX_ARTIFACTS_PER_RUN);
        assert_eq!(admission.refused(), 1);
    }

    /// A malformed handle never reaches the record.
    #[test]
    fn an_inadmissible_ref_is_refused_before_the_bound_is_touched() {
        let mut admission = ArtifactAdmission::default();
        let mut bad = artifact(1);
        bad.hash = "not-a-content-hash".into();
        assert!(matches!(
            admission.admit(&bad, |_| true),
            Err(ArtifactContractError::Invalid(_))
        ));
        assert_eq!(admission.admitted(), 0);
    }

    #[test]
    fn admission_accepts_provider_minted_correlation_ids() {
        for id in [
            "call_00_RFTSn3Qcw4Wu9i4Z276c9895",
            "chatcmpl-tool-abc123DEF456ghi789",
            "call_1",
        ] {
            let call = ToolUse {
                id: id.into(),
                name: "edit".into(),
                input: serde_json::json!({"path": "f"}),
            };
            assert_eq!(
                ToolCallAdmission::default().admit(&call),
                Ok(()),
                "provider correlation id `{id}` must be admitted"
            );
        }
    }

    #[test]
    fn admission_rejects_duplicates_secrets_bidi_and_unbounded_arguments() {
        let mut admission = ToolCallAdmission::default();
        let base = ToolUse {
            id: "call-1".into(),
            name: "edit".into(),
            input: serde_json::json!({"path":"f"}),
        };
        admission.admit(&base).unwrap();
        assert_eq!(
            admission.admit(&base),
            Err(ToolCallContractError::DuplicateId)
        );
        let mut secret = base.clone();
        secret.id = "sk-\
proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
            .into();
        assert_eq!(
            ToolCallAdmission::default().admit(&secret),
            Err(ToolCallContractError::SecretShapedIdentity)
        );
        let mut bidi = base.clone();
        bidi.id = "call-\u{202e}1".into();
        assert_eq!(
            ToolCallAdmission::default().admit(&bidi),
            Err(ToolCallContractError::UnsafeIdentity)
        );
        let mut huge = base;
        huge.input = serde_json::Value::String("x".repeat(MAX_TOOL_ARGUMENT_BYTES + 1));
        assert_eq!(
            ToolCallAdmission::default().admit(&huge),
            Err(ToolCallContractError::ArgumentsTooLarge)
        );
    }

    #[test]
    fn modern_terminal_correlates_by_harness_id_not_model_id() {
        let events = vec![
            intent(2, "fx1-00000002-0001", "model-id"),
            done(
                2,
                Some("fx1-00000002-0001"),
                "executor-returned-a-different-id",
            ),
        ];
        let journal = EffectJournal::replay(&events).unwrap();
        assert!(journal.pending().is_empty());
        assert_eq!(journal.unknown_count(), 0);
    }

    #[test]
    fn legacy_intent_still_correlates_with_tool_done() {
        let events = vec![
            intent(3, "legacy-tool-id", ""),
            done(3, None, "legacy-tool-id"),
        ];
        assert!(EffectJournal::replay(&events).unwrap().pending().is_empty());
    }

    #[test]
    fn duplicates_and_unauthenticated_unknown_resolution_fail_closed() {
        let i = intent(1, "fx1-00000001-0000", "call");
        assert_eq!(
            EffectJournal::replay(&[i.clone(), i.clone()]).unwrap_err(),
            EffectJournalError::DuplicateIntent
        );
        let unknown = Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::EffectUnknown {
                id: EffectId("fx1-00000001-0000".into()),
                tool: "edit".into(),
                reason: "crash window".into(),
                provider_route_attempt: None,
            },
        };
        assert_eq!(
            EffectJournal::replay(&[i, unknown, done(1, Some("fx1-00000001-0000"), "call"),])
                .unwrap_err(),
            EffectJournalError::TerminalAfterUnknown
        );
    }

    #[derive(Default)]
    struct FakeLog {
        events: Vec<Event>,
        fail_on_append: Option<usize>,
    }

    impl DurableEffectLog for FakeLog {
        fn append_effect(&mut self, event: &Event) -> Result<Seq, iteron_record::RecordError> {
            if self.fail_on_append == Some(self.events.len()) {
                return Err(std::io::Error::other("injected append failure").into());
            }
            self.events.push(event.clone());
            Ok(Seq((self.events.len() - 1) as u64))
        }
    }

    fn admitted() -> AdmittedRegistryTool {
        let mut intent = ToolIntent::denied(
            iteron_protocol::slot::SlotId("core/tool_policy".into()),
            ToolUse {
                id: "provider-call".into(),
                name: "edit".into(),
                input: serde_json::json!({"path":"f"}),
            },
            iteron_protocol::Purity::Effecting,
            Trust::Workspace,
        );
        intent.admitted =
            iteron_protocol::capability_set::CapabilitySet::only(Capability::ReversibleLocal);
        AdmittedRegistryTool {
            turn: TurnId(7),
            effect_id: effect_id(TurnId(7), EffectClass::RegistryTool, 2),
            intent,
            capability: Capability::ReversibleLocal,
            audit_arguments: serde_json::json!({"path":"f"}),
            workspace: "/repo".into(),
        }
    }

    #[tokio::test]
    async fn boundary_never_executes_before_a_durable_intent() {
        let mut log = FakeLog {
            fail_on_append: Some(0),
            ..FakeLog::default()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();
        let result = execute_registry_tool(
            &mut log,
            &mut EffectAdmissions::default(),
            admitted(),
            move |call| async move {
                executor_calls.fetch_add(1, Ordering::SeqCst);
                ToolResult {
                    tool_use_id: call.call.id,
                    content: "ran".into(),
                    is_error: false,
                    trust: Trust::Workspace,
                    latency_ms: 0,
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(log.events.is_empty());
    }

    #[tokio::test]
    async fn terminal_failure_leaves_one_recoverable_pending_intent() {
        let mut log = FakeLog {
            fail_on_append: Some(1),
            ..FakeLog::default()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();
        let result = execute_registry_tool(
            &mut log,
            &mut EffectAdmissions::default(),
            admitted(),
            move |call| async move {
                executor_calls.fetch_add(1, Ordering::SeqCst);
                ToolResult {
                    // A plugin cannot replace the admitted provider correlation id.
                    tool_use_id: "wrong-id".into(),
                    content: format!("ran {}", call.call.name),
                    is_error: false,
                    trust: Trust::Workspace,
                    latency_ms: 0,
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let journal = EffectJournal::replay(&log.events).unwrap();
        assert_eq!(journal.pending().len(), 1);
    }

    #[tokio::test]
    async fn successful_boundary_is_intent_then_terminal_and_normalizes_result_id() {
        let mut log = FakeLog::default();
        let result = execute_registry_tool(
            &mut log,
            &mut EffectAdmissions::default(),
            admitted(),
            |_| async {
                ToolResult {
                    tool_use_id: "plugin-controlled".into(),
                    content: "ok".into(),
                    is_error: false,
                    trust: Trust::Workspace,
                    latency_ms: 0,
                }
            },
        )
        .await
        .unwrap()
        .into_result();
        assert_eq!(result.tool_use_id, "provider-call");
        assert!(matches!(log.events[0].kind, EventKind::EffectIntent { .. }));
        assert!(matches!(
            log.events[1].kind,
            EventKind::ToolDone {
                effect_id: Some(_),
                ..
            }
        ));
        assert!(
            EffectJournal::replay(&log.events)
                .unwrap()
                .pending()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn runtime_unknown_is_durable_and_never_fabricates_tool_done() {
        let mut log = FakeLog::default();
        let outcome = execute_registry_tool(
            &mut log,
            &mut EffectAdmissions::default(),
            admitted(),
            |_| async {
                ToolExecution::Unknown(ToolResult {
                    tool_use_id: "plugin-controlled".into(),
                    content: "remote state unknown".into(),
                    is_error: true,
                    trust: Trust::Untrusted,
                    latency_ms: 0,
                })
            },
        )
        .await
        .unwrap();
        assert!(matches!(outcome, ToolExecution::Unknown(_)));
        assert!(matches!(log.events[0].kind, EventKind::EffectIntent { .. }));
        assert!(matches!(
            log.events[1].kind,
            EventKind::EffectUnknown { .. }
        ));
        assert!(
            !log.events
                .iter()
                .any(|event| matches!(event.kind, EventKind::ToolDone { .. }))
        );
        let journal = EffectJournal::replay(&log.events).unwrap();
        assert_eq!(journal.unknown_count(), 1);
        assert!(journal.pending().is_empty());
    }

    // ===================================================================
    // D1-08 — the effect broker must be UNIVERSAL, not registry-only.
    //
    // These drive the same single durable WAL boundary through the public
    // `broker_effect` entry for effects that are NOT registry tools: a
    // harness-internal "memory_write" with no provider tool_use_id at all,
    // and a "provider_request". They assert every ordering invariant the
    // boundary owns — intent fsynced before execution, exactly one terminal,
    // correlation by the harness-minted effect id even with no model id,
    // and `EffectUnknown` as the fail-closed fallback — so the boundary is
    // provably kind-agnostic rather than welded to `AdmittedRegistryTool`.
    // ===================================================================

    fn d1_08_memory_write_effect() -> (EffectId, BrokeredEffect) {
        let id = effect_id(TurnId(11), EffectClass::Checkpoint, 0);
        (
            id.clone(),
            BrokeredEffect {
                turn: TurnId(11),
                effect_id: id,
                // A harness-internal effect has no provider tool_use_id, but it may not leave the
                // field empty: empty is reserved for reading the first experimental WAL format, and
                // a NEW record written that way becomes completable by a model-chosen tool id. It
                // carries a harness-scoped correlation id instead.
                tool_use_id: crate::effect_class::harness_correlation_id(
                    TurnId(11),
                    EffectClass::Checkpoint,
                    0,
                ),
                kind: "memory_write".into(),
                capability: Capability::ReversibleLocal,
                audit_arguments: serde_json::json!({"key":"profile","bytes":42}),
                workspace: "/repo".into(),
                provider_route_attempt: None,
            },
        )
    }

    fn d1_08_generic_terminal(id: &EffectId) -> EventKind {
        EventKind::ToolDone {
            result: ToolResult {
                tool_use_id: String::new(),
                content: "committed".into(),
                is_error: false,
                trust: Trust::Workspace,
                latency_ms: 3,
            },
            effect_id: Some(id.clone()),
            tool: Some("memory_write".into()),
        }
    }

    #[tokio::test]
    async fn d1_08_universal_broker_records_intent_then_terminal_for_a_non_registry_effect() {
        let mut log = FakeLog::default();
        let (id, effect) = d1_08_memory_write_effect();
        let terminal_id = id.clone();

        let outcome: BrokeredOutcome<&'static str> = broker_effect(
            &mut log,
            &mut EffectAdmissions::default(),
            effect,
            move || async move {
                EffectDisposition::Definite {
                    terminal: d1_08_generic_terminal(&terminal_id),
                    value: "memory-committed",
                }
            },
        )
        .await
        .expect("a brokered non-registry effect must record cleanly");

        // The executor value is handed back only once its terminal is durable.
        match outcome {
            BrokeredOutcome::Definite(value) => assert_eq!(value, "memory-committed"),
            BrokeredOutcome::Unknown(_) => panic!("a proven effect must not be reported unknown"),
        }

        // Exactly intent-then-terminal, in that order.
        assert_eq!(log.events.len(), 2);
        match &log.events[0].kind {
            EventKind::EffectIntent {
                tool,
                tool_use_id,
                capability,
                ..
            } => {
                assert_eq!(tool, "memory_write");
                assert!(
                    crate::effect_class::is_harness_correlation_id(tool_use_id),
                    "a harness-internal effect carries a harness-scoped correlation id, never an \
                     empty one and never a model-controlled one"
                );
                assert_eq!(*capability, Capability::ReversibleLocal);
            }
            other => panic!("first durable event must be the intent, got {other:?}"),
        }
        assert!(matches!(
            log.events[1].kind,
            EventKind::ToolDone {
                effect_id: Some(_),
                ..
            }
        ));

        // The journal — a pure fold of the same durable events — sees a completed, non-pending
        // effect, correlated purely by the harness-minted id (there was no provider tool_use_id).
        let journal = EffectJournal::replay(&log.events).unwrap();
        assert!(journal.pending().is_empty());
        assert_eq!(journal.unknown_count(), 0);
        // Namespaced by class, so this identity can never collide with the turn's first registry
        // tool call (`fx1-0000000b-0000`) the way a bare ordinal would.
        assert_eq!(id.0, "fx1-0000000b-cp-0000");
    }

    #[tokio::test]
    async fn d1_08_universal_broker_never_executes_before_a_durable_intent() {
        // The intent append itself fails, so a NON-registry effect must never touch the world.
        let mut log = FakeLog {
            fail_on_append: Some(0),
            ..FakeLog::default()
        };
        let (_id, effect) = d1_08_memory_write_effect();
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();

        let result: Result<BrokeredOutcome<()>, BrokerError> = broker_effect(
            &mut log,
            &mut EffectAdmissions::default(),
            effect,
            move || async move {
                executor_calls.fetch_add(1, Ordering::SeqCst);
                EffectDisposition::Definite {
                    terminal: EventKind::Notice {
                        text: "must never be reached".into(),
                    },
                    value: (),
                }
            },
        )
        .await;

        assert!(
            result.is_err(),
            "a failed intent append must fail the effect"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the executor must not run before a durable intent"
        );
        assert!(log.events.is_empty());
    }

    #[tokio::test]
    async fn d1_08_universal_broker_journals_unknown_and_never_fabricates_a_terminal() {
        let mut log = FakeLog::default();
        // A provider request dispatched but whose remote outcome we cannot prove.
        let effect = BrokeredEffect {
            turn: TurnId(4),
            effect_id: effect_id(TurnId(4), EffectClass::RegistryTool, 1),
            tool_use_id: "prov-req-1".into(),
            kind: "provider_request".into(),
            capability: Capability::IrreversibleExternal,
            audit_arguments: serde_json::json!({"endpoint":"/v1/messages"}),
            workspace: "/repo".into(),
            provider_route_attempt: None,
        };

        let outcome: BrokeredOutcome<u8> = broker_effect(
            &mut log,
            &mut EffectAdmissions::default(),
            effect,
            move || async move {
                EffectDisposition::Unknown {
                    reason: "dispatched but no authoritative terminal observed".into(),
                    value: 7,
                }
            },
        )
        .await
        .expect("recording an unknown is itself durable");

        match outcome {
            BrokeredOutcome::Unknown(value) => assert_eq!(value, 7),
            BrokeredOutcome::Definite(_) => panic!("an unprovable effect must not report definite"),
        }

        assert!(matches!(log.events[0].kind, EventKind::EffectIntent { .. }));
        assert!(matches!(
            log.events[1].kind,
            EventKind::EffectUnknown { .. }
        ));
        assert!(
            !log.events
                .iter()
                .any(|event| matches!(event.kind, EventKind::ToolDone { .. })),
            "an unknown outcome must never fabricate a ToolDone terminal"
        );

        let journal = EffectJournal::replay(&log.events).unwrap();
        assert_eq!(journal.unknown_count(), 1);
        assert!(journal.pending().is_empty());
    }

    #[tokio::test]
    async fn d1_08_universal_broker_terminal_failure_leaves_one_recoverable_pending_intent() {
        // Intent append (index 0) succeeds; the terminal append (index 1) fails.
        let mut log = FakeLog {
            fail_on_append: Some(1),
            ..FakeLog::default()
        };
        let (id, effect) = d1_08_memory_write_effect();
        let terminal_id = id.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();

        let result: Result<BrokeredOutcome<()>, BrokerError> = broker_effect(
            &mut log,
            &mut EffectAdmissions::default(),
            effect,
            move || async move {
                executor_calls.fetch_add(1, Ordering::SeqCst);
                EffectDisposition::Definite {
                    terminal: d1_08_generic_terminal(&terminal_id),
                    value: (),
                }
            },
        )
        .await;

        assert!(
            result.is_err(),
            "a failed terminal append must surface as an error"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the effect ran exactly once"
        );

        // The durable log holds only the intent; replay reports one recoverable pending effect.
        let journal = EffectJournal::replay(&log.events).unwrap();
        let pending = journal.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].tool, "memory_write");
        assert_eq!(journal.unknown_count(), 0);
    }
}
