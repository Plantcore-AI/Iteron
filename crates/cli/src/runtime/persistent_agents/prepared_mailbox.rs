//! Host-rendered mailbox receipts meet the actual immutable native request. Semantic transcript
//! selection alone never consumes an input; the complete native user text must match its digest.
use super::{
    AgentMailboxMessage, AgentMessageIdV1, ControllerError, LiveAgentMailbox, MAX_INPUT_BATCH,
};
use iteron_protocol::{Block, Role};
use iteron_provider::AdapterKind;
use iteron_provider::request_capture::{ProviderWireRequest, RequestCaptureError};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_FIELDS: usize = 4096;
const MAX_PROJECTIONS: usize = MAX_INPUT_BATCH * 3;
type TextDigest = [u8; 32];

#[derive(Default)]
pub(super) struct MailboxWitnesses {
    pub(super) envelopes: BTreeMap<AgentMessageIdV1, String>,
    projections: BTreeMap<TextDigest, BTreeSet<AgentMessageIdV1>>,
    agent_sources: BTreeSet<AgentMessageIdV1>,
    admitted_agent_sources: BTreeSet<AgentMessageIdV1>,
}
impl MailboxWitnesses {
    pub(super) fn register_envelope(
        &mut self,
        id: AgentMessageIdV1,
        envelope: String,
        agent_authored: bool,
    ) -> Result<(), ControllerError> {
        if self.envelopes.len() >= MAX_INPUT_BATCH && !self.envelopes.contains_key(&id) {
            return Err(ControllerError::Capacity);
        }
        self.register(&[id], &envelope)?;
        self.envelopes.insert(id, envelope);
        if agent_authored {
            self.agent_sources.insert(id);
        }
        Ok(())
    }
    pub(super) fn register(
        &mut self,
        ids: &[AgentMessageIdV1],
        text: &str,
    ) -> Result<(), ControllerError> {
        let digest = digest(text);
        if text.len() > MAX_BODY_BYTES
            || ids.len() > MAX_INPUT_BATCH
            || (self.projections.len() >= MAX_PROJECTIONS
                && !self.projections.contains_key(&digest))
        {
            return Err(ControllerError::Capacity);
        }
        self.projections.entry(digest).or_default().extend(ids);
        Ok(())
    }
    pub(super) fn has_projection(&self, ids: &[AgentMessageIdV1], text: &str) -> bool {
        self.projections.get(&digest(text)).is_some_and(|bound| {
            ids.iter()
                .all(|id| bound.contains(id) && self.envelopes.contains_key(id))
        })
    }
    pub(super) fn admit_source_projection(
        &mut self,
        ids: &[AgentMessageIdV1],
        projection_sha256: &str,
    ) -> Result<(), ControllerError> {
        let bound = self.projections.iter().find_map(|(hash, bound)| {
            (hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                == projection_sha256)
                .then_some(bound)
        });
        if !bound.is_some_and(|bound| {
            ids.iter().all(|id| {
                bound.contains(id)
                    && self.envelopes.contains_key(id)
                    && self.agent_sources.contains(id)
            })
        }) {
            return Err(ControllerError::Invalid(
                "agent source admission is not bound to its host projection",
            ));
        }
        self.admitted_agent_sources.extend(ids);
        Ok(())
    }
    fn remove(&mut self, ids: &[AgentMessageIdV1]) {
        for id in ids {
            self.envelopes.remove(id);
            self.agent_sources.remove(id);
            self.admitted_agent_sources.remove(id);
            for projection in self.projections.values_mut() {
                projection.remove(id);
            }
        }
        self.projections.retain(|_, ids| !ids.is_empty());
    }
}

/// Opaque same-mailbox proof, minted only from the native typed request bytes. It is not a wire
/// DTO and cannot be populated by model/client JSON, body prefixes or a public message label.
pub(in crate::runtime) struct PreparedMailboxDelivery {
    ids: Vec<AgentMessageIdV1>,
    owner: Arc<Mutex<MailboxWitnesses>>,
}

/// Shared with the actual safe-point producer so wrapper changes cannot silently invent a proof.
pub(in crate::runtime) fn steer_text(text: &str) -> String {
    format!("Operator steering received while the run was active:\n{text}")
}

impl LiveAgentMailbox {
    pub(in crate::runtime) fn render_initial(
        &self,
        inputs: &[AgentMailboxMessage],
    ) -> Result<String, ControllerError> {
        if inputs.len() > MAX_INPUT_BATCH {
            return Err(ControllerError::Capacity);
        }
        let texts = inputs
            .iter()
            .map(|input| self.render(input))
            .collect::<Result<Vec<_>, _>>()?;
        let total = texts.iter().try_fold(0usize, |total, text| {
            total.checked_add(text.len()).and_then(|n| n.checked_add(2))
        });
        if total.is_none_or(|bytes| bytes > MAX_BODY_BYTES) {
            return Err(ControllerError::Capacity);
        }
        let text = texts.join("\n\n");
        self.witnesses
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .register(
                &inputs.iter().map(|input| input.id).collect::<Vec<_>>(),
                &text,
            )?;
        Ok(text)
    }

    pub(in crate::runtime) fn render_steer(
        &self,
        input: &AgentMailboxMessage,
    ) -> Result<String, ControllerError> {
        let text = self.render(input)?;
        self.witnesses
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .register(&[input.id], &steer_text(&text))?;
        Ok(text)
    }

    pub(in crate::runtime) fn prepared_delivery(
        &self,
        wire: &ProviderWireRequest<'_>,
    ) -> Result<PreparedMailboxDelivery, RequestCaptureError> {
        let witnesses = self
            .witnesses
            .lock()
            .map_err(|_| RequestCaptureError::ReconciliationNeeded)?;
        if witnesses.envelopes.is_empty() {
            return Ok(PreparedMailboxDelivery {
                ids: Vec::new(),
                owner: self.witnesses.clone(),
            });
        }
        let ids = native_included(wire, &witnesses.projections)?;
        if ids.iter().any(|id| {
            witnesses.agent_sources.contains(id) && !witnesses.admitted_agent_sources.contains(id)
        }) {
            return Err(RequestCaptureError::Unavailable);
        }
        Ok(PreparedMailboxDelivery {
            ids,
            owner: self.witnesses.clone(),
        })
    }

    /// Called only after retained prepared-manifest publication, before local dispatch intent
    /// and actual transport. A failed/uncertain controller barrier stops provider IO.
    pub(in crate::runtime) fn confirm_prepared(
        &self,
        proof: PreparedMailboxDelivery,
    ) -> Result<(), ControllerError> {
        if !Arc::ptr_eq(&proof.owner, &self.witnesses) {
            return Err(ControllerError::Permission);
        }
        let mut witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let pending: Vec<_> = proof
            .ids
            .into_iter()
            .filter(|id| witnesses.envelopes.contains_key(id))
            .collect();
        if !pending.is_empty() {
            // Concurrent hedge callbacks share this lock and the same durable mailbox owner.
            self.port.consumed(self.id, self.epoch, &pending)?;
            witnesses.remove(&pending);
        }
        Ok(())
    }

    pub(in crate::runtime) fn refuse_unsupported_pending(&self) -> Result<(), RequestCaptureError> {
        if self
            .witnesses
            .lock()
            .map_err(|_| RequestCaptureError::ReconciliationNeeded)?
            .envelopes
            .is_empty()
        {
            Ok(())
        } else {
            Err(RequestCaptureError::Unavailable)
        }
    }
}

fn digest(text: &str) -> TextDigest {
    Sha256::digest(text.as_bytes()).into()
}

fn native_included(
    wire: &ProviderWireRequest<'_>,
    projections: &BTreeMap<TextDigest, BTreeSet<AgentMessageIdV1>>,
) -> Result<Vec<AgentMessageIdV1>, RequestCaptureError> {
    if wire.body.len() > MAX_BODY_BYTES || wire.request.messages.len() > MAX_FIELDS {
        return Err(RequestCaptureError::Bounds);
    }
    // Expected fields are full host-rendered text commitments. Chat's adapter concatenates all
    // Text blocks in each user message; Anthropic/Responses retain each individual text block.
    let mut expected: BTreeMap<TextDigest, BTreeSet<AgentMessageIdV1>> = BTreeMap::new();
    let mut fields = 0usize;
    let mut bytes = 0usize;
    for message in &wire.request.messages {
        if message.role != Role::User {
            continue;
        }
        let mut joined = String::new();
        let mut joined_ids = BTreeSet::new();
        for block in &message.content {
            fields = fields.checked_add(1).ok_or(RequestCaptureError::Bounds)?;
            if fields > MAX_FIELDS {
                return Err(RequestCaptureError::Bounds);
            }
            let Block::Text { text } = block else {
                continue;
            };
            bytes = bytes
                .checked_add(text.len())
                .ok_or(RequestCaptureError::Bounds)?;
            if bytes > MAX_BODY_BYTES {
                return Err(RequestCaptureError::Bounds);
            }
            let ids = projections.get(&digest(text));
            match wire.adapter {
                AdapterKind::OpenAiCompatibleChat => {
                    joined.push_str(text);
                    if let Some(ids) = ids {
                        joined_ids.extend(ids);
                    }
                }
                AdapterKind::AnthropicMessages | AdapterKind::OpenAiResponses => {
                    if let Some(ids) = ids {
                        expected.entry(digest(text)).or_default().extend(ids);
                    }
                }
            }
        }
        if !joined_ids.is_empty() {
            expected
                .entry(digest(&joined))
                .or_default()
                .extend(joined_ids);
        }
    }
    if expected.is_empty() {
        // This auxiliary/current request selected no host mailbox publication. Newly delivered
        // inputs may still be waiting for their defined safe point; they are not consumed here.
        return Ok(Vec::new());
    }
    let body: Value =
        serde_json::from_slice(wire.body).map_err(|_| RequestCaptureError::Unavailable)?;
    let native = native_user_fields(wire.adapter, &body)?;
    if expected.keys().any(|hash| !native.contains(hash)) {
        return Err(RequestCaptureError::Unavailable);
    }
    Ok(expected
        .into_values()
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn native_user_fields(
    adapter: AdapterKind,
    body: &Value,
) -> Result<BTreeSet<TextDigest>, RequestCaptureError> {
    let key = if adapter == AdapterKind::OpenAiResponses {
        "input"
    } else {
        "messages"
    };
    let rows = body
        .get(key)
        .and_then(Value::as_array)
        .ok_or(RequestCaptureError::Unavailable)?;
    if rows.len() > MAX_FIELDS {
        return Err(RequestCaptureError::Bounds);
    }
    let mut hashes = BTreeSet::new();
    let mut fields = rows.len();
    for row in rows {
        if row.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        let content = row.get("content").ok_or(RequestCaptureError::Unavailable)?;
        if adapter == AdapterKind::OpenAiCompatibleChat
            && let Some(text) = content.as_str()
        {
            hashes.insert(digest(text));
            continue;
        }
        let blocks = content.as_array().ok_or(RequestCaptureError::Unavailable)?;
        fields = fields
            .checked_add(blocks.len())
            .ok_or(RequestCaptureError::Bounds)?;
        if fields > MAX_FIELDS {
            return Err(RequestCaptureError::Bounds);
        }
        let expected_kind = if adapter == AdapterKind::OpenAiResponses {
            "input_text"
        } else {
            "text"
        };
        for block in blocks {
            if block.get("type").and_then(Value::as_str) == Some(expected_kind) {
                let text = block
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or(RequestCaptureError::Unavailable)?;
                hashes.insert(digest(text));
            }
        }
    }
    Ok(hashes)
}

#[cfg(test)]
#[path = "prepared_mailbox_tests.rs"]
pub(super) mod tests;
