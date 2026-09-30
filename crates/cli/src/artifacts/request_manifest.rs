//! Sealed, content-free physical request manifests. Only this constructor computes commitments;
//! free text and the retained body are scrubbed. Raw endpoints and authentication are absent.
use super::{ArtifactStoreError, ArtifactTextSchema, DurableArtifactStore};
use iteron_ctx::{ContextSegmentEvidence, MAX_CONTEXT_LEDGER_SEGMENTS};
use iteron_kernel::effects::EffectTicket;
use iteron_protocol::client_artifact::ClientArtifactDescriptorV1;
use iteron_protocol::{Budget, ProviderRouteAttemptIdentity, ReasoningEffort, Seq, TurnId};
use iteron_provider::request_capture::ProviderWireRequest;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize)]
pub(crate) struct RequestManifestScope {
    source_event_seq: Seq,
    turn: TurnId,
    effect_id_sha256: String,
    route_display: String,
    route: ScopedRoute,
    budget: Budget,
    context_sources: Vec<ContextSegmentEvidence>,
}

#[derive(Clone, Serialize)]
struct ScopedRoute {
    route_id_sha256: String,
    physical_attempt: u32,
    max_cost_reservation_microusd: Option<u64>,
}

impl RequestManifestScope {
    pub(crate) fn capture(
        ticket: &EffectTicket,
        budget: &Budget,
        sources: &[ContextSegmentEvidence],
    ) -> Result<Self, ArtifactStoreError> {
        let route: &ProviderRouteAttemptIdentity = ticket
            .provider_route_attempt()
            .ok_or(ArtifactStoreError::InvalidRequest)?;
        if ticket.intent_sequence() == Seq::ZERO
            || route.physical_attempt == 0
            || route.route_id.len() > 512
            || ticket.effect_id().0.len() > 512
            || sources.len() > MAX_CONTEXT_LEDGER_SEGMENTS
            || budget.validate().is_err()
        {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        Ok(Self {
            source_event_seq: ticket.intent_sequence(),
            turn: ticket.turn(),
            effect_id_sha256: commitment(ticket.effect_id().0.as_bytes()),
            route_display: iteron_record::redact::scrub(&route.route_id),
            route: ScopedRoute {
                route_id_sha256: commitment(route.route_id.as_bytes()),
                physical_attempt: route.physical_attempt,
                max_cost_reservation_microusd: route.max_cost_reservation_microusd,
            },
            budget: budget.clone(),
            context_sources: sources.to_vec(),
        })
    }
}

#[derive(Serialize)]
struct PreparedRequestManifest<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    scope: &'a RequestManifestScope,
    adapter: &'static str,
    method: &'static str,
    endpoint_sha256: String,
    content_type: &'static str,
    wire_body_sha256: String,
    wire_body_bytes: usize,
    system_sha256: String,
    tool_schemas_sha256: String,
    max_output_tokens: u32,
    reasoning_effort: ReasoningEffort,
    thinking_budget_tokens: u32,
    controls: PreparedControls,
    served_body_sha256: String,
    served_body_bytes: usize,
    served_body_chunks: Vec<ClientArtifactDescriptorV1>,
    retention: &'static str,
    reconstruction: &'static str,
    per_material_resolution: &'static str,
}

#[derive(Serialize)]
struct PreparedControls {
    service_tier: &'static str,
    verbosity: &'static str,
    compression: &'static str,
    cache_breakpoint: String,
    cache_scope: String,
    cache_ttl_seconds: u32,
    idempotent: bool,
    connect_tls_ms: u128,
    request_total_ms: u128,
    stream_idle_ms: u128,
}

#[derive(Serialize)]
struct DispatchManifest<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    scope: &'a RequestManifestScope,
    prepared: &'a ClientArtifactDescriptorV1,
    evidence: &'static str,
}

#[derive(Serialize)]
struct UnavailableManifest<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    scope: &'a RequestManifestScope,
    reason_code: &'static str,
}

fn commitment(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

impl DurableArtifactStore {
    pub(crate) fn publish_prepared_request(
        &self,
        scope: &RequestManifestScope,
        wire: ProviderWireRequest<'_>,
    ) -> Result<ClientArtifactDescriptorV1, ArtifactStoreError> {
        if wire.method != "POST"
            || wire.content_type != "application/json"
            || wire.body.len() > 32 * 1024 * 1024
            || wire.endpoint.len() > 16 * 1024
        {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        let original =
            std::str::from_utf8(wire.body).map_err(|_| ArtifactStoreError::InvalidRequest)?;
        // Scrub the complete body before splitting, so a credential crossing a chunk edge cannot
        // escape redaction. Chunk identities always refer to the actual scrubbed served bytes.
        let served = iteron_record::redact::scrub(original);
        if served.len() > 32 * 1024 * 1024 {
            return Err(ArtifactStoreError::Capacity);
        }
        let mut remaining = served.as_str();
        let mut chunks = Vec::with_capacity(5);
        while !remaining.is_empty() {
            if chunks.len() >= 8 {
                return Err(ArtifactStoreError::Capacity);
            }
            let mut end = remaining.len().min(super::MAX_PRIVATE_CONTENT_BYTES);
            while !remaining.is_char_boundary(end) {
                end -= 1;
            }
            if end == 0 {
                return Err(ArtifactStoreError::Capacity);
            }
            chunks.push(self.publish_served(
                scope.source_event_seq.0,
                ArtifactTextSchema::ProviderRequestBody,
                &remaining[..end],
                &[],
                &[],
            )?);
            remaining = &remaining[end..];
        }
        let controls = wire.request.controls;
        let manifest = PreparedRequestManifest {
            kind: "provider_request_prepared_v1",
            scope,
            adapter: match wire.adapter {
                iteron_provider::AdapterKind::AnthropicMessages => "anthropic_messages",
                iteron_provider::AdapterKind::OpenAiCompatibleChat => "openai_chat_completions",
                iteron_provider::AdapterKind::OpenAiResponses => "openai_responses",
            },
            method: "POST",
            endpoint_sha256: commitment(wire.endpoint.as_bytes()),
            content_type: "application/json",
            wire_body_sha256: commitment(wire.body),
            wire_body_bytes: wire.body.len(),
            system_sha256: commitment(wire.request.system.as_bytes()),
            tool_schemas_sha256: commitment(wire.request.tools.canonical_json().as_bytes()),
            max_output_tokens: wire.request.max_tokens,
            reasoning_effort: wire.request.reasoning_effort,
            thinking_budget_tokens: wire.request.thinking_budget,
            controls: PreparedControls {
                service_tier: controls.service_tier.label(),
                verbosity: controls.verbosity.label(),
                compression: controls.compression.label(),
                cache_breakpoint: format!("{:?}", controls.prompt_cache.breakpoint),
                cache_scope: format!("{:?}", controls.prompt_cache.scope),
                cache_ttl_seconds: controls.prompt_cache.ttl_seconds,
                idempotent: controls.idempotent,
                connect_tls_ms: controls.transport.connect_tls.as_millis(),
                request_total_ms: controls.transport.request_total.as_millis(),
                stream_idle_ms: controls.transport.stream_idle.as_millis(),
            },
            served_body_sha256: commitment(served.as_bytes()),
            served_body_bytes: served.len(),
            served_body_chunks: chunks.clone(),
            retention: "scrubbed_complete_body",
            reconstruction: "original_wire_commitment_plus_scrubbed_body",
            per_material_resolution: "source_digests_and_decisions_only_locators_not_yet_available",
        };
        let text = serde_json::to_string(&manifest).map_err(|_| ArtifactStoreError::Corrupt)?;
        // This sealed vocabulary contains only computed commitments, actual retained references,
        // closed enums/numbers, and already scrubbed route text. Generic JSON receives no bypass.
        self.publish_served(
            scope.source_event_seq.0,
            ArtifactTextSchema::ProviderRequestManifest,
            &text,
            &[],
            &chunks,
        )
    }

    pub(crate) fn publish_request_dispatch_intent(
        &self,
        scope: &RequestManifestScope,
        prepared: &ClientArtifactDescriptorV1,
    ) -> Result<(), ArtifactStoreError> {
        let text = serde_json::to_string(&DispatchManifest {
            kind: "provider_request_dispatch_intent_v1",
            scope,
            prepared,
            evidence: "local_dispatch_intent_only_not_socket_write_or_remote_ack",
        })
        .map_err(|_| ArtifactStoreError::Corrupt)?;
        self.publish_served(
            scope.source_event_seq.0,
            ArtifactTextSchema::ProviderRequestManifest,
            &text,
            &[],
            std::slice::from_ref(prepared),
        )
        .map(|_| ())
    }

    pub(crate) fn publish_request_unavailable(
        &self,
        scope: &RequestManifestScope,
        reason: &'static str,
    ) -> Result<(), ArtifactStoreError> {
        if reason != "adapter_wire_capture_unavailable" {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        let text = serde_json::to_string(&UnavailableManifest {
            kind: "provider_request_capture_unavailable_v1",
            scope,
            reason_code: reason,
        })
        .map_err(|_| ArtifactStoreError::Corrupt)?;
        self.publish_served(
            scope.source_event_seq.0,
            ArtifactTextSchema::ProviderRequestManifest,
            &text,
            &[],
            &[],
        )
        .map(|_| ())
    }
}
