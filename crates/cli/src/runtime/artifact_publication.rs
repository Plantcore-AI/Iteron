//! Publication of captured runtime output before context or frontend projections.
//!
//! This adapter retains immutable host scope and durable source correlation. It owns no Agent,
//! transport, permission decision or execution settlement. A retention failure never changes a
//! known tool effect into an unknown effect.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use iteron_protocol::{RunId, Seq, TenantId, ToolResult, ToolUse};

use crate::artifacts::{ArtifactTextSchema, DurableArtifactStore};

pub(crate) const PUBLICATION_UNAVAILABLE: &str =
    "Artifact retention is unavailable for this captured output";

pub(crate) trait ToolOutputPublicationPort: Send + Sync {
    fn publish(
        &self,
        admitted_call: &ToolUse,
        raw_result: &ToolResult,
        effects_known: bool,
    ) -> Result<(), String>;

    fn publish_execution(
        &self,
        admitted_call: &ToolUse,
        captured: &iteron_tools::CapturedToolExecution,
    ) -> Result<(), String>;
}

pub(crate) trait ToolOutputPublicationFactory: Send + Sync {
    fn for_call(&self, call: &ToolUse, source: Seq) -> Arc<dyn ToolOutputPublicationPort>;
    fn for_calls(&self, calls: &[(ToolUse, Seq)]) -> Arc<dyn ToolOutputPublicationPort>;
}

struct CapturedOutputPublicationFactory {
    scope: CapturedOutputPublisher,
}

impl ToolOutputPublicationFactory for CapturedOutputPublicationFactory {
    fn for_call(&self, call: &ToolUse, source: Seq) -> Arc<dyn ToolOutputPublicationPort> {
        let mut publisher = self.scope.clone();
        publisher.sources = BTreeMap::from([(call.id.clone(), source.0)]);
        Arc::new(publisher)
    }

    fn for_calls(&self, calls: &[(ToolUse, Seq)]) -> Arc<dyn ToolOutputPublicationPort> {
        let mut publisher = self.scope.clone();
        // A malformed batch gets an empty correlation map. Every publication then refuses;
        // source identity must never fall back to the last event or a different tool's intent.
        if calls.len() > iteron_kernel::effects::MAX_TOOL_CALLS_PER_TURN {
            return Arc::new(publisher);
        }
        for (call, source) in calls {
            if source.0 == 0
                || call.id.is_empty()
                || publisher
                    .sources
                    .insert(call.id.clone(), source.0)
                    .is_some()
            {
                publisher.sources.clear();
                return Arc::new(publisher);
            }
        }
        Arc::new(publisher)
    }
}

#[derive(Clone)]
struct CapturedOutputPublisher {
    runs: PathBuf,
    tenant: TenantId,
    run: RunId,
    workspace: PathBuf,
    sources: BTreeMap<String, u64>,
}

impl CapturedOutputPublisher {
    fn store(&self) -> Result<DurableArtifactStore, String> {
        DurableArtifactStore::open(
            &self.runs,
            self.tenant.clone(),
            self.run.clone(),
            &self.workspace,
        )
        .map_err(|_| PUBLICATION_UNAVAILABLE.into())
    }

    fn publish_text(
        &self,
        sequence: u64,
        schema: ArtifactTextSchema,
        text: &str,
    ) -> Result<(), String> {
        self.retain_text(sequence, schema, text).map(|_| ())
    }

    fn retain_text(
        &self,
        sequence: u64,
        schema: ArtifactTextSchema,
        text: &str,
    ) -> Result<iteron_protocol::client_artifact::ClientArtifactDescriptorV1, String> {
        if sequence == 0 {
            return Err(PUBLICATION_UNAVAILABLE.into());
        }
        // These are newly captured primary bytes, not a derivative of a fabricated private
        // handle. The artifact owner scrubs and retains the served bytes under session erasure.
        self.store()?
            .publish_text(sequence, schema, text, &[])
            .map_err(|_| PUBLICATION_UNAVAILABLE.into())
    }

    fn publish_native(
        &self,
        sequence: u64,
        receipt: &iteron_tools::NativeMutationReceipt,
    ) -> Result<(), String> {
        // Each complete served snapshot has its own real artifact identity. The manifest records
        // the actual native receipt; it neither fabricates prior bytes nor calls a preview a diff.
        self.store()?
            .publish_native_diff(sequence, receipt)
            .map(|_| ())
            .map_err(|_| PUBLICATION_UNAVAILABLE.into())
    }
}

impl ToolOutputPublicationPort for CapturedOutputPublisher {
    fn publish(
        &self,
        call: &ToolUse,
        result: &ToolResult,
        effects_known: bool,
    ) -> Result<(), String> {
        if result.tool_use_id != call.id {
            return Err(PUBLICATION_UNAVAILABLE.into());
        }
        let source = *self.sources.get(&call.id).ok_or(PUBLICATION_UNAVAILABLE)?;
        self.publish_text(source, ArtifactTextSchema::ToolOutput, &result.content)?;
        // Capture the complete admitted replacement, rather than the line-capped UI diff.
        // Unknown or failed executions cannot prove that an edit landed.
        if effects_known
            && !result.is_error
            && let Some(diff) = admitted_replacement(call)
        {
            self.publish_text(source, ArtifactTextSchema::CapturedReplacement, &diff)?;
        }
        Ok(())
    }

    fn publish_execution(
        &self,
        call: &ToolUse,
        captured: &iteron_tools::CapturedToolExecution,
    ) -> Result<(), String> {
        let (result, known) = match &captured.execution {
            iteron_tools::ToolExecution::Definite(result) => (result, true),
            iteron_tools::ToolExecution::Unknown(result) => (result, false),
        };
        if result.tool_use_id != call.id {
            return Err(PUBLICATION_UNAVAILABLE.into());
        }
        let source = *self.sources.get(&call.id).ok_or(PUBLICATION_UNAVAILABLE)?;
        let mut unavailable = captured.capture_error.is_some();
        unavailable |= self.publish(call, result, known).is_err();
        for output in &captured.captured_outputs {
            let schema = match output.schema.as_str() {
                "iteron.mcp-result.v1" => ArtifactTextSchema::McpResult,
                _ => {
                    unavailable = true;
                    continue;
                }
            };
            unavailable |= self.publish_text(source, schema, &output.text).is_err();
        }
        if let Some(receipt) = &captured.native_mutation {
            if known
                && !result.is_error
                && receipt.tool_use_id() == call.id
                && receipt.tool_name() == call.name
            {
                unavailable |= self.publish_native(source, receipt).is_err();
            } else {
                unavailable = true;
            }
        }
        if unavailable {
            Err(PUBLICATION_UNAVAILABLE.into())
        } else {
            Ok(())
        }
    }
}

fn admitted_replacement(call: &ToolUse) -> Option<String> {
    let text = |key| call.input.get(key).and_then(serde_json::Value::as_str);
    let path = text("path")?;
    let (before, after) = match call.name.as_str() {
        "edit" | "str_replace" => (text("old")?, text("new")?),
        "write" | "create" | "write_file" => ("", text("content").or_else(|| text("file_text"))?),
        _ => return None,
    };
    serde_json::to_string(&serde_json::json!({
        "type":"admitted_replacement_v1", "tool_use_id":call.id,
        "path":path,"before":if matches!(call.name.as_str(),"edit"|"str_replace") { Some(before) } else { None },"after":after,
        "basis":"successful admitted native replacement", "whole_file_before_known":false
    })).ok()
}

impl super::Agent {
    fn output_publisher(&self, sources: BTreeMap<String, u64>) -> CapturedOutputPublisher {
        CapturedOutputPublisher {
            runs: self
                .rollout
                .path()
                .parent()
                .map_or_else(PathBuf::new, std::path::Path::to_path_buf),
            tenant: self.rollout.tenant().clone(),
            run: self.rollout.run_id().clone(),
            workspace: self.workspace.clone(),
            sources,
        }
    }

    pub(super) fn tool_output_publication_factory(&self) -> Arc<dyn ToolOutputPublicationFactory> {
        Arc::new(CapturedOutputPublicationFactory {
            scope: self.output_publisher(BTreeMap::new()),
        })
    }

    pub(super) fn tool_output_publication(
        &self,
        call: &ToolUse,
        source: Seq,
    ) -> Arc<dyn ToolOutputPublicationPort> {
        Arc::new(self.output_publisher(BTreeMap::from([(call.id.clone(), source.0)])))
    }

    pub(super) fn batch_output_publication(
        &self,
        pending: &[(usize, ToolUse, String, super::effects::EffectTicket)],
    ) -> Arc<dyn ToolOutputPublicationPort> {
        Arc::new(
            self.output_publisher(
                pending
                    .iter()
                    .map(|(_, call, _, ticket)| (call.id.clone(), ticket.intent_sequence().0))
                    .collect(),
            ),
        )
    }

    pub(super) fn publish_captured_result(
        &self,
        call: &ToolUse,
        source: Seq,
        result: &ToolResult,
        known: bool,
    ) -> Option<String> {
        self.tool_output_publication(call, source)
            .publish(call, result, known)
            .err()
    }

    pub(super) fn publish_captured_answer(&self) {
        if self.run_assistant_text.is_empty() {
            return;
        }
        let Some(source) = self.last_assistant_source else {
            return;
        };
        if self
            .output_publisher(BTreeMap::new())
            .publish_text(
                source.0,
                ArtifactTextSchema::FinalAnswer,
                &self.run_assistant_text,
            )
            .is_err()
        {
            self.ui(super::UiEvent::Notice(PUBLICATION_UNAVAILABLE.into()));
        }
    }
}
