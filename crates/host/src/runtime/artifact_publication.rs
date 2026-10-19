//! Publication of captured runtime output before context or frontend projections.
//!
//! This adapter retains immutable host scope and durable source correlation. It owns no Agent,
//! transport, permission decision or execution settlement. A retention failure never changes a
//! known tool effect into an unknown effect.

use std::collections::BTreeMap;
use std::sync::Arc;

use iteron_protocol::{Seq, ToolResult, ToolUse};

use crate::artifacts::{ArtifactSchema, ArtifactWriterCapture, DurableArtifactStore};

pub const PUBLICATION_UNAVAILABLE: &str =
    "Artifact retention is unavailable for this captured output";

pub trait ToolOutputPublicationPort: Send + Sync {
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

pub trait ToolOutputPublicationFactory: Send + Sync {
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
    store: Arc<ArtifactWriterCapture>,
    sources: BTreeMap<String, u64>,
}

impl CapturedOutputPublisher {
    fn store(&self) -> Result<&DurableArtifactStore, String> {
        self.store.get().map_err(|_| PUBLICATION_UNAVAILABLE.into())
    }

    fn publish_text(
        &self,
        sequence: u64,
        schema: ArtifactSchema,
        text: &str,
    ) -> Result<(), String> {
        self.retain_text(sequence, schema, text).map(|_| ())
    }

    fn retain_text(
        &self,
        sequence: u64,
        schema: ArtifactSchema,
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
        self.publish_text(source, ArtifactSchema::ToolOutput, &result.content)?;
        // Capture the complete admitted replacement, rather than the line-capped UI diff.
        // Unknown or failed executions cannot prove that an edit landed.
        if effects_known
            && !result.is_error
            && let Some(diff) = admitted_replacement(call)
        {
            self.publish_text(source, ArtifactSchema::CapturedReplacement, &diff)?;
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
                "iteron.mcp-result.v1" => ArtifactSchema::McpResult,
                "iteron.browser-observation.v1"
                    if matches!(call.name.as_str(), "browser" | "computer") =>
                {
                    ArtifactSchema::BrowserObservation
                }
                "iteron.desktop-observation.v1" if call.name == "desktop" => {
                    ArtifactSchema::DesktopObservation
                }
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
                && receipt.logical_tool_name() == call.name
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
            // Capture the current writer each time this factory is requested. A later adopted
            // run gets its own scope; public readers retain their independent metadata checks.
            store: Arc::new(ArtifactWriterCapture::from_rollout_writer(
                &self.rollout,
                &self.workspace,
            )),
            sources,
        }
    }

    pub(super) fn tool_output_publication_factory(&self) -> Arc<dyn ToolOutputPublicationFactory> {
        Arc::new(CapturedOutputPublicationFactory {
            scope: self.output_publisher(BTreeMap::new()),
        })
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
                ArtifactSchema::FinalAnswer,
                &self.run_assistant_text,
            )
            .is_err()
        {
            self.ui(super::UiEvent::Notice(PUBLICATION_UNAVAILABLE.into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::client_artifact::ClientArtifactCommandV1;
    use iteron_protocol::{Effort, Event, EventKind, RunId, SessionId, TenantId, Trust, TurnId};
    use iteron_record::Rollout;
    use std::path::Path;

    fn writer(runs: &Path, workspace: &Path, run: &RunId) -> Rollout {
        let mut rollout = Rollout::open(runs, run, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: workspace.to_string_lossy().into_owned(),
                    model: "fixture".into(),
                    effort: Effort::Low,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        rollout
    }

    fn publisher(rollout: &Rollout, workspace: &Path) -> CapturedOutputPublisher {
        CapturedOutputPublisher {
            store: Arc::new(ArtifactWriterCapture::from_rollout_writer(
                rollout, workspace,
            )),
            sources: BTreeMap::from([("actual-call".into(), 1)]),
        }
    }

    #[test]
    fn writer_publication_keeps_call_scope_and_reopens_only_its_actual_run() {
        let root = crate::runtime::test_tempdir::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let other_workspace = root.path().join("other");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&other_workspace).unwrap();
        let runs = root.path().join("runs");
        let first_run = RunId("first".into());
        let first = writer(&runs, &workspace, &first_run);
        let captured = publisher(&first, &workspace);
        drop(first);
        // The first factory has not resolved its paths yet. A later writer in another workspace
        // must not replace the immutable run/workspace captured for that pending publication.
        let second = writer(&runs, &other_workspace, &RunId("second".into()));
        let second_capture = publisher(&second, &other_workspace);
        let second_id = second_capture
            .retain_text(1, ArtifactSchema::ToolOutput, "second output")
            .unwrap()
            .artifact_id;
        let call = ToolUse {
            id: "actual-call".into(),
            name: "list_dir".into(),
            input: serde_json::json!({"path":"."}),
        };
        let mut result = ToolResult {
            tool_use_id: "forged-call".into(),
            content: "first output".into(),
            is_error: false,
            trust: Trust::Workspace,
            latency_ms: 0,
        };
        assert!(captured.publish(&call, &result, true).is_err());
        result.tool_use_id = call.id.clone();
        captured.publish(&call, &result, true).unwrap();
        let first_id = captured
            .retain_text(1, ArtifactSchema::ToolOutput, "first output")
            .unwrap()
            .artifact_id;
        drop(captured);
        drop(second_capture);
        drop(second);
        let reopened = Rollout::open_existing(&runs, &first_run, TenantId::default()).unwrap();
        let restored = publisher(&reopened, &workspace);
        let thread = SessionId("authenticated".into());
        let listed = restored
            .store()
            .unwrap()
            .read(
                &thread,
                ClientArtifactCommandV1::List {
                    thread_id: thread.clone(),
                },
            )
            .unwrap();
        let artifacts = listed["artifacts"].as_array().unwrap();
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact["artifact_id"] == first_id)
        );
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact["artifact_id"] != second_id)
        );
        // Writer capture is internal only; public scope construction still independently checks
        // tenant and canonical workspace against the recovered journal.
        assert!(
            DurableArtifactStore::open(
                &runs,
                TenantId("wrong-tenant".into()),
                first_run.clone(),
                &workspace
            )
            .is_err()
        );
        assert!(
            DurableArtifactStore::open(&runs, TenantId::default(), first_run, &other_workspace)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn deferred_writer_publication_refuses_redirected_directories_before_any_write() {
        for redirect_runs in [false, true] {
            let root = crate::runtime::test_tempdir::tempdir().unwrap();
            let workspace = root.path().join("workspace");
            let runs = root.path().join("runs");
            std::fs::create_dir(&workspace).unwrap();
            let run = RunId("captured".into());
            let rollout = writer(&runs, &workspace, &run);
            let captured = publisher(&rollout, &workspace);
            drop(rollout);

            let redirected = if redirect_runs { &runs } else { &workspace };
            let original = root.path().join("original");
            let other = root.path().join("other");
            std::fs::rename(redirected, &original).unwrap();
            std::fs::create_dir(&other).unwrap();
            std::os::unix::fs::symlink(&other, redirected).unwrap();
            assert!(
                captured
                    .retain_text(1, ArtifactSchema::ToolOutput, "must not escape")
                    .is_err()
            );
            for directory in [&runs, &original, &other] {
                assert!(!directory.join(".public-artifacts").exists());
            }

            std::fs::remove_file(redirected).unwrap();
            std::fs::rename(&original, redirected).unwrap();
            // A failed deferred capture stays failed, even if its old path is restored. Cloned
            // per-call publishers must share that outcome instead of silently recapturing it.
            assert!(
                captured
                    .clone()
                    .retain_text(1, ArtifactSchema::ToolOutput, "must remain refused")
                    .is_err()
            );
            let reopened = Rollout::open_existing(&runs, &run, TenantId::default()).unwrap();
            publisher(&reopened, &workspace)
                .retain_text(1, ArtifactSchema::ToolOutput, "fresh authenticated capture")
                .unwrap();
        }
    }
}
