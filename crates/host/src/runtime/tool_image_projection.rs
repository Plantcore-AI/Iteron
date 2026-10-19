//! Post-terminal private pixels and model projection. No model/input can mint the receipt.
use super::{UiEvent, tool_execution_journal::ToolTerminalReceipt};
use crate::artifacts::DurableArtifactStore;
use base64::Engine as _;
use iteron_protocol::{
    Block, ImageContent, ImageMediaType, ToolUse,
    tool_image::{MAX_TOOL_IMAGE_ENCODED_BYTES, ToolImageObservationV1},
};
use iteron_tools::CapturedToolImage;

const IMAGE_UNAVAILABLE: &str =
    "Tool screenshot remains unavailable to the model; the confirmed tool terminal is unchanged";
pub(super) struct ToolImageProjection<'a> {
    pub(super) journal: super::session_transcript::TranscriptAdmissionJournal<'a>,
    pub(super) workspace: &'a std::path::Path,
    pub(super) vision: bool,
    pub(super) events: super::stream_tool_events::StreamToolEvents,
}
impl ToolImageProjection<'_> {
    /// Caller carries captured bytes only on the actual image path. Ordinary tools use the
    /// existing allocation-free terminal wrapper and never mint an optional receipt.
    pub(super) fn project_captured_tool_images(
        &mut self,
        receipt: &ToolTerminalReceipt,
        images: &[CapturedToolImage],
    ) -> Vec<Block> {
        if images.is_empty() {
            return Vec::new();
        }
        if !receipt.successful()
            || receipt.tenant() != self.journal.rollout.tenant()
            || receipt.run() != self.journal.rollout.run_id()
            || !matches!(receipt.tool(), "browser" | "computer" | "desktop")
        {
            self.events
                .present(UiEvent::Notice(IMAGE_UNAVAILABLE.into()));
            return Vec::new();
        }
        let images = self.retain_tool_images(receipt, images);
        match images {
            Ok(images) => images,
            Err(()) => {
                self.events
                    .present(UiEvent::Notice(IMAGE_UNAVAILABLE.into()));
                Vec::new()
            }
        }
    }
    fn retain_tool_images(
        &mut self,
        receipt: &ToolTerminalReceipt,
        images: &[CapturedToolImage],
    ) -> Result<Vec<Block>, ()> {
        if images.len() > iteron_protocol::tool_image::MAX_TOOL_IMAGES_PER_MESSAGE {
            return Err(());
        }
        let runs = self.journal.rollout.path().parent().ok_or(())?;
        let store = DurableArtifactStore::open(
            runs,
            self.journal.rollout.tenant().clone(),
            self.journal.rollout.run_id().clone(),
            self.workspace,
        )
        .map_err(|_| ())?;
        let call = ToolUse {
            id: receipt.tool_use_id().into(),
            name: receipt.tool().into(),
            input: serde_json::Value::Null,
        };
        // Retention is independent of model capability. Finish every bounded raw publication
        // before model projection can refuse the route or one observation.
        for image in images {
            store
                .publish_tool_image(receipt.sequence().0, &call, image)
                .map_err(|_| ())?;
        }
        if !self.vision {
            return Err(());
        }
        let mut blocks = Vec::with_capacity(images.len());
        for image in images {
            let source = image.observation().ok_or(())?;
            if (receipt.tool() == "desktop")
                != (source.scope()
                    == iteron_protocol::tool_image::ToolImageScopeV1::NativeMacDesktop)
            {
                return Err(());
            }
            let encoded_bytes = image.bytes().len().div_ceil(3).checked_mul(4).ok_or(())?;
            if encoded_bytes > MAX_TOOL_IMAGE_ENCODED_BYTES {
                return Err(());
            }
            let observation = ToolImageObservationV1 {
                version: 1,
                owner_tenant: receipt.tenant().clone(),
                owner_run: receipt.run().clone(),
                tool_use_id: call.id.clone(),
                terminal_seq: receipt.sequence(),
                observed_unix_ms: source.observed_unix_ms(),
                source_url_display: iteron_record::redact::scrub(source.source_url()),
                scope: source.scope(),
                artifact_id: image.sha256().into(),
                width: image.width(),
                height: image.height(),
                image: ImageContent::new(
                    ImageMediaType::Png,
                    base64::engine::general_purpose::STANDARD.encode(image.bytes()),
                )
                .map_err(|_| ())?,
            };
            observation.validate().map_err(|_| ())?;
            self.journal
                .tool_image(receipt.turn(), observation.clone())
                .map_err(|_| ())?;
            blocks.push(Block::ToolImage(observation));
        }
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{gate_integration_tests, tool_execution_journal::ToolExecutionJournal};
    use base64::Engine as _;
    use iteron_protocol::client_artifact::ClientArtifactCommandV1;
    use iteron_protocol::{Capability, EventKind, SessionId, ToolResult, ToolUse, TurnId};
    use iteron_tools::CapturedToolImage;

    fn captured(pixel: [u8; 3]) -> CapturedToolImage {
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&pixel).unwrap();
        }
        CapturedToolImage::png(bytes)
            .unwrap()
            .with_browser_observation("https://fixture.invalid/viewport".into(), 42)
            .unwrap()
    }

    #[test]
    fn text_only_route_retains_all_confirmed_pixels_without_a_model_observation() {
        let workspace = gate_integration_tests::temp_ws("text-only-multiple-pixels");
        let mut agent = gate_integration_tests::agent_for(&workspace);
        gate_integration_tests::record_test_genesis(&mut agent, &workspace);
        assert!(!agent.provider.supports_image_input());
        let turn = TurnId(1);
        let call = ToolUse {
            id: "captured-two".into(),
            name: "browser".into(),
            input: serde_json::json!({"action":"screenshot"}),
        };
        let events = agent.tool_events(turn);
        // Only the real effect journal may mint this fixture's terminal receipt. The PNGs are
        // explicit captured-data fixtures; this does not claim a native browser execution.
        let receipt = {
            let mut journal = ToolExecutionJournal {
                rollout: &mut agent.rollout,
                effects: &mut agent.effect_journal,
                ledger: &mut agent.ledger,
                failed_actions: &mut agent.failed_actions,
                record_failed: &mut agent.record_failed,
                diagnostics: &agent.diagnostics,
                fault: &mut agent.fail_next_durable_append,
            };
            let ticket = journal
                .open_tool(
                    &workspace,
                    turn,
                    0,
                    &call,
                    Capability::CodeExecuting,
                    &events,
                )
                .unwrap();
            let result = ToolResult {
                tool_use_id: call.id.clone(),
                content: "captured fixture pixels".into(),
                trust: iteron_protocol::Trust::Untrusted,
                is_error: false,
                latency_ms: 1,
            };
            journal
                .known_result_receipt(ticket, "browser", &result, 0, &events)
                .unwrap()
        };
        let images = [captured([255, 0, 0]), captured([0, 255, 0])];
        assert!(
            agent
                .project_captured_tool_images(&receipt, &images)
                .is_empty()
        );
        let store = crate::artifacts::DurableArtifactStore::open(
            agent.rollout.path().parent().unwrap(),
            agent.rollout.tenant().clone(),
            agent.rollout.run_id().clone(),
            &workspace,
        )
        .unwrap();
        let thread = SessionId(format!("session-{}", agent.rollout.run_id().0));
        for image in &images {
            let chunk = store
                .read(
                    &thread,
                    ClientArtifactCommandV1::Read {
                        thread_id: thread.clone(),
                        artifact_id: image.sha256().into(),
                        offset: 0,
                        max_bytes: 65536,
                    },
                )
                .unwrap();
            assert_eq!(chunk["artifact"]["source_event_seq"], receipt.sequence().0);
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(chunk["content_base64"].as_str().unwrap())
                    .unwrap(),
                image.bytes()
            );
            assert_eq!(chunk["eof"], true);
        }
        let replay = iteron_record::replay(agent.rollout.path()).unwrap();
        assert_eq!(
            replay
                .iter()
                .filter(|event| matches!(event.kind, EventKind::ToolDone { .. }))
                .count(),
            1
        );
        assert!(
            !replay
                .iter()
                .any(|event| matches!(event.kind, EventKind::ToolImageObservedV1 { .. }))
        );
    }
}
