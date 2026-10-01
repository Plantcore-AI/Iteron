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
        let mut blocks = Vec::with_capacity(images.len());
        for image in images {
            // Private raw retention happens after the terminal even on a text-only model route;
            // a missing vision route is reported explicitly, never a false image observation.
            store
                .publish_tool_image(receipt.sequence().0, &call, image)
                .map_err(|_| ())?;
            if !self.vision {
                return Err(());
            }
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
