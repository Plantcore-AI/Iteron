//! Post-terminal private pixels and model projection. No model/input can mint the receipt.
use super::{Agent, KernelError, UiEvent, tool_execution_journal::ToolTerminalReceipt};
use crate::artifacts::DurableArtifactStore;
use base64::Engine as _;
use iteron_protocol::{
    Block, EventKind, ImageContent, ImageMediaType, Message, ToolUse,
    tool_image::{MAX_TOOL_IMAGE_ENCODED_BYTES, ToolImageObservationV1, ToolImageScopeV1},
};
use iteron_tools::CapturedToolImage;

pub(super) struct PendingToolImageProjection {
    pub(super) receipt: ToolTerminalReceipt,
    pub(super) images: Vec<CapturedToolImage>,
}

const IMAGE_UNAVAILABLE: &str =
    "Tool screenshot remains unavailable to the model; the confirmed tool terminal is unchanged";
impl Agent {
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
            || receipt.tenant() != self.rollout.tenant()
            || receipt.run() != self.rollout.run_id()
            || !matches!(receipt.tool(), "browser" | "computer")
        {
            self.ui(UiEvent::Notice(IMAGE_UNAVAILABLE.into()));
            return Vec::new();
        }
        let images = self.retain_tool_images(receipt, images);
        match images {
            Ok(images) => images,
            Err(()) => {
                self.ui(UiEvent::Notice(IMAGE_UNAVAILABLE.into()));
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
        let runs = self.rollout.path().parent().ok_or(())?;
        let store = DurableArtifactStore::open(
            runs,
            self.rollout.tenant().clone(),
            self.rollout.run_id().clone(),
            &self.workspace,
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
            if !self.provider.supports_image_input() {
                return Err(());
            }
            let source = image.observation().ok_or(())?;
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
                scope: ToolImageScopeV1::IsolatedBrowserViewport,
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
            self.emit_durable_seq(
                receipt.turn(),
                EventKind::ToolImageObservedV1 {
                    observation: observation.clone(),
                },
            )
            .map_err(|_| ())?;
            blocks.push(Block::ToolImage(observation));
        }
        Ok(blocks)
    }
    /// Invoke before physical provider preparation whenever a tool-image block is present. Full
    /// immutable decoder/budget policy is reused; pixels remain Untrusted across compaction/resume.
    pub(super) fn admit_tool_image_context(
        &self,
        messages: &[Message],
        input_images: &[ImageContent],
    ) -> Result<(), KernelError> {
        if !messages
            .iter()
            .flat_map(|message| &message.content)
            .any(|block| matches!(block, Block::ToolImage(_)))
        {
            return Ok(());
        }
        let mut count = 0usize;
        let mut raw = 0usize;
        let mut encoded = 0usize;
        let mut tokens = 0usize;
        for image in messages
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(|block| match block {
                Block::ToolImage(image) => Some(image),
                _ => None,
            })
        {
            if !self.provider.supports_image_input() {
                return Err(KernelError::ContextResolution(
                    "tool image route has no verified vision support".into(),
                ));
            }
            image
                .validate()
                .map_err(|reason| KernelError::ContextResolution(reason.into()))?;
            count = count.saturating_add(1);
            encoded = encoded.saturating_add(image.image.data.encoded_len());
            let inspected = self
                .binary_media_policy
                .inspect_content_evidence_with_envelope(
                    &image.image,
                    self.multimodal_decode_envelope,
                )
                .map_err(|_| {
                    KernelError::ContextResolution("tool image decoder envelope refused".into())
                })?;
            raw = raw.saturating_add(inspected.raw_bytes);
            tokens = tokens.saturating_add(
                self.context_estimator
                    .estimate_decoded_image(inspected.total_pixels)
                    .tokens,
            );
            if count > self.multimodal_decode_envelope.max_images
                || raw > self.multimodal_decode_envelope.aggregate_raw_bytes
                || encoded > 32 * 1024 * 1024
            {
                return Err(KernelError::ContextResolution(
                    "tool images exceed the admitted multimodal envelope".into(),
                ));
            }
        }
        for image in input_images {
            count = count.saturating_add(1);
            encoded = encoded.saturating_add(image.data.encoded_len());
            let inspected = self
                .binary_media_policy
                .inspect_content_evidence_with_envelope(image, self.multimodal_decode_envelope)
                .map_err(|_| {
                    KernelError::ContextResolution(
                        "combined tool/operator image decoder envelope refused".into(),
                    )
                })?;
            raw = raw.saturating_add(inspected.raw_bytes);
            tokens = tokens.saturating_add(
                self.context_estimator
                    .estimate_decoded_image(inspected.total_pixels)
                    .tokens,
            );
            if count > self.multimodal_decode_envelope.max_images
                || raw > self.multimodal_decode_envelope.aggregate_raw_bytes
                || encoded > 32 * 1024 * 1024
            {
                return Err(KernelError::ContextResolution(
                    "combined tool/operator images exceed the admitted multimodal envelope".into(),
                ));
            }
        }
        self.context_budget_policy
            .admit_multimodal(tokens)
            .map_err(|reason| KernelError::ContextBudget(reason.to_string()))?;
        Ok(())
    }
}
