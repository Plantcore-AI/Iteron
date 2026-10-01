//! Post-terminal private pixels and model projection. No model/input can mint the receipt.
use super::{Agent, KernelError, tool_execution_journal::ToolTerminalReceipt};
use iteron_protocol::{Block, ImageContent, Message};
use iteron_tools::CapturedToolImage;

pub(super) struct PendingToolImageProjection {
    pub(super) receipt: ToolTerminalReceipt,
    pub(super) images: Vec<CapturedToolImage>,
}

impl Agent {
    #[cfg(test)]
    pub(super) fn project_captured_tool_images(
        &mut self,
        receipt: &ToolTerminalReceipt,
        images: &[CapturedToolImage],
    ) -> Vec<Block> {
        self.tool_image_projection(receipt.turn())
            .project_captured_tool_images(receipt, images)
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
