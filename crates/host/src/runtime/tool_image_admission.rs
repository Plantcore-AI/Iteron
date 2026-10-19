//! Immutable image admission against the current native route and pinned decoder envelope.
//! Receipt validation does not grant provider authority or retain unconfirmed pixels.
use super::KernelError;
use crate::image_input::{BinaryMediaInspectionPolicy, MultimodalDecodeEnvelope};
use iteron_ctx::{ContextBudgetPolicy, RequestEstimator};
use iteron_protocol::{Block, ImageContent, Message};

pub(super) struct ToolImageAdmission<'a> {
    pub(super) vision: bool,
    pub(super) policy: &'a BinaryMediaInspectionPolicy,
    pub(super) envelope: MultimodalDecodeEnvelope,
    pub(super) estimator: &'a RequestEstimator,
    pub(super) budget: &'a ContextBudgetPolicy,
}
impl ToolImageAdmission<'_> {
    pub(super) fn admit(
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
            if !self.vision {
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
                .policy
                .inspect_content_evidence_with_envelope(&image.image, self.envelope)
                .map_err(|_| {
                    KernelError::ContextResolution("tool image decoder envelope refused".into())
                })?;
            raw = raw.saturating_add(inspected.raw_bytes);
            tokens = tokens.saturating_add(
                self.estimator
                    .estimate_decoded_image(inspected.total_pixels)
                    .tokens,
            );
            if count > self.envelope.max_images
                || raw > self.envelope.aggregate_raw_bytes
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
                .policy
                .inspect_content_evidence_with_envelope(image, self.envelope)
                .map_err(|_| {
                    KernelError::ContextResolution(
                        "combined tool/operator image decoder envelope refused".into(),
                    )
                })?;
            raw = raw.saturating_add(inspected.raw_bytes);
            tokens = tokens.saturating_add(
                self.estimator
                    .estimate_decoded_image(inspected.total_pixels)
                    .tokens,
            );
            if count > self.envelope.max_images
                || raw > self.envelope.aggregate_raw_bytes
                || encoded > 32 * 1024 * 1024
            {
                return Err(KernelError::ContextResolution(
                    "combined tool/operator images exceed the admitted multimodal envelope".into(),
                ));
            }
        }
        self.budget
            .admit_multimodal(tokens)
            .map_err(|reason| KernelError::ContextBudget(reason.to_string()))?;
        Ok(())
    }
}
