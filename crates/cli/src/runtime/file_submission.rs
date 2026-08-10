//! First-class file submission admission and content-free context provenance.

use super::*;

/// Content-free provenance for file bytes carried by one top-level submission.
///
/// The rendered file text is already authoritative in the durable user message. Keeping only an
/// aggregate digest here lets the Context Ledger classify those bytes without retaining a second
/// copy of operator content or making a later turn re-open workspace paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InputFileEvidence {
    pub(super) count: u32,
    pub(super) bytes: u64,
    pub(super) estimated_tokens: u64,
    pub(super) digest_sha256: [u8; 32],
}

impl InputFileEvidence {
    fn from_rendered(rendered: &str, count: usize, estimated_tokens: usize) -> Self {
        Self {
            count: u32::try_from(count).unwrap_or(u32::MAX),
            bytes: u64::try_from(rendered.len()).unwrap_or(u64::MAX),
            estimated_tokens: u64::try_from(estimated_tokens).unwrap_or(u64::MAX),
            digest_sha256: Sha256::digest(rendered.as_bytes()).into(),
        }
    }
}

impl Agent {
    /// Run one submission carrying first-class file references.
    ///
    /// Admission is repeated at the kernel boundary. Attached files then become durable framed
    /// text for every provider, while the separate evidence contains no operator content.
    pub async fn run_files(
        &mut self,
        text: &str,
        images: &[core_protocol::ImageContent],
        files: &[core_protocol::FileContent],
    ) -> Result<Outcome, KernelError> {
        core_protocol::input::validate_file_submission(text, images, files)
            .map_err(KernelError::InvalidSubmission)?;
        let mut task = crate::file_input::render_attached_files("", files);
        let evidence = (!files.is_empty()).then(|| {
            InputFileEvidence::from_rendered(
                &task,
                files.len(),
                self.context_estimator.estimate_text(&task),
            )
        });
        task.push_str(text);
        self.run_with_images_mode(&task, images.to_vec(), true, evidence)
            .await
    }

    /// Continue an already-run agent with one file-carrying submission.
    pub async fn follow_up_files(
        &mut self,
        text: &str,
        images: &[core_protocol::ImageContent],
        files: &[core_protocol::FileContent],
    ) -> Result<Outcome, KernelError> {
        // Refusal happens before transcript staging, leaving the resident session unchanged.
        core_protocol::input::validate_file_submission(text, images, files)
            .map_err(KernelError::InvalidSubmission)?;
        self.stage_follow_up_transcript().await?;
        self.verify_attempts = 0;
        self.run_files(text, images, files).await
    }
}
