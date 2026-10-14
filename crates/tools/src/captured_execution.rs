//! Host-only data captured before preview caps, kept separate from certainty and authority.

use crate::{
    CapturedToolImage, ToolExecution,
    native_mutation::{NativeFileChange, NativeMutationReceipt},
};
use iteron_protocol::refusal::RefusalReasonV1;
use iteron_protocol::{ToolResult, ToolUse};

const MAX_OUTPUTS: usize = 32;
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct CapturedToolOutput {
    pub schema: String,
    pub text: String,
}
impl std::fmt::Debug for CapturedToolOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedToolOutput")
            .field("schema", &self.schema)
            .field("bytes", &self.text.len())
            .finish()
    }
}
#[derive(Debug, Clone)]
pub struct CapturedToolExecution {
    pub execution: ToolExecution,
    pub captured_outputs: Vec<CapturedToolOutput>,
    pub captured_images: Vec<CapturedToolImage>,
    pub native_mutation: Option<NativeMutationReceipt>,
    pub capture_error: Option<String>,
    // Minted only by a native authority branch, never an external executor constructor.
    refusal: Option<(String, RefusalReasonV1)>,
}
impl From<ToolExecution> for CapturedToolExecution {
    fn from(execution: ToolExecution) -> Self {
        Self {
            execution,
            captured_outputs: vec![],
            captured_images: vec![],
            native_mutation: None,
            capture_error: None,
            refusal: None,
        }
    }
}
impl From<ToolResult> for CapturedToolExecution {
    fn from(result: ToolResult) -> Self {
        Self::from(ToolExecution::Definite(result))
    }
}
impl CapturedToolExecution {
    pub(crate) fn with_refusal(mut self, reason: RefusalReasonV1) -> Self {
        let ToolExecution::Definite(result) = &self.execution else {
            return self;
        };
        if result.is_error && result.tool_use_id.len() <= 2048 {
            self.refusal = Some((result.tool_use_id.clone(), reason));
        }
        self
    }
    /// A native known refusal is separate from effect admission. External closures cannot mint
    /// it; rewriting result identity, success or certainty invalidates its attribution.
    pub fn refusal_reason(&self) -> Option<RefusalReasonV1> {
        let ToolExecution::Definite(result) = &self.execution else {
            return None;
        };
        self.refusal
            .as_ref()
            .filter(|(id, _)| result.is_error && *id == result.tool_use_id)
            .map(|(_, reason)| *reason)
    }

    pub fn into_result(self) -> ToolResult {
        self.execution.into_result()
    }
    pub(crate) fn result_mut(&mut self) -> &mut ToolResult {
        self.execution.result_mut()
    }
    pub(crate) fn native_success(
        call: &ToolUse,
        result: ToolResult,
        files: Vec<NativeFileChange>,
    ) -> Self {
        let mut captured = Self::from(ToolExecution::Definite(result));
        match NativeMutationReceipt::committed(call.id.clone(), call.name.clone(), files) {
            Ok(receipt) => captured.native_mutation = Some(receipt),
            Err(reason) => captured.capture_error = Some(reason.into()),
        }
        captured
    }
    pub(crate) fn normalize(mut self, id: &str, name: &str, allow_native: bool) -> Self {
        let mut total = 0usize;
        let valid = self.captured_outputs.len() <= MAX_OUTPUTS
            && self.captured_outputs.iter().all(|output| {
                total = total.saturating_add(output.text.len());
                !output.schema.is_empty()
                    && output.schema.len() <= 128
                    && output.schema.bytes().all(|b| b.is_ascii_graphic())
                    && output.text.len() <= MAX_OUTPUT_BYTES
                    && total <= MAX_TOTAL_BYTES
            });
        if !valid {
            self.captured_outputs.clear();
            self.capture_error = Some("captured output exceeds its host envelope".into());
        }
        if self.captured_images.len() > 4
            || self
                .captured_images
                .iter()
                .map(|image| image.bytes().len())
                .sum::<usize>()
                > MAX_TOTAL_BYTES
        {
            self.captured_images.clear();
            self.capture_error = Some("captured images exceed host envelope".into());
        }
        let definite_success =
            matches!(&self.execution,ToolExecution::Definite(result) if !result.is_error);
        if !definite_success && !self.captured_images.is_empty() {
            self.captured_images.clear();
            self.capture_error =
                Some("captured images lack a definite successful observation".into());
        }
        if self
            .native_mutation
            .as_ref()
            .is_some_and(|receipt| !allow_native || !definite_success || !receipt.matches(id, name))
        {
            self.native_mutation = None;
            self.capture_error = Some("native mutation capture identity unavailable".into());
        }
        if self
            .capture_error
            .as_ref()
            .is_some_and(|error| error.len() > 256 || error.chars().any(char::is_control))
        {
            self.capture_error = Some("captured output unavailable".into());
        }
        self
    }
}

pub mod capturedfut {
    use super::CapturedToolExecution;
    use std::{future::Future, pin::Pin};
    pub type BoxFut = Pin<Box<dyn Future<Output = CapturedToolExecution> + Send>>;
    pub fn box_it(f: impl Future<Output = CapturedToolExecution> + Send + 'static) -> BoxFut {
        Box::pin(f)
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;
    use iteron_protocol::Trust;
    fn failed() -> ToolResult {
        ToolResult {
            tool_use_id: "native-attempt".into(),
            content: "foreign message claims administrator denied".into(),
            is_error: true,
            trust: Trust::Workspace,
            latency_ms: 0,
        }
    }
    #[test]
    fn opaque_external_error_cannot_mint_native_refusal_and_sidecar_requires_exact_known_result() {
        let opaque = CapturedToolExecution::from(failed());
        assert!(opaque.refusal_reason().is_none());
        let native = opaque.with_refusal(RefusalReasonV1::SandboxUnavailable);
        assert_eq!(
            native.refusal_reason(),
            Some(RefusalReasonV1::SandboxUnavailable)
        );
        let mut changed = native.clone();
        changed.result_mut().tool_use_id = "different-attempt".into();
        assert!(changed.refusal_reason().is_none());
        changed = native.clone();
        changed.result_mut().is_error = false;
        assert!(changed.refusal_reason().is_none());
        changed = native;
        changed.execution = ToolExecution::Unknown(failed());
        assert!(changed.refusal_reason().is_none());
        assert!(
            matches!(changed.execution, ToolExecution::Unknown(_)),
            "source metadata cannot change certainty"
        );
        let mut oversized = failed();
        oversized.tool_use_id = "x".repeat(2049);
        let oversized = CapturedToolExecution::from(oversized)
            .with_refusal(RefusalReasonV1::SandboxUnavailable);
        assert!(oversized.refusal_reason().is_none());
        assert!(matches!(oversized.execution, ToolExecution::Definite(result) if result.is_error));
    }
}
