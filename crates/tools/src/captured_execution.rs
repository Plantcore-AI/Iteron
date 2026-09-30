//! Host-only data captured before preview caps, kept separate from certainty and authority.

use crate::{
    ToolExecution,
    native_mutation::{NativeFileChange, NativeMutationReceipt},
};
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
    pub native_mutation: Option<NativeMutationReceipt>,
    pub capture_error: Option<String>,
}
impl From<ToolExecution> for CapturedToolExecution {
    fn from(execution: ToolExecution) -> Self {
        Self {
            execution,
            captured_outputs: vec![],
            native_mutation: None,
            capture_error: None,
        }
    }
}
impl CapturedToolExecution {
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
        let definite_success =
            matches!(&self.execution,ToolExecution::Definite(result) if !result.is_error);
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
