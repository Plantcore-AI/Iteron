//! Single declaration-ordered tool-result working set. Physical executors settle their effects
//! independently; this owner refuses incomplete or substituted results at the transcript edge.
use super::KernelError;
use super::frontend_events::UiEvent;
use super::submitted_turn_state::SubmittedTurnState;
use super::tool_images::PendingToolImageProjection;
use super::tool_presentation::tool_end_ui;
use iteron_protocol::{Block, Message, Role, ToolResult, ToolUse};
use std::collections::BTreeMap;

pub(super) struct ToolResponseSink<'a> {
    pub(super) results: &'a mut Vec<Option<ToolResult>>,
    pub(super) any_error: &'a mut bool,
    pub(super) images: &'a mut Vec<PendingToolImageProjection>,
}

pub(super) struct ToolResponseOwner {
    declarations: std::sync::Arc<[ToolUse]>,
    results: Vec<Option<ToolResult>>,
    any_error: bool,
    images: Vec<PendingToolImageProjection>,
}

pub(super) struct ToolResponseParts {
    pub(super) message: ToolResponseMessage,
    pub(super) images: Vec<PendingToolImageProjection>,
}

/// Only already-authenticated model image projections may be appended by the host. This owner
/// controls the finite response envelope; it never hydrates pixels or invents image provenance.
pub(super) struct ToolResponseMessage {
    blocks: Vec<Block>,
}

impl ToolResponseOwner {
    #[cfg(test)]
    pub(super) fn new(declarations: &[ToolUse]) -> Self {
        Self::retain(declarations.into())
    }

    pub(super) fn retain(declarations: std::sync::Arc<[ToolUse]>) -> Self {
        let count = declarations.len();
        Self {
            declarations,
            results: (0..count).map(|_| None).collect(),
            any_error: false,
            images: Vec::new(),
        }
    }

    pub(super) fn replay(
        &mut self,
        recovered: BTreeMap<usize, ToolResult>,
    ) -> Result<Vec<UiEvent>, KernelError> {
        let mut events = Vec::with_capacity(recovered.len());
        for (index, result) in recovered {
            let call = self.declarations.get(index).ok_or_else(boundary_error)?;
            self.validate_result(index, &result)?;
            events.push(tool_end_ui(call, &result));
            self.accept(index, result)?;
        }
        Ok(events)
    }

    pub(super) fn sink(&mut self) -> ToolResponseSink<'_> {
        ToolResponseSink {
            results: &mut self.results,
            any_error: &mut self.any_error,
            images: &mut self.images,
        }
    }

    pub(super) fn has_result(&self, index: usize) -> Result<bool, KernelError> {
        self.results
            .get(index)
            .map(Option::is_some)
            .ok_or_else(boundary_error)
    }

    pub(super) fn accept(&mut self, index: usize, result: ToolResult) -> Result<(), KernelError> {
        self.validate_result(index, &result)?;
        self.any_error |= result.is_error;
        self.results[index] = Some(result);
        Ok(())
    }

    pub(super) fn retain_image(&mut self, image: Option<PendingToolImageProjection>) {
        if let Some(image) = image {
            self.images.push(image);
        }
    }

    pub(super) fn has_images(&self) -> bool {
        !self.images.is_empty()
    }
    pub(super) fn results(&self) -> &[Option<ToolResult>] {
        &self.results
    }

    pub(super) fn had_error(&self) -> bool {
        self.any_error || self.results.iter().flatten().any(|result| result.is_error)
    }

    pub(super) fn schemas_changed(&self) -> bool {
        self.declarations
            .iter()
            .zip(&self.results)
            .any(|(call, result)| {
                call.name == "tool_search" && result.as_ref().is_some_and(|result| !result.is_error)
            })
    }

    /// Validate every result before optional verification or recovery mutates other owners. A
    /// missing slot must never silently vanish through flatten() into a dangling model call.
    pub(super) fn validate_complete(&self) -> Result<(), KernelError> {
        if self.results.len() != self.declarations.len() {
            return Err(boundary_error());
        }
        for (call, result) in self.declarations.iter().zip(&self.results) {
            if result
                .as_ref()
                .is_none_or(|result| result.tool_use_id != call.id)
            {
                return Err(boundary_error());
            }
        }
        Ok(())
    }

    pub(super) fn retain_recovery(
        &self,
        state: &mut SubmittedTurnState,
    ) -> Result<(), KernelError> {
        self.validate_complete()?;
        for (call, result) in self.declarations.iter().zip(&self.results) {
            state.retain_recovered_tool(call, result.as_ref().expect("validated complete slot"))?;
        }
        Ok(())
    }

    pub(super) fn into_parts(self) -> Result<ToolResponseParts, KernelError> {
        self.validate_complete()?;
        Ok(ToolResponseParts {
            message: ToolResponseMessage {
                blocks: self
                    .results
                    .into_iter()
                    .map(|result| Block::ToolResult(result.expect("validated complete slot")))
                    .collect(),
            },
            images: self.images,
        })
    }

    fn validate_result(&self, index: usize, result: &ToolResult) -> Result<(), KernelError> {
        let call = self.declarations.get(index).ok_or_else(boundary_error)?;
        if result.tool_use_id != call.id
            || self.results.get(index).is_none_or(|slot| slot.is_some())
        {
            return Err(boundary_error());
        }
        Ok(())
    }
}

impl ToolResponseMessage {
    /// Returns true only when actual retained projections exceed this one model message's cap.
    pub(super) fn append_images(&mut self, projected: Vec<Block>) -> bool {
        let remaining = iteron_protocol::tool_image::MAX_TOOL_IMAGES_PER_MESSAGE.saturating_sub(
            self.blocks
                .iter()
                .filter(|block| matches!(block, Block::ToolImage(_)))
                .count(),
        );
        let exceeded = projected.len() > remaining;
        self.blocks.extend(projected.into_iter().take(remaining));
        exceeded
    }

    pub(super) fn guidance(&mut self, text: String) {
        self.blocks.push(Block::Text { text });
    }

    pub(super) fn into_message(self) -> Message {
        Message {
            role: Role::User,
            content: self.blocks,
        }
    }
}

fn boundary_error() -> KernelError {
    KernelError::EffectBoundary("tool response does not match its complete declaration set".into())
}

#[cfg(test)]
#[path = "tool_response_tests.rs"]
mod tests;
