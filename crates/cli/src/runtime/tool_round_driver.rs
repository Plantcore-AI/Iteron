//! Single mutable completed-response tool phase. Real early handles, the selected batch,
//! ordered declarations and settled response slots have one owner across physical awaits.
use super::KernelError;
use super::deferred_batch_admission::DeferredBatchAdmission;
use super::deferred_tools::{AutoApprovedCall, DeferredBatchPolicy};
use super::early_tool_collection::{EarlyToolCollection, EarlyToolWindow};
use super::frontend_events::UiEvent;
use super::submitted_turn_state::SubmittedTurnState;
use super::tool_images::PendingToolImageProjection;
use super::tool_response::{ToolResponseOwner, ToolResponseParts};
use super::tool_turn::{DeferredToolCall, EarlyToolInFlight, ToolTurnWork};
use iteron_protocol::{ToolResult, ToolUse};
use std::collections::{BTreeSet, VecDeque};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ToolRoundPhase {
    Retained,
    EarlyPending,
    EarlySettled,
    BatchPending,
    Ordered,
    Failed,
    Completed,
}
pub(super) struct ToolRoundDriver {
    phase: ToolRoundPhase,
    early: Vec<EarlyToolInFlight>,
    window: Option<EarlyToolWindow>,
    deferred: VecDeque<DeferredToolCall>,
    selected_batch: Option<Vec<AutoApprovedCall>>,
    active: Option<usize>,
    response: Option<ToolResponseOwner>,
}
impl ToolRoundDriver {
    #[cfg(test)]
    pub(super) fn retain(
        declarations: &[ToolUse],
        work: ToolTurnWork,
        window: EarlyToolWindow,
    ) -> Result<(Self, Vec<UiEvent>), KernelError> {
        Self::retain_owned(declarations.into(), work, window)
    }
    pub(super) fn retain_owned(
        declarations: std::sync::Arc<[ToolUse]>,
        work: ToolTurnWork,
        window: EarlyToolWindow,
    ) -> Result<(Self, Vec<UiEvent>), KernelError> {
        let ToolTurnWork {
            early,
            mut deferred,
            replayed,
        } = work;
        for (index, call, _) in &deferred {
            if declarations
                .get(*index)
                .is_none_or(|declared| declared != call)
            {
                return Err(boundary());
            }
        }
        // Recovered physical receipts are immutable. They retain exact declaration IDs and never
        // enter the ordered/batch executor queue again.
        deferred.retain(|(index, ..)| !replayed.contains_key(index));
        let mut response = ToolResponseOwner::retain(declarations);
        let events = response.replay(replayed)?;
        Ok((
            Self {
                phase: ToolRoundPhase::Retained,
                early,
                window: Some(window),
                deferred: deferred.into(),
                selected_batch: None,
                active: None,
                response: Some(response),
            },
            events,
        ))
    }
    pub(super) async fn collect_early(
        &mut self,
        collection: EarlyToolCollection<'_>,
    ) -> Result<usize, KernelError> {
        self.require(ToolRoundPhase::Retained)?;
        // Cancellation cannot rearm consumed task ownership. EarlyToolTask's existing Drop
        // revokes every retained physical task, including those inside the collection future.
        self.phase = ToolRoundPhase::EarlyPending;
        let early = std::mem::take(&mut self.early);
        let window = self.window.take().ok_or_else(boundary)?;
        let sink = self
            .response
            .as_mut()
            .expect("retained response owner")
            .sink();
        match collection
            .collect(early, window, sink.results, sink.any_error, sink.images)
            .await
        {
            Ok(unknown) => {
                self.phase = if unknown == 0 {
                    ToolRoundPhase::EarlySettled
                } else {
                    ToolRoundPhase::Failed
                };
                Ok(unknown)
            }
            Err(error) => {
                self.phase = ToolRoundPhase::Failed;
                Err(error)
            }
        }
    }
    /// Select once and retain the actual permitted proposals internally. The host receives only
    /// whether a concurrent prefix exists, never a duplicate queue or replacement proposal.
    pub(super) fn select_batch(
        &mut self,
        policy: DeferredBatchPolicy<'_>,
        excluded: &BTreeSet<usize>,
    ) -> Result<bool, KernelError> {
        self.require(ToolRoundPhase::EarlySettled)?;
        self.phase = ToolRoundPhase::Failed;
        let batch = policy.select(self.deferred.make_contiguous(), excluded)?;
        if batch.len() > 1 {
            self.selected_batch = Some(batch);
            self.phase = ToolRoundPhase::BatchPending;
            Ok(true)
        } else {
            self.phase = ToolRoundPhase::Ordered;
            Ok(false)
        }
    }
    pub(super) async fn execute_batch(
        &mut self,
        admission: DeferredBatchAdmission<'_>,
    ) -> Result<(), KernelError> {
        self.require(ToolRoundPhase::BatchPending)?;
        self.phase = ToolRoundPhase::Failed;
        let batch = self.selected_batch.take().ok_or_else(boundary)?;
        let sink = self
            .response
            .as_mut()
            .expect("retained response owner")
            .sink();
        admission
            .run(batch, sink.results, sink.any_error, sink.images)
            .await?;
        self.phase = ToolRoundPhase::Ordered;
        Ok(())
    }
    /// Ordered dispatch cannot advance while its preceding declaration lacks a real result.
    /// Replayed and batch-settled calls are skipped only from the same validated response owner.
    pub(super) fn next_declaration(&mut self) -> Result<Option<DeferredToolCall>, KernelError> {
        self.require(ToolRoundPhase::Ordered)?;
        if self.active.is_some() {
            return Err(boundary());
        }
        while let Some((index, call, proposal)) = self.deferred.pop_front() {
            if self.response().has_result(index)? {
                continue;
            }
            self.active = Some(index);
            return Ok(Some((index, call, proposal)));
        }
        Ok(None)
    }
    pub(super) fn accept(&mut self, index: usize, result: ToolResult) -> Result<(), KernelError> {
        self.require(ToolRoundPhase::Ordered)?;
        if self.active != Some(index) {
            return Err(boundary());
        }
        self.response
            .as_mut()
            .expect("retained response owner")
            .accept(index, result)?;
        self.active = None;
        Ok(())
    }
    pub(super) fn accept_ordered(
        &mut self,
        index: usize,
        result: ToolResult,
        image: Option<PendingToolImageProjection>,
    ) -> Result<(), KernelError> {
        self.accept(index, result)?;
        self.response
            .as_mut()
            .expect("retained response owner")
            .retain_image(image);
        Ok(())
    }
    pub(super) fn validate_complete(&self) -> Result<(), KernelError> {
        self.require(ToolRoundPhase::Ordered)?;
        if self.active.is_some() || !self.deferred.is_empty() {
            return Err(boundary());
        }
        self.response().validate_complete()
    }
    pub(super) fn has_images(&self) -> bool {
        self.response().has_images()
    }
    pub(super) fn results(&self) -> &[Option<ToolResult>] {
        self.response().results()
    }
    pub(super) fn had_error(&self) -> bool {
        self.response().had_error()
    }
    pub(super) fn schemas_changed(&self) -> bool {
        self.response().schemas_changed()
    }
    pub(super) fn retain_recovery(
        &self,
        state: &mut SubmittedTurnState,
    ) -> Result<(), KernelError> {
        self.validate_complete()?;
        self.response().retain_recovery(state)
    }
    pub(super) fn into_parts(mut self) -> Result<ToolResponseParts, KernelError> {
        self.validate_complete()?;
        self.phase = ToolRoundPhase::Completed;
        self.response
            .take()
            .expect("retained response owner")
            .into_parts()
    }
    fn response(&self) -> &ToolResponseOwner {
        self.response.as_ref().expect("retained response owner")
    }
    fn require(&self, phase: ToolRoundPhase) -> Result<(), KernelError> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(boundary())
        }
    }
}
fn boundary() -> KernelError {
    KernelError::EffectBoundary(
        "tool round cannot advance outside its retained physical phase".into(),
    )
}
