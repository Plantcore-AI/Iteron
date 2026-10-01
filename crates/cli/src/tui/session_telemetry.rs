//! Private observed session economics and exact-request telemetry. Renderers cannot write a
//! provider observation, infer pricing or turn a static catalog capacity into measured usage.
use crate::app_server::SessionSnapshot;
use iteron_ctx::ContextEstimate;
use iteron_obs::CostState;
use iteron_protocol::Usage;
use iteron_provider::EffortApplication;

pub(super) struct ProviderTurnTelemetry {
    pub(super) cost: CostState,
    pub(super) usage: Usage,
    pub(super) context: ContextEstimate,
    pub(super) model_context_window: Option<u64>,
    pub(super) reserved_output_tokens: u32,
    pub(super) compaction_trigger_tokens: usize,
    pub(super) effort: EffortApplication,
}

pub(super) struct SessionTelemetry {
    cost: CostState,
    usage: Option<Usage>,
    context: Option<ContextEstimate>,
    window: Option<u64>,
    reserve: Option<u32>,
    trigger: usize,
    effort: Option<EffortApplication>,
    completed_turns: u32,
}
impl Default for SessionTelemetry {
    fn default() -> Self {
        Self {
            cost: CostState::Zero,
            usage: None,
            context: None,
            window: None,
            reserve: None,
            trigger: iteron_ctx::CompactionPolicy::default().trigger_tokens,
            effort: None,
            completed_turns: 0,
        }
    }
}
impl SessionTelemetry {
    pub(super) fn observe_provider_turn(&mut self, observed: ProviderTurnTelemetry) {
        self.cost = observed.cost;
        self.usage = Some(observed.usage);
        self.context = Some(observed.context);
        self.window = observed.model_context_window;
        self.reserve = Some(observed.reserved_output_tokens);
        self.trigger = observed.compaction_trigger_tokens;
        self.effort = Some(observed.effort);
        self.completed_turns = self.completed_turns.saturating_add(1);
    }
    /// Terminal/control replies can refresh settled economics without inventing another turn.
    pub(super) fn refresh_economics(&mut self, snapshot: &SessionSnapshot) {
        self.cost = snapshot.cost.clone();
        self.usage = snapshot.last_turn_usage;
    }
    /// A selected run replaces all request-specific evidence. Capacity comes from the actual
    /// captured route; usage comes only from the host snapshot, never the prior selected run.
    pub(super) fn bind_run(
        &mut self,
        snapshot: &SessionSnapshot,
        completed_turns: u32,
        window: Option<u64>,
        trigger: usize,
    ) {
        self.refresh_economics(snapshot);
        self.completed_turns = completed_turns;
        self.window = window;
        self.trigger = trigger;
        self.invalidate_request(snapshot);
    }
    pub(super) fn bind_model_capacity(&mut self, window: Option<u64>) {
        self.window = window;
    }
    /// A durable route/effort transition invalidates preflight and serialized-effort evidence.
    /// A published last usage remains whatever the same host actually retained in its snapshot.
    pub(super) fn invalidate_request(&mut self, snapshot: &SessionSnapshot) {
        self.usage = snapshot.last_turn_usage;
        self.context = None;
        self.reserve = None;
        self.effort = None;
    }
    pub(super) fn cost(&self) -> &CostState {
        &self.cost
    }
    pub(super) fn usage(&self) -> Option<Usage> {
        self.usage
    }
    pub(super) fn context(&self) -> Option<ContextEstimate> {
        self.context
    }
    pub(super) fn window(&self) -> Option<u64> {
        self.window
    }
    pub(super) fn reserve(&self) -> Option<u32> {
        self.reserve
    }
    pub(super) fn trigger(&self) -> usize {
        self.trigger
    }
    pub(super) fn effort(&self) -> Option<EffortApplication> {
        self.effort
    }
    pub(super) fn turns(&self) -> u32 {
        self.completed_turns
    }
    pub(super) fn admission_headroom(&self) -> Option<u64> {
        let window = self.window.filter(|window| *window > 0)?;
        let input = u64::try_from(self.context?.total_tokens).unwrap_or(u64::MAX);
        let reserve = self.reserve?;
        Some(window.saturating_sub(input.saturating_add(u64::from(reserve))))
    }
    pub(super) fn context_remaining_percent(&self) -> Option<u8> {
        let window = self.window.filter(|window| *window > 0)?;
        let input = self
            .context
            .map(|context| u64::try_from(context.total_tokens).unwrap_or(u64::MAX))
            .or_else(|| self.usage.map(super::request_input_tokens))?;
        let used = input.saturating_add(u64::from(self.reserve.unwrap_or_default()));
        let remaining = u128::from(window.saturating_sub(used)) * 100 / u128::from(window);
        Some(u8::try_from(remaining.min(100)).unwrap_or(100))
    }
}

#[cfg(test)]
mod tests;
