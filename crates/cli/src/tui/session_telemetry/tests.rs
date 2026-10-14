use super::{ProviderTurnTelemetry, SessionTelemetry};
use crate::tui::Session;
use iteron_ctx::{ContextEstimate, TokenEstimateProvenance};
use iteron_obs::{CostState, CostUnknownReason};
use iteron_protocol::{ReasoningEffort, Usage};
use iteron_provider::EffortApplication;

fn observation() -> ProviderTurnTelemetry {
    ProviderTurnTelemetry {
        cost: CostState::Unknown {
            reason: CostUnknownReason::NoVerifiedRateCard,
        },
        usage: Usage {
            input: 700,
            cache_read: 100,
            ..Usage::default()
        },
        context: ContextEstimate {
            system_tokens: 200,
            tool_tokens: 200,
            conversation_tokens: 400,
            tool_result_tokens: 0,
            lsp_result_tokens: 0,
            transcript_tokens: 400,
            framing_tokens: 0,
            total_tokens: 800,
            provenance: TokenEstimateProvenance::HeuristicBytesPerToken35,
            components: None,
        },
        model_context_window: Some(1_000),
        reserved_output_tokens: 200,
        compaction_trigger_tokens: 750,
        effort: EffortApplication::Unsupported {
            requested: ReasoningEffort::High,
        },
    }
}
fn snapshot() -> crate::app_server::SessionSnapshot {
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    Session::for_test(sender).state
}

#[test]
fn catalog_capacity_without_a_request_never_becomes_measured_full_headroom() {
    let mut owner = SessionTelemetry::default();
    owner.bind_model_capacity(Some(1_000));
    assert_eq!(owner.window(), Some(1_000));
    assert_eq!(owner.context_remaining_percent(), None);
    assert_eq!(owner.admission_headroom(), None);
    assert_eq!(owner.usage(), None);
}

#[test]
fn actual_request_fields_stay_together_and_unpriced_usage_does_not_become_dollars() {
    let mut owner = SessionTelemetry::default();
    owner.observe_provider_turn(observation());
    assert_eq!(owner.cost().usd(), None);
    assert_eq!(owner.turns(), 1);
    assert_eq!(owner.reserve(), Some(200));
    assert_eq!(owner.trigger(), 750);
    assert_eq!(owner.admission_headroom(), Some(0));
    assert_eq!(owner.context_remaining_percent(), Some(0));
    assert_eq!(
        owner.effort(),
        Some(EffortApplication::Unsupported {
            requested: ReasoningEffort::High
        })
    );
    let mut observed = snapshot();
    observed.cost = owner.cost().clone();
    observed.last_turn_usage = owner.usage();
    owner.refresh_economics(&observed);
    assert_eq!(
        owner.turns(),
        1,
        "a terminal snapshot does not count the same request twice"
    );
    assert_eq!(owner.admission_headroom(), Some(0));
}

#[test]
fn verified_selected_run_replaces_old_economics_and_all_request_specific_evidence() {
    let mut owner = SessionTelemetry::default();
    owner.observe_provider_turn(observation());
    let observed = snapshot();
    owner.bind_run(&observed, 12, Some(2_000), 1_500);
    assert_eq!(owner.cost(), &observed.cost);
    assert_eq!(owner.usage(), observed.last_turn_usage);
    assert_eq!(owner.turns(), 12);
    assert_eq!(owner.window(), Some(2_000));
    assert_eq!(owner.trigger(), 1_500);
    assert_eq!(owner.context(), None);
    assert_eq!(owner.reserve(), None);
    assert_eq!(owner.effort(), None);
    assert_eq!(owner.admission_headroom(), None);
    assert_eq!(owner.context_remaining_percent(), None);
}

#[test]
fn route_transition_preserves_only_host_retained_usage_and_cannot_reuse_old_preflight() {
    let mut owner = SessionTelemetry::default();
    owner.observe_provider_turn(observation());
    let mut observed = snapshot();
    observed.last_turn_usage = owner.usage();
    owner.invalidate_request(&observed);
    assert_eq!(owner.usage(), observed.last_turn_usage);
    assert_eq!(owner.context(), None);
    assert_eq!(owner.effort(), None);
    assert_eq!(owner.admission_headroom(), None);
    owner.bind_model_capacity(None);
    assert_eq!(owner.context_remaining_percent(), None);
}
