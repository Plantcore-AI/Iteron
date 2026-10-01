//! Durable model-selection transaction shared by all operator clients.

use super::control::snapshot_of;
use super::{Agent, ControlReply, EventPublisher, ModelSelection, ServerEvent};

pub(super) async fn apply(
    agent: &mut Agent,
    events: &mut EventPublisher,
    selection: ModelSelection,
) -> ControlReply {
    // One transaction, in the kernel's required order: the durable audit append happens
    // FIRST, so a failure leaves the old selection in force rather than a half-applied one.
    let ModelSelection {
        provider,
        provider_id,
        model_id,
        catalog_digest,
        capability_digest,
        context_window_tokens,
        max_output_tokens,
    } = selection;
    let changed = agent.model != model_id;
    match agent.record_operator_model_selection(
        provider,
        provider_id,
        model_id,
        catalog_digest,
        capability_digest,
    ) {
        Ok(()) => {
            agent.model_context_window = context_window_tokens;
            agent.model_max_output_tokens = max_output_tokens;
            if changed {
                // Last-turn usage belongs to the model that produced it. Carrying it across
                // a switch would print the old model's token counts under the new one's
                // name; the frontend used to clear this itself, back when it held the
                // ledger.
                agent.ledger.last_turn_usage = None;
            }
            if let Err(error) = agent.refresh_persistent_native_context(iteron_protocol::TurnId(0))
            {
                let _ = events
                    .publish(ServerEvent::Notice(format!(
                        "child model configuration unavailable: {}",
                        error.public_summary()
                    )))
                    .await;
            }
            match agent.bind_selected_rate_card() {
                Ok(bound) => {
                    if !bound && agent.budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) {
                        // Advisory, not a refusal: the route is recorded and in force. The
                        // operator needs to know the ceiling will stop provider calls, so it
                        // goes out on the EQ where every other runtime advisory goes.
                        let _ = events
                            .publish(ServerEvent::Notice(
                                "selected route has no active verified rate card; the USD \
                                         ceiling will block provider calls"
                                    .into(),
                            ))
                            .await;
                    }
                    ControlReply::State(Box::new(snapshot_of(agent)))
                }
                Err(error) => {
                    // ModelSelected is already committed. RateCardBound failure retains the
                    // actual journal poison and admission refusal, but cannot restore the old
                    // route or make presentation repeat the committed model transaction.
                    let _ = events
                        .publish(ServerEvent::Notice(format!(
                            "model selected; rate-card binding failed: {}",
                            error.public_summary()
                        )))
                        .await;
                    ControlReply::State(Box::new(snapshot_of(agent)))
                }
            }
        }
        Err(error) => ControlReply::Refused(format!(
            "cannot record model switch; old selection retained: {error}"
        )),
    }
}
