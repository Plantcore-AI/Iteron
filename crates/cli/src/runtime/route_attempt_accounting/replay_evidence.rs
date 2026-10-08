//! Bounded correlation of the actual physical provider WAL. Billing evidence is independent of
//! process/wall recovery state; neither an idle controller nor a recovery label proves a charge.
use iteron_protocol::{
    EventKind, ProviderRouteAttemptAccounting, ProviderRouteAttemptIdentity,
    ProviderRouteCostTruth, ProviderRouteUsageTruth, RunId, TenantId, TurnId,
};
use iteron_record::ScopedEvent;
use std::collections::{BTreeMap, BTreeSet};

const MAX_PHYSICAL_ATTEMPTS: usize = 65_536;
type Key<'a> = (&'a str, &'a str, &'a str);
struct Attempt<'a> {
    turn: TurnId,
    identity: Option<&'a ProviderRouteAttemptIdentity>,
    terminal: Option<&'a ProviderRouteAttemptAccounting>,
    closed: bool,
    pricing_at: Option<u64>,
}
pub(in crate::runtime) struct ProviderReplayEvidence<'a> {
    attempts: BTreeMap<Key<'a>, Attempt<'a>>,
    invalid: bool,
}
impl<'a> ProviderReplayEvidence<'a> {
    pub(in crate::runtime) fn inspect(events: &'a [ScopedEvent]) -> Self {
        let mut result = Self {
            attempts: BTreeMap::new(),
            invalid: false,
        };
        let mut physical = BTreeSet::new();
        for row in events {
            match &row.event.kind {
                EventKind::EffectIntent {
                    id,
                    tool,
                    provider_route_attempt,
                    arguments,
                    ..
                } if tool == "provider" => {
                    let key = (row.tenant.0.as_str(), row.run_id.0.as_str(), id.0.as_str());
                    if result.attempts.len() >= MAX_PHYSICAL_ATTEMPTS
                        || id.0.is_empty()
                        || id.0.len() > 256
                        || result.attempts.contains_key(&key)
                    {
                        result.invalid = true;
                        continue;
                    }
                    if let Some(identity) = provider_route_attempt
                        && (identity.validate().is_err()
                            || !physical.insert((
                                key.0,
                                key.1,
                                row.event.turn.0,
                                identity.physical_attempt,
                            )))
                    {
                        result.invalid = true;
                    }
                    let pricing_at = arguments
                        .get("provider_pricing_at_unix_secs")
                        .and_then(serde_json::Value::as_u64);
                    if arguments.get("provider_pricing_at_unix_secs").is_some()
                        && pricing_at.is_none()
                    {
                        result.invalid = true;
                    }
                    result.attempts.insert(
                        key,
                        Attempt {
                            turn: row.event.turn,
                            identity: provider_route_attempt.as_ref(),
                            terminal: None,
                            closed: false,
                            pricing_at,
                        },
                    );
                }
                EventKind::EffectDone {
                    id,
                    tool,
                    provider_route_attempt,
                    ..
                }
                | EventKind::EffectFailed {
                    id,
                    tool,
                    provider_route_attempt,
                    ..
                }
                | EventKind::EffectUnknown {
                    id,
                    tool,
                    provider_route_attempt,
                    ..
                } if tool == "provider" => {
                    let key = (row.tenant.0.as_str(), row.run_id.0.as_str(), id.0.as_str());
                    let Some(attempt) = result.attempts.get_mut(&key) else {
                        // Historical logical-only journals remain readable; a physical terminal
                        // without its intent cannot authorize a restored hard monetary ceiling.
                        result.invalid = true;
                        continue;
                    };
                    if attempt.closed || attempt.turn != row.event.turn {
                        result.invalid = true;
                        continue;
                    }
                    attempt.closed = true;
                    attempt.terminal = provider_route_attempt.as_ref();
                    if matches!(&row.event.kind, EventKind::EffectUnknown { .. })
                        && attempt.terminal.is_some_and(|terminal| {
                            matches!(
                                terminal.cost,
                                ProviderRouteCostTruth::Known { .. }
                                    | ProviderRouteCostTruth::NotDispatched
                            )
                        })
                    {
                        result.invalid = true;
                    }
                    match (attempt.identity, attempt.terminal) {
                        (Some(identity), Some(terminal)) => {
                            if terminal.validate().is_err()
                                || !matches_identity(identity, terminal)
                                || matches!(&terminal.cost, ProviderRouteCostTruth::Known { projection: Some(projection), .. }
                                    if attempt.pricing_at.is_some_and(|stamp| stamp != projection.projected_at_unix_secs))
                            {
                                result.invalid = true;
                            }
                        }
                        (None, None) => {}
                        _ => result.invalid = true,
                    }
                }
                _ => {}
            }
        }
        result
    }
    pub(in crate::runtime) fn has_unknown(&self) -> bool {
        self.invalid || self.attempts.values().any(|attempt| !attempt.closed)
    }
    pub(in crate::runtime) fn matching_terminal(
        &self,
        tenant: &TenantId,
        run: &RunId,
        effect: &str,
        turn: u32,
        expected: &ProviderRouteAttemptIdentity,
    ) -> Option<&'a ProviderRouteAttemptAccounting> {
        if self.invalid {
            return None;
        }
        let attempt = self
            .attempts
            .get(&(tenant.0.as_str(), run.0.as_str(), effect))?;
        if attempt.turn.0 != turn || attempt.identity != Some(expected) {
            return None;
        }
        attempt.terminal
    }
}
fn matches_identity(
    identity: &ProviderRouteAttemptIdentity,
    terminal: &ProviderRouteAttemptAccounting,
) -> bool {
    let not_dispatched = matches!(
        (&terminal.usage, &terminal.cost),
        (
            ProviderRouteUsageTruth::NotDispatched,
            ProviderRouteCostTruth::NotDispatched
        )
    );
    identity.version == terminal.version
        && identity.route_id == terminal.route_id
        && identity.physical_attempt == terminal.physical_attempt
        && (identity.max_cost_reservation_microusd == terminal.max_cost_reservation_microusd
            || (not_dispatched && terminal.max_cost_reservation_microusd.is_none()))
}
