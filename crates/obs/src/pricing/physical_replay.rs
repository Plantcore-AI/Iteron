//! Correlate a logical cost sample with an actual sealed physical admission and terminal.
//! Legacy journals have no admission stamp; they retain the prior replay path. Once a sealed
//! intent exists for a turn, missing/unknown/truncated terminal evidence cannot use that fallback.
use super::{PricingError, validate_projection_digest, validate_route};
use iteron_protocol::{
    CostProjection, Event, EventKind, PricingRoute, ProviderRouteAttemptIdentity,
    ProviderRouteCostTruth, ProviderRouteUsageTruth, RunId, TenantId, Usage,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const MAX_SCOPES: usize = 256;
const MAX_ATTEMPTS_PER_SCOPE: usize = 256;
type Scope = (String, String, u32);

struct Admission {
    identity: ProviderRouteAttemptIdentity,
    pricing_at: u64,
    route: Option<PricingRoute>,
    card: Option<String>,
    closed: bool,
}
#[derive(Default)]
struct OpenScope {
    attempts: HashMap<String, Admission>,
    ordinals: HashSet<u32>,
    known: Vec<PhysicalProjection>,
}
struct PhysicalProjection {
    projection: CostProjection,
    bound: bool,
}
struct ModernRun {
    first_turn: u32,
    latest_turn: u32,
}
#[derive(Default)]
pub(super) struct PhysicalPricingReplay {
    scopes: HashMap<Scope, OpenScope>,
    // One bounded content-free frontier per actual run, not a tombstone for every old turn.
    modern_runs: HashMap<(String, String), ModernRun>,
}
/// Owned only until the next event after TurnEnd. It never retains all run history.
pub(super) struct PhysicalTurnProof {
    usage: Usage,
    candidates: Vec<PhysicalProjection>,
}
impl PhysicalTurnProof {
    pub(super) fn matching_binding(&self, projection: &CostProjection) -> Option<bool> {
        if self.usage != projection.usage {
            return None;
        }
        self.candidates
            .iter()
            .find(|candidate| candidate.projection == *projection)
            .map(|candidate| candidate.bound)
    }
}
impl PhysicalPricingReplay {
    pub(super) fn observe(
        &mut self,
        event: &Event,
        tenant: &TenantId,
        run: &RunId,
        route: Option<&PricingRoute>,
        active_card: Option<&str>,
    ) -> Result<(), PricingError> {
        match &event.kind {
            EventKind::EffectIntent {
                id,
                tool,
                arguments,
                provider_route_attempt,
                ..
            } if tool == "provider" && arguments.get("provider_pricing_at_unix_secs").is_some() => {
                valid_scope(tenant, run)?;
                if id.0.is_empty() || id.0.len() > 256 {
                    return Err(PricingError::InvalidField("physical_effect_id"));
                }
                let pricing_at = arguments["provider_pricing_at_unix_secs"]
                    .as_u64()
                    .ok_or(PricingError::InvalidField("physical_pricing_admission"))?;
                let identity = provider_route_attempt
                    .as_ref()
                    .ok_or(PricingError::ProjectionIdentityMismatch)?;
                identity
                    .validate()
                    .map_err(|_| PricingError::ProjectionIdentityMismatch)?;
                if let Some(route) = route {
                    validate_route(route)?;
                    if route_hash(route) != identity.route_id {
                        return Err(PricingError::ProjectionIdentityMismatch);
                    }
                }
                let run_key = (tenant.0.clone(), run.0.clone());
                if !self.modern_runs.contains_key(&run_key) && self.modern_runs.len() >= MAX_SCOPES
                {
                    return Err(PricingError::InvalidField("physical_pricing_run_bound"));
                }
                let frontier = self.modern_runs.entry(run_key).or_insert(ModernRun {
                    first_turn: event.turn.0,
                    latest_turn: event.turn.0,
                });
                if event.turn.0 < frontier.latest_turn {
                    return Err(PricingError::ProjectionIdentityMismatch);
                }
                frontier.latest_turn = event.turn.0;
                // Missing-usage responses deliberately have no TurnEnd. A real newer stamped
                // admission retires their fully closed physical proof, while the run frontier
                // prevents an old/fabricated TurnEnd from using legacy counter matching.
                self.scopes
                    .retain(|(scope_tenant, scope_run, scope_turn), open| {
                        scope_tenant != &tenant.0
                            || scope_run != &run.0
                            || *scope_turn >= event.turn.0
                            || open.attempts.values().any(|attempt| !attempt.closed)
                    });
                let scope = (tenant.0.clone(), run.0.clone(), event.turn.0);
                if !self.scopes.contains_key(&scope) && self.scopes.len() >= MAX_SCOPES {
                    return Err(PricingError::InvalidField("physical_pricing_scope_bound"));
                }
                let open = self.scopes.entry(scope).or_default();
                if open.attempts.len() >= MAX_ATTEMPTS_PER_SCOPE
                    || open.attempts.contains_key(&id.0)
                    || !open.ordinals.insert(identity.physical_attempt)
                {
                    return Err(PricingError::DuplicateProjection);
                }
                open.attempts.insert(
                    id.0.clone(),
                    Admission {
                        identity: identity.clone(),
                        pricing_at,
                        route: route.cloned(),
                        card: active_card.map(str::to_owned),
                        closed: false,
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
                let scope = (tenant.0.clone(), run.0.clone(), event.turn.0);
                let Some(open) = self.scopes.get_mut(&scope) else {
                    return Ok(());
                };
                let Some(admission) = open.attempts.get_mut(&id.0) else {
                    // A historical sibling intent may exist in a partly upgraded turn. It cannot
                    // establish modern logical pricing, but is still left readable.
                    return Ok(());
                };
                if admission.closed {
                    return Err(PricingError::DuplicateProjection);
                }
                admission.closed = true;
                let accounting = provider_route_attempt
                    .as_ref()
                    .ok_or(PricingError::ProjectionIdentityMismatch)?;
                accounting
                    .validate()
                    .map_err(|_| PricingError::ProjectionIdentityMismatch)?;
                let zero = matches!(
                    (&accounting.usage, &accounting.cost),
                    (
                        ProviderRouteUsageTruth::NotDispatched,
                        ProviderRouteCostTruth::NotDispatched
                    )
                );
                if accounting.version != admission.identity.version
                    || accounting.route_id != admission.identity.route_id
                    || accounting.physical_attempt != admission.identity.physical_attempt
                    || (accounting.max_cost_reservation_microusd
                        != admission.identity.max_cost_reservation_microusd
                        && !(zero && accounting.max_cost_reservation_microusd.is_none()))
                {
                    return Err(PricingError::ProjectionIdentityMismatch);
                }
                // OutcomeUnknown never establishes a definite physical usage sample.
                if matches!(&event.kind, EventKind::EffectUnknown { .. }) {
                    return Ok(());
                }
                let (
                    ProviderRouteUsageTruth::Known { usage },
                    ProviderRouteCostTruth::Known {
                        amount_microusd,
                        rate_card_digest,
                        projection: Some(projection),
                    },
                ) = (&accounting.usage, &accounting.cost)
                else {
                    return Ok(());
                };
                validate_projection_digest(projection)?;
                let identity = projection
                    .identity
                    .as_ref()
                    .ok_or(PricingError::MissingProjectionIdentity)?;
                if identity.tenant_id != tenant.0
                    || identity.run_id != run.0
                    || identity.turn_id != event.turn.0
                    || identity.provider_attempt != admission.identity.physical_attempt
                    || projection.projected_at_unix_secs != admission.pricing_at
                    || projection.usage != *usage
                    || projection.amount_microusd != *amount_microusd
                    || projection.rate_card_digest != *rate_card_digest
                    || route_hash(&projection.route) != admission.identity.route_id
                    || admission
                        .route
                        .as_ref()
                        .is_some_and(|route| *route != projection.route)
                    || admission
                        .card
                        .as_ref()
                        .is_some_and(|card| *card != projection.rate_card_digest)
                {
                    return Err(PricingError::ProjectionIdentityMismatch);
                }
                open.known.push(PhysicalProjection {
                    projection: projection.as_ref().clone(),
                    bound: admission.route.is_some() && admission.card.is_some(),
                });
            }
            _ => {}
        }
        Ok(())
    }
    pub(super) fn finish(
        &mut self,
        tenant: &TenantId,
        run: &RunId,
        turn: u32,
        usage: Usage,
    ) -> Option<PhysicalTurnProof> {
        let scope = (tenant.0.clone(), run.0.clone(), turn);
        if let Some(open) = self.scopes.remove(&scope) {
            return Some(PhysicalTurnProof {
                usage,
                candidates: open.known,
            });
        }
        self.modern_runs
            .get(&(tenant.0.clone(), run.0.clone()))
            .filter(|frontier| turn >= frontier.first_turn && turn <= frontier.latest_turn)
            .map(|_| PhysicalTurnProof {
                usage,
                candidates: Vec::new(),
            })
    }
}
fn valid_scope(tenant: &TenantId, run: &RunId) -> Result<(), PricingError> {
    if tenant.0.is_empty()
        || tenant.0.len() > 512
        || run.0.is_empty()
        || run.0.len() > 200
        || tenant.0.chars().chain(run.0.chars()).any(char::is_control)
    {
        Err(PricingError::InvalidField("physical_pricing_scope"))
    } else {
        Ok(())
    }
}
fn route_hash(route: &PricingRoute) -> String {
    let mut digest = Sha256::new();
    digest.update(b"iteron-provider-route-attempt-v1\0");
    digest.update(format!("{}:{}", route.provider_id, route.model_id).as_bytes());
    format!("sha256:{:x}", digest.finalize())
}
