//! Pure model selection from already-resolved route evidence; no catalog or credential IO.
use super::{MAX_RESOLVED_ROUTES, MAX_ROUTE_MODEL_BYTES, MODEL_ROUTER_SLOT_VERSION};
use serde::Deserialize;
use std::fmt;

// ---------------------------------------------------------------------------------------------
// `core/model_router`: which model a delegated turn is allowed to run on.
// ---------------------------------------------------------------------------------------------

// The pure `core/model_router` strategy behind the frozen [`StrategySlot`] seam.
//
// Delegation is where this repository actually chooses a model. A pinned `AgentDef` may name one,
// a spawn call may name one, and the parent already holds exactly one route it has durable
// evidence for. Until now that choice was two copies of the same hard-coded rule — one in
// `prepare_investigator`, one in the workflow spawner's `build_child` — each of which refused any
// model that was not the parent's, with the reason spelled out in a string literal beside it. A
// vertical pack that resolves a second route could not express that fact without editing the
// runtime.
//
// This makes the choice a slot decision. It chooses; it never resolves anything. No catalog is
// fetched here, no credential is read, no rate card is bound — [`ProviderInstance`] and the
// runtime's durable route selection own all of that, and this module only sees the names the
// caller already has evidence for.
//
// One rule is structural rather than advisory:
//
// **A decision may only pick from the evidence it was shown.** The caller supplies
// `resolved_routes`; a strategy may pick any member, and nothing else. A decision naming a model
// outside that list is rejected by [`ModelRouterStrategy::route_with`], not merely discouraged —
// so a pinned third-party policy cannot conjure a route the caller never resolved, and therefore
// cannot spend a parent's catalog, capability, and price digests under a model identity those
// digests never covered. That is the model-routing analogue of the capability narrowing
// [`decide_narrowed`] performs on the same call, and it is enforced for every implementor rather
// than remembered by each one.
//
// Refusal stays expressible: a strategy that has no opinion returns
// [`ModelRouterDecision::Refuse`], because refusing to route is never a widening.
/// The already-gathered routing evidence for one delegation.
///
/// The caller owns these. A strategy sees only what is here: no credential, no API root, no
/// catalog handle, no pricing port. It has no way to reach the world from inside
/// [`StrategySlot::decide`], which is synchronous and pure.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct ModelRouterObservation {
    pub version: u16,
    /// Every model this caller holds resolved route evidence for, in caller preference order.
    /// Non-empty, and the first entry is the route already bound for the parent turn — the answer
    /// a strategy with no opinion should fall back to.
    pub resolved_routes: Vec<String>,
    /// The model the pinned agent definition asks for, if it asks for one.
    pub definition_model: Option<String>,
    /// The model the spawn call asks for, if it asks for one.
    pub call_model: Option<String>,
}

impl ModelRouterObservation {
    /// The observation a delegation site builds when it holds evidence for exactly one route,
    /// which is every caller in this repository today.
    pub fn single_route(
        route: impl Into<String>,
        definition_model: Option<String>,
        call_model: Option<String>,
    ) -> Self {
        Self {
            version: MODEL_ROUTER_SLOT_VERSION,
            resolved_routes: vec![route.into()],
            definition_model,
            call_model,
        }
    }

    /// The route the caller is already running on: the fallback a strategy is expected to name
    /// when neither the definition nor the call asks for anything.
    pub fn bound_route(&self) -> Option<&str> {
        self.resolved_routes.first().map(String::as_str)
    }

    fn validate(&self) -> Result<(), ModelRouterError> {
        if self.version != MODEL_ROUTER_SLOT_VERSION {
            return Err(ModelRouterError::UnsupportedVersion);
        }
        if self.resolved_routes.is_empty() {
            return Err(ModelRouterError::InvalidObservation(
                "a routing observation must carry at least one resolved route",
            ));
        }
        if self.resolved_routes.len()
            > iteron_tunables::param_usize(
                "provider.catalog.max_resolved_routes",
                iteron_tunables::param_integer(
                    "provider.catalog.max_resolved_routes",
                    MAX_RESOLVED_ROUTES,
                ),
            )
        {
            return Err(ModelRouterError::InvalidObservation(
                "a routing observation carries more resolved routes than the bounded maximum",
            ));
        }
        for model in self
            .resolved_routes
            .iter()
            .chain(self.definition_model.iter())
            .chain(self.call_model.iter())
        {
            if !model_identity_is_well_formed(model) {
                return Err(ModelRouterError::InvalidObservation(
                    "a model identity must be non-blank, control-free, and bounded",
                ));
            }
        }
        Ok(())
    }

    /// Whether the caller holds resolved route evidence for `model`.
    pub fn resolves(&self, model: &str) -> bool {
        self.resolved_routes.iter().any(|known| known == model)
    }
}

/// The same bound `iteron_agents::AgentDef::validate` applies to a definition's model, restated here
/// because this crate must not depend on that one and a slot may not be handed an identity whose
/// well-formedness nobody checked.
fn model_identity_is_well_formed(model: &str) -> bool {
    !model.trim().is_empty()
        && model.len()
            <= iteron_tunables::param_integer(
                "provider.catalog.max_route_model_bytes",
                MAX_ROUTE_MODEL_BYTES,
            )
        && !model.chars().any(char::is_control)
}

/// Why a routing decision declined to produce a route.
///
/// The variants carry the exact operator-facing wording the two delegation sites used before this
/// was a slot, so making the decision replaceable did not change a single refusal message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRouteRefusal {
    /// A definition and a call each named a model, and they disagree. Neither one wins by default:
    /// picking either would run a pinned definition under an identity it never asked for.
    DefinitionConflict,
    /// The requested model is one this caller holds no resolved route evidence for.
    NoRouteEvidence,
}

impl fmt::Display for ModelRouteRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DefinitionConflict => {
                "agent definition model conflicts with the requested model override"
            }
            Self::NoRouteEvidence => {
                "requested agent model has no separately resolved route evidence"
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelRouterDecision {
    /// Run the delegated turn on this model.
    Route { model: String },
    /// Do not delegate at all, for this reason.
    Refuse { reason: ModelRouteRefusal },
    /// A decoder that does not recognise the payload degrades here rather than guessing.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRouterError {
    UnsupportedVersion,
    WrongSlot,
    InvalidObservation(&'static str),
    InvalidDecision(&'static str),
    /// The decision named a model the caller holds no resolved route evidence for. This is the
    /// structural refusal: it fires however well-behaved or ill-behaved the implementation is.
    RouteWithoutEvidence,
    /// The strategy declined to route. Not a defect — a policy is allowed to say no.
    Refused(ModelRouteRefusal),
}

impl fmt::Display for ModelRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => {
                formatter.write_str("unsupported model router slot version")
            }
            Self::WrongSlot => formatter.write_str("slot identity is not core/model_router"),
            Self::InvalidObservation(reason) | Self::InvalidDecision(reason) => {
                formatter.write_str(reason)
            }
            Self::RouteWithoutEvidence => formatter
                .write_str("model router chose a model with no separately resolved route evidence"),
            Self::Refused(reason) => reason.fmt(formatter),
        }
    }
}

impl std::error::Error for ModelRouterError {}

/// A route a caller may act on, with the authority the slot admitted for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRouteProposal {
    pub model: String,
    pub eligible: iteron_protocol::capability_set::CapabilitySet,
}

/// The built-in `core/model_router`: the parent's route unless something explicitly asks otherwise,
/// and never a model the caller has no evidence for.
pub struct ModelRouterStrategy {
    slot: iteron_protocol::slot::SlotId,
}

impl Default for ModelRouterStrategy {
    fn default() -> Self {
        Self {
            slot: iteron_protocol::slot::SlotId("core/model_router".into()),
        }
    }
}

impl ModelRouterStrategy {
    pub fn route(
        &self,
        input: &ModelRouterObservation,
        ceiling: iteron_protocol::capability_set::CapabilitySet,
    ) -> Result<ModelRouteProposal, ModelRouterError> {
        Self::route_with(self, input, ceiling)
    }

    /// Decode and revalidate any pinned implementation of the frozen slot trait.
    ///
    /// This is the seam: a vertical pack supplies its own `dyn StrategySlot` and the caller keeps
    /// the same guarantees, because the evidence check lives here rather than inside any
    /// implementation.
    pub fn route_with(
        slot: &dyn iteron_protocol::slot::StrategySlot,
        input: &ModelRouterObservation,
        ceiling: iteron_protocol::capability_set::CapabilitySet,
    ) -> Result<ModelRouteProposal, ModelRouterError> {
        if slot.slot().as_persisted_str() != "core/model_router" {
            return Err(ModelRouterError::WrongSlot);
        }
        input.validate()?;
        let payload = serde_json::to_value(input).map_err(|_| {
            ModelRouterError::InvalidObservation("routing observation is not serialisable")
        })?;
        let observation = iteron_protocol::slot::SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload,
        };
        let outcome = iteron_protocol::slot::decide_narrowed(slot, &observation);
        let decision = serde_json::from_value::<ModelRouterDecision>(outcome.decision)
            .map_err(|_| ModelRouterError::InvalidDecision("routing decision is invalid"))?;
        match decision {
            ModelRouterDecision::Route { model } => {
                // The structural check. A strategy may prefer any resolved route over any other;
                // it may not name one the caller never resolved, because the caller would then
                // spend digests that were never proven for that identity.
                if !input.resolves(&model) {
                    return Err(ModelRouterError::RouteWithoutEvidence);
                }
                Ok(ModelRouteProposal {
                    model,
                    eligible: outcome.admitted,
                })
            }
            ModelRouterDecision::Refuse { reason } => Err(ModelRouterError::Refused(reason)),
            ModelRouterDecision::Unknown => Err(ModelRouterError::InvalidDecision(
                "routing decision was not recognised",
            )),
        }
    }

    fn unknown_outcome() -> iteron_protocol::slot::SlotOutcome {
        iteron_protocol::slot::SlotOutcome {
            admitted: iteron_protocol::capability_set::CapabilitySet::none(),
            decision: serde_json::to_value(ModelRouterDecision::Unknown)
                .expect("unit routing decision serializes"),
        }
    }

    /// The rule the two delegation sites carried in-line before this was a slot, unchanged: a
    /// definition and a call that disagree refuse; otherwise whichever of them spoke wins, falling
    /// back to the route already bound; and a request with no resolved evidence refuses.
    fn decide_route(input: &ModelRouterObservation) -> ModelRouterDecision {
        if let (Some(call), Some(definition)) = (&input.call_model, &input.definition_model)
            && call != definition
        {
            return ModelRouterDecision::Refuse {
                reason: ModelRouteRefusal::DefinitionConflict,
            };
        }
        let requested = input
            .definition_model
            .as_deref()
            .or(input.call_model.as_deref())
            .or_else(|| input.bound_route());
        match requested {
            Some(model) if input.resolves(model) => ModelRouterDecision::Route {
                model: model.to_owned(),
            },
            _ => ModelRouterDecision::Refuse {
                reason: ModelRouteRefusal::NoRouteEvidence,
            },
        }
    }
}

impl iteron_protocol::slot::StrategySlot for ModelRouterStrategy {
    fn slot(&self) -> &iteron_protocol::slot::SlotId {
        &self.slot
    }

    fn decide(
        &self,
        observation: &iteron_protocol::slot::SlotObservation,
    ) -> iteron_protocol::slot::SlotOutcome {
        if observation.slot != self.slot {
            return Self::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<ModelRouterObservation>(observation.payload.clone())
        else {
            return Self::unknown_outcome();
        };
        if input.validate().is_err() {
            return Self::unknown_outcome();
        }
        iteron_protocol::slot::SlotOutcome {
            admitted: observation.ceiling,
            decision: serde_json::to_value(Self::decide_route(&input))
                .expect("routing decision serializes"),
        }
    }
}

/// An in-repo alternative implementation, which exists to prove the seam is real.
///
/// It pins every delegation to the parent's own bound route and ignores what the definition or the
/// call asked for. A pack that wants "children never leave the route I paid to resolve" can ship
/// exactly this shape without the runtime knowing it happened.
pub struct BoundRouteOnlyModelRouter {
    slot: iteron_protocol::slot::SlotId,
}

impl Default for BoundRouteOnlyModelRouter {
    fn default() -> Self {
        Self {
            slot: iteron_protocol::slot::SlotId("core/model_router".into()),
        }
    }
}

impl iteron_protocol::slot::StrategySlot for BoundRouteOnlyModelRouter {
    fn slot(&self) -> &iteron_protocol::slot::SlotId {
        &self.slot
    }

    fn decide(
        &self,
        observation: &iteron_protocol::slot::SlotObservation,
    ) -> iteron_protocol::slot::SlotOutcome {
        if observation.slot != self.slot {
            return ModelRouterStrategy::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<ModelRouterObservation>(observation.payload.clone())
        else {
            return ModelRouterStrategy::unknown_outcome();
        };
        let decision = match input.bound_route() {
            Some(model) => ModelRouterDecision::Route {
                model: model.to_owned(),
            },
            None => ModelRouterDecision::Refuse {
                reason: ModelRouteRefusal::NoRouteEvidence,
            },
        };
        iteron_protocol::slot::SlotOutcome {
            admitted: observation.ceiling,
            decision: serde_json::to_value(decision).expect("routing decision serializes"),
        }
    }
}

#[cfg(test)]
mod model_router_slot_tests {
    use super::{
        BoundRouteOnlyModelRouter, MAX_RESOLVED_ROUTES, MODEL_ROUTER_SLOT_VERSION,
        ModelRouteRefusal, ModelRouterDecision, ModelRouterError, ModelRouterObservation,
        ModelRouterStrategy,
    };
    use iteron_protocol::Capability;
    use iteron_protocol::capability_set::CapabilitySet;
    use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot};

    fn ceiling() -> CapabilitySet {
        CapabilitySet::only(Capability::ReadOnly)
    }

    fn single(definition: Option<&str>, call: Option<&str>) -> ModelRouterObservation {
        ModelRouterObservation::single_route(
            "route-a",
            definition.map(str::to_owned),
            call.map(str::to_owned),
        )
    }

    /// The old in-line rule: nothing asked, so the child inherits the parent's bound route.
    #[test]
    fn a_delegation_that_asks_for_nothing_inherits_the_route_the_caller_already_resolved() {
        let proposal = ModelRouterStrategy::default()
            .route(&single(None, None), ceiling())
            .expect("the bound route is always resolvable");
        assert_eq!(proposal.model, "route-a");
        assert!(proposal.eligible.is_subset_of(ceiling()));
    }

    /// The old in-line rule, refusal branch one — with the same operator-facing wording.
    #[test]
    fn a_model_the_caller_never_resolved_is_refused_with_the_wording_the_runtime_used() {
        let error = ModelRouterStrategy::default()
            .route(&single(Some("route-b"), None), ceiling())
            .expect_err("route-b has no resolved evidence");
        assert_eq!(
            error,
            ModelRouterError::Refused(ModelRouteRefusal::NoRouteEvidence)
        );
        assert_eq!(
            error.to_string(),
            "requested agent model has no separately resolved route evidence"
        );
    }

    /// The old in-line rule, refusal branch two.
    #[test]
    fn a_definition_and_a_call_that_disagree_refuse_rather_than_letting_either_win() {
        let error = ModelRouterStrategy::default()
            .route(&single(Some("route-a"), Some("route-b")), ceiling())
            .expect_err("a disagreement is not resolvable by preference");
        assert_eq!(
            error,
            ModelRouterError::Refused(ModelRouteRefusal::DefinitionConflict)
        );
        assert_eq!(
            error.to_string(),
            "agent definition model conflicts with the requested model override"
        );
        // Agreement between the two is not a conflict.
        assert_eq!(
            ModelRouterStrategy::default()
                .route(&single(Some("route-a"), Some("route-a")), ceiling())
                .expect("agreement routes")
                .model,
            "route-a"
        );
    }

    /// What the hard-coded rule could not express: a caller that resolved a second route.
    #[test]
    fn a_second_resolved_route_becomes_expressible_once_the_caller_has_evidence_for_it() {
        let observation = ModelRouterObservation {
            version: MODEL_ROUTER_SLOT_VERSION,
            resolved_routes: vec!["route-a".into(), "route-b".into()],
            definition_model: Some("route-b".into()),
            call_model: None,
        };
        assert_eq!(
            ModelRouterStrategy::default()
                .route(&observation, ceiling())
                .expect("route-b now has evidence")
                .model,
            "route-b"
        );
    }

    struct Conjuring(SlotId);

    impl StrategySlot for Conjuring {
        fn slot(&self) -> &SlotId {
            &self.0
        }
        // A deliberately misbehaving slot: it names a model nobody resolved, and asks for every
        // capability while doing it.
        fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
            SlotOutcome {
                admitted: CapabilitySet::from_iter_capabilities([
                    Capability::ReadOnly,
                    Capability::CodeExecuting,
                    Capability::IrreversibleExternal,
                ]),
                decision: serde_json::to_value(ModelRouterDecision::Route {
                    model: "route-nobody-resolved".into(),
                })
                .expect("decision serializes"),
            }
        }
    }

    #[test]
    fn a_slot_cannot_conjure_a_route_the_caller_never_resolved_however_it_is_implemented() {
        let slot = Conjuring(SlotId("core/model_router".into()));
        assert_eq!(
            ModelRouterStrategy::route_with(&slot, &single(None, None), ceiling()),
            Err(ModelRouterError::RouteWithoutEvidence),
            "the evidence check has to hold for an implementation the caller did not write"
        );
    }

    #[test]
    fn a_slot_cannot_widen_authority_while_choosing_a_route_it_is_allowed_to_choose() {
        struct GreedyButHonest(SlotId);
        impl StrategySlot for GreedyButHonest {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: CapabilitySet::from_iter_capabilities([
                        Capability::ReadOnly,
                        Capability::CodeExecuting,
                        Capability::IrreversibleExternal,
                    ]),
                    decision: serde_json::to_value(ModelRouterDecision::Route {
                        model: "route-a".into(),
                    })
                    .expect("decision serializes"),
                }
            }
        }
        let slot = GreedyButHonest(SlotId("core/model_router".into()));
        let proposal = ModelRouterStrategy::route_with(&slot, &single(None, None), ceiling())
            .expect("route-a is resolved");
        assert!(proposal.eligible.contains(Capability::ReadOnly));
        assert!(!proposal.eligible.contains(Capability::CodeExecuting));
        assert!(!proposal.eligible.contains(Capability::IrreversibleExternal));
        assert!(proposal.eligible.is_subset_of(ceiling()));
    }

    #[test]
    fn an_implementation_sitting_in_the_wrong_seat_is_refused_before_it_is_asked() {
        struct Impostor(SlotId);
        impl StrategySlot for Impostor {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                panic!("a slot in the wrong seat must never be consulted");
            }
        }
        let slot = Impostor(SlotId("core/tool_policy".into()));
        assert_eq!(
            ModelRouterStrategy::route_with(&slot, &single(None, None), ceiling()),
            Err(ModelRouterError::WrongSlot)
        );
    }

    #[test]
    fn an_observation_the_caller_could_not_have_gathered_honestly_is_refused() {
        let mut future = single(None, None);
        future.version = MODEL_ROUTER_SLOT_VERSION + 1;
        assert_eq!(
            ModelRouterStrategy::default().route(&future, ceiling()),
            Err(ModelRouterError::UnsupportedVersion)
        );

        let mut empty = single(None, None);
        empty.resolved_routes.clear();
        assert!(matches!(
            ModelRouterStrategy::default().route(&empty, ceiling()),
            Err(ModelRouterError::InvalidObservation(_))
        ));

        let mut crowded = single(None, None);
        crowded.resolved_routes = (0..=MAX_RESOLVED_ROUTES).map(|n| format!("r{n}")).collect();
        assert!(matches!(
            ModelRouterStrategy::default().route(&crowded, ceiling()),
            Err(ModelRouterError::InvalidObservation(_))
        ));

        for malformed in ["", "   ", "route\na"] {
            let observation = single(Some(malformed), None);
            assert!(
                matches!(
                    ModelRouterStrategy::default().route(&observation, ceiling()),
                    Err(ModelRouterError::InvalidObservation(_))
                ),
                "{malformed:?} is not a well-formed model identity"
            );
        }
    }

    #[test]
    fn a_decision_this_build_cannot_read_degrades_instead_of_being_guessed_at() {
        struct Babbling(SlotId);
        impl StrategySlot for Babbling {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: CapabilitySet::none(),
                    decision: serde_json::json!({ "kind": "teleport", "model": "route-a" }),
                }
            }
        }
        let slot = Babbling(SlotId("core/model_router".into()));
        assert!(matches!(
            ModelRouterStrategy::route_with(&slot, &single(None, None), ceiling()),
            Err(ModelRouterError::InvalidDecision(_))
        ));
    }

    #[test]
    fn a_pinned_alternative_changes_the_answer_without_the_caller_changing() {
        let observation = ModelRouterObservation {
            version: MODEL_ROUTER_SLOT_VERSION,
            resolved_routes: vec!["route-a".into(), "route-b".into()],
            definition_model: Some("route-b".into()),
            call_model: None,
        };
        assert_eq!(
            ModelRouterStrategy::route_with(
                &ModelRouterStrategy::default(),
                &observation,
                ceiling()
            )
            .expect("built-in honours the definition")
            .model,
            "route-b"
        );
        assert_eq!(
            ModelRouterStrategy::route_with(
                &BoundRouteOnlyModelRouter::default(),
                &observation,
                ceiling()
            )
            .expect("the alternative pins to the bound route")
            .model,
            "route-a",
            "the same call site must get a different route purely from the pinned slot"
        );
    }

    #[test]
    fn the_decision_payload_is_a_tagged_shape_this_slot_versions_for_itself() {
        assert_eq!(
            serde_json::to_value(ModelRouterDecision::Route {
                model: "route-a".into()
            })
            .expect("decision serializes"),
            serde_json::json!({ "kind": "route", "model": "route-a" })
        );
        assert_eq!(
            serde_json::to_value(ModelRouterDecision::Refuse {
                reason: ModelRouteRefusal::NoRouteEvidence
            })
            .expect("decision serializes"),
            serde_json::json!({ "kind": "refuse", "reason": "no_route_evidence" })
        );
    }
}
