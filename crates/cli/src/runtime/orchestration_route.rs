use super::*;

impl Agent {
    /// Ultracode entry. Admission is identical to the ordinary path; the selected main model is
    /// the first component allowed to choose whether the task benefits from a `Workflow` call.
    pub(super) async fn run_orchestrated(
        &mut self,
        task: &str,
        input_images: &[iteron_protocol::ImageContent],
    ) -> Result<Outcome, KernelError> {
        self.orchestrating = true;
        let input_images = self.admit_input_images(input_images)?;
        let messages = self.admit_submission(task)?;
        self.drive_admitted(messages, task, input_images).await
    }

    /// Ask `core/router` which handling path this submission takes.
    ///
    /// The call goes through `RouterStrategy::route_with`, never `decide`, so a pinned replacement
    /// is held to the same narrowing contract as the built-in baseline: it may decline fan-out or
    /// ask for fewer leaves, and it cannot reach past the ceiling assembled here.
    ///
    /// A refusal is not an error the run dies on. Fan-out is the *additional* thing a route can
    /// ask for, so the fail-closed answer is the single-agent loop — which is also what a
    /// `Localized` route means — and the refusal is said out loud rather than swallowed.
    #[cfg(test)]
    pub(super) fn route_submission(
        &mut self,
        task: &str,
        signals: iteron_agents::RepoSignals,
    ) -> Result<iteron_agents::RouterRoute, KernelError> {
        let observation = iteron_agents::RouterSlotObservation::baseline(task, signals);
        let ceiling = CapabilitySet::only(Capability::ReadOnly).intersect(self.authority_ceiling);
        let opportunity =
            self.begin_policy_decision(policy_evidence::ROUTER_SLOT, Some(TurnId(self.seq_turn)))?;
        if self.execution_policy.route_topology
            == crate::runtime_tunables::execution_policy::RouteTopology::Direct
        {
            let route = iteron_agents::RouterRoute::direct(iteron_agents::TaskClass::Localized);
            self.append_policy_decision(
                opportunity,
                policy_evidence::PolicyDecisionDraft::selected(
                    policy_evidence::ROUTER_SLOT,
                    &[
                        iteron_protocol::PolicyActionV1::RouterDirect,
                        iteron_protocol::PolicyActionV1::RouterFanOut,
                    ],
                    iteron_protocol::PolicyActionV1::RouterDirect,
                    "iteron:router-features-v1",
                    &(&observation, route),
                    &"immutable_route_topology_refuses_fan_out",
                )?,
            )?;
            return Ok(route);
        }
        match iteron_agents::RouterStrategy::route_with(self.router.as_ref(), &observation, ceiling)
        {
            Ok(proposal) => {
                let action = if proposal.route.fans_out() {
                    "fan_out"
                } else {
                    "direct"
                };
                self.append_policy_decision(
                    opportunity,
                    policy_evidence::PolicyDecisionDraft::selected(
                        policy_evidence::ROUTER_SLOT,
                        &[
                            iteron_protocol::PolicyActionV1::RouterDirect,
                            iteron_protocol::PolicyActionV1::RouterFanOut,
                        ],
                        if action == "fan_out" {
                            iteron_protocol::PolicyActionV1::RouterFanOut
                        } else {
                            iteron_protocol::PolicyActionV1::RouterDirect
                        },
                        "iteron:router-features-v1",
                        &(&observation, proposal.route),
                        &"fan_out_may_only_narrow_caller_ceiling",
                    )?,
                )?;
                Ok(proposal.route)
            }
            Err(error) => {
                self.append_policy_decision(
                    opportunity,
                    policy_evidence::PolicyDecisionDraft::baseline_fallback(
                        policy_evidence::ROUTER_SLOT,
                        &[
                            iteron_protocol::PolicyActionV1::RouterDirect,
                            iteron_protocol::PolicyActionV1::RouterFanOut,
                        ],
                        "iteron:router-features-v1",
                        &observation,
                        &"refusal_falls_back_to_direct",
                    )?,
                )?;
                self.emit(
                    TurnId(self.seq_turn),
                    EventKind::Notice {
                        text: format!(
                            "ultracode: core/router declined to route ({error}) — running single-agent"
                        ),
                    },
                );
                Ok(iteron_agents::RouterRoute::direct(
                    iteron_agents::TaskClass::Localized,
                ))
            }
        }
    }

    /// Resolve the effective pure-tool permit count through the pinned `core/scheduler` seat.
    /// Malformed/refusing replacements fail closed to one permit; no slot can exceed the runtime's
    /// existing product ceiling.
    pub(super) fn scheduled_tool_concurrency(&mut self) -> Result<usize, KernelError> {
        let max_concurrency =
            u32::try_from(self.max_tool_concurrency.min(self.pure_tool_concurrency))
                .unwrap_or(u32::MAX)
                .max(1);
        let opportunity = self
            .begin_policy_decision(policy_evidence::SCHEDULER_SLOT, Some(TurnId(self.seq_turn)))?;
        let observation = match iteron_sched::SchedulerSlotObservation::baseline(
            self.retry_policy,
            max_concurrency,
        ) {
            Ok(observation) => observation,
            Err(_) => {
                self.append_policy_decision(
                    opportunity,
                    policy_evidence::PolicyDecisionDraft::baseline_fallback(
                        policy_evidence::SCHEDULER_SLOT,
                        &[
                            iteron_protocol::PolicyActionV1::SchedulerBoundedPlan,
                            iteron_protocol::PolicyActionV1::SchedulerSinglePermit,
                        ],
                        "iteron:scheduler-features-v1",
                        &max_concurrency,
                        &"invalid_observation_falls_back_to_one_permit",
                    )?,
                )?;
                return Ok(1);
            }
        };
        match iteron_sched::SchedulerStrategy::plan_with(
            self.scheduler.as_ref(),
            &observation,
            CapabilitySet::only(Capability::ReadOnly).intersect(self.authority_ceiling),
        ) {
            Ok(proposal) => {
                self.append_policy_decision(
                    opportunity,
                    policy_evidence::PolicyDecisionDraft::selected(
                        policy_evidence::SCHEDULER_SLOT,
                        &[
                            iteron_protocol::PolicyActionV1::SchedulerBoundedPlan,
                            iteron_protocol::PolicyActionV1::SchedulerSinglePermit,
                        ],
                        iteron_protocol::PolicyActionV1::SchedulerBoundedPlan,
                        "iteron:scheduler-features-v1",
                        &(&observation, proposal.plan),
                        &"strategy_may_only_narrow_retry_and_concurrency",
                    )?,
                )?;
                Ok(proposal.plan.concurrency_permits())
            }
            Err(_) => {
                self.append_policy_decision(
                    opportunity,
                    policy_evidence::PolicyDecisionDraft::baseline_fallback(
                        policy_evidence::SCHEDULER_SLOT,
                        &[
                            iteron_protocol::PolicyActionV1::SchedulerBoundedPlan,
                            iteron_protocol::PolicyActionV1::SchedulerSinglePermit,
                        ],
                        "iteron:scheduler-features-v1",
                        &observation,
                        &"strategy_refusal_falls_back_to_one_permit",
                    )?,
                )?;
                Ok(1)
            }
        }
    }
}
