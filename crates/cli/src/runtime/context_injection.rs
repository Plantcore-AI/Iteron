//! One pending stable-prefix materialization. Historical bytes remain authoritative; live world
//! reads use the actual bounded ContextPort and frozen strategies. Only a real writer receipt
//! releases an installable value, while observational source evidence stays a separate port.
use super::KernelError;
use super::context_injection_journal::ContextInjectionJournal;
use super::decision_observability::ResolvedContextObservation;
use super::policy_evidence::{CONTEXT_SLOT, MEMORY_SLOT, PolicyDecisionDraft};
use super::request_context_evidence::RequestContextEvidenceOwner;
use super::strategy_runtime::{self, LiveContext, LiveContextRequest};
use iteron_ctx::{ContextMaterializationPolicy, ContextPort, MemoryRecallDisposition};
use iteron_protocol::slot::StrategySlot;
use iteron_protocol::{
    DurableEnvironmentContext, DurableInstructionContext, EventKind, PolicyActionV1, Trust, TurnId,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Default)]
pub(super) struct RecordedContextHistory {
    injection: Option<(String, Trust, Option<DurableInstructionContext>)>,
    genesis_environment: Option<DurableEnvironmentContext>,
}

impl RecordedContextHistory {
    pub(super) fn read(path: &Path) -> Result<Self, KernelError> {
        // The same fork-aware projection owns inherited genesis and context; replay failure never
        // grants permission to resolve today's live files instead.
        let events = super::route_validation::replay_logical_rollout(path)?;
        let mut history = Self::default();
        for event in events {
            match event.kind {
                EventKind::RunStart {
                    environment: Some(environment),
                    ..
                } => {
                    history.genesis_environment = Some(environment);
                }
                EventKind::ContextInjection {
                    text,
                    trust,
                    instructions,
                } => {
                    history.injection = Some((text, trust, instructions));
                }
                _ => {}
            }
        }
        Ok(history)
    }
}

pub(super) struct ContextInjectionWorld<'a> {
    pub(super) memory_workspace: Option<&'a Path>,
    pub(super) home: Option<&'a Path>,
    pub(super) dependency_skill_dirs: &'a [(PathBuf, PathBuf)],
    pub(super) context: &'a dyn StrategySlot,
    pub(super) memory: &'a dyn StrategySlot,
    pub(super) port: &'a dyn ContextPort,
    pub(super) benchmark_scope: Option<[u8; 32]>,
    pub(super) materialization: ContextMaterializationPolicy,
}

enum InjectionPlan {
    Recorded {
        body: String,
        trust: Trust,
        instructions: Option<DurableInstructionContext>,
        upgrade: bool,
    },
    Live {
        instructions: Option<DurableInstructionContext>,
        frontend_historical: bool,
        refresh: bool,
    },
}

pub(super) struct ContextInjectionPreparation {
    plan: InjectionPlan,
    started: Instant,
}

pub(super) enum ContextInjectionObservation<'a> {
    Recorded { text: &'a str, trust: Trust },
    Live(ResolvedContextObservation<'a>),
    Empty,
}

/// Actual selected bytes survive their evidence observation and final journal barrier together.
/// This value cannot be cloned, and committing consumes it before any cached prefix is installed.
pub(super) struct MaterializedContextInjection {
    body: String,
    body_trust: Trust,
    instructions: Option<DurableInstructionContext>,
    record: bool,
    recorded: bool,
    frontend_historical: bool,
    live: Option<LiveContext>,
    started: Instant,
    benchmark_scope: Option<[u8; 32]>,
}

pub(super) struct CommittedContextInjection {
    pub(super) text: String,
    pub(super) trust: Option<Trust>,
}

impl ContextInjectionPreparation {
    pub(super) fn new(
        recorded: RecordedContextHistory,
        instructions: Option<&(String, Trust)>,
        environment: Option<&(String, Trust)>,
        refresh: bool,
        started: Instant,
    ) -> Self {
        let frozen_frontend = refresh
            .then(|| {
                recorded
                    .injection
                    .as_ref()
                    .and_then(|(_, _, instructions)| instructions.clone())
            })
            .flatten();
        let frontend_historical = frozen_frontend.is_some();
        let proposed = || {
            frontend_proposal(
                instructions,
                environment,
                recorded.genesis_environment.as_ref(),
            )
        };
        let plan = if !refresh {
            match recorded.injection {
                Some((body, trust, Some(instructions))) => InjectionPlan::Recorded {
                    body,
                    trust,
                    instructions: Some(instructions),
                    upgrade: false,
                },
                Some((body, trust, None)) => {
                    let instructions = proposed();
                    InjectionPlan::Recorded {
                        body,
                        trust,
                        upgrade: instructions.is_some(),
                        instructions,
                    }
                }
                None => InjectionPlan::Live {
                    instructions: proposed(),
                    frontend_historical,
                    refresh,
                },
            }
        } else {
            InjectionPlan::Live {
                instructions: frozen_frontend.or_else(proposed),
                frontend_historical,
                refresh,
            }
        };
        Self { plan, started }
    }

    pub(super) fn needs_live_policy(&self, memory: bool) -> bool {
        memory && matches!(self.plan, InjectionPlan::Live { .. })
    }

    pub(super) fn materialize(
        self,
        turn: TurnId,
        task: &str,
        world: ContextInjectionWorld<'_>,
        journal: &mut ContextInjectionJournal<'_>,
    ) -> Result<MaterializedContextInjection, KernelError> {
        match self.plan {
            InjectionPlan::Recorded {
                body,
                trust,
                instructions,
                upgrade,
            } => {
                if upgrade {
                    journal.injection(turn, body.clone(), trust, instructions.clone())?;
                }
                let (body, trust) = match instructions {
                    Some(instructions) => {
                        iteron_ctx::assemble_recorded_context(&instructions, body, trust)
                    }
                    None => (body, trust),
                };
                Ok(MaterializedContextInjection {
                    body,
                    body_trust: trust,
                    instructions: None,
                    record: false,
                    recorded: true,
                    frontend_historical: false,
                    live: None,
                    started: self.started,
                    benchmark_scope: world.benchmark_scope,
                })
            }
            InjectionPlan::Live {
                instructions,
                frontend_historical,
                refresh,
            } => {
                let mut live = if let Some(workspace) = world.memory_workspace {
                    let opportunity = journal.begin_policy(CONTEXT_SLOT, turn)?;
                    let resolved = strategy_runtime::resolve_live_context(
                        world.context,
                        world.memory,
                        world.port,
                        LiveContextRequest {
                            workspace,
                            home_dir: world.home,
                            dependency_skill_dirs: world.dependency_skill_dirs,
                            turn,
                            task,
                            memory_benchmark_scope: world.benchmark_scope,
                            materialization: world.materialization,
                        },
                    );
                    let resolved = match resolved {
                        Ok(resolved) => {
                            journal.decision(
                                opportunity,
                                PolicyDecisionDraft::selected(
                                    CONTEXT_SLOT,
                                    &[PolicyActionV1::ContextMaterialize],
                                    PolicyActionV1::ContextMaterialize,
                                    "iteron:context-features-v1",
                                    &(&resolved.policy_observation, &resolved.policy_plan),
                                    &"world_reads_remain_in_context_port",
                                )?,
                            )?;
                            resolved
                        }
                        Err(error) => {
                            journal.decision(
                                opportunity,
                                PolicyDecisionDraft::abstained(
                                    CONTEXT_SLOT,
                                    &[PolicyActionV1::ContextMaterialize],
                                    "iteron:context-features-v1",
                                    &(turn.0, task.len()),
                                    &"context_failure_is_fail_closed",
                                )?,
                            )?;
                            return Err(KernelError::ContextResolution(error));
                        }
                    };
                    record_memory_decision(journal, turn, &resolved)?;
                    Some(resolved)
                } else {
                    None
                };
                let body_trust = live
                    .as_ref()
                    .filter(|live| !live.text.is_empty())
                    .map(|live| live.governing_trust)
                    .unwrap_or(Trust::Trusted);
                let body = live
                    .as_mut()
                    .map(|live| std::mem::take(&mut live.text))
                    .unwrap_or_default();
                let record = refresh || instructions.is_some() || !body.is_empty();
                Ok(MaterializedContextInjection {
                    body,
                    body_trust,
                    instructions,
                    record,
                    recorded: false,
                    frontend_historical,
                    live,
                    started: self.started,
                    benchmark_scope: world.benchmark_scope,
                })
            }
        }
    }
}

impl MaterializedContextInjection {
    pub(super) fn observation<'a>(
        &'a self,
        turn: TurnId,
        task: &'a str,
    ) -> ContextInjectionObservation<'a> {
        if self.recorded {
            return ContextInjectionObservation::Recorded {
                text: &self.body,
                trust: self.body_trust,
            };
        }
        match &self.live {
            Some(live) => ContextInjectionObservation::Live(ResolvedContextObservation {
                turn,
                task,
                segments: &live.segments,
                materialization: &live.materialization_audit,
                memory_audit: live.memory_audit.as_ref(),
                memory_benchmark_scope: self.benchmark_scope.as_ref(),
                benchmark_memory_rejections: live.benchmark_memory_rejections,
                elapsed_us: super::provider_accounting::elapsed_us(self.started),
            }),
            None => ContextInjectionObservation::Empty,
        }
    }

    pub(super) fn commit(
        self,
        turn: TurnId,
        journal: &mut ContextInjectionJournal<'_>,
        sources: &mut RequestContextEvidenceOwner,
    ) -> Result<CommittedContextInjection, KernelError> {
        if self.recorded {
            return Ok(CommittedContextInjection {
                text: self.body,
                trust: Some(self.body_trust),
            });
        }
        if let Some(instructions) = &self.instructions {
            sources.bind_frontend_materials(
                &instructions.text,
                instructions.trust,
                journal.frontend_scope()?,
                self.frontend_historical,
            );
            if let Some(environment) = &instructions.environment
                && !environment.text.is_empty()
            {
                sources.append_material(
                    iteron_ctx::context_provenance::CapturedContextMaterial::historical_source(
                        iteron_ctx::ContextSourceClass::Environment,
                        &environment.text,
                        environment.trust,
                    ),
                );
            }
        }
        if self.record {
            journal.injection(
                turn,
                self.body.clone(),
                self.body_trust,
                self.instructions.clone(),
            )?;
        }
        let (text, trust) = match self.instructions {
            Some(instructions) => {
                let (text, trust) = iteron_ctx::assemble_recorded_context(
                    &instructions,
                    self.body,
                    self.body_trust,
                );
                (text, Some(trust))
            }
            None => (self.body, self.record.then_some(self.body_trust)),
        };
        Ok(CommittedContextInjection { text, trust })
    }
}

fn record_memory_decision(
    journal: &mut ContextInjectionJournal<'_>,
    turn: TurnId,
    resolved: &LiveContext,
) -> Result<(), KernelError> {
    let Some(audit) = &resolved.memory_audit else {
        return Ok(());
    };
    if audit.disposition == MemoryRecallDisposition::NotInvokedScopeDenied {
        return Ok(());
    }
    let opportunity = journal.begin_policy(MEMORY_SLOT, turn)?;
    let eligible = [PolicyActionV1::MemoryNoRecall, PolicyActionV1::MemoryRecall];
    let features = (&audit.observation, &audit.selected, &audit.scores_ppm);
    let draft = match audit.disposition {
        MemoryRecallDisposition::Selected => PolicyDecisionDraft::selected(
            MEMORY_SLOT,
            &eligible,
            if audit.selected.is_empty() {
                PolicyActionV1::MemoryNoRecall
            } else {
                PolicyActionV1::MemoryRecall
            },
            "iteron:memory-features-v1",
            &features,
            &"selection_is_bounded_to_gathered_candidates",
        )?,
        MemoryRecallDisposition::Abstained => PolicyDecisionDraft::abstained(
            MEMORY_SLOT,
            &eligible,
            "iteron:memory-features-v1",
            &features,
            &"invalid_or_refused_memory_plans_inject_no_bodies",
        )?,
        MemoryRecallDisposition::NotInvokedScopeDenied => {
            unreachable!("scope denial filtered above")
        }
    };
    journal.decision(opportunity, draft)
}

fn frontend_proposal(
    instructions: Option<&(String, Trust)>,
    environment: Option<&(String, Trust)>,
    genesis: Option<&DurableEnvironmentContext>,
) -> Option<DurableInstructionContext> {
    let environment = genesis.cloned().or_else(|| {
        environment.map(|(text, trust)| DurableEnvironmentContext {
            text: text.clone(),
            trust: *trust,
        })
    });
    match instructions {
        Some((text, trust)) => Some(DurableInstructionContext {
            text: text.clone(),
            trust: *trust,
            environment,
        }),
        None if environment.is_some() => Some(DurableInstructionContext {
            text: String::new(),
            trust: Trust::Trusted,
            environment,
        }),
        None => None,
    }
}

#[cfg(test)]
#[path = "context_injection_tests.rs"]
mod tests;
