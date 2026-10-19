//! Trusted capture for the concrete injection owners. No executable domain retains Agent; the
//! existing observer and UI keep their current source/SDK projection after actual admission.
use super::context_injection::{
    ContextInjectionObservation, ContextInjectionPreparation, ContextInjectionWorld,
    RecordedContextHistory,
};
use super::context_injection_gate::ContextInjectionGate;
use super::context_injection_journal::ContextInjectionJournal;
use super::session_transcript::TranscriptAdmissionJournal;
use super::{Agent, KernelError};
use iteron_protocol::{EventKind, Phase, TurnId};

impl Agent {
    pub(super) async fn resolve_injection_before_provider(
        &mut self,
        task: &str,
    ) -> Result<(), KernelError> {
        self.ensure_record_healthy()?;
        if self.injected.is_some() {
            return Ok(());
        }
        let turn = TurnId(self.seq_turn);
        // Preserve the actual host UI/SDK observer and bounded queued-phase writer. Hook commands
        // still execute only through their own durable effect intents in the gate below.
        self.emit(
            turn,
            EventKind::Phase {
                phase: Phase::Context,
            },
        );
        self.ensure_record_healthy()?;
        let memory = self.memory_workspace.is_some();
        let events = self.context_preparation_events();
        let timing = ContextInjectionGate {
            hooks: self.hook_execution(turn),
            events,
        }
        .run(turn, task.len(), memory)
        .await?;
        let result = self.resolve_injection(turn, task);
        timing.finish(&mut self.ledger);
        result
    }

    pub(super) fn resolve_injection(
        &mut self,
        turn: TurnId,
        task: &str,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Ok(());
        }
        let started = std::time::Instant::now();
        let recorded = RecordedContextHistory::read(self.rollout.path())?;
        let preparation = ContextInjectionPreparation::new(
            recorded,
            self.instruction_context.as_ref(),
            self.environment_context.as_ref(),
            self.context_refresh_requested,
            started,
        );
        let live = preparation.needs_live_policy(self.memory_workspace.is_some());
        if live {
            self.ensure_policy_evidence()?;
        }
        // Historical replay and the ordinary no-memory path do not inspect plugin skill masks or
        // resolve live world files. A present live workspace uses the exact current skill policy.
        let eligible = if live {
            self.eligible_dependency_skill_dirs()
        } else {
            None
        };
        let materialized = preparation.materialize(
            turn,
            task,
            ContextInjectionWorld {
                memory_workspace: self.memory_workspace.as_deref(),
                home: self.context_home_dir.as_deref(),
                dependency_skill_dirs: eligible.as_deref().unwrap_or(&self.dependency_skill_dirs),
                context: self.compiled_policy_bundle.slots().context.as_ref(),
                memory: self.compiled_policy_bundle.slots().memory.as_ref(),
                port: self.context_port.as_ref(),
                benchmark_scope: self.memory_benchmark_scope,
                materialization: self.context_materialization_policy,
            },
            &mut ContextInjectionJournal {
                transcript: TranscriptAdmissionJournal {
                    rollout: &mut self.rollout,
                    ledger: &mut self.ledger,
                    record_failed: &mut self.record_failed,
                    diagnostics: &self.diagnostics,
                    publications: &mut self.turn_publications,
                    #[cfg(test)]
                    fault: &mut self.fail_next_durable_append,
                },
                policy: self.policy_evidence.as_mut(),
            },
        )?;
        match materialized.observation(turn, task) {
            ContextInjectionObservation::Recorded { text, trust } => {
                self.observe_recorded_context(turn, text, trust);
            }
            ContextInjectionObservation::Live(observation) => {
                self.observe_resolved_context(observation)
            }
            ContextInjectionObservation::Empty => {}
        }
        let committed = materialized.commit(
            turn,
            &mut ContextInjectionJournal {
                transcript: TranscriptAdmissionJournal {
                    rollout: &mut self.rollout,
                    ledger: &mut self.ledger,
                    record_failed: &mut self.record_failed,
                    diagnostics: &self.diagnostics,
                    publications: &mut self.turn_publications,
                    #[cfg(test)]
                    fault: &mut self.fail_next_durable_append,
                },
                policy: self.policy_evidence.as_mut(),
            },
            &mut self.context_source_evidence,
        )?;
        self.injected = Some(committed.text);
        self.injected_trust = committed.trust;
        self.context_refresh_requested = false;
        self.clear_frontend_context_proposals();
        Ok(())
    }
}
