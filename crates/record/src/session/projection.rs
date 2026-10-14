//! The sole incremental session projection owner. Only durable committed events may update it.
//! Publication is performed separately by the record writer after its exact tail is prepared.
use super::cache_receipts::{
    complete_record_len, file_mtime, json_f64_fixed_point, projection_digest, projection_is_current,
};
use super::model::{Provenance, SessionMeta, parse_outcome, title_from_message};
use super::paths::rollout_path;
use super::replay::{LogicalReplayBudget, expand_scoped_from, read_chain_budgeted};
use crate::RecordError;
use iteron_obs::{CostState, Ledger, PricingPort, PricingReplay};
use iteron_protocol::{Effort, Event, EventKind, Role, RunId, Seq, TenantId, Usage};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// Incremental, rebuildable projection for the current physical run.
///
/// Construction performs one bounded, hash-verified logical replay (including a fork's pinned
/// parent prefix). After that, the kernel feeds only events whose append+fsync already succeeded,
/// so turn-boundary cache refreshes are O(1) in historical rollout length rather than replaying
/// the entire journal on every turn. The projection is never authoritative: a structurally
/// current projection may be persisted for every session shape, while only an honest `Unknown`
/// monetary state is directly readable without replay. Stale/corrupt bytes always degrade to
/// verified replay.
pub(crate) struct SessionProjection {
    runs_dir: PathBuf,
    meta: SessionMeta,
    turns: u32,
    usage: Usage,
    title: String,
    cost_ledger: Ledger,
    pricing_replay: PricingReplay,
}

impl SessionProjection {
    pub(crate) fn publication_meta(&self) -> &SessionMeta {
        &self.meta
    }
    /// Build from the authoritative logical rollout once. Subsequent events must be supplied only
    /// after their durable append succeeds.
    pub(crate) fn load(runs_dir: &Path, run: &RunId) -> Result<Self, RecordError> {
        load_session_projection(runs_dir, run, None)
    }

    /// Apply one newly durable event from this projection's physical run.
    pub(crate) fn observe_committed(
        &mut self,
        event: &Event,
        seq: Seq,
        hash: &str,
    ) -> Result<(), RecordError> {
        let tenant = self.meta.tenant.clone();
        let run = self.meta.run_id.clone();
        self.observe_scoped(event, &tenant, &run)?;
        self.meta.record_tail_seq = Some(seq.0);
        self.meta.record_tail_hash = hash.to_string();
        Ok(())
    }

    pub(crate) fn prepare_publication(
        &mut self,
        expected_record_bytes: u64,
    ) -> Result<bool, RecordError> {
        if complete_record_len(&rollout_path(&self.runs_dir, &self.meta.run_id)?)
            != Some(expected_record_bytes)
        {
            self.meta.record_bytes = 0;
            return Ok(false);
        }
        let (updated_at, updated_at_subsec_nanos) =
            file_mtime(&rollout_path(&self.runs_dir, &self.meta.run_id)?)
                .unwrap_or((self.meta.created_at, 0));
        self.meta.updated_at = updated_at;
        self.meta.updated_at_subsec_nanos = updated_at_subsec_nanos;
        self.meta.record_bytes = expected_record_bytes;
        self.refresh_derived();
        self.meta.cache_hit = json_f64_fixed_point(self.meta.cache_hit)?;
        self.meta.projection_digest = projection_digest(&self.meta)?;
        if !projection_is_current(&self.runs_dir, &self.meta) {
            return Ok(false);
        }
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn projected(&self) -> &SessionMeta {
        &self.meta
    }

    fn observe_scoped(
        &mut self,
        event: &Event,
        tenant: &TenantId,
        run: &RunId,
    ) -> Result<(), RecordError> {
        self.pricing_replay
            .observe(event, tenant, run, &mut self.cost_ledger)?;
        match &event.kind {
            EventKind::TurnStart => {
                self.turns = self.turns.saturating_add(1);
            }
            EventKind::TurnEnd { usage, .. } => self.usage.add(usage),
            EventKind::SubagentFinished { metrics, .. }
            | EventKind::SubagentFinishedV2 { metrics, .. } => {
                self.turns = self.turns.saturating_add(metrics.provider_attempts);
                self.usage.add(&metrics.usage);
            }
            EventKind::Workflow {
                event: iteron_protocol::WorkflowEvent::ChildFinished { metrics, .. },
                ..
            }
            | EventKind::WorkflowV2 {
                event: iteron_protocol::WorkflowEvent::ChildFinished { metrics, .. },
                ..
            } => {
                self.turns = self.turns.saturating_add(metrics.provider_attempts);
                self.usage.add(&metrics.usage);
            }
            EventKind::ModelSelected {
                provider_id,
                model_id,
                ..
            } => {
                self.meta.provider_id = provider_id.clone();
                self.meta.model = model_id.clone();
            }
            EventKind::EffortChanged { effort, .. } => self.meta.effort = *effort,
            EventKind::Message { message } | EventKind::MessageV2 { message }
                if self.title.is_empty() && message.role == Role::User =>
            {
                self.title = title_from_message(message);
            }
            EventKind::Done { outcome } => self.meta.last_outcome = parse_outcome(outcome),
            _ => {}
        }
        self.refresh_derived();
        Ok(())
    }

    fn refresh_derived(&mut self) {
        self.meta.turns = self.turns;
        self.meta.cost = self.cost_ledger.cost_state();
        self.meta.cache_hit = self.usage.cache_hit_ratio();
        self.meta.title = if self.title.is_empty() {
            "(untitled)".to_string()
        } else {
            self.title.clone()
        };
    }

    pub(super) fn into_meta(self) -> SessionMeta {
        self.meta
    }
}

/// Build a [`SessionMeta`] by replaying the run's record (the degrade path, and the truth `reindex`
/// rebuilds the cache from). Never re-reads disk state that belongs in the record: `created_at`
/// comes from the genesis header, not the clock.
pub(super) fn meta_from_replay(
    runs_dir: &Path,
    run: &RunId,
    pricing: Option<Arc<dyn PricingPort>>,
) -> Result<SessionMeta, RecordError> {
    Ok(load_session_projection(runs_dir, run, pricing)?.into_meta())
}

fn load_session_projection(
    runs_dir: &Path,
    run: &RunId,
    pricing: Option<Arc<dyn PricingPort>>,
) -> Result<SessionProjection, RecordError> {
    load_session_projection_budgeted(runs_dir, run, pricing, LogicalReplayBudget::default())
}

fn load_session_projection_budgeted(
    runs_dir: &Path,
    run: &RunId,
    pricing: Option<Arc<dyn PricingPort>>,
    mut replay_budget: LogicalReplayBudget,
) -> Result<SessionProjection, RecordError> {
    let path = rollout_path(runs_dir, run)?;
    let complete_len_before = complete_record_len(&path);
    // Keep the child journal and its ancestry inside one logical read budget. The verified child
    // lines are reused below instead of opening and parsing the same near-cap file a second time.
    let lines = read_chain_budgeted(&path, &mut replay_budget)?;
    let physical_tail = lines.last().map(|line| (line.seq, line.hash.clone()));

    let mut tenant = TenantId::default();
    let mut cwd = PathBuf::new();
    let provider_id = String::new();
    let mut model = String::new();
    let mut effort = Effort::default();
    let mut agent_definition_tag = None;
    let mut created_at = 0u64;
    let mut parent: Option<Provenance> = None;

    if let Some(g) = lines.first() {
        tenant = g.tenant.clone();
        if let EventKind::RunStart {
            cwd: c,
            model: m,
            effort: ef,
            agent_definition_tag: tag,
            created_at: ca,
            parent_run,
            forked_at,
            parent_hash_at_seq,
            ..
        } = &g.event.kind
        {
            cwd = PathBuf::from(c);
            model = m.clone();
            effort = *ef;
            agent_definition_tag = tag.clone();
            created_at = *ca;
            if let (Some(pr), Some(fa), Some(ph)) =
                (parent_run.clone(), forked_at, parent_hash_at_seq.clone())
            {
                parent = Some(Provenance {
                    parent_run: RunId(pr),
                    forked_at: Seq(*fa),
                    parent_hash_at_seq: ph,
                });
            }
        }
    }

    // Physical fields above describe the child journal itself, but session activity is a logical
    // projection. A fork stores only its suffix, so usage/cost/title/selection/outcome must include
    // the bounded, cross-link-verified parent prefix. Preloading `lines` means every journal is
    // charged and parsed at most once in this top-level projection.
    let mut ancestry = Vec::new();
    let logical_events = expand_scoped_from(
        runs_dir,
        run,
        None,
        0,
        &mut replay_budget,
        Some(lines),
        &mut ancestry,
    )?;

    let mut projection = SessionProjection {
        runs_dir: runs_dir.to_path_buf(),
        meta: SessionMeta {
            pricing_schema_version: 2,
            projection_schema_version: 3,
            content_revocation_generation: crate::content_store::content_revocation_generation(
                runs_dir, &tenant,
            )?,
            run_id: run.clone(),
            tenant,
            cwd,
            provider_id,
            model,
            effort,
            agent_definition_tag,
            title: String::new(),
            created_at,
            updated_at: 0,
            updated_at_subsec_nanos: 0,
            record_bytes: 0,
            record_tail_seq: None,
            record_tail_hash: String::new(),
            projection_digest: String::new(),
            ancestry,
            turns: 0,
            cost: CostState::Zero,
            cache_hit: 0.0,
            last_outcome: None,
            parent,
        },
        turns: 0,
        usage: Usage::default(),
        title: String::new(),
        cost_ledger: Ledger::new(),
        pricing_replay: pricing.map(PricingReplay::trusted).unwrap_or_default(),
    };
    for scoped in &logical_events {
        projection.observe_scoped(&scoped.event, &scoped.tenant, &scoped.run_id)?;
    }
    let complete_len_after = complete_record_len(&path);
    if let (Some(before), Some(after)) = (complete_len_before, complete_len_after)
        && before == after
    {
        projection.meta.record_bytes = before;
        if let Some((seq, hash)) = physical_tail {
            projection.meta.record_tail_seq = Some(seq.0);
            projection.meta.record_tail_hash = hash;
        }
    }
    let (updated_at, updated_at_subsec_nanos) =
        file_mtime(&path).unwrap_or((projection.meta.created_at, 0));
    projection.meta.updated_at = updated_at;
    projection.meta.updated_at_subsec_nanos = updated_at_subsec_nanos;
    projection.refresh_derived();
    projection.meta.cache_hit = json_f64_fixed_point(projection.meta.cache_hit)?;
    projection.meta.projection_digest = projection_digest(&projection.meta)?;
    Ok(projection)
}

pub(crate) fn bounded_meta(
    runs: &Path,
    run: &RunId,
    limits: crate::bounded_replay::ReplayReadLimits,
) -> Result<SessionMeta, RecordError> {
    crate::require_strict_replay_policy()?;
    let budget = LogicalReplayBudget::bounded(limits)?;
    Ok(load_session_projection_budgeted(runs, run, None, budget)?.into_meta())
}
