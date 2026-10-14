//! Sole session owner of graph admission/reservations and its durable graph instances.

use super::pump;
use super::store::RegistryStore;
use super::types::{
    LIVE_WORKFLOW_CONTRACT_VERSION, LiveWorkflowCommandV1, LiveWorkflowError, LiveWorkflowPolicy,
    LiveWorkflowReplyV1, LiveWorkflowViewV1, RegistryEntry, RegistryIndex, budget_fits,
};
use crate::runtime::persistent_agents::AgentControlPort;
use iteron_workflow::live_scheduler::file_journal::WorkflowFileJournal;
use iteron_workflow::live_scheduler::{
    WorkflowConfigV1, WorkflowPlanJournal, WorkflowScheduler, WorkflowStoreError,
};
use iteron_workflow::task_dag::BudgetUsage;
use std::collections::BTreeMap;
use std::path::Path;

pub(super) type Graph = WorkflowScheduler<WorkflowFileJournal>;

pub(super) struct Registry {
    policy: LiveWorkflowPolicy,
    store: RegistryStore,
    index: RegistryIndex,
    graphs: BTreeMap<String, Graph>,
    driver_errors: BTreeMap<String, String>,
    receipt_cursors: BTreeMap<String, usize>,
    cursor: usize,
    poisoned: bool,
}

impl Registry {
    pub fn open(root: &Path, policy: LiveWorkflowPolicy) -> Result<Self, LiveWorkflowError> {
        policy.validate()?;
        let mut store = RegistryStore::open(root)?;
        let index = match store.load()? {
            Some(index) => index,
            None => {
                let index = RegistryIndex {
                    revision: 0,
                    root_agent_id: policy.root_agent_id,
                    entries: BTreeMap::new(),
                };
                store.commit(None, &index)?;
                index
            }
        };
        if index.root_agent_id != policy.root_agent_id || index.entries.len() > policy.max_workflows
        {
            return Err(LiveWorkflowError::Invalid(
                "registry owner/capacity differs from host policy",
            ));
        }
        validate_reservations(&index, &policy)?;
        let mut owner = Self {
            policy,
            store,
            index,
            graphs: BTreeMap::new(),
            driver_errors: BTreeMap::new(),
            receipt_cursors: BTreeMap::new(),
            cursor: 0,
            poisoned: false,
        };
        let ids: Vec<_> = owner.index.entries.keys().cloned().collect();
        for id in ids {
            owner.restore(&id)?;
        }
        Ok(owner)
    }

    fn restore(&mut self, id: &str) -> Result<(), LiveWorkflowError> {
        let entry = self
            .index
            .entries
            .get(id)
            .cloned()
            .ok_or(LiveWorkflowError::NotFound)?;
        let mut journal = self.store.graph_journal(id, entry.active)?;
        if entry.active && journal.load()?.is_none() {
            return Err(WorkflowStoreError::OutcomeUnknown.into());
        }
        let graph = WorkflowScheduler::open(journal, entry.config)?;
        if !entry.active {
            let mut next = self.index.clone();
            next.entries
                .get_mut(id)
                .ok_or(LiveWorkflowError::NotFound)?
                .active = true;
            self.publish_index(next)?;
        }
        self.graphs.insert(id.to_owned(), graph);
        Ok(())
    }

    fn open_graph(&mut self, id: &str, now: u64) -> Result<(), LiveWorkflowError> {
        self.ensure_live()?;
        if self.graphs.contains_key(id) {
            return Ok(());
        }
        if self.index.entries.contains_key(id) {
            return self.restore(id);
        }
        if self.index.entries.len() >= self.policy.max_workflows {
            return Err(LiveWorkflowError::Capacity);
        }
        let config = WorkflowConfigV1 {
            workflow_id: id.to_owned(),
            budget: self.policy.graph_budget,
            max_nodes: self.policy.max_nodes,
            max_edges: self.policy.max_edges,
            max_concurrency: self.policy.max_concurrency,
            started_at_unix_ms: now,
            deadline_unix_ms: now
                .checked_add(self.policy.graph_budget.max_wall_ms)
                .ok_or(LiveWorkflowError::Clock)?,
        };
        let mut next = self.index.clone();
        next.entries.insert(
            id.to_owned(),
            RegistryEntry {
                config,
                active: false,
            },
        );
        validate_reservations(&next, &self.policy)?;
        // Admission intent reserves the whole graph budget before any child journal is created.
        self.publish_index(next)?;
        self.restore(id)
    }

    fn publish_index(&mut self, mut next: RegistryIndex) -> Result<(), LiveWorkflowError> {
        self.ensure_live()?;
        next.revision = self
            .index
            .revision
            .checked_add(1)
            .ok_or(LiveWorkflowError::Capacity)?;
        if let Err(error) = self.store.commit(Some(self.index.revision), &next) {
            if matches!(
                error,
                LiveWorkflowError::Store(
                    WorkflowStoreError::OutcomeUnknown | WorkflowStoreError::Conflict
                )
            ) {
                self.poisoned = true;
            }
            return Err(error);
        }
        self.index = next;
        Ok(())
    }

    pub async fn command(
        &mut self,
        command: LiveWorkflowCommandV1,
        control: &dyn AgentControlPort,
    ) -> Result<LiveWorkflowReplyV1, LiveWorkflowError> {
        self.ensure_live()?;
        let id = command.workflow_id().to_owned();
        let mut receipt = None;
        if matches!(command, LiveWorkflowCommandV1::Open { .. }) {
            self.open_graph(&id, pump::now()?)?;
        }
        let graph = self
            .graphs
            .get_mut(&id)
            .ok_or(LiveWorkflowError::NotFound)?;
        match command {
            LiveWorkflowCommandV1::Open { .. } | LiveWorkflowCommandV1::Read { .. } => {}
            LiveWorkflowCommandV1::Replan {
                request_id, plan, ..
            } => {
                receipt = Some(graph.replan(&request_id, plan)?);
            }
            LiveWorkflowCommandV1::Pump { .. } => {
                pump::drive(
                    graph,
                    control,
                    self.receipt_cursors.entry(id.clone()).or_default(),
                )
                .await?;
                self.driver_errors.remove(&id);
            }
            LiveWorkflowCommandV1::Interrupt { node_id, .. } => {
                graph
                    .interrupt(node_id, control.workflow_port().as_ref())
                    .await?;
            }
            LiveWorkflowCommandV1::Reconcile { node_id, .. } => {
                pump::reconcile(graph, control, node_id)?;
            }
        }
        Ok(LiveWorkflowReplyV1 {
            view: self.view(&id)?,
            receipt,
        })
    }

    pub fn view(&self, id: &str) -> Result<LiveWorkflowViewV1, LiveWorkflowError> {
        self.ensure_live()?;
        let graph = self.graphs.get(id).ok_or(LiveWorkflowError::NotFound)?;
        let snapshot = graph.snapshot()?;
        let now = pump::now()?;
        Ok(LiveWorkflowViewV1 {
            version: LIVE_WORKFLOW_CONTRACT_VERSION,
            config: snapshot.config().clone(),
            revision: snapshot.revision(),
            sequence: snapshot.sequence(),
            nodes: snapshot.nodes().cloned().collect(),
            reserved: snapshot.reserved_budget(),
            ready: graph.ready_nodes(now)?,
            observed_at_unix_ms: now,
            driver_error: self.driver_errors.get(id).cloned(),
        })
    }

    /// Fair bounded background step. A graph error remains observable and does not spin forever.
    pub async fn tick(&mut self, control: &dyn AgentControlPort) -> bool {
        if self.poisoned || self.graphs.is_empty() {
            return false;
        }
        let ids: Vec<_> = self.graphs.keys().cloned().collect();
        for offset in 0..ids.len() {
            let index = (self.cursor + offset) % ids.len();
            let id = &ids[index];
            if self.driver_errors.contains_key(id) {
                continue;
            }
            let Some(graph) = self.graphs.get_mut(id) else {
                continue;
            };
            match pump::has_work(graph) {
                Ok(true) => {
                    self.cursor = (index + 1) % ids.len();
                    if let Err(error) = pump::drive(
                        graph,
                        control,
                        self.receipt_cursors.entry(id.clone()).or_default(),
                    )
                    .await
                    {
                        self.driver_errors
                            .insert(id.clone(), pump::bounded_detail(&error.to_string()));
                    }
                    return true;
                }
                Ok(false) => {}
                Err(error) => {
                    self.driver_errors
                        .insert(id.clone(), pump::bounded_detail(&error.to_string()));
                }
            }
        }
        false
    }

    pub fn resume_driver(&mut self, id: &str) {
        self.driver_errors.remove(id);
    }
    pub fn exhaust_driver(&mut self) {
        for (id, graph) in &self.graphs {
            if pump::has_work(graph).unwrap_or(true) {
                self.driver_errors.insert(
                    id.clone(),
                    "finite background observation limit reached; request pump/reconcile".into(),
                );
            }
        }
    }
    fn ensure_live(&self) -> Result<(), LiveWorkflowError> {
        if self.poisoned {
            Err(WorkflowStoreError::OutcomeUnknown.into())
        } else {
            Ok(())
        }
    }
}

fn validate_reservations(
    index: &RegistryIndex,
    policy: &LiveWorkflowPolicy,
) -> Result<(), LiveWorkflowError> {
    let mut total = BudgetUsage::default();
    for (id, entry) in &index.entries {
        super::types::validate_id(id)?;
        let config = &entry.config;
        // Stored admission survives restart under the original host ceiling; the new remaining
        // budget is an admission ceiling for additional graphs, not a reset of prior reservations.
        if config.workflow_id != *id
            || !budget_fits(config.budget, policy.aggregate_budget)
            || config.max_nodes > policy.max_nodes
            || config.max_edges > policy.max_edges
            || config.max_concurrency > policy.max_concurrency
        {
            return Err(LiveWorkflowError::Invalid(
                "stored graph exceeds host policy",
            ));
        }
        total.turns = total
            .turns
            .checked_add(u64::from(config.budget.max_turns))
            .ok_or(LiveWorkflowError::Capacity)?;
        total.tokens = total
            .tokens
            .checked_add(config.budget.max_tokens)
            .ok_or(LiveWorkflowError::Capacity)?;
        total.cost_microusd = total
            .cost_microusd
            .checked_add(config.budget.max_cost_microusd)
            .ok_or(LiveWorkflowError::Capacity)?;
        total.wall_ms = total.wall_ms.max(config.budget.max_wall_ms);
    }
    if total.turns > u64::from(policy.aggregate_budget.max_turns)
        || total.tokens > policy.aggregate_budget.max_tokens
        || total.cost_microusd > policy.aggregate_budget.max_cost_microusd
        || total.wall_ms > policy.aggregate_budget.max_wall_ms
    {
        return Err(LiveWorkflowError::Capacity);
    }
    Ok(())
}
