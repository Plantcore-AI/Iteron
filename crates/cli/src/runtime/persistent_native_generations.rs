//! Bounded immutable native contexts for newly admitted children and retained committed bindings.
use super::persistent_agents::AgentEngineRequest;
use super::workflow_spawner::{KernelSpawner, KernelSpawnerContext};
use iteron_agents::{
    AgentEngineExecution, AgentEngineOrigin, AgentEngineParentSource, ControllerError,
};
use iteron_protocol::native_child_context::{NativeChildContextRefV1, NativeChildContextV1};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
#[path = "persistent_native_generations/archive.rs"]
mod archive;
// A first current context for each actual scoped owner is independent of retained history.
// No eviction can erase a committed resident's old reference. 64 scopes plus 16 historical
// publications bounds the owner to 80 retained contexts; every scope still has exact WAL truth.
const MAX_CURRENT_SCOPES: usize = 64;
const MAX_HISTORICAL_GENERATIONS: usize = 16;
const MAX_GENERATIONS: usize = MAX_CURRENT_SCOPES + MAX_HISTORICAL_GENERATIONS;

struct Generation {
    spawner: Arc<KernelSpawner>,
    reference: NativeChildContextRefV1,
    publication: NativeChildContextV1,
}
pub(super) struct NativeGenerations {
    refreshing: BTreeSet<String>,
    admitted_scopes: BTreeSet<String>,
    #[cfg(test)]
    legacy_main_fixture: bool,
    invalidated: BTreeSet<iteron_protocol::agent_control::AgentIdV1>,
    bootstrap: Arc<KernelSpawner>,
    held: BTreeMap<String, Generation>,
    active: BTreeMap<String, String>,
    owners: BTreeMap<iteron_protocol::agent_control::AgentIdV1, String>,
}
impl NativeGenerations {
    pub(super) fn new(mut context: KernelSpawnerContext) -> Self {
        context.execution_deadline = None; // exact epoch/Invocation owns its deadline lease.
        Self {
            refreshing: BTreeSet::new(),
            admitted_scopes: BTreeSet::new(),
            #[cfg(test)]
            legacy_main_fixture: false,
            invalidated: BTreeSet::new(),
            bootstrap: Arc::new(KernelSpawner::new(context)),
            held: BTreeMap::new(),
            active: BTreeMap::new(),
            owners: BTreeMap::new(),
        }
    }
    #[cfg(test)]
    pub(super) fn allow_legacy_main_fixture(&mut self) {
        self.legacy_main_fixture = true;
    }
    pub(super) fn bootstrap(&self) -> &KernelSpawner {
        &self.bootstrap
    }
    pub(super) fn reference(
        &mut self,
        owner: iteron_protocol::agent_control::AgentIdV1,
        source: &AgentEngineParentSource,
        context: &KernelSpawnerContext,
    ) -> Result<Option<NativeChildContextRefV1>, ControllerError> {
        if self.invalidated.len() >= 64 && !self.invalidated.contains(&owner) {
            return Err(ControllerError::Capacity);
        }
        self.invalidated.insert(owner);
        if self.refreshing.len() >= 64 && !self.refreshing.contains(&source.provider_scope_sha256) {
            return Err(ControllerError::Capacity);
        }
        self.refreshing.insert(source.provider_scope_sha256.clone());
        for generation in self.held.values() {
            if generation.reference.tenant != source.tenant
                || generation.reference.run != source.run
                || !generation.spawner.same_native_primary(&context.provider)
            {
                continue;
            }
            let candidate = super::workflow_spawner::native_context::capture(
                context,
                source,
                generation.reference.sequence,
            )?;
            if candidate == generation.publication {
                return Ok(Some(generation.reference.clone()));
            }
        }
        self.capacity(source)?;
        Ok(None)
    }
    pub(super) fn install(
        &mut self,
        owner: iteron_protocol::agent_control::AgentIdV1,
        mut context: KernelSpawnerContext,
        source: &AgentEngineParentSource,
        publication: &NativeChildContextV1,
        reference: NativeChildContextRefV1,
    ) -> Result<(), ControllerError> {
        let actual =
            super::workflow_spawner::native_context::capture(&context, source, reference.sequence)?;
        if &actual != publication
            || reference.generation_sha256 != actual.generation_sha256
            || reference.tenant != source.tenant
            || reference.run != source.run
        {
            return Err(ControllerError::RequestConflict);
        }
        reference.validate().map_err(ControllerError::Invalid)?;
        let digest = actual.generation_sha256;
        if let Some(existing) = self.held.get(&digest) {
            if existing.reference != reference
                || !existing.spawner.same_native_primary(&context.provider)
            {
                return Err(ControllerError::RequestConflict);
            }
        } else {
            self.capacity(source)?;
            let (run, workflow) = self.bootstrap.persistent_namespace();
            context.parent_run_id = run.to_owned();
            context.workflow_id = workflow.to_owned();
            context.execution_deadline = None;
            context.native_context_reference = Some(reference.clone());
            self.held.insert(
                digest.clone(),
                Generation {
                    spawner: Arc::new(KernelSpawner::new(context)),
                    reference,
                    publication: publication.clone(),
                },
            );
        }
        self.admitted_scopes
            .insert(source.provider_scope_sha256.clone());
        self.refreshing.remove(&source.provider_scope_sha256);
        self.invalidated.remove(&owner);
        self.owners.insert(owner, digest.clone());
        self.active
            .insert(source.provider_scope_sha256.clone(), digest);
        Ok(())
    }
    fn capacity(&self, source: &AgentEngineParentSource) -> Result<(), ControllerError> {
        let new_scope = !self.admitted_scopes.contains(&source.provider_scope_sha256);
        let scopes = self.admitted_scopes.len() + usize::from(new_scope);
        if scopes > MAX_CURRENT_SCOPES
            || self.held.len() >= scopes + MAX_HISTORICAL_GENERATIONS
            || self.held.len() >= MAX_GENERATIONS
        {
            Err(ControllerError::Capacity)
        } else {
            Ok(())
        }
    }
    pub(super) fn prepare(
        &self,
        request: &AgentEngineRequest,
        origin: AgentEngineOrigin,
    ) -> Result<AgentEngineExecution, ControllerError> {
        if self
            .refreshing
            .contains(&origin.parent().provider_scope_sha256)
        {
            return Err(ControllerError::RecoveryRequired);
        }
        if self.owners.iter().any(|(owner, id)| {
            self.invalidated.contains(owner)
                && self.held.get(id).is_some_and(|generation| {
                    generation.publication.scope_sha256 == origin.parent().provider_scope_sha256
                })
        }) {
            return Err(ControllerError::RecoveryRequired);
        }
        let spawner = match self
            .active
            .get(&origin.parent().provider_scope_sha256)
            .and_then(|id| self.held.get(id))
        {
            Some(generation) => &generation.spawner,
            None => {
                // Existing provider-free unit fixtures explicitly begin with no Main
                // native publication. This exception never exists in a production build.
                #[cfg(test)]
                if self.legacy_main_fixture
                    && origin.parent().run == self.bootstrap.persistent_namespace().0
                {
                    return self
                        .bootstrap
                        .prepare_engine_execution(request, origin)
                        .map_err(|_| ControllerError::Permission);
                }
                return Err(ControllerError::RecoveryRequired);
            }
        };
        spawner
            .prepare_engine_execution(request, origin)
            .map_err(|_| {
                ControllerError::Invalid("child profile has no admitted native execution binding")
            })
    }
    pub(super) fn default_child(
        &self,
        parent: iteron_protocol::agent_control::AgentIdV1,
        writer: bool,
    ) -> Result<Option<AgentEngineExecution>, ControllerError> {
        if self.invalidated.contains(&parent) {
            return Err(ControllerError::RecoveryRequired);
        }
        let Some(generation) = self.owners.get(&parent).and_then(|id| self.held.get(id)) else {
            #[cfg(test)]
            if parent == iteron_protocol::agent_control::AgentIdV1(1) && self.legacy_main_fixture {
                return Ok(None); // Explicit unbound legacy Main fixture only.
            }
            return Err(ControllerError::RecoveryRequired);
        };
        let source = AgentEngineParentSource {
            tenant: generation.publication.tenant.clone(),
            run: generation.publication.run.clone(),
            provider_scope_sha256: generation.publication.scope_sha256.clone(),
        };
        let request = AgentEngineRequest {
            profile: Some(if writer {
                iteron_agents::ISOLATED_WRITER_NAME.into()
            } else {
                "generic".into()
            }),
            model: None,
            effort: None,
        };
        generation
            .spawner
            .prepare_ordinary_execution(
                &request,
                AgentEngineOrigin::DirectSubagent { parent: source },
            )
            .map(Some)
            .map_err(|_| ControllerError::Permission)
    }
    pub(super) fn for_execution(
        &mut self,
        execution: Option<&AgentEngineExecution>,
    ) -> Result<Arc<KernelSpawner>, ControllerError> {
        let Some(execution) = execution else {
            #[cfg(test)]
            if self.legacy_main_fixture {
                return Ok(self.bootstrap.clone()); // Unbound legacy fixture, not cold authority.
            }
            return Err(ControllerError::RecoveryRequired);
        };
        let selected = if let Some(reference) = &execution.native_context {
            if !self.held.contains_key(&reference.generation_sha256) {
                self.capacity(execution.origin.parent())?;
                let publication = archive::load(self.bootstrap(), reference)?;
                let context = self
                    .bootstrap
                    .restore_native_context(&publication, reference.clone())?;
                self.admitted_scopes
                    .insert(publication.scope_sha256.clone());
                self.held.insert(
                    reference.generation_sha256.clone(),
                    Generation {
                        spawner: Arc::new(KernelSpawner::new(context)),
                        reference: reference.clone(),
                        publication,
                    },
                );
            }
            let generation = self
                .held
                .get(&reference.generation_sha256)
                .ok_or(ControllerError::RecoveryRequired)?;
            if &generation.reference != reference {
                return Err(ControllerError::RequestConflict);
            }
            generation.spawner.clone()
        } else {
            #[cfg(test)]
            if self.legacy_main_fixture
                && execution.origin.parent().run == self.bootstrap.persistent_namespace().0
            {
                self.bootstrap
                    .validate_engine_execution(execution)
                    .map_err(|_| ControllerError::RequestConflict)?;
                return Ok(self.bootstrap.clone());
            }
            return Err(ControllerError::RecoveryRequired);
        };
        selected
            .validate_engine_execution(execution)
            .map_err(|_| ControllerError::RequestConflict)?;
        Ok(selected)
    }
}
