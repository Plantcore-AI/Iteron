//! Pure resolution against the held native catalog, route and child execution policy.
use super::{KernelSpawner, KernelSpawnerContext, safe_agent_refusal};
use iteron_agents::{AgentDef, AgentEngineExecution, AgentEngineOrigin};
use iteron_protocol::Effort;
use iteron_workflow::AgentCall;

pub(super) struct ResolvedAgentProfile {
    pub definition: AgentDef,
    pub effort: Effort,
}
pub(super) fn resolve(
    cx: &KernelSpawnerContext,
    call: &AgentCall,
) -> Result<ResolvedAgentProfile, String> {
    if cx.tunables_pin.is_none() {
        return Err("child runtime tunables were not pinned".into());
    }
    call.validate_request_metadata()
        .map_err(|error| safe_agent_refusal(error.public_reason()))?;
    let requested = call.agent_type.as_deref().unwrap_or("generic");
    if cx.plugin_management.as_ref().is_some_and(|owner| {
        !owner.dispatch_policy().admits(
            iteron_protocol::extension_dispatch::ExtensionSurfaceV1::Agent,
            requested,
        )
    }) {
        return Err("verified plugin future agent dispatch was revoked".into());
    }
    let definition = cx
        .agent_catalog
        .get(requested)
        .cloned()
        .ok_or("requested agent type is absent from the pinned catalog")?;
    definition
        .validate()
        .map_err(|_| "pinned agent definition is invalid")?;
    cx.execution_policy
        .per_agent_model
        .validate_owner(&cx.provider_id, &cx.model)
        .map_err(safe_agent_refusal)?;
    cx.execution_policy
        .per_agent_tool_profile
        .validate_owner(&cx.permission_rules)
        .map_err(safe_agent_refusal)?;
    if cx.fallback_provider_routes.len() >= iteron_provider::catalog::MAX_RESOLVED_ROUTES {
        return Err("native child route set exceeds its bound".into());
    }
    let native_routes: Vec<_> = cx
        .fallback_provider_routes
        .iter()
        .map(|route| {
            (
                route.route.provider_id.as_str(),
                route.route.model_id.as_str(),
            )
        })
        .collect();
    let roles = cx
        .execution_policy
        .role_specific_models
        .validate_owner_with_routes(
            &cx.agent_catalog,
            &cx.provider_id,
            &cx.model,
            &native_routes,
        )
        .map_err(safe_agent_refusal)?;
    if definition.model.is_some() && !roles.contains_key(requested) {
        return Err("agent definition model has no admitted native role route".into());
    }
    let effort = cx
        .execution_policy
        .admit_child_effort(call.effort, &cx.effort_policy)
        .map_err(safe_agent_refusal)?;
    Ok(ResolvedAgentProfile { definition, effort })
}

impl KernelSpawner {
    pub(super) fn prepare_engine_execution(
        &self,
        request: &super::super::persistent_agents::AgentEngineRequest,
        origin: AgentEngineOrigin,
    ) -> Result<AgentEngineExecution, String> {
        origin
            .validate()
            .map_err(|_| "invalid native engine parent source")?;
        if origin.parent().tenant != self.cx.tenant.0 {
            return Err("engine source belongs to another tenant".into());
        }
        let call = request.call();
        let profile = resolve(&self.cx, &call)?;
        if profile.definition.is_isolated_writer() {
            return Err("engine investigator cannot request isolated writer authority".into());
        }
        let observation = super::agent_route_binding::observation(
            &self.cx,
            profile.definition.model.clone(),
            call.model.clone(),
        )
        .map_err(|error| safe_agent_refusal(&error.to_string()))?;
        let native = super::agent_route_binding::select(&self.cx, &observation)
            .map_err(|error| safe_agent_refusal(&error.to_string()))?;
        Ok(AgentEngineExecution {
            profile: profile.definition.name.clone(),
            profile_digest: profile.definition.execution_digest(),
            provider_id: native.identity.provider_id,
            model_id: native.identity.model_id,
            catalog_digest: native.identity.catalog_digest,
            capability_digest: native.identity.capability_digest,
            effort: profile.effort,
            origin,
        })
    }
    pub(super) fn validate_engine_execution(
        &self,
        execution: &AgentEngineExecution,
    ) -> Result<(), String> {
        execution
            .validate()
            .map_err(|_| "invalid committed child execution binding")?;
        let request = super::super::persistent_agents::AgentEngineRequest {
            profile: Some(execution.profile.clone()),
            model: Some(execution.model_id.clone()),
            effort: Some(execution.effort),
        };
        if self.prepare_engine_execution(&request, execution.origin.clone())? != *execution {
            return Err("committed child execution differs from held native evidence".into());
        }
        Ok(())
    }
}
