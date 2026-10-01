//! Capture mutable host posture independently from the immutable admitted composition.
use super::{KernelSpawner, KernelSpawnerContext};
use crate::runtime::provider_selection::ProviderSelectionOwner;
use iteron_agents::{AgentEngineParentSource, ControllerError};
use iteron_protocol::PricingRoute;
use iteron_protocol::native_child_context::{NativeChildContextRefV1, NativeChildContextV1};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const MAX_CAPTURE_BYTES: usize = 2 * 1024 * 1024;
fn base(context: &KernelSpawnerContext) -> Result<String, ControllerError> {
    let mut size = context.hooks.catalog_identity().canonical_bytes;
    let mut hash = Sha256::new();
    hash.update(b"iteron-native-child-base-v1\0");
    let mut part = |bytes: &[u8]| -> Result<(), ControllerError> {
        size = size
            .checked_add(bytes.len())
            .ok_or(ControllerError::Capacity)?;
        if size > MAX_CAPTURE_BYTES {
            return Err(ControllerError::Capacity);
        }
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        Ok(())
    };
    if context.agent_catalog.defs().len() > 256 || context.dependency_skill_dirs.len() > 128 {
        return Err(ControllerError::Capacity);
    }
    let pin = context
        .tunables_pin
        .as_ref()
        .ok_or(ControllerError::Permission)?;
    part(pin.resolution_digest_sha256().as_bytes())?;
    for path in [&context.workspace, &context.runtime_state_dir] {
        part(path.as_os_str().as_encoded_bytes())?;
    }
    if let Some(path) = &context.context_home_dir {
        part(path.as_os_str().as_encoded_bytes())?;
    }
    for (first, second) in &context.dependency_skill_dirs {
        part(first.as_os_str().as_encoded_bytes())?;
        part(second.as_os_str().as_encoded_bytes())?;
    }
    for value in &context.sensitive_env_names {
        part(value.as_bytes())?;
    }
    for definition in context.agent_catalog.defs() {
        // Hash the actual complete bounded definition, not its label alone.
        definition
            .validate()
            .map_err(|_| ControllerError::Permission)?;
        part(definition.system.as_bytes())?;
        part(definition.execution_digest().as_bytes())?;
    }
    part(context.hooks.catalog_identity().digest_sha256.as_bytes())?;
    for text in [&context.compaction_summary_prompt, &context.verify_command] {
        if let Some(text) = text {
            part(text.as_bytes())?;
        }
    }
    if let Some((text, trust)) = &context.environment_context {
        part(text.as_bytes())?;
        part(format!("{trust:?}").as_bytes())?;
    }
    // The pin commits executable controls, strategies and policy families. Process-local
    // observers and a transient invocation deadline are not new child authority.
    Ok(format!("sha256:{:x}", hash.finalize()))
}
pub(crate) fn capture(
    context: &KernelSpawnerContext,
    source: &AgentEngineParentSource,
    sequence: u64,
) -> Result<NativeChildContextV1, ControllerError> {
    source.validate()?;
    if context.tenant.0 != source.tenant || context.parent_run_id != source.run {
        return Err(ControllerError::Permission);
    }
    let route = PricingRoute {
        provider_id: context.provider_id.clone(),
        model_id: context.model.clone(),
        catalog_digest: context.catalog_digest.clone(),
        capability_digest: context.capability_digest.clone(),
    };
    ProviderSelectionOwner::validate_selection(&context.provider, &route)
        .map_err(|_| ControllerError::Permission)?;
    if context.permission_rules.tool_rules().len() > 256
        || context.permission_rules.capability_rules().len() > 5
        || context.permission_rules.tool_rules().any(|(name, _)| {
            name.is_empty() || name.len() > 128 || name.chars().any(char::is_control)
        })
    {
        return Err(ControllerError::Capacity);
    }
    let mut value = NativeChildContextV1 {
        version: 1,
        generation_sha256: String::new(),
        base_sha256: base(context)?,
        publication_sequence: sequence,
        tenant: source.tenant.clone(),
        run: source.run.clone(),
        scope_sha256: source.provider_scope_sha256.clone(),
        route,
        context_window: context.model_context_window,
        output_cap: context.model_max_output_tokens,
        permission_mode: context.permission_mode,
        permission_rules: context.permission_rules.clone(),
        authority_ceiling: context.authority_ceiling,
        policy_capabilities: context.policy_capabilities,
        bypass_permissions: context.bypass_permissions,
        default_effort: context.default_effort,
    };
    // Validate nested allocations before the descriptor's canonical clone/hash.
    if value.permission_rules.tool_rules().len() > 256 {
        return Err(ControllerError::Capacity);
    }
    value.generation_sha256 = value.digest().map_err(ControllerError::Invalid)?;
    value.validate().map_err(ControllerError::Invalid)?;
    Ok(value)
}
impl KernelSpawner {
    pub(crate) fn native_state_root(&self) -> &std::path::Path {
        &self.cx.runtime_state_dir
    }
    pub(crate) fn native_base_digest(&self) -> Result<String, ControllerError> {
        base(&self.cx)
    }
    pub(crate) fn persistent_namespace(&self) -> (&str, &str) {
        (&self.cx.parent_run_id, &self.cx.workflow_id)
    }
    pub(crate) fn same_native_primary(
        &self,
        provider: &Arc<dyn iteron_provider::Provider>,
    ) -> bool {
        Arc::ptr_eq(&self.cx.provider, provider)
    }
    pub(crate) fn restore_native_context(
        &self,
        publication: &NativeChildContextV1,
        reference: NativeChildContextRefV1,
    ) -> Result<KernelSpawnerContext, ControllerError> {
        publication.validate().map_err(ControllerError::Invalid)?;
        if publication.base_sha256 != self.native_base_digest()?
            || !publication
                .authority_ceiling
                .is_subset_of(self.cx.authority_ceiling)
            || !publication
                .policy_capabilities
                .is_subset_of(self.cx.policy_capabilities)
        {
            return Err(ControllerError::RequestConflict);
        }
        let mut context = self.cx.clone();
        // Select only exact already-held native transport evidence. Never create a provider from
        // a journal's scalar model/provider fields.
        let primary = PricingRoute {
            provider_id: context.provider_id.clone(),
            model_id: context.model.clone(),
            catalog_digest: context.catalog_digest.clone(),
            capability_digest: context.capability_digest.clone(),
        };
        if primary != publication.route {
            let matches: Vec<_> = context
                .fallback_provider_routes
                .iter()
                .filter(|route| route.route == publication.route)
                .collect();
            if matches.len() != 1 {
                return Err(ControllerError::RecoveryRequired);
            }
            context.provider = matches[0].provider.clone();
        }
        ProviderSelectionOwner::validate_selection(&context.provider, &publication.route)
            .map_err(|_| ControllerError::Permission)?;
        context.model = publication.route.model_id.clone();
        context.provider_id = publication.route.provider_id.clone();
        context.catalog_digest = publication.route.catalog_digest.clone();
        context.capability_digest = publication.route.capability_digest.clone();
        context.model_context_window = publication.context_window;
        context.model_max_output_tokens = publication.output_cap;
        context.permission_mode = publication.permission_mode;
        context.permission_rules = publication.permission_rules.clone();
        context.authority_ceiling = publication.authority_ceiling;
        context.policy_capabilities = publication.policy_capabilities;
        context.bypass_permissions = publication.bypass_permissions;
        context.default_effort = publication.default_effort;
        context.execution_deadline = None;
        context.native_context_reference = Some(reference);
        Ok(context)
    }
}
