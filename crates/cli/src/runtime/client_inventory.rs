//! Safe boundary snapshots from the actual installed runtime authorities.

use std::sync::Arc;

use iteron_protocol::client_inventory::{ClientInventoryKindV1, ClientInventoryQueryV1};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::Agent;
use crate::client_inventory::{ClientInventoryOwner, page, safe};

const MAX_RUNTIME_ENTRIES: usize = 2048;

pub(crate) struct RuntimeClientInventory {
    bootstrap: Option<Arc<ClientInventoryOwner>>,
    overview: Vec<Value>,
    tools: Vec<Value>,
    hooks: Vec<Value>,
    agents: Vec<Value>,
    skills: Option<Vec<Value>>,
    effective: Option<Vec<Value>>,
    checkpoint: Value,
    permissions: Vec<Value>,
}

impl Agent {
    pub(crate) fn install_client_inventory(
        &mut self,
        owner: Arc<ClientInventoryOwner>,
    ) -> Result<(), &'static str> {
        if self.client_inventory.is_some() {
            return Err("bootstrap inventory is already installed");
        }
        self.client_inventory = Some(owner);
        Ok(())
    }

    pub(crate) fn client_inventory_owner(&self) -> Option<Arc<ClientInventoryOwner>> {
        self.client_inventory.clone()
    }

    pub(crate) fn capture_client_inventory(&self) -> RuntimeClientInventory {
        let specs = self.registry.spec_snapshot();
        let tools = specs.specs().iter().take(MAX_RUNTIME_ENTRIES).map(|spec| {
            let schema = serde_json::to_vec(&spec.input_schema).ok().map(|bytes| hex::encode(Sha256::digest(bytes)));
            json!({"name":safe(&spec.name),"purity":spec.purity,"declared_capability":spec.capability,"input_schema_digest_sha256":schema,
                "named_rule":self.permission_rules().tool_rule(&spec.name),
                "declared_gate":if self.authority_ceiling.contains(spec.capability) && self.policy_capabilities.contains(spec.capability) {
                    iteron_protocol::permission::gate(self.permission_mode(),self.permission_rules(),&spec.name,spec.capability)
                } else { iteron_protocol::Verdict::Deny },
                "operation_requirements_checked_at_dispatch":true})
        }).collect::<Vec<_>>();
        let identity = self.hooks.catalog_identity();
        let hooks = self
            .hooks
            .inventory_events()
            .into_iter()
            .map(|(event, handlers)| json!({"event":event,"handlers":handlers}))
            .collect::<Vec<_>>();
        let catalog = self.agent_catalog_snapshot();
        let agents = catalog.defs().iter().take(MAX_RUNTIME_ENTRIES).map(|agent| json!({"name":safe(&agent.name),"trust":agent.trust,"model":agent.model.as_deref().map(safe)})).collect::<Vec<_>>();
        let skills = iteron_ctx::skills::captured_metadata_for(self.context_home_dir.as_deref(),&self.workspace,&self.dependency_skill_dirs)
            .map(|catalog| catalog.defs().iter().take(MAX_RUNTIME_ENTRIES).map(|skill| json!({"name":safe(&skill.name),"trust":skill.trust,"tier":match skill.tier {
                iteron_ctx::skills::SkillTier::User=>"user",iteron_ctx::skills::SkillTier::Project=>"project",iteron_ctx::skills::SkillTier::Dependency=>"dependency"}})).collect::<Vec<_>>());
        let (checkpoint, effective) = match self.tunables_checkpoint() {
            Ok(iteron_record::TunablesCheckpoint::V2(snapshot)) => (
                json!({"version":2,"snapshot_digest_sha256":snapshot.snapshot_digest_sha256,"effective_digest_sha256":snapshot.effective_digest_sha256,
                "registry_digest_sha256":snapshot.registry_digest_sha256,"input_digest_sha256":snapshot.input_digest_sha256,"canonicalization":snapshot.canonicalization}),
                Some(
                    snapshot
                        .entries
                        .iter()
                        .take(MAX_RUNTIME_ENTRIES)
                        .filter_map(|entry| serde_json::to_value(entry).ok())
                        .collect::<Vec<_>>(),
                ),
            ),
            Ok(checkpoint) => (
                json!({"version":1,"snapshot_digest_sha256":checkpoint.snapshot_digest_sha256(),"effective_digest_sha256":checkpoint.effective_digest_sha256(),"reconstruction_unavailable":true}),
                None,
            ),
            Err(_) => (Value::Null, None),
        };
        let permissions = vec![
            json!({"mode":self.permission_mode(),"rules":self.permission_rules(),"authority_ceiling":self.authority_ceiling,"policy_capabilities":self.policy_capabilities,
            "operation_rule_aliases":["bash:external","browser:external","computer:external","bash:trust_mutating","write_file:trust_mutating","edit:trust_mutating","apply_patch:trust_mutating"],
            "semantics":"declared tool gate is informative; dispatch also intersects the task envelope and actual operation requirements"}),
        ];
        let overview = vec![
            json!({"provider_id":iteron_provider::Provider::provider_instance_id(self.provider.as_ref()),"model_id":safe(&self.model),
            "model_context_window_tokens":self.model_context_window,"model_max_output_tokens":self.model_max_output_tokens,
            "tool_registry_revision":specs.revision(),"tool_count":specs.specs().len(),"tools_truncated":specs.specs().len()>MAX_RUNTIME_ENTRIES,
            "hook_digest_sha256":identity.digest_sha256,"hook_handlers":identity.entry_count,
            "agent_catalog_identity":catalog.runtime_identity(),"skill_metadata_captured":skills.is_some(),
            "checkpoint":checkpoint,"bootstrap_inventory_available":self.client_inventory.is_some(),
            "snapshot_boundary":"last idle/turn boundary; live process/MCP/controller state is available through its own status controls"}),
        ];
        RuntimeClientInventory {
            bootstrap: self.client_inventory_owner(),
            overview,
            tools,
            hooks,
            agents,
            skills,
            effective,
            checkpoint,
            permissions,
        }
    }
}

impl RuntimeClientInventory {
    pub(crate) fn read(&self, query: ClientInventoryQueryV1) -> Result<Value, &'static str> {
        query.validate()?;
        if let Some(value) = self.bootstrap.as_ref().and_then(|owner| owner.read(&query)) {
            return Ok(value);
        }
        let (records, available, provenance) = match query.kind {
            ClientInventoryKindV1::Overview => (&self.overview, true, "installed_runtime_boundary"),
            ClientInventoryKindV1::Tools => (&self.tools, true, "installed_registry_snapshot"),
            ClientInventoryKindV1::Hooks => (&self.hooks, true, "installed_hook_catalog"),
            ClientInventoryKindV1::Agents => (&self.agents, true, "pinned_agent_catalog"),
            ClientInventoryKindV1::Skills => (
                self.skills.as_ref().unwrap_or(&self.overview),
                self.skills.is_some(),
                "captured_context_skill_metadata",
            ),
            ClientInventoryKindV1::EffectiveConfig => (
                self.effective.as_ref().unwrap_or(&self.overview),
                self.effective.is_some(),
                "immutable_run_checkpoint",
            ),
            ClientInventoryKindV1::Permissions => {
                (&self.permissions, true, "installed_runtime_policy_boundary")
            }
            _ => (&self.overview, false, "bootstrap_inventory_unavailable"),
        };
        let mut value = if available {
            page(
                &query,
                records,
                provenance,
                true,
                self.bootstrap
                    .as_ref()
                    .map(|owner| owner.digest())
                    .as_deref(),
            )
        } else {
            page::<Value>(
                &query,
                &[],
                provenance,
                false,
                self.bootstrap
                    .as_ref()
                    .map(|owner| owner.digest())
                    .as_deref(),
            )
        };
        if matches!(query.kind, ClientInventoryKindV1::EffectiveConfig) {
            value["checkpoint"] = self.checkpoint.clone();
        }
        Ok(value)
    }
}
