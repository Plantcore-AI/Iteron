//! Durable plugin settings and sealed installation receipts share the actual bootstrap dispatch mask.
use super::{RuntimePluginIdentity, dispatch::DispatchMask};
use iteron_marketplace::{PluginStore, PreparedPluginInstall};
use iteron_protocol::{
    extension_dispatch::ExtensionDispatchPolicy, plugin_control::PluginControlV1,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

struct State {
    configuration: Value,
    revision: u64,
    pending: bool,
    last_error: Option<&'static str>,
}
pub(crate) struct PluginManagementOwner {
    root: PathBuf,
    mask: Arc<DispatchMask>,
    captured: Vec<RuntimePluginIdentity>,
    composition: Value,
    receipts: BTreeMap<String, PreparedPluginInstall>,
    state: Mutex<State>,
    capacity: Arc<Semaphore>,
}
impl std::fmt::Debug for PluginManagementOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginManagementOwner")
            .field("captured_packages", &self.captured.len())
            .field("prepared_receipts", &self.receipts.len())
            .finish_non_exhaustive()
    }
}
impl PluginManagementOwner {
    pub(super) fn new(
        root: &Path,
        mask: Arc<DispatchMask>,
        captured: Vec<RuntimePluginIdentity>,
        composition: Value,
        configuration: Value,
        receipts: BTreeMap<String, PreparedPluginInstall>,
    ) -> Result<Arc<Self>, &'static str> {
        Ok(Arc::new(Self {
            root: root.to_path_buf(),
            mask,
            captured,
            composition,
            receipts,
            state: Mutex::new(State {
                configuration,
                revision: 0,
                pending: false,
                last_error: None,
            }),
            capacity: Arc::new(Semaphore::new(1)),
        }))
    }
    pub(crate) fn dispatch_policy(&self) -> Arc<dyn ExtensionDispatchPolicy> {
        self.mask.clone()
    }
    pub(crate) fn snapshot(&self) -> Value {
        self.snapshot_page(0, 16)
    }
    fn snapshot_page(&self, offset: usize, limit: usize) -> Value {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let captured=self.captured.iter().skip(offset).take(limit).map(|identity|json!({
            "plugin_id":identity.plugin_id,"version":identity.version,"manifest_digest_sha256":identity.manifest_digest_sha256,"digest_kind":identity.digest_kind,
            "bound_surfaces":identity.bound_surfaces.iter().take(16).collect::<Vec<_>>(),"omitted_bound_surfaces":identity.bound_surfaces.len().saturating_sub(16),
            "future_dispatch_revoked":self.mask.is_revoked(&identity.plugin_id)})).collect::<Vec<_>>();
        let prepared=self.receipts.iter().skip(offset).take(limit).map(|(id,receipt)|json!({"receipt_id":id,"plugin_id":receipt.plugin(),"version":receipt.artifact().version,"package_digest_sha256":receipt.artifact().digest,"digest_kind":"verified_signed_package_tree_v1","publisher_key_id":receipt.artifact().key_id})).collect::<Vec<_>>();
        let mut composition = self.composition.clone();
        for field in ["conflicts", "refusals"] {
            let page = page(&composition[field], offset, limit);
            composition[field] = page;
        }
        if let Some(conflicts) = composition["conflicts"]["items"].as_array_mut() {
            for conflict in conflicts {
                if let Some(shadowed) = conflict["shadowed"].as_array_mut() {
                    let omitted = shadowed.len().saturating_sub(16);
                    shadowed.truncate(16);
                    conflict["omitted_shadowed"] = json!(omitted);
                }
            }
        }
        let mut configuration = state.configuration.clone();
        configuration["plugins"] = page(&configuration["plugins"], offset, limit);
        json!({"configuration":configuration,"configuration_source":"captured_plugin_registry_generation","configuration_revision":state.revision,
            "current_generation":{"items":captured,"total":self.captured.len()},"bootstrap_composition":composition,"prepared_installs":{"items":prepared,"total":self.receipts.len()},
            "page":{"offset":offset,"limit":limit},"next_bootstrap_pending":state.pending,"last_error_code":state.last_error,
            "cost_attribution":"tool_and_provider_ledgers; package-level totals unavailable","enable_semantics":"persistent selection for next verified bootstrap; current revocation remains monotone"})
    }
    fn inspect(&self, plugin_id: &str, offset: usize, limit: usize) -> Result<Value, &'static str> {
        let identity = self
            .captured
            .iter()
            .find(|identity| identity.plugin_id == plugin_id);
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let configuration = state.configuration["plugins"]
            .as_array()
            .and_then(|plugins| {
                plugins
                    .iter()
                    .find(|entry| entry[0].as_str() == Some(plugin_id))
            });
        if identity.is_none() && configuration.is_none() {
            return Err("plugin_identity_unavailable");
        }
        Ok(
            json!({"plugin_id":plugin_id,"configuration":configuration,"configuration_generation":state.configuration["generation"],
            "current_generation":identity.map(|identity|json!({"version":identity.version,"manifest_digest_sha256":identity.manifest_digest_sha256,"digest_kind":identity.digest_kind,
                "bound_surfaces":{"items":identity.bound_surfaces.iter().skip(offset).take(limit).collect::<Vec<_>>(),"total":identity.bound_surfaces.len(),"has_more":offset.saturating_add(limit)<identity.bound_surfaces.len()},
                "future_dispatch_revoked":self.mask.is_revoked(plugin_id)})),"page":{"offset":offset,"limit":limit},"next_bootstrap_pending":state.pending}),
        )
    }
    pub(crate) async fn execute(
        self: &Arc<Self>,
        command: PluginControlV1,
    ) -> Result<Value, &'static str> {
        command.validate()?;
        if let PluginControlV1::List { offset, limit, .. } = &command {
            return Ok(self.snapshot_page(*offset as usize, *limit as usize));
        }
        if let PluginControlV1::Inspect {
            plugin_id,
            binding_offset,
            limit,
            ..
        } = &command
        {
            return self.inspect(plugin_id, *binding_offset as usize, *limit as usize);
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| "plugin_management_busy")?;
        let owner = self.clone();
        tokio::task::spawn_blocking(move || {
            // Disable/rollback tighten the actual installed generation before any filesystem work.
            // Failure to persist cannot silently restore its future dispatch authority.
            match &command {PluginControlV1::SetEnabled{plugin_id,enabled:false,..}|PluginControlV1::Rollback{plugin_id,..}=>{owner.mask.revoke(plugin_id);},_=>{}}
            let store=PluginStore::new(&owner.root);
            let result=match command {
                PluginControlV1::SetEnabled{plugin_id,enabled,..}=>store.set_enabled(&plugin_id,enabled),
                PluginControlV1::SetPrecedence{plugin_id,precedence,..}=>store.set_precedence(&plugin_id,precedence),
                PluginControlV1::Rollback{plugin_id,..}=>store.rollback(&plugin_id).map(|_|()),
                PluginControlV1::Install{receipt_id,..}=>match owner.receipts.get(&receipt_id) {Some(receipt)=>store.install_prepared(receipt).map(|_|()),None=>{drop(permit);return Err("plugin_install_receipt_unavailable");}},
                PluginControlV1::List{..}|PluginControlV1::Inspect{..}=>unreachable!(),
            };
            let persisted=result.is_ok();
            let fresh=configuration(&owner.root);
            {
                let mut state=owner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Ok(configuration)=fresh {state.configuration=configuration;}
                if persisted {state.revision=state.revision.saturating_add(1);state.pending=true;state.last_error=None;}
                else {state.last_error=Some("persistent_change_unconfirmed");}
            }
            let snapshot=owner.snapshot();drop(permit);
            // The snapshot exposes real current revocation even when the durable change failed.
            Ok(json!({"change_confirmed":persisted,"snapshot":snapshot,"reason_code":(!persisted).then_some("persistent_change_unconfirmed")}))
        }).await.map_err(|_|"plugin_management_worker_unavailable")?
    }
}
fn configuration(root: &Path) -> Result<Value, &'static str> {
    let snapshot = PluginStore::new(root)
        .snapshot()
        .map_err(|_| "plugin_registry_unavailable")?;
    if snapshot.plugins.len() > 128 {
        return Err("plugin_registry_capacity");
    }
    Ok(json!({"generation":snapshot.generation,"plugins":snapshot.plugins}))
}

fn page(value: &Value, offset: usize, limit: usize) -> Value {
    let items = value.as_array().map(Vec::as_slice).unwrap_or(&[]);
    json!({"items":items.iter().skip(offset).take(limit).collect::<Vec<_>>(),"total":items.len(),"has_more":offset.saturating_add(limit)<items.len()})
}
