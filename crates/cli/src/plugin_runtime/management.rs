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
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let captured=self.captured.iter().map(|identity|json!({"identity":identity,"future_dispatch_revoked":self.mask.is_revoked(&identity.plugin_id)})).collect::<Vec<_>>();
        let prepared=self.receipts.iter().map(|(id,receipt)|json!({"receipt_id":id,"plugin_id":receipt.plugin(),"version":receipt.artifact().version,"package_digest_sha256":receipt.artifact().digest,"digest_kind":"verified_signed_package_tree_v1","publisher_key_id":receipt.artifact().key_id})).collect::<Vec<_>>();
        json!({"configuration":state.configuration,"configuration_source":"captured_plugin_registry_generation","configuration_revision":state.revision,"current_generation":captured,"bootstrap_composition":self.composition,"prepared_installs":prepared,"next_bootstrap_pending":state.pending,"last_error_code":state.last_error,"cost_attribution":"tool_and_provider_ledgers; package-level totals unavailable","enable_semantics":"persistent selection for next verified bootstrap; current revocation remains monotone"})
    }
    pub(crate) async fn execute(
        self: &Arc<Self>,
        command: PluginControlV1,
    ) -> Result<Value, &'static str> {
        command.validate()?;
        if command.is_read_only() {
            return Ok(self.snapshot());
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
                PluginControlV1::List{..}=>unreachable!(),
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
