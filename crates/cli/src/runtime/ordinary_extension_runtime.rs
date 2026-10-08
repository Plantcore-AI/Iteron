//! Composition/adoption adapter; SDK state owns only concrete route/status/event ports.
use super::ordinary_extensions::{HostFacts, OrdinaryExtensionHost};
use super::{Agent, KernelError};
use crate::plugin_runtime::ordinary::{OrdinaryBinding, OrdinaryDescriptor};
use crate::providers::{ModelSelection, ProviderDirectory};
use iteron_extension_sdk::{ExtensionDispatchPolicy, OrdinaryExtensionsReadPort, TextStatusReader};
use iteron_protocol::{EventKind, TurnId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, atomic::AtomicU64};
impl Agent {
    pub(crate) fn ordinary_extensions_port(&self) -> Option<Arc<dyn OrdinaryExtensionsReadPort>> {
        self.ordinary_extensions
            .as_ref()
            .map(|owner| owner.clone() as Arc<dyn OrdinaryExtensionsReadPort>)
    }
    pub(crate) fn install_ordinary_extensions(
        &mut self,
        bindings: Vec<OrdinaryBinding>,
        directory: &ProviderDirectory,
        policy: Option<Arc<dyn ExtensionDispatchPolicy>>,
    ) -> Result<Vec<OrdinaryBinding>, KernelError> {
        if bindings.is_empty() {
            return Ok(Vec::new());
        }
        if self.ordinary_extensions.is_some() || bindings.len() > iteron_extension_sdk::MAX_BINDINGS
        {
            return Err(KernelError::OrdinaryExtension(
                "ordinary SDK catalog is already installed or exceeds its bound",
            ));
        }
        // Budget and capability owners remain authoritative; descriptor capabilities are already
        // manifest∩host and are additionally met with this resident task's immutable ceiling.
        let mut aliases = Vec::new();
        let result =
            (|| -> Result<(Vec<OrdinaryBinding>, Arc<OrdinaryExtensionHost>), KernelError> {
                let mut native_evidence = Vec::new();
                let mut installed = Vec::new();
                let mut routes = Vec::new();
                let mut widgets = Vec::new();
                let mut subscriptions = Vec::new();
                for binding in bindings {
                    let capabilities = binding.capabilities.intersect(self.authority_ceiling);
                    match &binding.descriptor {
                        OrdinaryDescriptor::Tool(recipe) => {
                            self.registry
                                .register_ordinary_recipe(
                                    recipe.clone(),
                                    capabilities,
                                    policy.clone(),
                                )
                                .map_err(|_| {
                                    KernelError::OrdinaryExtension(
                                        "ordinary native tool recipe refused",
                                    )
                                })?;
                            aliases.push(recipe.name.clone());
                        }
                        OrdinaryDescriptor::Provider(route) => {
                            if !capabilities
                                .contains(iteron_protocol::Capability::IrreversibleExternal)
                            {
                                return Err(KernelError::OrdinaryExtension(
                                    "ordinary provider export lacks host egress capability",
                                ));
                            }
                            let selection = ModelSelection {
                                provider_id: route.host_provider_id.clone(),
                                model_id: route.host_model_id.clone(),
                            };
                            directory
                                .validate_selection(&selection, true)
                                .map_err(|_| {
                                    KernelError::OrdinaryExtension(
                                        "ordinary provider export has no admitted native route",
                                    )
                                })?;
                            // Actual existing native builder is the only adapter proof. Constructing it
                            // performs no transport IO and does not select it or invent a rate card.
                            directory.build(&selection).map_err(|_| {
                                KernelError::OrdinaryExtension(
                                    "ordinary provider adapter unavailable",
                                )
                            })?;
                            if iteron_record::redact::scrub(&route.host_provider_id)
                                != route.host_provider_id
                                || iteron_record::redact::scrub(&route.host_model_id)
                                    != route.host_model_id
                            {
                                return Err(KernelError::OrdinaryExtension(
                                    "ordinary provider identity is not safe metadata",
                                ));
                            }
                            native_evidence.push((
                                route.name.clone(),
                                directory.selection_digests(&selection),
                            ));
                            routes.push(route.clone());
                        }
                        OrdinaryDescriptor::Ui(widget) => {
                            if !capabilities.contains(iteron_protocol::Capability::ReadOnly) {
                                return Err(KernelError::OrdinaryExtension(
                                    "ordinary UI lacks read capability",
                                ));
                            }
                            widgets.push(widget.clone());
                        }
                        OrdinaryDescriptor::EventSubscription(subscription) => {
                            if !capabilities.contains(iteron_protocol::Capability::ReadOnly) {
                                return Err(KernelError::OrdinaryExtension(
                                    "ordinary events lack read capability",
                                ));
                            }
                            subscriptions.push(subscription.clone());
                        }
                    }
                    installed.push(binding);
                }
                let bytes = serde_json::to_vec(&(&installed, &native_evidence)).map_err(|_| {
                    KernelError::OrdinaryExtension("ordinary SDK catalog commitment unavailable")
                })?;
                if bytes.len() > 1024 * 1024 {
                    return Err(KernelError::OrdinaryExtension(
                        "ordinary SDK catalog byte bound exceeded",
                    ));
                }
                let digest = hex::encode(Sha256::digest(bytes));
                let recovered = iteron_record::bounded_replay::load_forked_scoped_bounded(
                    self.rollout
                        .path()
                        .parent()
                        .ok_or(KernelError::OrdinaryExtension(
                            "SDK record directory unavailable",
                        ))?,
                    self.rollout.run_id(),
                    iteron_record::bounded_replay::ReplayReadLimits {
                        physical_bytes: 64 * 1024 * 1024,
                        hydrated_bytes: 64 * 1024 * 1024,
                        events: 65_536,
                    },
                )?;
                let mut latest = None;
                let mut current = None;
                let mut writers = BTreeSet::new();
                for scoped in &recovered {
                    if let EventKind::OrdinaryExtensionBindingsV1 {
                        catalog_sha256,
                        bindings,
                    } = &scoped.event.kind
                    {
                        if !writers.insert((scoped.tenant.0.as_str(), scoped.run_id.0.as_str()))
                            || catalog_sha256.len() != 64
                            || !catalog_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                            || !(1..=iteron_extension_sdk::MAX_BINDINGS)
                                .contains(&(*bindings as usize))
                        {
                            return Err(KernelError::OrdinaryExtension(
                                "ordinary SDK durable catalog is invalid",
                            ));
                        }
                        latest = Some((catalog_sha256, bindings));
                        if scoped.tenant == *self.rollout.tenant()
                            && scoped.run_id == *self.rollout.run_id()
                        {
                            current = latest;
                        }
                    }
                }
                let needs_publication = current.is_none();
                if let Some((old, count)) = latest {
                    if old != &digest || *count as usize != installed.len() {
                        return Err(KernelError::OrdinaryExtension(
                            "ordinary SDK catalog changed on an admitted lineage",
                        ));
                    }
                } else if recovered.iter().any(|scoped| {
                    matches!(
                        scoped.event.kind,
                        EventKind::Message { .. }
                            | EventKind::MessageV2 { .. }
                            | EventKind::EffectIntent { .. }
                    )
                }) {
                    return Err(KernelError::OrdinaryExtension(
                        "ordinary SDK cannot replace an unbound historical lineage",
                    ));
                }
                if subscriptions.len() > 8 {
                    return Err(KernelError::OrdinaryExtension(
                        "ordinary SDK event subscription capacity exceeded",
                    ));
                }
                let facts = Arc::new(HostFacts {
                    state: Mutex::new((self.operator_status_sources(), "idle".into())),
                });
                let status = TextStatusReader::bind(widgets, facts.clone(), policy.clone())
                    .map_err(|_| KernelError::OrdinaryExtension("ordinary status port refused"))?;
                let owner = Arc::new(OrdinaryExtensionHost {
                    catalog_sha256: digest,
                    routes,
                    #[cfg(test)]
                    directory: directory.frozen_client_snapshot(),
                    policy,
                    status,
                    facts,
                    subscriptions,
                    events: Mutex::new((0, BTreeMap::new())),
                    event_generation: AtomicU64::new(0),
                });
                if !owner.subscriptions.is_empty() {
                    if self.lifecycle_emitter.is_none() {
                        self.lifecycle_emitter =
                            Some(iteron_obs::lifecycle::LifecycleEmitter::new(
                                iteron_obs::lifecycle::LifecycleBus::default(),
                            ));
                    }
                    owner
                        .bind_lifecycle(
                            self.lifecycle_emitter
                                .as_ref()
                                .expect("ordinary subscription emitter")
                                .bus(),
                        )
                        .map_err(|_| {
                            KernelError::OrdinaryExtension(
                                "ordinary event subscription unavailable",
                            )
                        })?;
                }
                if needs_publication {
                    self.emit_durable(
                        TurnId(self.seq_turn),
                        EventKind::OrdinaryExtensionBindingsV1 {
                            catalog_sha256: owner.catalog_sha256.clone(),
                            bindings: u32::try_from(installed.len())
                                .map_err(|_| KernelError::IdentityExhausted("ordinary bindings"))?,
                        },
                    )?;
                }
                Ok((installed, owner))
            })();
        match result {
            Ok((installed, owner)) => {
                self.ordinary_extensions = Some(owner);
                Ok(installed)
            }
            Err(error) => {
                for name in aliases {
                    self.registry.remove_ordinary_recipe(&name);
                }
                Err(error)
            }
        }
    }
    #[cfg(test)]
    /// Trusted operator control, the same actual durable route/pricing owners as `/model`.
    /// A plugin never calls this through a lifecycle or status read handle.
    pub(crate) fn select_ordinary_extension_provider(
        &mut self,
        name: &str,
    ) -> Result<(), KernelError> {
        let owner = self
            .ordinary_extensions
            .as_ref()
            .ok_or(KernelError::InvalidRoute("ordinary SDK is absent"))?
            .clone();
        let selection = owner
            .resolve_selection(name)
            .map_err(|_| KernelError::InvalidRoute("ordinary provider export unavailable"))?;
        let provider = owner.directory.build(&selection).map_err(|_| {
            KernelError::InvalidRoute("ordinary native provider adapter unavailable")
        })?;
        let (catalog, capability) = owner.directory.selection_digests(&selection);
        let capabilities = owner.directory.selection_capabilities(&selection);
        let changed = self.model != selection.model_id;
        self.record_operator_model_selection(
            provider,
            selection.provider_id,
            selection.model_id,
            catalog,
            capability,
        )?;
        self.model_context_window = capabilities.context_window_tokens;
        self.model_max_output_tokens = capabilities.max_output_tokens;
        if changed {
            self.ledger.last_turn_usage = None;
        }
        self.bind_selected_rate_card()?;
        Ok(())
    }
}

impl Agent {
    /// Explicit session adoption keeps the same installed native SDK executors only when the
    /// target writer already admitted the same immutable catalog. Default absent is zero IO.
    pub(super) fn validate_ordinary_extension_adoption(
        &self,
        path: &std::path::Path,
    ) -> Result<(), KernelError> {
        let Some(owner) = &self.ordinary_extensions else {
            return Ok(());
        };
        let events = iteron_record::bounded_replay::replay_bounded(
            path,
            iteron_record::bounded_replay::ReplayReadLimits {
                physical_bytes: 64 * 1024 * 1024,
                hydrated_bytes: 64 * 1024 * 1024,
                events: 65_536,
            },
        )?;
        let mut receipts = events.iter().filter_map(|event| match &event.kind {
            EventKind::OrdinaryExtensionBindingsV1 { catalog_sha256, .. } => Some(catalog_sha256),
            _ => None,
        });
        if receipts.next() != Some(&owner.catalog_sha256) || receipts.next().is_some() {
            return Err(KernelError::OrdinaryExtension(
                "target session did not admit the installed SDK catalog",
            ));
        }
        Ok(())
    }
}
