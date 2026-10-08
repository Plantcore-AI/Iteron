//! Inert ordinary SDK descriptors captured only from verified composed manifest details.
use super::RuntimePlugins;
use iteron_extension_sdk::{
    EventSubscriptionV1, MAX_BINDINGS, MAX_DESCRIPTOR_BYTES, NativeProviderRegistrationV1,
    ToolRecipeV1, UiStatusV1,
};
use iteron_marketplace::{Binding, Slot, Surface, Wiring};
use iteron_protocol::capability_set::CapabilitySet;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize)]
pub(crate) struct OrdinaryBinding {
    pub(crate) plugin: String,
    pub(crate) version: String,
    pub(crate) manifest_sha256: String,
    pub(crate) surface: Surface,
    pub(crate) key: String,
    pub(crate) capabilities: CapabilitySet,
    pub(crate) descriptor: OrdinaryDescriptor,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind", content = "descriptor", rename_all = "snake_case")]
pub(crate) enum OrdinaryDescriptor {
    Tool(ToolRecipeV1),
    Provider(NativeProviderRegistrationV1),
    Ui(UiStatusV1),
    EventSubscription(EventSubscriptionV1),
}
impl OrdinaryDescriptor {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Tool(v) => &v.name,
            Self::Provider(v) => &v.name,
            Self::Ui(v) => &v.name,
            Self::EventSubscription(v) => &v.name,
        }
    }
}
fn parse<T: for<'de> Deserialize<'de>>(detail: &str) -> Result<T, &'static str> {
    if detail.len() > MAX_DESCRIPTOR_BYTES {
        return Err("ordinary descriptor byte bound exceeded");
    }
    serde_json::from_str(detail).map_err(|_| "ordinary descriptor schema refused")
}
fn descriptor(slot: &Slot, binding: &Binding) -> Result<OrdinaryDescriptor, &'static str> {
    let descriptor = match slot.surface {
        Surface::Tool => OrdinaryDescriptor::Tool(parse(&binding.detail)?),
        Surface::Provider => {
            let v: NativeProviderRegistrationV1 = parse(&binding.detail)?;
            if !v.validate() {
                return Err("native provider descriptor refused");
            }
            OrdinaryDescriptor::Provider(v)
        }
        Surface::Ui => {
            let v: UiStatusV1 = parse(&binding.detail)?;
            if !v.validate() {
                return Err("UI status descriptor refused");
            }
            OrdinaryDescriptor::Ui(v)
        }
        Surface::EventSubscription => {
            let v: EventSubscriptionV1 = parse(&binding.detail)?;
            if !v.validate() {
                return Err("event subscriber descriptor refused");
            }
            OrdinaryDescriptor::EventSubscription(v)
        }
        _ => return Err("not an ordinary SDK surface"),
    };
    if descriptor.name() != slot.key {
        return Err("ordinary binding key differs from descriptor name");
    }
    Ok(descriptor)
}
impl RuntimePlugins {
    /// Called before any bootstrap policy Arc escapes. Parsed descriptors restrict dispatch only;
    /// they become inventory bindings only after actual native/status/subscriber installation.
    pub(super) fn materialize_ordinary(&mut self, wiring: &Wiring) {
        for slot in wiring.slots().into_iter().filter(|slot| {
            matches!(
                slot.surface,
                Surface::Tool | Surface::Provider | Surface::Ui | Surface::EventSubscription
            )
        }) {
            let Some(binding) = wiring.binding(slot.surface, &slot.key) else {
                continue;
            };
            if self.ordinary.len() >= MAX_BINDINGS {
                self.note("ordinary SDK binding capacity exceeded".into());
                break;
            }
            match descriptor(slot, binding) {
                Ok(descriptor) => {
                    let mask = std::sync::Arc::get_mut(
                        self.dispatch_mask
                            .as_mut()
                            .expect("verified bootstrap mask"),
                    )
                    .expect("ordinary materialization precedes policy clones");
                    if mask
                        .bind(
                            &binding.plugin,
                            super::dispatch::surface(slot.surface),
                            &slot.key,
                        )
                        .is_err()
                    {
                        self.note("ordinary dispatch binding refused".into());
                        continue;
                    }
                    let Some(identity) = self.inventory.identity(&binding.plugin) else {
                        self.note("ordinary verified identity unavailable".into());
                        continue;
                    };
                    self.ordinary.push(OrdinaryBinding {
                        plugin: binding.plugin.clone(),
                        version: identity.version.clone(),
                        manifest_sha256: identity.manifest_digest_sha256.clone(),
                        surface: slot.surface,
                        key: slot.key.clone(),
                        capabilities: binding.capabilities,
                        descriptor,
                    });
                }
                Err(reason) => self.note(format!(
                    "ordinary plugin {} {} refused: {reason}",
                    binding.plugin, slot
                )),
            }
        }
    }
    pub(crate) fn has_ordinary(&self) -> bool {
        !self.ordinary.is_empty()
    }
    pub(crate) fn install_ordinary(
        &mut self,
        agent: &mut crate::runtime::Agent,
        directory: &crate::providers::ProviderDirectory,
    ) -> Result<(), crate::runtime::KernelError> {
        if self.ordinary.is_empty() {
            return Ok(());
        }
        let bindings = std::mem::take(&mut self.ordinary);
        let installed =
            agent.install_ordinary_extensions(bindings, directory, self.dispatch_policy())?;
        for binding in installed {
            self.inventory
                .bound(&binding.plugin, binding.surface, &binding.key);
        }
        Ok(())
    }
}
