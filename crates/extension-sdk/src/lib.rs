//! Ordinary extension SDK v1: native tools/routes, text-only UI/status and lifecycle readers.
//!
//! Ordinary descriptors are inert data. The verified host binds them before admission, narrows
//! their capabilities, and retains the existing physical sandbox, named denies and budgets.
//! No Rust callback receives a workspace, credential, mutable ledger or lifecycle writer here.
//! Native `Provider` implementations remain a trusted host backend API; a plugin cannot turn an
//! arbitrary backend into financially attested transport by implementing that trait.
mod descriptors;
mod events;
mod status;
pub use descriptors::{
    EventSubscriptionV1, MAX_BINDINGS, MAX_DESCRIPTOR_BYTES, NativeProviderRegistrationV1,
    StatusFactV1, UiStatusV1, validate_key,
};
pub use events::{ExtensionEventBatchV1, ExtensionEventReader, ExtensionEventsReadPort};
pub use iteron_protocol::capability_set::CapabilitySet;
pub use iteron_protocol::extension_dispatch::{ExtensionDispatchPolicy, ExtensionSurfaceV1};
pub use iteron_provider::Provider;
pub use iteron_tools::ToolRecipeV1;
use serde::{Deserialize, Serialize};
pub use status::{
    ExtensionStatusReadPort, ExtensionStatusSnapshotV1, ExtensionStatusWidgetV1, HostStatusFactsV1,
    HostStatusReadPort, HostStatusValueV1, TextStatusReader,
};
use std::sync::Arc;

pub const SDK_VERSION: u32 = 1;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionReadErrorV1 {
    InvalidRequest,
    NotBound,
    Revoked,
    Busy,
    Unavailable,
}
/// Route names address a host-native configured provider/model. This port resolves metadata only;
/// selecting one still requires the host's ordinary operator model-selection control path.
pub trait NativeProviderReadPort: Send + Sync {
    fn routes(&self) -> Result<Vec<NativeProviderRegistrationV1>, ExtensionReadErrorV1>;
    fn resolve(&self, name: &str) -> Result<NativeProviderRegistrationV1, ExtensionReadErrorV1>;
}
#[cfg(test)]
mod conformance;

#[derive(Debug, Clone, Serialize)]
pub struct OrdinaryExtensionsSnapshotV1 {
    pub version: u32,
    pub catalog_sha256: String,
    pub providers: Vec<NativeProviderRegistrationV1>,
    pub status: ExtensionStatusSnapshotV1,
    pub event_subscriptions: Vec<String>,
}
/// Same host instance as runtime producers. Every method is read-only and independently bounded.
pub trait OrdinaryExtensionsReadPort: Send + Sync {
    fn snapshot(&self) -> Result<OrdinaryExtensionsSnapshotV1, ExtensionReadErrorV1>;
    fn events(
        &self,
        name: &str,
        limit: usize,
        timeout_ms: u64,
    ) -> Result<ExtensionEventBatchV1, ExtensionReadErrorV1>;
}
/// A consumer can retain these ports while the resident Agent is exclusively running a turn.
pub type OrdinaryExtensionsHandle = Arc<dyn OrdinaryExtensionsReadPort>;
