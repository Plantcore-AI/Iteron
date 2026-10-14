//! Text-only UI descriptors select closed host facts; they cannot evaluate code or inject HTML.
use crate::{
    ExtensionDispatchPolicy, ExtensionReadErrorV1, ExtensionSurfaceV1, MAX_BINDINGS, StatusFactV1,
    UiStatusV1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "availability", rename_all = "snake_case")]
pub enum HostStatusValueV1 {
    Known { value: String },
    Unavailable { reason: String },
}
#[derive(Debug, Clone, Serialize)]
pub struct HostStatusFactsV1 {
    pub version: u32,
    pub source: &'static str,
    pub values: BTreeMap<StatusFactV1, HostStatusValueV1>,
}
pub trait HostStatusReadPort: Send + Sync {
    fn snapshot(&self) -> Result<HostStatusFactsV1, ExtensionReadErrorV1>;
}
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionStatusWidgetV1 {
    pub name: String,
    pub label: String,
    pub values: BTreeMap<StatusFactV1, HostStatusValueV1>,
}
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionStatusSnapshotV1 {
    pub version: u32,
    pub source: &'static str,
    pub widgets: Vec<ExtensionStatusWidgetV1>,
}
pub trait ExtensionStatusReadPort: Send + Sync {
    fn snapshot(&self) -> Result<ExtensionStatusSnapshotV1, ExtensionReadErrorV1>;
}
pub struct TextStatusReader {
    widgets: Vec<UiStatusV1>,
    host: Arc<dyn HostStatusReadPort>,
    policy: Option<Arc<dyn ExtensionDispatchPolicy>>,
}
impl TextStatusReader {
    pub fn bind(
        widgets: Vec<UiStatusV1>,
        host: Arc<dyn HostStatusReadPort>,
        policy: Option<Arc<dyn ExtensionDispatchPolicy>>,
    ) -> Result<Self, ExtensionReadErrorV1> {
        if widgets.len() > MAX_BINDINGS
            || widgets.iter().any(|widget| !widget.validate())
            || widgets
                .iter()
                .map(|w| &w.name)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != widgets.len()
        {
            return Err(ExtensionReadErrorV1::InvalidRequest);
        }
        Ok(Self {
            widgets,
            host,
            policy,
        })
    }
}
impl ExtensionStatusReadPort for TextStatusReader {
    fn snapshot(&self) -> Result<ExtensionStatusSnapshotV1, ExtensionReadErrorV1> {
        let host = self.host.snapshot()?;
        if host.version != 1
            || host.values.len() > 8
            || host.source.len() > 128
            || host.source.chars().any(char::is_control)
            || host.values.values().any(|value| match value {
                HostStatusValueV1::Known { value } => {
                    value.len() > 128 || value.chars().any(char::is_control)
                }
                HostStatusValueV1::Unavailable { reason } => {
                    reason.len() > 128 || reason.chars().any(char::is_control)
                }
            })
        {
            return Err(ExtensionReadErrorV1::Unavailable);
        }
        let widgets = self
            .widgets
            .iter()
            .filter(|w| {
                self.policy
                    .as_ref()
                    .is_none_or(|p| p.admits(ExtensionSurfaceV1::Ui, &w.name))
            })
            .map(|widget| ExtensionStatusWidgetV1 {
                name: widget.name.clone(),
                label: widget.label.clone(),
                values: widget
                    .facts
                    .iter()
                    .map(|fact| {
                        (
                            *fact,
                            host.values.get(fact).cloned().unwrap_or_else(|| {
                                HostStatusValueV1::Unavailable {
                                    reason: "host_fact_not_available".into(),
                                }
                            }),
                        )
                    })
                    .collect(),
            })
            .collect();
        Ok(ExtensionStatusSnapshotV1 {
            version: 1,
            source: host.source,
            widgets,
        })
    }
}
