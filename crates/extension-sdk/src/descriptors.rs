use iteron_protocol::LifecycleEventId;
use serde::{Deserialize, Serialize};
pub const MAX_BINDINGS: usize = 64;
pub const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024;
pub fn validate_key(name: &str) -> bool {
    name.len() <= 64
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && name
            .split_once("__")
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
fn identifier(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProviderRegistrationV1 {
    pub version: u32,
    pub name: String,
    pub host_provider_id: String,
    pub host_model_id: String,
}
impl NativeProviderRegistrationV1 {
    pub fn validate(&self) -> bool {
        self.version == 1
            && validate_key(&self.name)
            && identifier(&self.host_provider_id, 128)
            && identifier(&self.host_model_id, 256)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusFactV1 {
    Phase,
    ProviderAdmissionSlotsUsed,
    TokensUsed,
    ToolCalls,
    ToolErrors,
    ProviderAdmissionSlotsRemaining,
    TokensRemaining,
    SessionSpawnsRemaining,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiStatusV1 {
    pub version: u32,
    pub name: String,
    pub label: String,
    pub facts: Vec<StatusFactV1>,
}
impl UiStatusV1 {
    pub fn validate(&self) -> bool {
        self.version == 1
            && validate_key(&self.name)
            && identifier(&self.label, 128)
            && !self.facts.is_empty()
            && self.facts.len() <= 8
            && self
                .facts
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.facts.len()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSubscriptionV1 {
    pub version: u32,
    pub name: String,
    pub event_ids: Vec<String>,
    pub queue_capacity: usize,
}
impl EventSubscriptionV1 {
    pub fn validate(&self) -> bool {
        self.version == 1
            && validate_key(&self.name)
            && !self.event_ids.is_empty()
            && self.event_ids.len() <= 16
            && (1..=256).contains(&self.queue_capacity)
            && self.event_ids.iter().all(|id| {
                id.len() <= 96
                    && LifecycleEventId::new(id.clone())
                        .ok()
                        .and_then(|id| id.spec())
                        .is_some_and(|spec| {
                            matches!(
                                spec.availability,
                                iteron_protocol::lifecycle::LifecycleAvailability::Active
                            )
                        })
            })
            && self
                .event_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.event_ids.len()
    }
}
