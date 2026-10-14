//! Third-party sample uses only public SDK types and real native/lifecycle ports.
use super::*;
use iteron_obs::lifecycle::{LifecycleBus, LifecycleCorrelation, LifecycleEmitter};
use iteron_protocol::{Capability, LifecyclePayload};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[derive(Debug)]
struct Mask(AtomicBool);
impl ExtensionDispatchPolicy for Mask {
    fn admits(&self, _: ExtensionSurfaceV1, _: &str) -> bool {
        !self.0.load(Ordering::Acquire)
    }
}
struct Facts;
impl HostStatusReadPort for Facts {
    fn snapshot(&self) -> Result<HostStatusFactsV1, ExtensionReadErrorV1> {
        Ok(HostStatusFactsV1 {
            version: 1,
            source: "fixture_existing_host_owner",
            values: BTreeMap::from([(
                StatusFactV1::ToolCalls,
                HostStatusValueV1::Known { value: "2".into() },
            )]),
        })
    }
}
#[test]
fn ordinary_sample_status_and_actual_emitter_have_no_write_port_and_obey_revocation() {
    let bus = LifecycleBus::default();
    let emitter = LifecycleEmitter::new(bus.clone());
    let policy = Arc::new(Mask(AtomicBool::new(false)));
    let reader = ExtensionEventReader::bind(
        &bus,
        EventSubscriptionV1 {
            version: 1,
            name: "sample__events".into(),
            event_ids: vec!["model.request_sent".into()],
            queue_capacity: 2,
        },
        Some(policy.clone()),
    )
    .unwrap();
    emitter
        .emit(
            "model.request_sent",
            LifecycleCorrelation::default(),
            LifecyclePayload::default(),
        )
        .unwrap();
    let batch = reader.read(64, 0).unwrap();
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].event_id.as_str(), "model.request_sent");
    assert!(reader.read(65, 0).is_err());
    assert!(reader.read(1, 60_001).is_err());
    let status = TextStatusReader::bind(
        vec![UiStatusV1 {
            version: 1,
            name: "sample__status".into(),
            label: "Native tool calls".into(),
            facts: vec![StatusFactV1::ToolCalls, StatusFactV1::TokensRemaining],
        }],
        Arc::new(Facts),
        Some(policy.clone()),
    )
    .unwrap();
    let projected = status.snapshot().unwrap();
    assert_eq!(projected.widgets.len(), 1);
    assert!(matches!(
        projected.widgets[0].values[&StatusFactV1::TokensRemaining],
        HostStatusValueV1::Unavailable { .. }
    ));
    policy.0.store(true, Ordering::Release);
    assert!(status.snapshot().unwrap().widgets.is_empty());
    assert_eq!(
        reader.read(1, 0).unwrap_err(),
        ExtensionReadErrorV1::Revoked
    );
}
#[test]
fn ordinary_wire_descriptors_do_not_accept_a_financial_or_html_capability_claim() {
    assert!(serde_json::from_value::<NativeProviderRegistrationV1>(json!({"version":1,"name":"sample__native","host_provider_id":"native","host_model_id":"model","budget_ceiling":100})).is_err());
    assert!(serde_json::from_value::<UiStatusV1>(json!({"version":1,"name":"sample__status","label":"status","facts":["tool_calls"],"raw_html":"<script/>"})).is_err());
    assert!(
        !EventSubscriptionV1 {
            version: 1,
            name: "sample__events".into(),
            event_ids: vec!["made.up.event".into()],
            queue_capacity: 1
        }
        .validate()
    );
    assert!(serde_json::from_value::<ToolRecipeV1>(json!({"version":1,"name":"sample__read","description":"sample","primitive":"read_file","fixed_arguments":{},"write_paths":[],"purity":"pure","capability":"read_only"})).is_err());
    assert_eq!(
        CapabilitySet::only(Capability::ReadOnly)
            .intersect(CapabilitySet::only(Capability::IrreversibleExternal)),
        CapabilitySet::none()
    );
}
