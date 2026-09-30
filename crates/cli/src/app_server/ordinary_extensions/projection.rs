//! Closed SDK metadata projection. Structural catalog identity survives ordinary text redaction.
use iteron_extension_sdk::{
    ExtensionEventBatchV1, ExtensionReadErrorV1, HostStatusValueV1, MAX_BINDINGS,
    OrdinaryExtensionsSnapshotV1, validate_key,
};
use iteron_protocol::RunId;
use serde_json::{Value, json};
const MAX_REPLY_BYTES: usize = 256 * 1024;
fn text(value: &str) -> String {
    iteron_record::redact::scrub(value)
}
fn bounded(value: Value) -> Result<Value, ExtensionReadErrorV1> {
    if serde_json::to_vec(&value)
        .map_err(|_| ExtensionReadErrorV1::Unavailable)?
        .len()
        > MAX_REPLY_BYTES
    {
        return Err(ExtensionReadErrorV1::Unavailable);
    }
    Ok(value)
}
pub(super) fn snapshot(
    mut source: OrdinaryExtensionsSnapshotV1,
    offset: usize,
    limit: usize,
) -> Result<Value, ExtensionReadErrorV1> {
    if source.version != 1
        || source.catalog_sha256.len() != 64
        || !source
            .catalog_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || source.providers.len() > MAX_BINDINGS
        || source.status.version != 1
        || source.status.widgets.len() > MAX_BINDINGS
        || source.event_subscriptions.len() > MAX_BINDINGS
        || source.status.source.len() > 128
        || source.providers.iter().any(|provider| !provider.validate())
        || source
            .event_subscriptions
            .iter()
            .any(|name| !validate_key(name))
        || source.status.widgets.iter().any(|widget| {
            !validate_key(&widget.name)
                || widget.label.len() > 128
                || widget.values.len() > 8
                || widget.values.values().any(|value| match value {
                    HostStatusValueV1::Known { value } => value.len() > 128,
                    HostStatusValueV1::Unavailable { reason } => reason.len() > 128,
                })
        })
    {
        return Err(ExtensionReadErrorV1::Unavailable);
    }
    let providers_total = source.providers.len();
    let widgets_total = source.status.widgets.len();
    let subscriptions_total = source.event_subscriptions.len();
    // These fields are display text, never authority. Selecting a provider continues through the
    // ordinary host inventory/model gate; this projection cannot introduce a new credential.
    for provider in &mut source.providers {
        provider.host_provider_id = text(&provider.host_provider_id);
        provider.host_model_id = text(&provider.host_model_id);
    }
    for widget in &mut source.status.widgets {
        widget.label = text(&widget.label);
        for value in widget.values.values_mut() {
            match value {
                HostStatusValueV1::Known { value } => *value = text(value),
                HostStatusValueV1::Unavailable { reason } => *reason = text(reason),
            }
        }
    }
    bounded(
        json!({"version":source.version,"catalog_sha256":source.catalog_sha256,
        "page":{"offset":offset,"limit":limit},
        "providers":{"total":providers_total,"items":source.providers.into_iter().skip(offset).take(limit).collect::<Vec<_>>()},
        "status":{"version":source.status.version,"source":text(source.status.source),"widgets":{"total":widgets_total,"items":source.status.widgets.into_iter().skip(offset).take(limit).collect::<Vec<_>>()}},
        "event_subscriptions":{"total":subscriptions_total,"items":source.event_subscriptions.into_iter().skip(offset).take(limit).collect::<Vec<_>>()},
        "extension_cost":"not_available"}),
    )
}
pub(super) fn events(
    source: ExtensionEventBatchV1,
    run: &RunId,
    name: &str,
) -> Result<Value, ExtensionReadErrorV1> {
    if source.version != 1
        || source.scanned > 64
        || source.events.len() > 64
        || source.delivery != "lossy_content_free_lifecycle_bus_not_durable_replay"
        || source.events.iter().any(|event| event.validate().is_err())
    {
        return Err(ExtensionReadErrorV1::Unavailable);
    }
    // The lifecycle bus is shared with children. Only explicit matching origins belong to this
    // run; an absent origin remains unattributed. Filtering is presentation, not durable replay.
    let mut filtered_foreign_run = 0_usize;
    let mut unscoped_observations = 0_usize;
    let matching = source
        .events
        .into_iter()
        .filter(|event| match &event.run_id {
            Some(origin) if origin == run => true,
            Some(_) => {
                filtered_foreign_run += 1;
                false
            }
            None => {
                unscoped_observations += 1;
                false
            }
        })
        .collect::<Vec<_>>();
    let serialized =
        serde_json::to_value(matching).map_err(|_| ExtensionReadErrorV1::Unavailable)?;
    let safe = scrub_strings(serialized);
    bounded(
        json!({"version":source.version,"name":name,"events":safe,"scanned":source.scanned,
            "filtered_foreign_run":filtered_foreign_run,"unscoped_observations":unscoped_observations,
            "delivery":source.delivery}),
    )
}

#[cfg(test)]
mod tests {
    use super::events;
    use iteron_extension_sdk::{
        EventSubscriptionV1, ExtensionEventReader, ExtensionEventsReadPort,
    };
    use iteron_obs::lifecycle::{LifecycleBus, LifecycleCorrelation, LifecycleEmitter};
    use iteron_protocol::{LifecyclePayload, RunId};

    #[test]
    fn shared_actual_bus_preserves_matching_rows_and_reports_unattributed_rows() {
        let bus = LifecycleBus::default();
        let emitter = LifecycleEmitter::new(bus.clone());
        let reader = ExtensionEventReader::bind(
            &bus,
            EventSubscriptionV1 {
                version: 1,
                name: "sample__events".into(),
                event_ids: vec!["model.request_sent".into()],
                queue_capacity: 8,
            },
            None,
        )
        .unwrap();
        let run = RunId("parent".into());
        for origin in [
            Some(run.clone()),
            Some(RunId("child".into())),
            None,
            Some(run.clone()),
        ] {
            emitter
                .emit(
                    "model.request_sent",
                    LifecycleCorrelation {
                        run_id: origin,
                        ..LifecycleCorrelation::default()
                    },
                    LifecyclePayload::default(),
                )
                .unwrap();
        }
        let projected = events(reader.read(64, 0).unwrap(), &run, "sample__events").unwrap();
        let rows = projected["events"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row["run_id"] == "parent"));
        assert_eq!(projected["scanned"], 4);
        assert_eq!(projected["filtered_foreign_run"], 1);
        assert_eq!(projected["unscoped_observations"], 1);
        assert!(rows.iter().all(|row| row.get("durable_seq").is_none()));
    }
}
fn scrub_strings(value: Value) -> Value {
    match value {
        Value::String(value) => Value::String(text(&value)),
        Value::Array(values) => Value::Array(values.into_iter().map(scrub_strings).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, scrub_strings(value)))
                .collect(),
        ),
        other => other,
    }
}
