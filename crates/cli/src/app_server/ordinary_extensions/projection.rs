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
        || source.events.iter().any(|event| {
            event.validate().is_err() || event.run_id.as_ref().is_some_and(|origin| origin != run)
        })
    {
        return Err(ExtensionReadErrorV1::Unavailable);
    }
    let serialized =
        serde_json::to_value(source.events).map_err(|_| ExtensionReadErrorV1::Unavailable)?;
    let safe = scrub_strings(serialized);
    bounded(
        json!({"version":source.version,"name":name,"events":safe,"scanned":source.scanned,"delivery":source.delivery}),
    )
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
