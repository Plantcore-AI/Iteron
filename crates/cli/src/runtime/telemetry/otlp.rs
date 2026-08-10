use core_obs::otel::Export;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_OTLP_BATCH_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct Batch {
    pub endpoint: String,
    pub body: Vec<u8>,
}

pub(super) fn encode(endpoint: &str, export: &Export) -> Result<Vec<Batch>, ()> {
    let resource = json!({
        "attributes": [
            attribute("service.name", "core-code"),
            attribute("service.namespace", "plantcore"),
            attribute("core.run.id", &export.run_id),
        ]
    });
    let trace_body = traces(export, &resource);
    let metric_body = metrics(export, &resource);
    let log_body = logs(export, &resource);
    [
        ("traces", trace_body),
        ("metrics", metric_body),
        ("logs", log_body),
    ]
    .into_iter()
    .map(|(signal, value)| {
        let body = serde_json::to_vec(&value).map_err(|_| ())?;
        if body.len() > MAX_OTLP_BATCH_BYTES {
            return Err(());
        }
        Ok(Batch {
            endpoint: signal_endpoint(endpoint, signal)?,
            body,
        })
    })
    .collect()
}

fn traces(export: &Export, resource: &Value) -> Value {
    let mut spans = Vec::with_capacity(
        export.spans.len()
            + export
                .lifecycle
                .as_ref()
                .map_or(0, |snapshot| snapshot.spans.len()),
    );
    for span in &export.spans {
        let (trace_id, span_id) = correlated_ids(&export.run_id, span.seq);
        let mut attributes = span
            .attributes
            .iter()
            .map(|(key, value)| attribute(key, value))
            .collect::<Vec<_>>();
        attributes.push(attribute("core.record.sequence", span.seq.to_string()));
        attributes.push(attribute(
            "core.duration.us",
            span.duration_ms.saturating_mul(1_000).to_string(),
        ));
        spans.push(json!({
            "traceId": trace_id,
            "spanId": span_id,
            "name": span.name,
            "kind": 1,
            // The durable record stores a monotonic origin, never wall time. Zero is the honest
            // OTLP default; the measured duration is carried as an attribute instead of inventing
            // an epoch timestamp during export.
            "startTimeUnixNano": "0",
            "endTimeUnixNano": "0",
            "attributes": attributes,
            "status": {"code": 1},
        }));
    }
    if let Some(snapshot) = &export.lifecycle {
        for span in &snapshot.spans {
            let Some((trace_id, span_id)) = parse_traceparent(&span.traceparent) else {
                continue;
            };
            spans.push(json!({
                "traceId": trace_id,
                "spanId": span_id,
                "name": span.template,
                "kind": 1,
                "startTimeUnixNano": "0",
                "endTimeUnixNano": "0",
                "attributes": [
                    attribute("core.start.monotonic_ns", span.start_mono_ns.to_string()),
                    attribute("core.end.monotonic_ns", span.end_mono_ns.to_string()),
                    attribute("core.duration.us", span.duration_us.to_string()),
                    attribute_opt("core.outcome", span.outcome_code.as_deref()),
                ],
                "status": {"code": if span.outcome_code.as_deref() == Some("failed") { 2 } else { 1 }},
            }));
        }
    }
    json!({
        "resourceSpans": [{
            "resource": resource,
            "scopeSpans": [{
                "scope": {"name": "core.lifecycle", "version": "1"},
                "spans": spans,
            }],
        }],
    })
}

fn metrics(export: &Export, resource: &Value) -> Value {
    let mut metrics = export
        .metrics
        .iter()
        .map(|metric| {
            json!({
                "name": metric.name,
                "gauge": {"dataPoints": [{
                    "attributes": metric.attributes.iter().map(|(key, value)| attribute(key, value)).collect::<Vec<_>>(),
                    "timeUnixNano": "0",
                    "asInt": metric.value.to_string(),
                }]},
            })
        })
        .collect::<Vec<_>>();
    if let Some(snapshot) = &export.lifecycle {
        metrics.extend(snapshot.metrics.iter().map(|metric| {
            let point = json!({
                "timeUnixNano": "0",
                "asInt": metric.value.to_string(),
                "attributes": [
                    attribute("core.observations", metric.observations.to_string()),
                    attribute_opt("core.min", metric.min.map(|value| value.to_string()).as_deref()),
                    attribute_opt("core.max", metric.max.map(|value| value.to_string()).as_deref()),
                ],
            });
            let data = if metric.kind == "counter" {
                json!({"sum": {"aggregationTemporality": 2, "isMonotonic": true, "dataPoints": [point]}})
            } else if metric.kind == "histogram" {
                json!({"histogram": {
                    "aggregationTemporality": 2,
                    "dataPoints": [{
                        "timeUnixNano": "0",
                        "count": metric.observations.to_string(),
                        "sum": metric.value,
                        "min": metric.min.unwrap_or(0),
                        "max": metric.max.unwrap_or(0),
                        "explicitBounds": [],
                        "bucketCounts": [metric.observations.to_string()],
                    }]
                }})
            } else {
                json!({"gauge": {"dataPoints": [point]}})
            };
            let mut encoded = json!({"name": metric.name, "unit": metric.unit});
            if let (Some(object), Some(data)) = (encoded.as_object_mut(), data.as_object()) {
                object.extend(data.clone());
            }
            encoded
        }));
    }
    json!({
        "resourceMetrics": [{
            "resource": resource,
            "scopeMetrics": [{
                "scope": {"name": "core.lifecycle", "version": "1"},
                "metrics": metrics,
            }],
        }],
    })
}

fn logs(export: &Export, resource: &Value) -> Value {
    let records = export
        .lifecycle
        .as_ref()
        .map(|snapshot| {
            snapshot
                .logs
                .iter()
                .filter_map(|record| {
                    let (trace_id, span_id) = parse_traceparent(&record.traceparent)?;
                    Some(json!({
                        "timeUnixNano": "0",
                        "observedTimeUnixNano": "0",
                        "severityNumber": 9,
                        "severityText": "INFO",
                        "body": {"stringValue": record.schema},
                        "traceId": trace_id,
                        "spanId": span_id,
                        "attributes": [
                            attribute("core.schema.version", record.schema_version.to_string()),
                            attribute("core.ordinal", record.ordinal.to_string()),
                            attribute("core.occurred.monotonic_ns", record.occurred_at_mono_ns.to_string()),
                            attribute_opt("core.outcome", record.outcome_code.as_deref()),
                            attribute_opt("core.reason", record.reason_code.as_deref()),
                            attribute_opt("core.count", record.count.map(|value| value.to_string()).as_deref()),
                            attribute_opt("core.duration.us", record.duration_us.map(|value| value.to_string()).as_deref()),
                            attribute_opt("core.magnitude", record.magnitude.map(|value| value.to_string()).as_deref()),
                        ],
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "resourceLogs": [{
            "resource": resource,
            "scopeLogs": [{
                "scope": {"name": "core.lifecycle", "version": "1"},
                "logRecords": records,
            }],
        }],
    })
}

fn signal_endpoint(endpoint: &str, signal: &str) -> Result<String, ()> {
    let mut url = url::Url::parse(endpoint).map_err(|_| ())?;
    let path = url.path().trim_end_matches('/');
    let base = ["/v1/traces", "/v1/metrics", "/v1/logs"]
        .iter()
        .find_map(|suffix| path.strip_suffix(suffix))
        .unwrap_or(path);
    url.set_path(&format!("{base}/v1/{signal}"));
    Ok(url.to_string())
}

fn attribute(key: impl AsRef<str>, value: impl ToString) -> Value {
    json!({"key": key.as_ref(), "value": {"stringValue": value.to_string()}})
}

fn attribute_opt(key: &str, value: Option<&str>) -> Value {
    attribute(key, value.unwrap_or(""))
}

fn correlated_ids(run_id: &str, ordinal: u64) -> (String, String) {
    let mut trace = Sha256::new();
    trace.update(run_id.as_bytes());
    let trace = trace.finalize();
    let mut span = Sha256::new();
    span.update(&trace[..16]);
    span.update(ordinal.to_be_bytes());
    let span = span.finalize();
    (hex::encode(&trace[..16]), hex::encode(&span[..8]))
}

fn parse_traceparent(value: &str) -> Option<(String, String)> {
    let mut parts = value.split('-');
    let version = parts.next()?;
    let trace = parts.next()?;
    let span = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some()
        || version.len() != 2
        || trace.len() != 32
        || span.len() != 16
        || flags.len() != 2
        || !trace.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !span.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((trace.to_ascii_lowercase(), span.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_configured_signal_endpoint_resolves_all_three_otlp_paths() {
        assert_eq!(
            signal_endpoint("http://127.0.0.1:4318/v1/traces", "logs").unwrap(),
            "http://127.0.0.1:4318/v1/logs"
        );
        assert_eq!(
            signal_endpoint("http://127.0.0.1:4318", "metrics").unwrap(),
            "http://127.0.0.1:4318/v1/metrics"
        );
    }
}
