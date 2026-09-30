//! Native Responses usage normalization. Missing cache-write evidence remains unknown; an
//! explicitly reported zero is evidence, rather than a compatibility-schema default.
use crate::{ProviderError, UsageReport};
use iteron_protocol::Usage;

pub(super) fn parse_usage(response: &serde_json::Value) -> Result<UsageReport, ProviderError> {
    let Some(usage) = response.get("usage").filter(|usage| !usage.is_null()) else {
        return Ok(UsageReport::provider_omitted());
    };
    let total_input = required_u64(usage, "input_tokens")?;
    let cache_read = optional_nested_u64(usage, "/input_tokens_details/cached_tokens")?;
    let reported_creation = usage.pointer("/input_tokens_details/cache_write_tokens");
    let cache_creation = match reported_creation {
        Some(value) => value.as_u64().ok_or_else(|| {
            ProviderError::Decode(
                "Responses cache write tokens were not an unsigned integer".into(),
            )
        })?,
        None => 0,
    };
    let cached = cache_read.checked_add(cache_creation).ok_or_else(|| {
        ProviderError::Decode("Responses cache counters overflowed total input tokens".into())
    })?;
    let input = total_input.checked_sub(cached).ok_or_else(|| {
        ProviderError::Decode("Responses cache counters exceeded total input tokens".into())
    })?;
    let output = required_u64(usage, "output_tokens")?;
    let thinking = optional_nested_u64(usage, "/output_tokens_details/reasoning_tokens")?;
    if thinking > output {
        return Err(ProviderError::Decode(
            "Responses reasoning tokens exceeded total output tokens".into(),
        ));
    }
    let usage = Usage {
        input,
        output,
        cache_creation,
        cache_read,
        thinking,
    };
    Ok(if reported_creation.is_some() {
        UsageReport::complete(usage)
    } else {
        UsageReport::cache_creation_unreported(usage)
    })
}

fn required_u64(value: &serde_json::Value, field: &str) -> Result<u64, ProviderError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ProviderError::Decode(format!("Responses event lacked integer {field}")))
}

fn optional_nested_u64(value: &serde_json::Value, pointer: &str) -> Result<u64, ProviderError> {
    let Some(token) = value.pointer(pointer) else {
        return Ok(0);
    };
    token.as_u64().ok_or_else(|| {
        ProviderError::Decode(format!(
            "Responses usage field {pointer} was not an unsigned integer"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::parse_usage;
    use crate::UsageReport;
    use iteron_protocol::Usage;

    #[test]
    fn real_native_creation_report_is_complete_and_partitions_total_input() {
        let result = parse_usage(&serde_json::json!({"usage": {
            "input_tokens":100, "input_tokens_details":{"cached_tokens":20,"cache_write_tokens":30},
            "output_tokens":40,"output_tokens_details":{"reasoning_tokens":15}
        }}))
        .unwrap();
        assert_eq!(
            result,
            UsageReport::complete(Usage {
                input: 50,
                output: 40,
                cache_read: 20,
                cache_creation: 30,
                thinking: 15,
            })
        );
    }

    #[test]
    fn explicit_zero_is_reported_but_missing_zero_stays_unpriceable() {
        let mut response = serde_json::json!({"usage": {
            "input_tokens":10,"input_tokens_details":{"cached_tokens":0},"output_tokens":1
        }});
        assert!(!parse_usage(&response).unwrap().cache_creation_reported());
        response["usage"]["input_tokens_details"]["cache_write_tokens"] = serde_json::json!(0);
        assert!(parse_usage(&response).unwrap().cache_creation_reported());
    }

    #[test]
    fn invalid_native_partitions_are_not_accepted_as_known_charge_evidence() {
        for (read, write, output, thinking) in [(9, 2, 1, 0), (u64::MAX, 1, 1, 0), (0, 0, 1, 2)] {
            assert!(parse_usage(&serde_json::json!({"usage": {
                "input_tokens":10,"input_tokens_details":{"cached_tokens":read,"cache_write_tokens":write},
                "output_tokens":output,"output_tokens_details":{"reasoning_tokens":thinking}
            }})).is_err());
        }
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!(-1),
            serde_json::json!("0"),
        ] {
            assert!(parse_usage(&serde_json::json!({"usage": {
                "input_tokens":10,"input_tokens_details":{"cache_write_tokens":invalid},"output_tokens":1
            }})).is_err());
        }
    }
}
