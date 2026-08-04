use super::MAX_FIELD_CHARS;
use core_tunables::{ConstraintViolation, CrossFieldRule};
use serde::Serialize;
use serde_json::Value;

pub(super) fn constraint_summary(rules: &[CrossFieldRule]) -> String {
    if rules.is_empty() {
        return "none".into();
    }
    let rendered = rules
        .iter()
        .map(|rule| match rule {
            CrossFieldRule::LessOrEqual { left, right } => format!("{left} <= {right}"),
            CrossFieldRule::SumLessOrEqual { terms, limit } => {
                format!("{} <= {limit}", terms.join(" + "))
            }
            CrossFieldRule::Requires {
                if_field,
                equals,
                then_field,
            } => format!(
                "if {if_field}={} then require {then_field}",
                compact_json(equals)
            ),
            CrossFieldRule::MutuallyExclusive { fields } => {
                format!("mutually exclusive: {}", fields.join(", "))
            }
            CrossFieldRule::ExternalCeiling {
                field,
                ceiling,
                projection,
                relation,
                violation,
            } => {
                let action = match violation {
                    ConstraintViolation::Reject => "reject".into(),
                    ConstraintViolation::ClampNumeric => "clamp_numeric".into(),
                    ConstraintViolation::DegradeAttested { policy_id } => {
                        format!("degrade_attested({policy_id})")
                    }
                };
                format!(
                    "{field}: {} / {} / {} -> {action}",
                    code(ceiling),
                    code(projection),
                    code(relation)
                )
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    clipped(&rendered, MAX_FIELD_CHARS)
}

pub(super) fn row(label: impl Into<String>, value: impl Into<String>) -> (String, String) {
    let label = label.into();
    let value = value.into();
    (clipped(&label, 64), clipped(&value, MAX_FIELD_CHARS))
}

pub(super) fn code<T: Serialize>(value: &T) -> String {
    // Every caller passes a registry enum serialized as a snake_case string.
    match serde_json::to_value(value) {
        Ok(Value::String(value)) => value,
        _ => "invalid".into(),
    }
}

pub(super) fn compact_json<T: Serialize>(value: &T) -> String {
    clipped(
        &serde_json::to_string(value).unwrap_or_else(|_| "<unavailable>".into()),
        MAX_FIELD_CHARS,
    )
}

pub(super) fn clipped(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.into();
    }
    let mut output: String = value.chars().take(maximum.saturating_sub(1)).collect();
    output.push('…');
    output
}
