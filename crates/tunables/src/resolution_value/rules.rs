use crate::resolution_types::ResolutionValue;
use crate::{CrossFieldRule, DecimalValue, RuleValue};
use std::cmp::Ordering;

pub(crate) fn validate_rules(
    value: &ResolutionValue,
    rules: &[CrossFieldRule],
) -> Result<(), String> {
    for rule in rules {
        match *rule {
            CrossFieldRule::LessOrEqual { left, right } => {
                let (Some(left_value), Some(right_value)) =
                    (value_at(value, left), value_at(value, right))
                else {
                    continue;
                };
                if numeric_cmp(left_value, right_value).is_none_or(|ordering| ordering.is_gt()) {
                    return Err(format!("`{left}` must be less than or equal to `{right}`"));
                }
            }
            CrossFieldRule::SumLessOrEqual { terms, limit } => {
                let Some(limit_value) = value_at(value, limit).and_then(integer) else {
                    continue;
                };
                let mut sum = 0i128;
                for term in terms {
                    let term_value = value_at(value, term)
                        .and_then(integer)
                        .ok_or_else(|| format!("sum term `{term}` is not an integer"))?;
                    sum = sum
                        .checked_add(term_value)
                        .ok_or_else(|| "sum rule overflowed".to_owned())?;
                }
                if sum > limit_value {
                    return Err(format!("sum of terms exceeds `{limit}`"));
                }
            }
            CrossFieldRule::Requires {
                if_field,
                equals,
                then_field,
            } => {
                if value_at(value, if_field).is_some_and(|actual| rule_value_eq(actual, equals))
                    && value_at(value, then_field).is_none()
                {
                    return Err(format!("`{if_field}` requires `{then_field}`"));
                }
            }
            CrossFieldRule::MutuallyExclusive { fields } => {
                if fields
                    .iter()
                    .filter(|field| value_at(value, field).is_some())
                    .count()
                    > 1
                {
                    return Err(format!("fields {fields:?} are mutually exclusive"));
                }
            }
            CrossFieldRule::ExternalCeiling { .. } => {}
        }
    }
    Ok(())
}

pub(crate) fn value_at<'a>(value: &'a ResolutionValue, path: &str) -> Option<&'a ResolutionValue> {
    if path == "$" {
        return Some(value);
    }
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let ResolutionValue::Object { fields } = value else {
        return None;
    };
    let child = fields.get(head)?;
    if tail.is_empty() {
        Some(child)
    } else {
        value_at(child, tail)
    }
}

pub(crate) fn replace_at(
    value: &mut ResolutionValue,
    path: &str,
    replacement: ResolutionValue,
) -> Result<(), String> {
    if path == "$" {
        *value = replacement;
        return Ok(());
    }
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let ResolutionValue::Object { fields } = value else {
        return Err(format!(
            "constraint path `{path}` does not address an object"
        ));
    };
    let child = fields
        .get_mut(head)
        .ok_or_else(|| format!("constraint path `{path}` is absent"))?;
    if tail.is_empty() {
        *child = replacement;
        Ok(())
    } else {
        replace_at(child, tail, replacement)
    }
}

pub(crate) fn numeric_cmp(left: &ResolutionValue, right: &ResolutionValue) -> Option<Ordering> {
    match (left, right) {
        (ResolutionValue::Integer { value: left }, ResolutionValue::Integer { value: right }) => {
            Some(left.cmp(right))
        }
        (ResolutionValue::Decimal { value: left }, ResolutionValue::Decimal { value: right }) => {
            decimal_cmp(*left, *right)
        }
        _ => None,
    }
}

pub(super) fn decimal_cmp(left: DecimalValue, right: DecimalValue) -> Option<Ordering> {
    let scale = left.scale.max(right.scale);
    let left = i128::from(left.coefficient)
        .checked_mul(10i128.checked_pow(u32::from(scale - left.scale))?)?;
    let right = i128::from(right.coefficient)
        .checked_mul(10i128.checked_pow(u32::from(scale - right.scale))?)?;
    Some(left.cmp(&right))
}

fn integer(value: &ResolutionValue) -> Option<i128> {
    match value {
        ResolutionValue::Integer { value } => Some(i128::from(*value)),
        _ => None,
    }
}

fn rule_value_eq(value: &ResolutionValue, expected: RuleValue) -> bool {
    match (value, expected) {
        (ResolutionValue::Boolean { value }, RuleValue::Boolean { value: expected }) => {
            *value == expected
        }
        (ResolutionValue::Integer { value }, RuleValue::Integer { value: expected }) => {
            *value == expected
        }
        (ResolutionValue::Enum { value }, RuleValue::Enum { value: expected }) => value == expected,
        _ => false,
    }
}
