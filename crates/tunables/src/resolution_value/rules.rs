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
            CrossFieldRule::SumEquals { terms, total } => {
                let values = terms
                    .iter()
                    .map(|term| {
                        value_at(value, term)
                            .and_then(decimal_value)
                            .ok_or_else(|| format!("sum term `{term}` is not numeric"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if fixed_sum(&values, total).is_none_or(|equal| !equal) {
                    return Err("sum of terms does not equal the required total".to_owned());
                }
            }
            CrossFieldRule::Requires {
                if_field,
                equals,
                then_field,
            } => {
                if value_at(value, if_field).is_some_and(|actual| rule_value_eq(actual, equals))
                    && value_at(value, then_field).is_none_or(|required| !required_truthy(required))
                {
                    return Err(format!("`{if_field}` requires truthy `{then_field}`"));
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
            CrossFieldRule::MapEntryDomain { key, domain } => {
                if let Some(entry) = value_at(value, key) {
                    validate_scalar_against_domain(entry, domain)
                        .map_err(|_| format!("map entry `{key}` is outside its typed domain"))?;
                }
            }
            CrossFieldRule::AtLeastOneNonZero { fields } => {
                let mut any_non_zero = false;
                for field in fields {
                    if let Some(actual) = value_at(value, field) {
                        any_non_zero |= numeric_non_zero(actual)
                            .ok_or_else(|| format!("non-zero field `{field}` is not numeric"))?;
                    }
                }
                if !any_non_zero {
                    return Err(format!("at least one of {fields:?} must be non-zero"));
                }
            }
            CrossFieldRule::Equals {
                field,
                value: expected,
            } => {
                if value_at(value, field).is_some_and(|actual| !rule_value_eq(actual, expected)) {
                    return Err(format!("`{field}` must equal its fixed admissible value"));
                }
            }
            CrossFieldRule::ResolvedSetSumLessOrEqual { .. } => {}
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
    let fields = match value {
        ResolutionValue::Object { fields } => fields,
        ResolutionValue::Map { entries } => entries,
        _ => return None,
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

fn validate_scalar_against_domain(
    value: &ResolutionValue,
    domain: crate::ScalarDomain,
) -> Result<(), String> {
    super::validate_scalar(value, domain, &std::collections::BTreeMap::new())
}

fn numeric_non_zero(value: &ResolutionValue) -> Option<bool> {
    match value {
        ResolutionValue::Integer { value } => Some(*value != 0),
        ResolutionValue::Decimal { value } => Some(value.coefficient != 0),
        _ => None,
    }
}

fn required_truthy(value: &ResolutionValue) -> bool {
    match value {
        ResolutionValue::Boolean { value } => *value,
        ResolutionValue::Integer { value } => *value != 0,
        ResolutionValue::Decimal { value } => value.coefficient != 0,
        _ => false,
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

fn decimal_value(value: &ResolutionValue) -> Option<DecimalValue> {
    match value {
        ResolutionValue::Integer { value } => Some(DecimalValue {
            coefficient: *value,
            scale: 0,
        }),
        ResolutionValue::Decimal { value } => Some(*value),
        _ => None,
    }
}

fn fixed_sum(values: &[DecimalValue], total: DecimalValue) -> Option<bool> {
    let scale = values
        .iter()
        .map(|value| value.scale)
        .chain([total.scale])
        .max()?;
    let scaled = |value: DecimalValue| {
        i128::from(value.coefficient)
            .checked_mul(10i128.checked_pow(u32::from(scale - value.scale))?)
    };
    let sum = values
        .iter()
        .copied()
        .try_fold(0i128, |sum, value| sum.checked_add(scaled(value)?))?;
    Some(sum == scaled(total)?)
}

fn rule_value_eq(value: &ResolutionValue, expected: RuleValue) -> bool {
    match (value, expected) {
        (ResolutionValue::Boolean { value }, RuleValue::Boolean { value: expected }) => {
            *value == expected
        }
        (ResolutionValue::Integer { value }, RuleValue::Integer { value: expected }) => {
            *value == expected
        }
        (ResolutionValue::Decimal { value }, RuleValue::Decimal { value: expected }) => {
            decimal_cmp(*value, expected).is_some_and(|ordering| ordering.is_eq())
        }
        (ResolutionValue::Enum { value }, RuleValue::Enum { value: expected }) => value == expected,
        _ => false,
    }
}
