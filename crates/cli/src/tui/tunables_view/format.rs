use super::Detail;
use core_tunables::{ConstraintViolation, CrossFieldRule};
use serde::Serialize;
use serde_json::Value;
use std::io;

pub(super) const MAX_DETAIL_TITLE_CHARS: usize = 256;
pub(super) const MAX_DETAIL_TITLE_BYTES: usize = 1_024;
pub(super) const MAX_DETAIL_ID_CHARS: usize = 128;
pub(super) const MAX_DETAIL_ID_BYTES: usize = 512;
pub(super) const MAX_DETAIL_LABEL_CHARS: usize = 256;
pub(super) const MAX_DETAIL_LABEL_BYTES: usize = 1_024;
pub(super) const MAX_DETAIL_FIELD_CHARS: usize = 768;
pub(super) const MAX_DETAIL_FIELD_BYTES: usize = 3_072;
pub(super) const MAX_DETAIL_ROW_LABEL_CHARS: usize = 64;
pub(super) const MAX_DETAIL_ROW_LABEL_BYTES: usize = 256;

pub(super) fn constraint_summary(rules: &[CrossFieldRule]) -> String {
    if rules.is_empty() {
        return "none".into();
    }
    join_bounded(
        rules.iter().map(|rule| match rule {
            CrossFieldRule::LessOrEqual { left, right } => format!("{left} <= {right}"),
            CrossFieldRule::SumLessOrEqual { terms, limit } => {
                format!("{} <= {limit}", join_bounded(terms.iter().copied(), " + "))
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
                format!(
                    "mutually exclusive: {}",
                    join_bounded(fields.iter().copied(), ", ")
                )
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
        }),
        "; ",
    )
}

pub(super) fn row(label: impl Into<String>, value: impl Into<String>) -> (String, String) {
    let label = label.into();
    let value = value.into();
    (
        bounded_text(
            &label,
            MAX_DETAIL_ROW_LABEL_CHARS,
            MAX_DETAIL_ROW_LABEL_BYTES,
        ),
        bounded_field(&value),
    )
}

pub(super) fn code<T: Serialize>(value: &T) -> String {
    // Every caller passes a registry enum serialized as a snake_case string.
    match serde_json::to_value(value) {
        Ok(Value::String(value)) => value,
        _ => "invalid".into(),
    }
}

pub(super) fn compact_json<T: Serialize>(value: &T) -> String {
    let mut writer = BoundedJson::default();
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => bounded_field(&String::from_utf8_lossy(&writer.bytes)),
        Err(_) if writer.truncated => {
            let mut partial = String::from_utf8_lossy(&writer.bytes).into_owned();
            partial.push('…');
            bounded_field(&partial)
        }
        Err(_) => "<unavailable>".into(),
    }
}

#[derive(Default)]
struct BoundedJson {
    bytes: Vec<u8>,
    truncated: bool,
}

impl io::Write for BoundedJson {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = MAX_DETAIL_FIELD_BYTES.saturating_sub(self.bytes.len());
        if buffer.len() <= remaining {
            self.bytes.extend_from_slice(buffer);
            return Ok(buffer.len());
        }
        self.bytes.extend_from_slice(&buffer[..remaining]);
        self.truncated = true;
        Err(io::Error::other("bounded JSON display limit reached"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn bounded_title(value: &str) -> String {
    bounded_text(value, MAX_DETAIL_TITLE_CHARS, MAX_DETAIL_TITLE_BYTES)
}

pub(super) fn bounded_hint(value: &str) -> String {
    bounded_field(value)
}

pub(super) fn bounded_field(value: &str) -> String {
    bounded_text(value, MAX_DETAIL_FIELD_CHARS, MAX_DETAIL_FIELD_BYTES)
}

pub(super) fn bounded_detail(mut detail: Detail) -> Detail {
    detail.family_id = bounded_text(&detail.family_id, MAX_DETAIL_ID_CHARS, MAX_DETAIL_ID_BYTES);
    detail.label = bounded_text(
        &detail.label,
        MAX_DETAIL_LABEL_CHARS,
        MAX_DETAIL_LABEL_BYTES,
    );
    detail.hint = bounded_hint(&detail.hint);
    detail.rows = detail
        .rows
        .into_iter()
        .map(|(label, value)| row(label, value))
        .collect();
    detail.notes = detail
        .notes
        .into_iter()
        .map(|note| bounded_field(&note))
        .collect();
    detail
}

pub(super) fn join_bounded<I, S>(values: I, separator: &str) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut output = String::new();
    let mut chars = 0;
    let mut first = true;
    for value in values {
        if !first
            && !push_bounded(
                &mut output,
                &mut chars,
                separator,
                MAX_DETAIL_FIELD_CHARS,
                MAX_DETAIL_FIELD_BYTES,
            )
        {
            mark_truncated(
                &mut output,
                &mut chars,
                MAX_DETAIL_FIELD_CHARS,
                MAX_DETAIL_FIELD_BYTES,
            );
            break;
        }
        first = false;
        if !push_bounded(
            &mut output,
            &mut chars,
            value.as_ref(),
            MAX_DETAIL_FIELD_CHARS,
            MAX_DETAIL_FIELD_BYTES,
        ) {
            mark_truncated(
                &mut output,
                &mut chars,
                MAX_DETAIL_FIELD_CHARS,
                MAX_DETAIL_FIELD_BYTES,
            );
            break;
        }
    }
    output
}

fn bounded_text(value: &str, maximum_chars: usize, maximum_bytes: usize) -> String {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut chars = 0;
    if !push_bounded(&mut output, &mut chars, value, maximum_chars, maximum_bytes) {
        mark_truncated(&mut output, &mut chars, maximum_chars, maximum_bytes);
    }
    output
}

/// Append sanitized Unicode without examining input after the output bound has been reached.
fn push_bounded(
    output: &mut String,
    chars: &mut usize,
    value: &str,
    maximum_chars: usize,
    maximum_bytes: usize,
) -> bool {
    for source in value.chars() {
        let safe = if is_unsafe_display_char(source) {
            ' '
        } else {
            source
        };
        if *chars >= maximum_chars || output.len().saturating_add(safe.len_utf8()) > maximum_bytes {
            return false;
        }
        output.push(safe);
        *chars += 1;
    }
    true
}

pub(super) fn is_unsafe_display_char(character: char) -> bool {
    let value = character as u32;
    character.is_control()
        || matches!(
            value,
            0x061c
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x206f
                | 0xfeff
        )
}

fn mark_truncated(
    output: &mut String,
    chars: &mut usize,
    maximum_chars: usize,
    maximum_bytes: usize,
) {
    const ELLIPSIS: char = '…';
    while (*chars >= maximum_chars
        || output.len().saturating_add(ELLIPSIS.len_utf8()) > maximum_bytes)
        && output.pop().is_some()
    {
        *chars = chars.saturating_sub(1);
    }
    if *chars < maximum_chars && output.len().saturating_add(ELLIPSIS.len_utf8()) <= maximum_bytes {
        output.push(ELLIPSIS);
        *chars += 1;
    }
}
