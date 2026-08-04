use super::super::is_unsafe_display_char;
use core_tunables::{ConstraintViolation, CrossFieldRule};
use serde::Serialize;
use std::fmt::{self, Display, Write as _};
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

#[derive(Clone, Copy)]
struct Limits {
    chars: usize,
    bytes: usize,
}

const TITLE_LIMITS: Limits = Limits {
    chars: MAX_DETAIL_TITLE_CHARS,
    bytes: MAX_DETAIL_TITLE_BYTES,
};
const ID_LIMITS: Limits = Limits {
    chars: MAX_DETAIL_ID_CHARS,
    bytes: MAX_DETAIL_ID_BYTES,
};
const LABEL_LIMITS: Limits = Limits {
    chars: MAX_DETAIL_LABEL_CHARS,
    bytes: MAX_DETAIL_LABEL_BYTES,
};
const FIELD_LIMITS: Limits = Limits {
    chars: MAX_DETAIL_FIELD_CHARS,
    bytes: MAX_DETAIL_FIELD_BYTES,
};
const ROW_LABEL_LIMITS: Limits = Limits {
    chars: MAX_DETAIL_ROW_LABEL_CHARS,
    bytes: MAX_DETAIL_ROW_LABEL_BYTES,
};

/// A formatting sink that sanitizes as it receives fragments and returns `fmt::Error` at its
/// first char/byte limit. A hostile `Display` implementation therefore stops being called at the
/// cap instead of first allocating an unbounded `format!` result that is truncated afterwards.
pub(super) struct BoundedText {
    output: String,
    chars: usize,
    limits: Limits,
    truncated: bool,
}

impl BoundedText {
    fn new(limits: Limits) -> Self {
        Self {
            output: String::with_capacity(limits.bytes),
            chars: 0,
            limits,
            truncated: false,
        }
    }

    pub(super) fn field() -> Self {
        Self::new(FIELD_LIMITS)
    }

    /// Stream one display value. `false` means the sink reached its cap and already owns the
    /// ellipsis; callers must stop iterating additional registry input.
    pub(super) fn push(&mut self, value: impl Display) -> bool {
        if self.truncated {
            return false;
        }
        write!(self, "{value}").is_ok()
    }

    pub(super) fn push_str(&mut self, value: &str) -> bool {
        if self.truncated {
            return false;
        }
        fmt::Write::write_str(self, value).is_ok()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.output.is_empty()
    }

    pub(super) fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub(super) fn truncate(&mut self) {
        if !self.truncated {
            self.truncated = true;
            self.mark_ellipsis();
        }
    }

    pub(super) fn finish(self) -> String {
        self.output
    }

    fn mark_ellipsis(&mut self) {
        const ELLIPSIS: char = '…';
        while (self.chars >= self.limits.chars
            || self.output.len().saturating_add(ELLIPSIS.len_utf8()) > self.limits.bytes)
            && self.output.pop().is_some()
        {
            self.chars = self.chars.saturating_sub(1);
        }
        if self.chars < self.limits.chars
            && self.output.len().saturating_add(ELLIPSIS.len_utf8()) <= self.limits.bytes
        {
            self.output.push(ELLIPSIS);
            self.chars += 1;
        }
    }
}

impl fmt::Write for BoundedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated {
            return Err(fmt::Error);
        }
        for source in value.chars() {
            let safe = if is_unsafe_display_char(source) {
                ' '
            } else {
                source
            };
            if self.chars >= self.limits.chars
                || self.output.len().saturating_add(safe.len_utf8()) > self.limits.bytes
            {
                self.truncated = true;
                self.mark_ellipsis();
                return Err(fmt::Error);
            }
            self.output.push(safe);
            self.chars += 1;
        }
        Ok(())
    }
}

fn render(value: impl Display, limits: Limits) -> String {
    let mut output = BoundedText::new(limits);
    let _ = output.push(value);
    output.finish()
}

pub(super) fn bounded_title(value: impl Display) -> String {
    render(value, TITLE_LIMITS)
}

pub(super) fn bounded_id(value: impl Display) -> String {
    render(value, ID_LIMITS)
}

pub(super) fn bounded_label(value: impl Display) -> String {
    render(value, LABEL_LIMITS)
}

pub(super) fn bounded_hint(value: impl Display) -> String {
    bounded_field(value)
}

pub(super) fn bounded_field(value: impl Display) -> String {
    render(value, FIELD_LIMITS)
}

pub(super) struct DetailNote(String);

impl DetailNote {
    pub(super) fn into_inner(self) -> String {
        self.0
    }
}

pub(super) fn bounded_note(value: impl Display) -> DetailNote {
    DetailNote(bounded_field(value))
}

pub(super) struct DetailRow(String, String);

impl DetailRow {
    pub(super) fn into_parts(self) -> (String, String) {
        (self.0, self.1)
    }
}

pub(super) fn row(label: impl Display, value: impl Display) -> DetailRow {
    DetailRow(render(label, ROW_LABEL_LIMITS), render(value, FIELD_LIMITS))
}

pub(super) fn join_strs<I, S>(values: I, separator: &str) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut output = BoundedText::field();
    for value in values {
        if !output.is_empty() && !output.push_str(separator) {
            break;
        }
        if !output.push_str(value.as_ref()) {
            break;
        }
    }
    output.finish()
}

pub(super) fn constraint_summary(rules: &[CrossFieldRule]) -> String {
    if rules.is_empty() {
        return bounded_field("none");
    }
    let mut output = BoundedText::field();
    for rule in rules {
        if !output.is_empty() && !output.push_str("; ") {
            break;
        }
        match rule {
            CrossFieldRule::LessOrEqual { left, right } => {
                let _ = output.push(format_args!("{left} <= {right}"));
            }
            CrossFieldRule::SumLessOrEqual { terms, limit } => {
                for (index, term) in terms.iter().enumerate() {
                    if index > 0 && !output.push_str(" + ") {
                        break;
                    }
                    if !output.push_str(term) {
                        break;
                    }
                }
                if !output.is_truncated() {
                    let _ = output.push(format_args!(" <= {limit}"));
                }
            }
            CrossFieldRule::Requires {
                if_field,
                equals,
                then_field,
            } => {
                let _ = output.push(format_args!("if {if_field}="));
                if !output.is_truncated() {
                    let json = compact_json(equals);
                    let _ = output.push_str(&json);
                }
                if !output.is_truncated() {
                    let _ = output.push(format_args!(" then require {then_field}"));
                }
            }
            CrossFieldRule::MutuallyExclusive { fields } => {
                let _ = output.push_str("mutually exclusive: ");
                for (index, field) in fields.iter().enumerate() {
                    if index > 0 && !output.push_str(", ") {
                        break;
                    }
                    if !output.push_str(field) {
                        break;
                    }
                }
            }
            CrossFieldRule::ExternalCeiling {
                field,
                ceiling,
                projection,
                relation,
                violation,
            } => {
                let _ = output.push(format_args!(
                    "{field}: {} / {} / {} -> ",
                    code(ceiling),
                    code(projection),
                    code(relation)
                ));
                if !output.is_truncated() {
                    match violation {
                        ConstraintViolation::Reject => {
                            let _ = output.push_str("reject");
                        }
                        ConstraintViolation::ClampNumeric => {
                            let _ = output.push_str("clamp_numeric");
                        }
                        ConstraintViolation::DegradeAttested { policy_id } => {
                            let _ = output.push(format_args!("degrade_attested({policy_id})"));
                        }
                    }
                }
            }
        }
        if output.is_truncated() {
            break;
        }
    }
    output.finish()
}

pub(super) fn code<T: Serialize>(value: &T) -> String {
    let mut writer = BoundedIo::new(MAX_DETAIL_FIELD_BYTES);
    if serde_json::to_writer(&mut writer, value).is_err() || writer.truncated {
        return bounded_field("invalid");
    }
    match serde_json::from_slice::<String>(&writer.bytes) {
        Ok(value) => bounded_field(value),
        Err(_) => bounded_field("invalid"),
    }
}

pub(super) fn compact_json<T: Serialize>(value: &T) -> String {
    let mut writer = BoundedIo::new(MAX_DETAIL_FIELD_BYTES);
    let result = serde_json::to_writer(&mut writer, value);
    let partial = String::from_utf8_lossy(&writer.bytes);
    let mut output = BoundedText::field();
    let _ = output.push_str(&partial);
    match result {
        Ok(()) => {}
        Err(_) if writer.truncated => output.truncate(),
        Err(_) => return bounded_field("<unavailable>"),
    }
    output.finish()
}

struct BoundedIo {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl BoundedIo {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit),
            limit,
            truncated: false,
        }
    }
}

impl io::Write for BoundedIo {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if buffer.len() <= remaining {
            self.bytes.extend_from_slice(buffer);
            return Ok(buffer.len());
        }
        self.bytes.extend_from_slice(&buffer[..remaining]);
        self.truncated = true;
        Err(io::Error::other(
            "bounded display serialization limit reached",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
