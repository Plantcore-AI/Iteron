//! Shared redaction and unsafe-display admission rules.
/// Convert untrusted display text into the only representation allowed to enter retained UI
/// state. Secret-shaped substrings are redacted and terminal control characters are escaped so a
/// tool/user string cannot inject terminal commands or rewrite earlier rows.
pub fn ui_safe_text(text: &str) -> String {
    let scrubbed = iteron_record::redact::scrub(text);
    let mut safe = String::with_capacity(scrubbed.len());
    for ch in scrubbed.chars() {
        match ch {
            '\n' | '\t' => safe.push(ch),
            ch if ch.is_control() => safe.extend(ch.escape_default()),
            ch => safe.push(ch),
        }
    }
    safe
}

/// Invisible directional/formatting characters and terminal controls are unsafe in every bounded
/// display/query projection. Keeping this outside the TUI lets non-interactive projections use the
/// same admission rule without depending on terminal state.
pub fn is_unsafe_display_char(character: char) -> bool {
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

/// Recursively sanitize untrusted JSON before it enters a retained presentation model.
pub fn ui_safe_json(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(text) => Value::String(ui_safe_text(text)),
        Value::Array(values) => Value::Array(values.iter().map(ui_safe_json).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (ui_safe_text(key), ui_safe_json(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}
