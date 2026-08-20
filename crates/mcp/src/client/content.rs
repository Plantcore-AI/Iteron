use crate::{McpError, McpResultPolicy, result_policy::McpSpillStore};
use serde_json::Value;

pub(crate) fn render_tool_content(
    result: &Value,
    policy: McpResultPolicy,
    spill_store: &McpSpillStore,
) -> Result<String, McpError> {
    let output = render_tool_content_with_limit(result, policy.spill_max_bytes())?;
    cap_and_spill(output, policy, spill_store)
}

pub(crate) fn render_extension_content(
    result: &Value,
    policy: McpResultPolicy,
    spill_store: &McpSpillStore,
) -> Result<String, McpError> {
    let output = serde_json::to_string_pretty(result)?;
    if output.len() > policy.spill_max_bytes() {
        return Err(McpError::OutputTooLarge {
            limit: policy.spill_max_bytes(),
        });
    }
    cap_and_spill(output, policy, spill_store)
}

fn cap_and_spill(
    output: String,
    policy: McpResultPolicy,
    spill_store: &McpSpillStore,
) -> Result<String, McpError> {
    if output.len() <= policy.visible_max_bytes() {
        return Ok(output);
    }

    let spill_handle = spill_store.retain(output.as_bytes())?;
    let marker = format!(
        "\n[MCP spill {spill_handle} {}/{}B {}]\n",
        policy.visible_max_bytes(),
        output.len(),
        policy.cleanup().label(),
    );
    let visible = policy.visible_max_bytes();
    if marker.len() >= visible {
        return Ok(utf8_prefix(&marker, visible).to_owned());
    }
    let retained = visible - marker.len();
    let head_bytes = retained / 2;
    let tail_bytes = retained - head_bytes;
    let head = utf8_prefix(&output, head_bytes);
    let tail = utf8_suffix(&output, tail_bytes);
    Ok(format!("{head}{marker}{tail}"))
}

fn render_tool_content_with_limit(result: &Value, limit: usize) -> Result<String, McpError> {
    let blocks = result
        .get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let omitted = blocks
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) != Some("text"))
        .count();
    let omission = (omitted > 0).then(|| format!("[{omitted} non-text blocks omitted]"));

    let mut output = String::new();
    for block in blocks {
        if block.get("type").and_then(Value::as_str) != Some("text") {
            continue;
        }
        push_line(
            &mut output,
            block.get("text").and_then(Value::as_str).unwrap_or(""),
            limit,
        )?;
    }
    if let Some(omission) = omission {
        push_line(&mut output, &omission, limit)?;
    }
    Ok(output)
}

fn push_line(output: &mut String, text: &str, limit: usize) -> Result<(), McpError> {
    let required = text.len().saturating_add(1);
    if required > limit.saturating_sub(output.len()) {
        return Err(McpError::OutputTooLarge { limit });
    }
    output.push_str(text);
    output.push('\n');
    Ok(())
}

fn utf8_prefix(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut end = maximum_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn utf8_suffix(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut start = value.len() - maximum_bytes;
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    &value[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn non_text_blocks_are_counted_once_without_reflecting_untrusted_types() {
        let result = json!({"content": [
            {"type":"text", "text":"visible"},
            {"type":"image", "data":"opaque"},
            {"type":"audio", "data":"opaque"},
            {"type":"hostile\nforged", "value":"opaque"}
        ]});
        let rendered = render_tool_content_with_limit(&result, 128).unwrap();
        assert_eq!(rendered, "visible\n[3 non-text blocks omitted]\n");
        assert!(!rendered.contains("hostile"));
        assert!(!rendered.contains("opaque"));
    }

    #[test]
    fn text_plus_omission_notice_obeys_one_total_ceiling() {
        let result = json!({"content": [
            {"type":"text", "text":"1234567890"},
            {"type":"resource", "resource":{}}
        ]});
        let expected = "1234567890\n[1 non-text blocks omitted]\n";
        assert_eq!(
            render_tool_content_with_limit(&result, expected.len()).unwrap(),
            expected
        );
        assert!(matches!(
            render_tool_content_with_limit(&result, expected.len() - 1),
            Err(McpError::OutputTooLarge { limit }) if limit == expected.len() - 1
        ));
    }

    #[test]
    fn oversized_text_is_privately_spilled_with_bounded_head_and_tail_visible() {
        let result =
            json!({"content": [{"type":"text", "text":format!("HEAD{}TAIL", "界".repeat(80))}]});
        let policy = McpResultPolicy::new(128, 1024, crate::McpSpillCleanup::SessionEnd).unwrap();
        let store = McpSpillStore::create().unwrap();
        let rendered = render_tool_content(&result, policy, &store).unwrap();
        assert!(rendered.len() <= 128);
        assert!(rendered.contains("[MCP spill sha256:"));
        assert!(rendered.contains(" session_end]"));
        assert!(rendered.starts_with("HEAD"));
        assert!(rendered.ends_with("TAIL\n"));
        assert!(!rendered.contains(std::env::temp_dir().to_string_lossy().as_ref()));
        assert_eq!(store.retained_count(), 1);
        assert!(std::str::from_utf8(rendered.as_bytes()).is_ok());
    }
}
