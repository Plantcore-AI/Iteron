use crate::{MAX_FRAME_BYTES, McpError};
use serde_json::Value;

pub(crate) fn render_tool_content(result: &Value) -> Result<String, McpError> {
    render_tool_content_with_limit(result, MAX_FRAME_BYTES)
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
}
