//! Host-only retention of an authoritative MCP response before visible result projection.
//!
//! These bytes are untrusted server data. They confer no permission or effect authority and
//! never serialize into model-visible timing evidence. The runtime owns redaction and erasure.

use crate::MAX_RESPONSE_BYTES;
use std::io::{self, Write};
use std::sync::Arc;

#[derive(Clone, PartialEq, Eq)]
pub struct McpCapturedResult {
    json: Option<Arc<str>>,
}

impl McpCapturedResult {
    pub(crate) fn capture(result: &serde_json::Value) -> Self {
        let mut sink = BoundedJson::default();
        let json = serde_json::to_writer(&mut sink, result)
            .ok()
            .and_then(|()| String::from_utf8(sink.bytes).ok())
            .map(Arc::<str>::from);
        Self { json }
    }

    /// Complete compact JSON of the matching response's result object, including structured
    /// content and non-text blocks. It is never a reconstruction from the visible preview.
    pub fn json(&self) -> Option<&str> {
        self.json.as_deref()
    }

    /// A matching body existed, but its host retention exceeded the fixed response envelope.
    /// This changes neither transport certainty nor the server's `isError` field.
    pub fn is_unavailable(&self) -> bool {
        self.json.is_none()
    }
}

impl std::fmt::Debug for McpCapturedResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpCapturedResult")
            .field("complete", &self.json.is_some())
            .field("bytes", &self.json.as_ref().map(|value| value.len()))
            .finish()
    }
}

#[derive(Default)]
struct BoundedJson {
    bytes: Vec<u8>,
}

impl Write for BoundedJson {
    fn write(&mut self, incoming: &[u8]) -> io::Result<usize> {
        if incoming.len() > MAX_RESPONSE_BYTES.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(
                "MCP captured result exceeds the host response envelope",
            ));
        }
        self.bytes.extend_from_slice(incoming);
        Ok(incoming.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::McpCapturedResult;
    use crate::MAX_RESPONSE_BYTES;

    #[test]
    fn capture_preserves_structured_and_non_text_data_without_debug_exposure() {
        let value = serde_json::json!({
            "content": [
                {"type":"text","text":"full untrusted payload"},
                {"type":"image","data":"private non-text payload"}
            ],
            "structuredContent":{"answer":42}, "isError":false
        });
        let captured = McpCapturedResult::capture(&value);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(captured.json().unwrap()).unwrap(),
            value
        );
        let debug = format!("{captured:?}");
        assert!(!debug.contains("private non-text payload"));
        assert!(!debug.contains("full untrusted payload"));
    }

    #[test]
    fn oversize_body_is_unavailable_without_retaining_a_truncated_json() {
        let value = serde_json::json!({"content":"x".repeat(MAX_RESPONSE_BYTES)});
        let captured = McpCapturedResult::capture(&value);
        assert!(captured.is_unavailable());
        assert!(captured.json().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_stdio_keeps_the_complete_response_after_preview_and_tool_end_cleanup() {
        let payload = "complete transport payload ".repeat(4096);
        let result = serde_json::json!({
            "content":[
                {"type":"text","text":payload},
                {"type":"image","data":"opaque fixture bytes"}
            ],
            "structuredContent":{"final_item":"retained structured tail"},
            "isError":false
        });
        let initialize = serde_json::json!({
            "jsonrpc":"2.0","id":1,"result":{
                "resultType":"complete","supportedVersions":["2026-07-28"],
                "capabilities":{"tools":{}}
            }
        });
        let response = serde_json::json!({"jsonrpc":"2.0","id":2,"result":result});
        // The shell sees only these fixed fixture values; neither body contains a quote that
        // could escape the literal printf argument. The actual stdio client owns/reaps the child.
        assert!(!initialize.to_string().contains('\''));
        assert!(!response.to_string().contains('\''));
        let script = format!(
            "IFS= read -r initialize; printf '%s\\n' '{initialize}'; \
             IFS= read -r call; printf '%s\\n' '{response}'; \
             while IFS= read -r request; do :; done"
        );
        let observed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut client =
                crate::McpClient::connect_2026("/bin/sh", &["-c".into(), script], "retained")
                    .await
                    .unwrap();
            client.set_result_policy(
                crate::McpResultPolicy::new(
                    128,
                    MAX_RESPONSE_BYTES,
                    crate::McpSpillCleanup::ToolEnd,
                )
                .unwrap(),
            );
            let outcome = client
                .call_tool_outcome("complete-result", serde_json::json!({}))
                .await;
            let crate::McpToolOutcome::Completed {
                content,
                is_error,
                evidence,
            } = outcome
            else {
                panic!("matching stdio result did not complete");
            };
            assert!(!is_error);
            assert!(content.len() <= 128);
            assert!(!content.contains("retained structured tail"));
            client
                .cleanup_spills(crate::McpSpillCleanup::ToolEnd)
                .unwrap();
            evidence
        })
        .await
        .expect("bounded actual MCP fixture completes");
        let captured = observed.captured_result().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(captured.json().unwrap()).unwrap(),
            result
        );
    }
}
