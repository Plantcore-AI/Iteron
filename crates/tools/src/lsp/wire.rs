use super::LspToolError;
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SERVER_STRING_ID_BYTES: usize = 256;
const MAX_CONFIGURATION_ITEMS: usize = 64;

pub(super) async fn write_value<W>(writer: &mut W, value: &Value) -> Result<(), LspToolError>
where
    W: AsyncWrite + Unpin,
{
    let body = serde_json::to_string(value).map_err(|_| LspToolError::Serialization)?;
    let frame = iteron_lsp::framing::encode(&body).map_err(LspToolError::Protocol)?;
    tokio::time::timeout(
        iteron_tunables::param_duration("tools.lsp.wire.write_timeout", WRITE_TIMEOUT),
        async {
            writer.write_all(&frame).await?;
            writer.flush().await
        },
    )
    .await
    .map_err(|_| LspToolError::WriteTimeout)?
    .map_err(|_| LspToolError::Transport)
}

/// The only server-initiated request this driver can answer truthfully without widening
/// authority is configuration discovery: it has no live LSP settings, so it returns one `null`
/// for every bounded requested section. Dynamic registration, edits, prompts and commands remain
/// unsupported and receive MethodNotFound rather than a false acknowledgement.
pub(super) fn safe_server_request_result(method: &str, params: Option<&Value>) -> Option<Value> {
    if method != "workspace/configuration" {
        return None;
    }
    let items = params?.get("items")?.as_array()?;
    if items.len()
        > iteron_tunables::param_integer(
            "tools.lsp.wire.max_configuration_items",
            MAX_CONFIGURATION_ITEMS,
        )
    {
        return None;
    }
    Some(Value::Array(vec![Value::Null; items.len()]))
}

pub(super) fn validate_server_request_id(value: &Value) -> Result<(), LspToolError> {
    match value {
        Value::Number(number)
            if number.as_i64().is_some_and(|value| {
                (i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&value)
            }) =>
        {
            Ok(())
        }
        Value::String(value)
            if !value.is_empty()
                && value.len()
                    <= iteron_tunables::param_integer(
                        "tools.lsp.wire.max_server_string_id_bytes",
                        MAX_SERVER_STRING_ID_BYTES,
                    )
                && !value.chars().any(char::is_control) =>
        {
            Ok(())
        }
        _ => Err(LspToolError::MalformedEnvelope),
    }
}

#[cfg(test)]
mod tests {
    use super::write_value;
    use serde_json::json;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn writer_uses_content_length_framing() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_value(&mut client, &json!({"jsonrpc":"2.0","id":1,"result":null}))
            .await
            .unwrap();
        let mut bytes = vec![0_u8; 256];
        let read = server.read(&mut bytes).await.unwrap();
        let frame = String::from_utf8(bytes[..read].to_vec()).unwrap();
        assert!(frame.starts_with("Content-Length: "));
        assert!(frame.contains("\r\n\r\n{"));
    }
}
