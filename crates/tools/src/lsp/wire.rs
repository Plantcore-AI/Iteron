use super::LspToolError;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INTERLEAVED_MESSAGES: usize = 64;
const MAX_INTERLEAVED_BYTES: usize = 32 * 1024 * 1024;
const MAX_METHOD_BYTES: usize = 256;
const MAX_SERVER_STRING_ID_BYTES: usize = 256;
const MAX_CONFIGURATION_ITEMS: usize = 64;

pub(super) async fn write_value<W>(writer: &mut W, value: &Value) -> Result<(), LspToolError>
where
    W: AsyncWrite + Unpin,
{
    let body = serde_json::to_string(value).map_err(|_| LspToolError::Serialization)?;
    let frame = iteron_lsp::framing::encode(&body).map_err(LspToolError::Protocol)?;
    tokio::time::timeout(WRITE_TIMEOUT, async {
        writer.write_all(&frame).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| LspToolError::WriteTimeout)?
    .map_err(|_| LspToolError::Transport)
}

pub(super) async fn read_response<R, W>(
    reader: &mut R,
    writer: &mut W,
    expected_id: u32,
    deadline: Duration,
) -> Result<Value, LspToolError>
where
    R: AsyncBufRead + AsyncReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(deadline, read_response_inner(reader, writer, expected_id))
        .await
        .map_err(|_| LspToolError::ResponseTimeout)?
}

async fn read_response_inner<R, W>(
    reader: &mut R,
    writer: &mut W,
    expected_id: u32,
) -> Result<Value, LspToolError>
where
    R: AsyncBufRead + AsyncReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut aggregate = 0usize;
    for _ in 0..MAX_INTERLEAVED_MESSAGES {
        let Some((mut message, wire_bytes)) = iteron_lsp::framing::read_message_with_size(reader)
            .await
            .map_err(LspToolError::Protocol)?
        else {
            return Err(LspToolError::UnexpectedEof);
        };
        aggregate =
            aggregate
                .checked_add(wire_bytes)
                .ok_or(LspToolError::InterleavedOutputTooLarge {
                    limit: MAX_INTERLEAVED_BYTES,
                })?;
        if aggregate > MAX_INTERLEAVED_BYTES {
            return Err(LspToolError::InterleavedOutputTooLarge {
                limit: MAX_INTERLEAVED_BYTES,
            });
        }

        let object = message
            .as_object_mut()
            .ok_or(LspToolError::MalformedEnvelope)?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(LspToolError::MalformedEnvelope);
        }
        if response_id(object.get("id")) == Some(expected_id) {
            let has_result = object.contains_key("result");
            let has_error = object.contains_key("error");
            if has_result == has_error {
                return Err(LspToolError::MalformedEnvelope);
            }
            if has_error {
                let code = object
                    .get("error")
                    .and_then(Value::as_object)
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_i64);
                return Err(LspToolError::ServerResponse { code });
            }
            return object
                .remove("result")
                .ok_or(LspToolError::MalformedEnvelope);
        }

        if let Some(method) = object.get("method").and_then(Value::as_str) {
            if method.is_empty()
                || method.len() > MAX_METHOD_BYTES
                || method.chars().any(char::is_control)
            {
                return Err(LspToolError::MalformedEnvelope);
            }
            if let Some(id) = object.get("id").cloned() {
                validate_server_request_id(&id)?;
                let response = safe_server_request_result(method, object.get("params"))
                    .map(|result| json!({"jsonrpc":"2.0","id":id,"result":result}))
                    .unwrap_or_else(|| {
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {"code": -32601, "message": "unsupported server request"}
                        })
                    });
                write_value(writer, &response).await?;
            }
            continue;
        }

        // Calls are serialized. A response for any other id cannot belong to a live request and
        // must not be silently discarded, because doing so could alias a future correlation.
        return Err(LspToolError::ForeignResponse);
    }
    Err(LspToolError::TooManyInterleavedMessages {
        limit: MAX_INTERLEAVED_MESSAGES,
    })
}

/// The only server-initiated request this driver can answer truthfully without widening
/// authority is configuration discovery: it has no live LSP settings, so it returns one `null`
/// for every bounded requested section. Dynamic registration, edits, prompts and commands remain
/// unsupported and receive MethodNotFound rather than a false acknowledgement.
fn safe_server_request_result(method: &str, params: Option<&Value>) -> Option<Value> {
    if method != "workspace/configuration" {
        return None;
    }
    let items = params?.get("items")?.as_array()?;
    if items.len() > MAX_CONFIGURATION_ITEMS {
        return None;
    }
    Some(Value::Array(vec![Value::Null; items.len()]))
}

fn response_id(value: Option<&Value>) -> Option<u32> {
    let value = value?.as_u64()?;
    u32::try_from(value).ok()
}

fn validate_server_request_id(value: &Value) -> Result<(), LspToolError> {
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
                && value.len() <= MAX_SERVER_STRING_ID_BYTES
                && !value.chars().any(char::is_control) =>
        {
            Ok(())
        }
        _ => Err(LspToolError::MalformedEnvelope),
    }
}

#[cfg(test)]
mod tests {
    use super::{read_response, write_value};
    use serde_json::json;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn skips_notification_but_returns_only_exact_response() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let (read, mut write) = tokio::io::split(client);
        let server_task = tokio::spawn(async move {
            for value in [
                json!({"jsonrpc":"2.0","method":"window/logMessage","params":{}}),
                json!({"jsonrpc":"2.0","id":7,"result":{"ok":true}}),
            ] {
                let body = serde_json::to_string(&value).unwrap();
                server
                    .write_all(&iteron_lsp::framing::encode(&body).unwrap())
                    .await
                    .unwrap();
            }
        });
        let mut reader = BufReader::new(read);
        let result = read_response(&mut reader, &mut write, 7, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result, json!({"ok":true}));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn answers_bounded_configuration_request_before_target_response() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let (read, mut write) = tokio::io::split(client);
        let server_task = tokio::spawn(async move {
            let request = json!({"jsonrpc":"2.0","id":"server-1","method":"workspace/configuration","params":{"items":[{"section":"rust-analyzer"}]}});
            let body = serde_json::to_string(&request).unwrap();
            server
                .write_all(&iteron_lsp::framing::encode(&body).unwrap())
                .await
                .unwrap();
            let mut response = vec![0_u8; 256];
            let read = server.read(&mut response).await.unwrap();
            let response = String::from_utf8_lossy(&response[..read]);
            assert!(response.contains("\"result\":[null]"), "{response}");
            let target = json!({"jsonrpc":"2.0","id":3,"result":null});
            let body = serde_json::to_string(&target).unwrap();
            server
                .write_all(&iteron_lsp::framing::encode(&body).unwrap())
                .await
                .unwrap();
        });
        let mut reader = BufReader::new(read);
        assert_eq!(
            read_response(&mut reader, &mut write, 3, Duration::from_secs(1))
                .await
                .unwrap(),
            serde_json::Value::Null
        );
        server_task.await.unwrap();
    }

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
