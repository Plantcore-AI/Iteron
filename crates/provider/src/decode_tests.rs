use crate::guard_tests::{request, spawn_one_shot_sse};
use crate::{
    AdapterKind, Anthropic, DecodeCode, DecodeDiagnostic, DecodeField, OpenAiCompat,
    OpenAiResponses, Provider, ProviderError, RetryDisposition, StreamItem,
};

const SECRET: &str = "synthetic-secret https://example.invalid/private?token=synthetic";

async fn live_failure(adapter: AdapterKind, body: String) -> ProviderError {
    let (root, server) = spawn_one_shot_sse(body);
    let provider: Box<dyn Provider> = match adapter {
        AdapterKind::OpenAiCompatibleChat => {
            Box::new(OpenAiCompat::try_new("synthetic-key".into(), Some(root)).unwrap())
        }
        AdapterKind::OpenAiResponses => {
            Box::new(OpenAiResponses::new("synthetic-key".into(), Some(root)).unwrap())
        }
        AdapterKind::AnthropicMessages => {
            Box::new(Anthropic::new("synthetic-key".into(), Some(root)).unwrap())
        }
    };
    let mut completed = false;
    let error = provider
        .turn(&request("synthetic-model"), &mut |item| {
            completed |= matches!(
                item,
                StreamItem::TurnComplete { .. } | StreamItem::ToolUseComplete(_)
            );
        })
        .await
        .unwrap_err();
    server.join().unwrap();
    assert!(
        !completed,
        "invalid response must not publish a completed turn or tool"
    );
    assert_eq!(error.retry_disposition(), RetryDisposition::Never);
    for rendered in [
        error.public_summary(),
        error.to_string(),
        format!("{error:?}"),
    ] {
        assert!(!rendered.contains("synthetic-secret"));
        assert!(!rendered.contains("https://"));
        assert!(!rendered.contains("synthetic-key"));
    }
    error
}

fn assert_diagnostic(error: ProviderError, code: DecodeCode, field: DecodeField, frame: u64) {
    assert_eq!(
        error.decode_diagnostic(),
        Some(DecodeDiagnostic {
            code,
            field,
            frame: Some(frame),
        })
    );
    assert_eq!(
        error.public_summary(),
        format!(
            "provider response was invalid [code={}, field={}, frame={frame}]",
            code.as_str(),
            field.as_str(),
        )
    );
}

#[tokio::test]
async fn live_decoders_report_safe_json_frame_positions() {
    // The malicious key is syntactically valid up to a missing colon. serde errors must never
    // carry it into Display, Debug or the operator summary. Wire metadata is not a data frame.
    let bad_json = format!("{{{} false}}", serde_json::to_string(SECRET).unwrap());
    let metadata = ": keepalive\nid: metadata\nretry: 1000\n\n";
    for (adapter, prefix, event) in [
        (
            AdapterKind::OpenAiCompatibleChat,
            "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\n",
            "",
        ),
        (
            AdapterKind::OpenAiResponses,
            "event: response.created\ndata: {\"type\":\"response.created\"}\n\n",
            "event: response.output_text.delta\n",
        ),
        (
            AdapterKind::AnthropicMessages,
            "event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":1}}}\n\n",
            "event: content_block_start\n",
        ),
    ] {
        let body = format!("{metadata}{prefix}{metadata}{event}data: {bad_json}\n\n");
        let error = live_failure(adapter, body).await;
        assert_eq!(
            error.public_summary(),
            "provider response was invalid [code=json_syntax, field=sse.data, frame=2]"
        );
        assert_diagnostic(error, DecodeCode::JsonSyntax, DecodeField::SseData, 2);
    }
}

#[tokio::test]
async fn live_decoders_report_typed_field_paths() {
    for missing in [false, true] {
        let code = if missing {
            DecodeCode::MissingField
        } else {
            DecodeCode::InvalidType
        };
        for adapter in [
            AdapterKind::OpenAiCompatibleChat,
            AdapterKind::OpenAiResponses,
            AdapterKind::AnthropicMessages,
        ] {
            let (prefix, event, mut value, field, path, key) = match adapter {
                AdapterKind::OpenAiCompatibleChat => (
                    "data: {\"choices\":[{\"delta\":{},\"finish_reason\":null}]}\n\n",
                    "",
                    serde_json::json!({"usage":{"prompt_tokens":SECRET,"completion_tokens":1}}),
                    DecodeField::PromptTokens,
                    "$.usage.prompt_tokens",
                    "prompt_tokens",
                ),
                AdapterKind::OpenAiResponses => (
                    "event: response.created\ndata: {\"type\":\"response.created\"}\n\n",
                    "event: response.output_text.delta\n",
                    serde_json::json!({"type":"response.output_text.delta","delta":"ok","output_index":SECRET,"content_index":0}),
                    DecodeField::OutputIndex,
                    "$.output_index",
                    "output_index",
                ),
                AdapterKind::AnthropicMessages => (
                    "event: ping\ndata: {}\n\n",
                    "event: message_start\n",
                    serde_json::json!({"message":{"usage":{"input_tokens":SECRET}}}),
                    DecodeField::InputTokens,
                    "$.message.usage.input_tokens",
                    "input_tokens",
                ),
            };
            if missing {
                let object = match adapter {
                    AdapterKind::OpenAiCompatibleChat => value["usage"].as_object_mut().unwrap(),
                    AdapterKind::OpenAiResponses => value.as_object_mut().unwrap(),
                    AdapterKind::AnthropicMessages => {
                        value["message"]["usage"].as_object_mut().unwrap()
                    }
                };
                let payload = object.remove(key).unwrap();
                object.insert(SECRET.into(), payload);
            }
            let body = format!("{prefix}: keepalive\n\n{event}data: {value}\n\n");
            let error = live_failure(adapter, body).await;
            let code_text = if missing {
                "missing_field"
            } else {
                "invalid_type"
            };
            assert_eq!(
                error.public_summary(),
                format!("provider response was invalid [code={code_text}, field={path}, frame=2]")
            );
            assert_diagnostic(error, code, field, 2);
        }
        let mut usage = serde_json::json!({"input_tokens":SECRET,"output_tokens":1});
        if missing {
            usage.as_object_mut().unwrap().remove("input_tokens");
        }
        let terminal = serde_json::json!({"type":"response.completed","response":{
            "status":"completed","output":[],"usage":usage
        }});
        let body = format!(
            "event: response.created\ndata: {{\"type\":\"response.created\"}}\n\nevent: response.completed\ndata: {terminal}\n\n"
        );
        assert_diagnostic(
            live_failure(AdapterKind::OpenAiResponses, body).await,
            code,
            DecodeField::ResponseInputTokens,
            2,
        );
    }
}

#[tokio::test]
async fn deferred_tool_json_error_keeps_its_origin_frame() {
    let invalid_arguments = format!("{{{} false}}", serde_json::to_string(SECRET).unwrap());
    let chat = serde_json::json!({"choices":[{"delta":{"tool_calls":[{
        "index":0,"id":"call_synthetic","function":{"name":"read_file","arguments":invalid_arguments}
    }]},"finish_reason":null}]});
    let body = format!(
        "data: {chat}\n\ndata: {{\"choices\":[{{\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}]}}\n\ndata: [DONE]\n\n"
    );
    assert_diagnostic(
        live_failure(AdapterKind::OpenAiCompatibleChat, body).await,
        DecodeCode::JsonSyntax,
        DecodeField::ChatToolArguments,
        2,
    );

    let delta = serde_json::json!({"index":0,"delta":{"type":"input_json_delta","partial_json":invalid_arguments}});
    let body = format!(
        concat!(
            "event: message_start\ndata: {{\"message\":{{\"usage\":{{\"input_tokens\":1}}}}}}\n\n",
            "event: content_block_start\ndata: {{\"index\":0,\"content_block\":{{\"type\":\"tool_use\",\"id\":\"call_synthetic\",\"name\":\"read_file\",\"input\":{{}}}}}}\n\n",
            "event: content_block_delta\ndata: {}\n\n",
            "event: content_block_stop\ndata: {{\"index\":0}}\n\n",
            "event: message_delta\ndata: {{\"delta\":{{\"stop_reason\":\"tool_use\"}},\"usage\":{{\"output_tokens\":1}}}}\n\n",
            "event: message_stop\ndata: {{}}\n\n"
        ),
        delta
    );
    assert_diagnostic(
        live_failure(AdapterKind::AnthropicMessages, body).await,
        DecodeCode::JsonSyntax,
        DecodeField::PartialJson,
        4,
    );
}

#[test]
fn legacy_decode_and_json_summaries_are_content_free() {
    let legacy = ProviderError::Decode(SECRET.into());
    assert_eq!(
        legacy.public_summary(),
        "provider response was invalid [code=invalid_response, field=$]"
    );
    let error = serde_json::from_str::<u64>(&serde_json::to_string(SECRET).unwrap()).unwrap_err();
    let legacy_json = ProviderError::Json(error);
    assert_eq!(
        legacy_json.public_summary(),
        "provider response was invalid [code=invalid_type, field=$]"
    );
    assert_eq!(legacy_json.retry_disposition(), RetryDisposition::Never);
    assert_eq!(
        crate::decode::DecodeField::schema_key(SECRET),
        DecodeField::Response
    );
}
