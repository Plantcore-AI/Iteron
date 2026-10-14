//! Provider-neutral verification before any native wire projection of tool pixels.
use crate::ProviderError;
use iteron_protocol::{Block, Message, Role, ToolResult, tool_image::ToolImageObservationV1};

pub(crate) fn validate_message(message: &Message) -> Result<(), ProviderError> {
    let mut count = 0;
    let mut total = 0usize;
    for block in &message.content {
        let Block::ToolImage(image) = block else {
            continue;
        };
        count += 1;
        total = total.saturating_add(image.image.data.encoded_len());
        if message.role!=Role::User||count>iteron_protocol::tool_image::MAX_TOOL_IMAGES_PER_MESSAGE||total>32*1024*1024
            ||!message.content.iter().any(|block|matches!(block,Block::ToolResult(result) if result.tool_use_id==image.tool_use_id && !result.is_error)) {return Err(ProviderError::Decode("tool image lacks its matching successful tool-result projection".into()));}
        image
            .validate()
            .map_err(|reason| ProviderError::Decode(reason.into()))?;
    }
    Ok(())
}
pub(crate) fn data_url(observation: &ToolImageObservationV1) -> String {
    format!(
        "data:{};base64,{}",
        observation.image.media_type.as_str(),
        observation.image.data.as_str()
    )
}
pub(crate) fn anthropic_result_content(
    message: &Message,
    result: &ToolResult,
) -> serde_json::Value {
    let images = message
        .content
        .iter()
        .filter_map(|block| match block {
            Block::ToolImage(image) if image.tool_use_id == result.tool_use_id => Some(image),
            _ => None,
        })
        .collect::<Vec<_>>();
    if images.is_empty() {
        return serde_json::json!(result.content);
    }
    let mut parts = vec![serde_json::json!({"type":"text","text":result.content})];
    for image in images {
        parts.push(serde_json::json!({"type":"text","text":image.observation_label()}));
        parts.push(serde_json::json!({"type":"image","source":{"type":"base64","media_type":image.image.media_type.as_str(),"data":image.image.data.as_str()}}));
    }
    serde_json::Value::Array(parts)
}

#[cfg(test)]
pub(crate) fn fixture() -> iteron_protocol::tool_image::ToolImageObservationV1 {
    use iteron_protocol::{ImageContent, ImageMediaType, Seq, tool_image::ToolImageScopeV1};
    ToolImageObservationV1{version:1,owner_tenant:iteron_protocol::TenantId::default(),owner_run:iteron_protocol::RunId("tool-image-private-cas".into()),tool_use_id:"vision-call".into(),terminal_seq:Seq(7),observed_unix_ms:42,source_url_display:"https://example.com/".into(),scope:ToolImageScopeV1::IsolatedBrowserViewport,artifact_id:"a38a4ff7320a3d8764ac959b264f15e335360d7c1e23a0627dee7f366c95c58f".into(),width:1,height:1,image:ImageContent::new(ImageMediaType::Png,"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=").unwrap()}
}
#[cfg(test)]
pub(crate) fn message_fixture() -> Message {
    Message {
        role: Role::User,
        content: vec![
            Block::ToolResult(ToolResult {
                tool_use_id: "vision-call".into(),
                content: "actual screenshot available".into(),
                is_error: false,
                trust: iteron_protocol::Trust::Untrusted,
                latency_ms: 0,
            }),
            Block::ToolImage(fixture()),
        ],
    }
}
