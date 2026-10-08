//! Top-level durable tags for the captured-pixel vocabulary. Legacy message and compaction
//! records keep their original nested Block set, so older readers can skip V2 as Unknown.
use crate::{Block, EventKind, Message};

fn has_pixels(message: &Message) -> bool {
    message
        .content
        .iter()
        .any(|block| matches!(block, Block::ToolImage(_)))
}
impl EventKind {
    pub fn message(message: Message) -> Self {
        if has_pixels(&message) {
            Self::MessageV2 { message }
        } else {
            Self::Message { message }
        }
    }
    pub fn compaction(messages: Vec<Message>) -> Self {
        if messages.iter().any(has_pixels) {
            Self::CompactionV2 { messages }
        } else {
            Self::Compaction { messages }
        }
    }
    /// Both tags carry the same actual model transcript; this is not a legacy-reader projection.
    pub fn message_value(&self) -> Option<&Message> {
        match self {
            Self::Message { message } | Self::MessageV2 { message } => Some(message),
            _ => None,
        }
    }
    pub fn compaction_value(&self) -> Option<&[Message]> {
        match self {
            Self::Compaction { messages } | Self::CompactionV2 { messages } => Some(messages),
            _ => None,
        }
    }
    pub(crate) fn validate_message_vocabulary(&self) -> Result<(), &'static str> {
        let messages: &[Message] = match self {
            Self::MessageV2 { message } => std::slice::from_ref(message),
            Self::CompactionV2 { messages } => messages,
            _ => &[],
        };
        for message in messages {
            for block in &message.content {
                if let Block::ToolImage(observation) = block {
                    observation.validate()?;
                }
            }
        }
        match self {
            Self::Message { message } if has_pixels(message) => {
                Err("captured pixels require the message_v2 record tag")
            }
            Self::Compaction { messages } if messages.iter().any(has_pixels) => {
                Err("captured pixels require the compaction_v2 record tag")
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_image::ToolImageObservationV1;
    use crate::{ImageContent, ImageMediaType, Role, RunId, Seq, TenantId};
    use serde::Deserialize;

    fn actual_image_message() -> Message {
        let observation = ToolImageObservationV1 {
            version: 1, tool_use_id: "captured-call".into(), owner_tenant: TenantId::default(),
            owner_run: RunId("image-schema".into()), terminal_seq: Seq(1), observed_unix_ms: 1,
            source_url_display: "https://example.com/".into(), scope: crate::tool_image::ToolImageScopeV1::IsolatedBrowserViewport,
            artifact_id: "a38a4ff7320a3d8764ac959b264f15e335360d7c1e23a0627dee7f366c95c58f".into(), width: 1, height: 1,
            image: ImageContent::new(ImageMediaType::Png, "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=").unwrap(),
        };
        observation.validate().unwrap();
        Message {
            role: Role::User,
            content: vec![Block::ToolImage(observation)],
        }
    }
    // The released Block vocabulary has no `other` arm. New pixels cannot enter its known tag.
    #[derive(Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum LegacyKind {
        Message {
            message: LegacyMessage,
        },
        Compaction {
            messages: Vec<LegacyMessage>,
        },
        #[serde(other)]
        Unknown,
    }
    #[derive(Deserialize)]
    struct LegacyMessage {
        role: Role,
        content: Vec<LegacyBlock>,
    }
    #[derive(Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum LegacyBlock {
        Text { text: String },
    }

    #[test]
    fn actual_pixel_vocabulary_is_skippable_only_with_new_top_level_tags() {
        let message = actual_image_message();
        let legacy = EventKind::Message {
            message: message.clone(),
        };
        assert!(legacy.validate_compatibility_tag().is_err());
        assert!(
            serde_json::from_value::<LegacyKind>(serde_json::to_value(legacy).unwrap()).is_err()
        );
        for kind in [
            EventKind::message(message.clone()),
            EventKind::compaction(vec![message]),
        ] {
            kind.validate_compatibility_tag().unwrap();
            let encoded = serde_json::to_value(&kind).unwrap();
            assert!(matches!(
                serde_json::from_value::<LegacyKind>(encoded.clone()).unwrap(),
                LegacyKind::Unknown
            ));
            let current: EventKind = serde_json::from_value(encoded).unwrap();
            assert!(current.message_value().is_some() || current.compaction_value().is_some());
        }
        let ordinary = EventKind::message(Message::user_text("ordinary input"));
        let LegacyKind::Message { message } =
            serde_json::from_value(serde_json::to_value(ordinary).unwrap()).unwrap()
        else {
            panic!("ordinary tag changed")
        };
        assert_eq!(message.role, Role::User);
        assert!(
            matches!(message.content.as_slice(),[LegacyBlock::Text{text}] if text=="ordinary input")
        );
        let ordinary = EventKind::compaction(vec![Message::user_text("ordinary compacted input")]);
        let LegacyKind::Compaction { messages } =
            serde_json::from_value(serde_json::to_value(ordinary).unwrap()).unwrap()
        else {
            panic!("ordinary compaction changed")
        };
        assert_eq!(messages.len(), 1);
    }
}
