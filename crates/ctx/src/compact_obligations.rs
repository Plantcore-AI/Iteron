//! Honest accounting of operator obligations across lossy transcript compaction.

use core_protocol::{Block, Message, Role};

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CompactionObligations {
    preserved: u32,
    lost: u32,
}

impl CompactionObligations {
    pub(crate) fn gather(
        compacted: &[Message],
        task_anchor: &Message,
        keep_verbatim: &[Message],
    ) -> Self {
        // The compressor is intentionally lossy. An operator message that survives in the anchor
        // or recent tail is provably preserved byte-for-byte; one folded into a model summary is
        // not. Count the latter as lost even when the summary may paraphrase it, rather than claim
        // preservation that cannot be demonstrated from the durable transcript.
        let preserved = std::iter::once(task_anchor)
            .chain(keep_verbatim)
            .filter(|message| is_operator_obligation(message))
            .count();
        let lost = compacted
            .iter()
            .filter(|message| is_operator_obligation(message))
            .count();
        Self {
            preserved: u32::try_from(preserved).unwrap_or(u32::MAX),
            lost: u32::try_from(lost).unwrap_or(u32::MAX),
        }
    }

    pub(crate) fn preserved_count(self) -> u32 {
        self.preserved
    }

    pub(crate) fn lost_count(self) -> u32 {
        self.lost
    }
}

fn is_operator_obligation(message: &Message) -> bool {
    message.role == Role::User
        && message
            .content
            .iter()
            .any(|block| matches!(block, Block::Text { text } if !text.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_operator_messages_are_preserved_and_summarized_ones_are_lost() {
        let compacted = vec![
            Message::user_text("must keep this exact constraint"),
            Message {
                role: Role::Assistant,
                content: vec![Block::Text {
                    text: "assistant prose is not an operator obligation".into(),
                }],
            },
            Message::user_text("必须先完成生命周期"),
        ];
        let task = Message::user_text("original task");
        let retained = vec![Message::user_text("latest correction")];
        let obligations = CompactionObligations::gather(&compacted, &task, &retained);
        assert_eq!(obligations.preserved_count(), 2);
        assert_eq!(obligations.lost_count(), 2);
    }

    #[test]
    fn tool_results_and_empty_user_text_do_not_invent_obligations() {
        let compacted = vec![Message::user_text("   ")];
        let task = Message {
            role: Role::User,
            content: vec![],
        };
        let obligations = CompactionObligations::gather(&compacted, &task, &[]);
        assert_eq!(obligations.preserved_count(), 0);
        assert_eq!(obligations.lost_count(), 0);
    }
}
