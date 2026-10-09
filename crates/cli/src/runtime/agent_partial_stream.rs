//! Actual resident stream projection. A real physical WAL ticket supplies the source and the
//! mailbox supplies the exact task/epoch. Lost observer capacity never changes effect truth.
use super::persistent_agents::LiveAgentMailbox;
use crate::machine_projection::StreamingScrubber;
use iteron_protocol::agent_control::MAX_AGENT_TEXT_BYTES;
use iteron_protocol::agent_output::AgentOutputSourceV1;

pub(super) struct AgentPartialStream {
    mailbox: LiveAgentMailbox,
    source: AgentOutputSourceV1,
    scrubber: StreamingScrubber,
    served: usize,
    closed: bool,
}
impl AgentPartialStream {
    pub(super) fn new(mailbox: LiveAgentMailbox, source: AgentOutputSourceV1) -> Self {
        Self {
            mailbox,
            source,
            scrubber: StreamingScrubber::default(),
            served: 0,
            closed: false,
        }
    }
    pub(super) fn observe(&mut self, delta: &str) {
        // Bound each redactor append before allocating even if a provider emits one giant delta.
        let mut rest = delta;
        while !rest.is_empty() && !self.closed {
            let mut end = rest.len().min(MAX_AGENT_TEXT_BYTES);
            while !rest.is_char_boundary(end) {
                end -= 1;
            }
            if let Some(served) = self.scrubber.push(&rest[..end]) {
                self.publish(&served);
            }
            rest = &rest[end..];
        }
    }
    pub(super) fn finish(&mut self) {
        if !self.closed
            && let Some(served) = self.scrubber.finish()
        {
            self.publish(&served);
        }
    }
    fn publish(&mut self, served: &str) {
        if self.mailbox.publish_partial(&self.source, served).is_err() {
            self.closed = true;
        }
        self.served = self.served.saturating_add(served.len());
        // The shared owner retains at most this prefix and reports truncation on the actual
        // overflow append. It receives no raw text and is not a successful task receipt.
        if self.served > MAX_AGENT_TEXT_BYTES {
            self.closed = true;
        }
    }
}
