//! Read-only product projection of the resident App Server event stream.

use super::ServerEvent;
use crate::runtime::{ApprovalResolution, UiEvent};
use iteron_protocol::product_contract::{
    ApprovalResolutionV1, ItemContentChannelV1, ItemKindV1, ItemSnapshotV1, ItemStateV1,
    MAX_PRODUCT_APPROVAL_ARGUMENTS_BYTES, MAX_PRODUCT_APPROVAL_FIELD_BYTES,
    MAX_PRODUCT_CONTENT_CHUNK_BYTES, MAX_PRODUCT_EVENT_BYTES, MAX_PRODUCT_EVENTS,
    MAX_PRODUCT_READ_BYTES, MAX_PRODUCT_READ_EVENTS, MAX_PRODUCT_SOURCE_CONTENT_BYTES,
    MAX_THREAD_ITEMS, MAX_THREAD_SUBMISSIONS, PRODUCT_CONTRACT_VERSION, ProductEventGapV1,
    ProductEventKindV1, ProductEventV1, ProductEventsPageV1, ProductEventsReadErrorV1,
    ProductTerminalDiagnosticsV1, ProductTerminalV1, ProductTurnId, SubmissionReceiptV1,
    TerminalEvidenceV1, ThreadSnapshotV1, TurnSnapshotV1, TurnStateV1,
};
use iteron_protocol::{Outcome, RunId, SessionId, SubmissionId};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Keep PEM block context across UI deltas before the shared token scrubber sees a newline.
/// The scan buffer is bounded; an overlong candidate is suppressed through its END marker.
#[derive(Default)]
struct ProductStreamScrubber {
    token: crate::output::StreamingScrubber,
    scan: String,
    candidate: bool,
    in_private_key: bool,
}

impl ProductStreamScrubber {
    fn push(&mut self, delta: &str) -> Option<String> {
        self.scan.push_str(delta);
        let mut output = String::new();
        loop {
            if self.in_private_key {
                let Some(end) = self.scan.find('\n') else {
                    if self.scan.len() > MAX_PRODUCT_CONTENT_CHUNK_BYTES {
                        self.scan.clear();
                    }
                    break;
                };
                let line = self.scan.drain(..=end).collect::<String>();
                if line.contains("END") && line.contains("PRIVATE KEY") {
                    self.in_private_key = false;
                }
                continue;
            }
            if self.candidate {
                let Some(end) = self.scan.find('\n') else {
                    if self.scan.len() > MAX_PRODUCT_CONTENT_CHUNK_BYTES {
                        self.scan.clear();
                        self.token = Default::default();
                        self.candidate = false;
                        self.in_private_key = true;
                        output.push_str("[REDACTED PRIVATE KEY]\n");
                    }
                    break;
                };
                let line = self.scan.drain(..=end).collect::<String>();
                self.candidate = false;
                if line.contains("PRIVATE KEY") {
                    self.token = Default::default();
                    self.in_private_key = true;
                    output.push_str("[REDACTED PRIVATE KEY]\n");
                } else if let Some(safe) = self.token.push(&line) {
                    output.push_str(&safe);
                }
                continue;
            }
            if let Some(start) = self.scan.find("BEGIN") {
                let safe = self.scan.drain(..start).collect::<String>();
                if let Some(safe) = self.token.push(&safe) {
                    output.push_str(&safe);
                }
                self.candidate = true;
                continue;
            }
            let keep = (1.."BEGIN".len())
                .rev()
                .find(|count| self.scan.ends_with(&"BEGIN"[..*count]))
                .unwrap_or(0);
            let release = self.scan.len() - keep;
            let safe = self.scan.drain(..release).collect::<String>();
            if let Some(safe) = self.token.push(&safe) {
                output.push_str(&safe);
            }
            break;
        }
        (!output.is_empty()).then_some(output)
    }

    fn finish(&mut self) -> Option<String> {
        let mut output = String::new();
        if self.in_private_key {
            self.scan.clear();
            self.token = Default::default();
            self.candidate = false;
            self.in_private_key = false;
        } else if self.candidate && self.scan.contains("PRIVATE KEY") {
            self.scan.clear();
            self.token = Default::default();
            self.candidate = false;
            output.push_str("[REDACTED PRIVATE KEY]");
        } else {
            let remainder = std::mem::take(&mut self.scan);
            if let Some(safe) = self.token.push(&remainder) {
                output.push_str(&safe);
            }
            if let Some(safe) = self.token.finish() {
                output.push_str(&safe);
            }
            self.candidate = false;
        }
        (!output.is_empty()).then_some(output)
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct ContractReader(Arc<Mutex<Projection>>);

#[derive(Default)]
struct Projection {
    snapshot: Option<ThreadSnapshotV1>,
    tool_sources: Vec<(String, String)>,
    next_item: u32,
    events: VecDeque<ProductEventV1>,
    event_bytes: usize,
    next_event_seq: u64,
    latest_terminal: Option<ProductTerminalV1>,
    latest_terminal_diagnostics: Option<ProductTerminalDiagnosticsV1>,
    approval_prompt_complete: Option<(SubmissionId, bool)>,
    assistant_scrubber: ProductStreamScrubber,
    reasoning_scrubber: ProductStreamScrubber,
}

impl std::fmt::Debug for Projection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Projection")
            .field("event_count", &self.events.len())
            .field("event_bytes", &self.event_bytes)
            .field("next_event_seq", &self.next_event_seq)
            .finish_non_exhaustive()
    }
}

fn scrub_bounded(text: &str, max_bytes: usize) -> (String, bool) {
    let redacted = iteron_record::redact::scrub(text);
    if redacted.len() <= max_bytes {
        return (redacted, true);
    }
    let mut end = max_bytes;
    while !redacted.is_char_boundary(end) {
        end -= 1;
    }
    (redacted[..end].to_owned(), false)
}

fn scrub_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => {
            serde_json::Value::String(iteron_record::redact::scrub(text))
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(scrub_json).collect())
        }
        serde_json::Value::Object(fields) => serde_json::Value::Object(
            fields
                .iter()
                .map(|(key, value)| (iteron_record::redact::scrub(key), scrub_json(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

impl ContractReader {
    fn with_mut<R>(&self, action: impl FnOnce(&mut Projection) -> R) -> R {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        action(&mut guard)
    }

    pub(super) fn bind_identity(&self, thread_id: SessionId, run_id: RunId) {
        self.with_mut(|projection| {
            if projection
                .snapshot
                .as_ref()
                .is_some_and(|current| current.thread_id == thread_id && current.run_id == run_id)
            {
                return;
            }
            projection.snapshot = Some(ThreadSnapshotV1 {
                contract_version: PRODUCT_CONTRACT_VERSION,
                thread_id,
                run_id,
                source_event_seq: 0,
                turn: None,
                submissions: Vec::new(),
                evicted_submissions: 0,
            });
            projection.events.clear();
            projection.event_bytes = 0;
            projection.next_event_seq = 0;
            projection.latest_terminal = None;
            projection.latest_terminal_diagnostics = None;
            projection.approval_prompt_complete = None;
            projection.tool_sources.clear();
            projection.next_item = 0;
            projection.assistant_scrubber = Default::default();
            projection.reasoning_scrubber = Default::default();
        });
    }

    pub(super) fn begin_turn(
        &self,
        run_id: RunId,
        turn_id: ProductTurnId,
        submission_id: Option<SubmissionId>,
    ) {
        self.with_mut(|projection| {
            let Some(snapshot) = projection.snapshot.as_mut() else {
                return;
            };
            snapshot.run_id = run_id;
            snapshot.turn = Some(TurnSnapshotV1 {
                turn_id,
                submission_id,
                state: TurnStateV1::Running,
                items: Vec::new(),
                omitted_items: 0,
                pending_approval: None,
                terminal_reason_code: None,
                terminal_error: None,
            });
            projection.tool_sources.clear();
            projection.next_item = 0;
            projection.approval_prompt_complete = None;
            projection.assistant_scrubber = Default::default();
            projection.reasoning_scrubber = Default::default();
            projection.emit(
                None,
                Some(turn_id),
                None,
                ProductEventKindV1::TurnStarted { submission_id },
            );
        });
    }

    pub(super) fn rebind_run(&self, run_id: RunId) -> bool {
        self.with_mut(|projection| {
            if projection
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.turn.as_ref())
                .is_some_and(|turn| turn.state == TurnStateV1::Running)
            {
                return false;
            }
            if let Some(snapshot) = projection.snapshot.as_mut() {
                snapshot.run_id = run_id;
                snapshot.turn = None;
                snapshot.submissions.clear();
                snapshot.evicted_submissions = 0;
            }
            // Older events keep their explicit run IDs, while latest-terminal authority must
            // belong to the newly bound run.
            projection.latest_terminal = None;
            projection.latest_terminal_diagnostics = None;
            projection.tool_sources.clear();
            projection.next_item = 0;
            projection.approval_prompt_complete = None;
            projection.assistant_scrubber = Default::default();
            projection.reasoning_scrubber = Default::default();
            true
        })
    }

    pub(super) fn can_rebind_run(&self) -> bool {
        self.with_mut(|projection| {
            !projection
                .snapshot
                .as_ref()
                .and_then(|s| s.turn.as_ref())
                .is_some_and(|turn| turn.state == TurnStateV1::Running)
        })
    }

    #[cfg(test)]
    pub(super) fn observe(&self, seq: u64, event: &ServerEvent) {
        self.observe_with_spill(seq, event, None);
    }

    pub(super) fn observe_with_spill(
        &self,
        seq: u64,
        event: &ServerEvent,
        terminal_spill_bytes: Option<usize>,
    ) {
        self.with_mut(|projection| projection.observe(seq, event, terminal_spill_bytes));
    }

    pub(crate) fn snapshot(&self) -> Option<ThreadSnapshotV1> {
        self.with_mut(|projection| projection.snapshot.clone())
    }

    pub(crate) fn events_read(
        &self,
        after: u64,
    ) -> Option<Result<ProductEventsPageV1, ProductEventsReadErrorV1>> {
        self.with_mut(|projection| projection.events_read(after))
    }

    pub(crate) fn terminal_diagnostics(
        &self,
        turn_id: ProductTurnId,
    ) -> Option<ProductTerminalDiagnosticsV1> {
        self.with_mut(|projection| {
            let diagnostics = projection.latest_terminal_diagnostics.as_ref()?;
            let snapshot = projection.snapshot.as_ref()?;
            (diagnostics.turn_id == turn_id && diagnostics.run_id == snapshot.run_id)
                .then(|| diagnostics.clone())
        })
    }

    pub(crate) fn approval_prompt_complete(&self, approval_id: SubmissionId) -> bool {
        self.with_mut(|projection| projection.approval_prompt_complete == Some((approval_id, true)))
    }
}

impl Projection {
    fn emit(
        &mut self,
        source_event_seq: Option<u64>,
        turn_id: Option<ProductTurnId>,
        item_id: Option<String>,
        event: ProductEventKindV1,
    ) {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return;
        };
        self.next_event_seq = self
            .next_event_seq
            .checked_add(1)
            .expect("product event cursor exhausted");
        let charge = 512
            + item_id.as_ref().map_or(0, String::len)
            + match &event {
                ProductEventKindV1::ItemContent { content, .. } => content.len(),
                ProductEventKindV1::ItemStarted { title, .. } => {
                    title.as_ref().map_or(0, String::len)
                }
                ProductEventKindV1::TurnEnded { error, .. } => {
                    error.as_ref().map_or(0, String::len)
                }
                ProductEventKindV1::ApprovalRequested {
                    tool,
                    reason,
                    arguments_json,
                    workspace,
                    ..
                } => {
                    tool.len()
                        + reason.len()
                        + arguments_json.as_ref().map_or(0, String::len)
                        + workspace.len()
                }
                ProductEventKindV1::ApprovalResolved { reason_code, .. } => reason_code.len(),
                _ => 0,
            };
        self.events.push_back(ProductEventV1 {
            event_seq: self.next_event_seq,
            source_event_seq,
            thread_id: snapshot.thread_id.clone(),
            run_id: snapshot.run_id.clone(),
            turn_id,
            item_id,
            event,
        });
        self.event_bytes = self.event_bytes.saturating_add(charge);
        while self.events.len() > MAX_PRODUCT_EVENTS || self.event_bytes > MAX_PRODUCT_EVENT_BYTES {
            if let Some(evicted) = self.events.pop_front() {
                self.event_bytes = self
                    .event_bytes
                    .saturating_sub(Self::event_charge(&evicted));
            }
        }
    }

    fn event_charge(event: &ProductEventV1) -> usize {
        512 + event.item_id.as_ref().map_or(0, String::len)
            + match &event.event {
                ProductEventKindV1::ItemContent { content, .. } => content.len(),
                ProductEventKindV1::ItemStarted { title, .. } => {
                    title.as_ref().map_or(0, String::len)
                }
                ProductEventKindV1::TurnEnded { error, .. } => {
                    error.as_ref().map_or(0, String::len)
                }
                ProductEventKindV1::ApprovalRequested {
                    tool,
                    reason,
                    arguments_json,
                    workspace,
                    ..
                } => {
                    tool.len()
                        + reason.len()
                        + arguments_json.as_ref().map_or(0, String::len)
                        + workspace.len()
                }
                ProductEventKindV1::ApprovalResolved { reason_code, .. } => reason_code.len(),
                _ => 0,
            }
    }

    fn emit_content(
        &mut self,
        seq: u64,
        item_id: String,
        channel: ItemContentChannelV1,
        content: &str,
    ) -> bool {
        let turn_id = self
            .snapshot
            .as_ref()
            .and_then(|s| s.turn.as_ref())
            .map(|t| t.turn_id);
        // Match `output::stream_event`'s public boundary: scrub the complete source value before
        // any chunking, so a token crossing an 8 KiB product chunk is still recognized. Tool
        // inputs are recursively scrubbed before serialization at their call site below.
        let redacted = iteron_record::redact::scrub(content);
        let mut end = redacted.len().min(MAX_PRODUCT_SOURCE_CONTENT_BYTES);
        while !redacted.is_char_boundary(end) {
            end -= 1;
        }
        let omitted_redacted_bytes = redacted.len() - end;
        let mut remaining = &redacted[..end];
        while !remaining.is_empty() {
            let mut end = remaining.len().min(MAX_PRODUCT_CONTENT_CHUNK_BYTES);
            while !remaining.is_char_boundary(end) {
                end -= 1;
            }
            let (chunk, rest) = remaining.split_at(end);
            self.emit(
                Some(seq),
                turn_id,
                Some(item_id.clone()),
                ProductEventKindV1::ItemContent {
                    channel,
                    content: chunk.to_owned(),
                },
            );
            remaining = rest;
        }
        if omitted_redacted_bytes > 0 {
            self.emit(
                Some(seq),
                turn_id,
                Some(item_id),
                ProductEventKindV1::ContentOmitted {
                    channel,
                    omitted_redacted_bytes,
                },
            );
        }
        omitted_redacted_bytes == 0
    }

    fn events_read(
        &self,
        after: u64,
    ) -> Option<Result<ProductEventsPageV1, ProductEventsReadErrorV1>> {
        let snapshot = self.snapshot.as_ref()?;
        if after > self.next_event_seq {
            return Some(Err(ProductEventsReadErrorV1::CursorAhead {
                requested_after: after,
                latest_cursor: self.next_event_seq,
            }));
        }
        let oldest_available = self
            .events
            .front()
            .map_or(self.next_event_seq.saturating_add(1), |e| e.event_seq);
        let gap = (after < oldest_available.saturating_sub(1)).then_some(ProductEventGapV1 {
            requested_after: after,
            oldest_available,
        });
        let mut events = Vec::new();
        let mut bytes = 0;
        for event in self.events.iter().filter(|e| e.event_seq > after) {
            let charge = Self::event_charge(event);
            if events.len() >= MAX_PRODUCT_READ_EVENTS
                || (!events.is_empty() && bytes + charge > MAX_PRODUCT_READ_BYTES)
            {
                break;
            }
            bytes += charge;
            events.push(event.clone());
        }
        let next_cursor = events.last().map_or(after, |event| event.event_seq);
        Some(Ok(ProductEventsPageV1 {
            contract_version: PRODUCT_CONTRACT_VERSION,
            thread_id: snapshot.thread_id.clone(),
            requested_after: after,
            next_cursor,
            latest_cursor: self.next_event_seq,
            oldest_available,
            gap,
            events,
            latest_terminal: self.latest_terminal.clone(),
        }))
    }
    fn add_item(
        &mut self,
        seq: Option<u64>,
        kind: ItemKindV1,
        title: Option<String>,
    ) -> Option<String> {
        let turn = self.snapshot.as_mut()?.turn.as_mut()?;
        if turn.state != TurnStateV1::Running {
            return None;
        }
        if turn.items.len() >= MAX_THREAD_ITEMS {
            turn.omitted_items = turn.omitted_items.saturating_add(1);
            return None;
        }
        self.next_item = self.next_item.saturating_add(1);
        let id = format!("item-{}", self.next_item);
        turn.items.push(ItemSnapshotV1 {
            item_id: id.clone(),
            kind,
            state: ItemStateV1::InProgress,
            title: title.clone(),
        });
        let turn_id = turn.turn_id;
        self.emit(
            seq,
            Some(turn_id),
            Some(id.clone()),
            ProductEventKindV1::ItemStarted { kind, title },
        );
        Some(id)
    }

    fn ensure_item(&mut self, seq: u64, kind: ItemKindV1) -> Option<String> {
        if let Some(item_id) = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.turn.as_ref())
            .and_then(|turn| {
                turn.items
                    .iter()
                    .find(|item| item.kind == kind && item.state == ItemStateV1::InProgress)
                    .map(|item| item.item_id.clone())
            })
        {
            return Some(item_id);
        }
        self.add_item(Some(seq), kind, None)
    }

    fn finish_stream_items(&mut self, state: ItemStateV1, seq: u64) {
        let mut ended = Vec::new();
        if let Some(turn) = self
            .snapshot
            .as_mut()
            .and_then(|snapshot| snapshot.turn.as_mut())
        {
            for item in &mut turn.items {
                if matches!(
                    item.kind,
                    ItemKindV1::AssistantMessage | ItemKindV1::Reasoning
                ) && item.state == ItemStateV1::InProgress
                {
                    item.state = state;
                    ended.push((turn.turn_id, item.item_id.clone()));
                }
            }
        }
        for (turn_id, item_id) in ended {
            self.emit(
                Some(seq),
                Some(turn_id),
                Some(item_id),
                ProductEventKindV1::ItemEnded { state },
            );
        }
    }

    fn flush_streams(&mut self, seq: u64) {
        if let Some(content) = self.assistant_scrubber.finish()
            && let Some(item_id) = self.ensure_item(seq, ItemKindV1::AssistantMessage)
        {
            self.emit_content(seq, item_id, ItemContentChannelV1::Assistant, &content);
        }
        if let Some(content) = self.reasoning_scrubber.finish()
            && let Some(item_id) = self.ensure_item(seq, ItemKindV1::Reasoning)
        {
            self.emit_content(seq, item_id, ItemContentChannelV1::Reasoning, &content);
        }
    }

    fn observe(&mut self, seq: u64, event: &ServerEvent, terminal_spill_bytes: Option<usize>) {
        let Some(snapshot) = self.snapshot.as_mut() else {
            return;
        };
        snapshot.source_event_seq = seq;
        match event {
            ServerEvent::Submission {
                id,
                state,
                reason_code,
            } => {
                if id.0 == 0 {
                    return;
                }
                let receipt = SubmissionReceiptV1 {
                    submission_id: *id,
                    state: *state,
                    reason_code: reason_code.map(str::to_owned),
                };
                if let Some(existing) = snapshot
                    .submissions
                    .iter_mut()
                    .find(|existing| existing.submission_id == *id)
                {
                    *existing = receipt.clone();
                } else {
                    if snapshot.submissions.len() >= MAX_THREAD_SUBMISSIONS {
                        snapshot.submissions.remove(0);
                        snapshot.evicted_submissions =
                            snapshot.evicted_submissions.saturating_add(1);
                    }
                    snapshot.submissions.push(receipt.clone());
                }
                let turn_id = snapshot.turn.as_ref().map(|turn| turn.turn_id);
                self.emit(
                    Some(seq),
                    turn_id,
                    None,
                    ProductEventKindV1::Submission { receipt },
                );
            }
            ServerEvent::Ui(UiEvent::Text(content)) => {
                if let Some(item_id) = self.ensure_item(seq, ItemKindV1::AssistantMessage)
                    && let Some(redacted) = self.assistant_scrubber.push(content)
                {
                    self.emit_content(seq, item_id, ItemContentChannelV1::Assistant, &redacted);
                }
            }
            ServerEvent::Ui(UiEvent::Thinking(content)) => {
                if let Some(item_id) = self.ensure_item(seq, ItemKindV1::Reasoning)
                    && let Some(redacted) = self.reasoning_scrubber.push(content)
                {
                    self.emit_content(seq, item_id, ItemContentChannelV1::Reasoning, &redacted);
                }
            }
            ServerEvent::Ui(UiEvent::ToolStart { id, name, args }) => {
                self.flush_streams(seq);
                if self.tool_sources.iter().any(|(source, _)| source == id) {
                    return;
                }
                if id.len() > 256 {
                    if let Some(turn) = self.snapshot.as_mut().and_then(|s| s.turn.as_mut()) {
                        turn.omitted_items = turn.omitted_items.saturating_add(1);
                    }
                    return;
                }
                if let Some(item_id) = self.add_item(
                    Some(seq),
                    ItemKindV1::ToolCall,
                    Some(
                        iteron_record::redact::scrub(name)
                            .chars()
                            .take(128)
                            .collect(),
                    ),
                ) {
                    self.tool_sources.push((id.clone(), item_id.clone()));
                    if let Ok(input) = serde_json::to_string(&scrub_json(args)) {
                        self.emit_content(
                            seq,
                            item_id,
                            ItemContentChannelV1::ToolInputJson,
                            &input,
                        );
                    }
                }
                if let Some(turn) = self.snapshot.as_mut().and_then(|s| s.turn.as_mut()) {
                    turn.pending_approval = None;
                }
                self.approval_prompt_complete = None;
            }
            ServerEvent::Ui(UiEvent::ToolEnd { id, ok, output, .. }) => {
                if let Some((_, item_id)) =
                    self.tool_sources.iter().rfind(|(source, _)| source == id)
                {
                    let item_id = item_id.clone();
                    if !self
                        .snapshot
                        .as_ref()
                        .and_then(|s| s.turn.as_ref())
                        .is_some_and(|turn| {
                            turn.items.iter().any(|item| {
                                item.item_id == item_id && item.state == ItemStateV1::InProgress
                            })
                        })
                    {
                        return;
                    }
                    self.emit_content(
                        seq,
                        item_id.clone(),
                        ItemContentChannelV1::ToolOutput,
                        output,
                    );
                    if let Some(turn) = self.snapshot.as_mut().and_then(|s| s.turn.as_mut())
                        && let Some(item) =
                            turn.items.iter_mut().find(|item| item.item_id == item_id)
                    {
                        item.state = if *ok {
                            ItemStateV1::Completed
                        } else {
                            ItemStateV1::Failed
                        };
                        let state = item.state;
                        let turn_id = turn.turn_id;
                        self.emit(
                            Some(seq),
                            Some(turn_id),
                            Some(item_id),
                            ProductEventKindV1::ItemEnded { state },
                        );
                    }
                }
            }
            ServerEvent::Lagged { dropped } => {
                // A missing delta could complete a credential token. Discard held fragments;
                // the explicit source gap tells clients the item content is incomplete.
                self.assistant_scrubber = Default::default();
                self.reasoning_scrubber = Default::default();
                let turn_id = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| s.turn.as_ref())
                    .map(|t| t.turn_id);
                self.emit(
                    Some(seq),
                    turn_id,
                    None,
                    ProductEventKindV1::SourceGap { dropped: *dropped },
                );
            }
            ServerEvent::Ui(UiEvent::ApprovalRequest {
                id,
                tool,
                capability,
                reason,
                arguments,
                workspace,
            }) => {
                let Some(turn) = self.snapshot.as_mut().and_then(|s| s.turn.as_mut()) else {
                    return;
                };
                if turn.state != TurnStateV1::Running {
                    return;
                }
                turn.pending_approval = Some(*id);
                let turn_id = turn.turn_id;
                let (tool, tool_complete) = scrub_bounded(tool, MAX_PRODUCT_APPROVAL_FIELD_BYTES);
                let (reason, reason_complete) =
                    scrub_bounded(reason, MAX_PRODUCT_APPROVAL_FIELD_BYTES);
                let (workspace, workspace_complete) =
                    scrub_bounded(workspace, MAX_PRODUCT_APPROVAL_FIELD_BYTES);
                let upstream_complete = arguments
                    .get("_truncated_for_ui")
                    .and_then(serde_json::Value::as_bool)
                    != Some(true);
                let arguments_json = serde_json::to_string(&scrub_json(arguments))
                    .ok()
                    .map(|json| iteron_record::redact::scrub(&json))
                    .filter(|json| serde_json::from_str::<serde_json::Value>(json).is_ok());
                let arguments_complete = arguments_json
                    .as_ref()
                    .is_some_and(|value| value.len() <= MAX_PRODUCT_APPROVAL_ARGUMENTS_BYTES)
                    && upstream_complete;
                let arguments_json = arguments_json
                    .filter(|value| value.len() <= MAX_PRODUCT_APPROVAL_ARGUMENTS_BYTES);
                let prompt_complete =
                    tool_complete && reason_complete && workspace_complete && arguments_complete;
                self.approval_prompt_complete = Some((*id, prompt_complete));
                self.emit(
                    Some(seq),
                    Some(turn_id),
                    None,
                    ProductEventKindV1::ApprovalRequested {
                        approval_id: *id,
                        tool,
                        capability: *capability,
                        reason,
                        arguments_json,
                        workspace,
                        prompt_complete,
                    },
                );
            }
            ServerEvent::Ui(UiEvent::ApprovalResolved {
                id,
                resolution,
                reason_code,
                ..
            }) => {
                let Some(turn) = self.snapshot.as_mut().and_then(|s| s.turn.as_mut()) else {
                    return;
                };
                if turn.state != TurnStateV1::Running {
                    return;
                }
                if turn.pending_approval == Some(*id) {
                    turn.pending_approval = None;
                }
                let turn_id = turn.turn_id;
                if self
                    .approval_prompt_complete
                    .is_some_and(|(pending, _)| pending == *id)
                {
                    self.approval_prompt_complete = None;
                }
                let resolution = match resolution {
                    ApprovalResolution::Approved => ApprovalResolutionV1::Approved,
                    ApprovalResolution::Denied => ApprovalResolutionV1::Denied,
                    ApprovalResolution::Cancelled => ApprovalResolutionV1::Cancelled,
                    ApprovalResolution::TimedOut => ApprovalResolutionV1::TimedOut,
                };
                let (reason_code, _) = scrub_bounded(reason_code, MAX_PRODUCT_APPROVAL_FIELD_BYTES);
                self.emit(
                    Some(seq),
                    Some(turn_id),
                    None,
                    ProductEventKindV1::ApprovalResolved {
                        approval_id: *id,
                        resolution,
                        reason_code,
                    },
                );
            }
            ServerEvent::RunEnded { summary, .. } => {
                if self
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.turn.as_ref())
                    .is_some_and(|turn| turn.state != TurnStateV1::Running)
                {
                    return;
                }
                self.flush_streams(seq);
                let outcome = summary.terminal.outcome();
                // `RunEnded` repairs cosmetic stream loss for the legacy EQ. Publish its exact
                // final assistant text as a separate replacement channel before item closure.
                // A spilled or oversized terminal is explicitly non-exact in this bounded view.
                let terminal_text_exact = if terminal_spill_bytes.is_some() {
                    let turn_id = self
                        .snapshot
                        .as_ref()
                        .and_then(|s| s.turn.as_ref())
                        .map(|t| t.turn_id);
                    self.emit(
                        Some(seq),
                        turn_id,
                        None,
                        ProductEventKindV1::TerminalTextUnavailable {
                            reason_code: "eq_terminal_spill".into(),
                        },
                    );
                    false
                } else if let Some(item_id) = self.ensure_item(seq, ItemKindV1::AssistantMessage) {
                    if summary.assistant_text.is_empty() {
                        let turn_id = self
                            .snapshot
                            .as_ref()
                            .and_then(|s| s.turn.as_ref())
                            .map(|t| t.turn_id);
                        self.emit(
                            Some(seq),
                            turn_id,
                            Some(item_id),
                            ProductEventKindV1::ItemContent {
                                channel: ItemContentChannelV1::FinalAnswer,
                                content: String::new(),
                            },
                        );
                        true
                    } else {
                        self.emit_content(
                            seq,
                            item_id,
                            ItemContentChannelV1::FinalAnswer,
                            &summary.assistant_text,
                        )
                    }
                } else {
                    false
                };
                self.finish_stream_items(
                    if matches!(outcome, Outcome::Done) {
                        ItemStateV1::Completed
                    } else {
                        ItemStateV1::Failed
                    },
                    seq,
                );
                if let Some(snapshot) = self.snapshot.as_mut() {
                    snapshot.run_id = RunId(summary.run_id.clone());
                    if let Some(turn) = snapshot.turn.as_mut() {
                        if turn.state != TurnStateV1::Running {
                            return;
                        }
                        turn.pending_approval = None;
                        self.approval_prompt_complete = None;
                        turn.terminal_reason_code = match outcome {
                            Outcome::BudgetExhausted(reason) => Some(reason.to_owned()),
                            _ => None,
                        };
                        turn.terminal_error = summary.error.as_ref().map(|error| {
                            iteron_record::redact::scrub(error)
                                .chars()
                                .take(4096)
                                .collect()
                        });
                        turn.state = match outcome {
                            Outcome::Done => TurnStateV1::Completed,
                            Outcome::Interrupted => TurnStateV1::Interrupted,
                            Outcome::Drained => TurnStateV1::Drained,
                            Outcome::BudgetExhausted(_) => TurnStateV1::BudgetExhausted,
                            Outcome::Stuck => TurnStateV1::Stuck,
                            _ => TurnStateV1::Failed,
                        };
                        let mut unfinished = Vec::new();
                        for item in &mut turn.items {
                            if item.state == ItemStateV1::InProgress {
                                item.state = ItemStateV1::Failed;
                                unfinished.push(item.item_id.clone());
                            }
                        }
                        let terminal = ProductTerminalV1 {
                            event_seq: 0,
                            thread_id: snapshot.thread_id.clone(),
                            run_id: snapshot.run_id.clone(),
                            turn_id: turn.turn_id,
                            state: turn.state,
                            reason_code: turn.terminal_reason_code.clone(),
                            error: turn.terminal_error.clone(),
                            terminal_text_exact,
                        };
                        for item_id in unfinished {
                            self.emit(
                                Some(seq),
                                Some(terminal.turn_id),
                                Some(item_id),
                                ProductEventKindV1::ItemEnded {
                                    state: ItemStateV1::Failed,
                                },
                            );
                        }
                        self.emit(
                            Some(seq),
                            Some(terminal.turn_id),
                            None,
                            ProductEventKindV1::TurnEnded {
                                state: terminal.state,
                                reason_code: terminal.reason_code.clone(),
                                error: terminal.error.clone(),
                                terminal_text_exact,
                            },
                        );
                        self.latest_terminal_diagnostics = Some(ProductTerminalDiagnosticsV1 {
                            contract_version: PRODUCT_CONTRACT_VERSION,
                            thread_id: terminal.thread_id.clone(),
                            run_id: terminal.run_id.clone(),
                            turn_id: terminal.turn_id,
                            terminal_event_seq: self.next_event_seq,
                            evidence: summary
                                .terminal_evidence
                                .unwrap_or_else(TerminalEvidenceV1::unavailable),
                        });
                        self.latest_terminal = Some(ProductTerminalV1 {
                            event_seq: self.next_event_seq,
                            ..terminal
                        });
                    }
                }
            }
            ServerEvent::Ui(UiEvent::TurnEnd { .. } | UiEvent::Done(_)) => self.flush_streams(seq),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal_event(outcome: Outcome, error: Option<&str>) -> ServerEvent {
        ServerEvent::RunEnded {
            snapshot: Box::new(super::super::SessionSnapshot {
                mode: iteron_protocol::PermissionMode::default(),
                effort: iteron_protocol::Effort::default(),
                model: "test-model".into(),
                provider_id: "test-provider".into(),
                cost: iteron_obs::CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                unadmitted_internal_notifications: Vec::new(),
                unadmitted_client_steers: 0,
                unadmitted_steer_submission_ids: Vec::new(),
                permission_rules: iteron_protocol::PermissionRules::new(),
                runtime_policy: None,
                ledger_summary: String::new(),
                rate_limit: None,
                mcp_health: Vec::new(),
            }),
            summary: Box::new(super::super::TerminalSummary {
                terminal: super::super::TerminalAuthority::Runtime(outcome),
                assistant_text: String::new(),
                v7_assistant_text: None,
                run_id: "r".into(),
                cost: iteron_obs::CostState::Zero,
                turns: 1,
                kernel_tax: iteron_obs::KernelTax::default(),
                error: error.map(str::to_owned),
                memo_hits: 0,
                memo_misses: 0,
                terminal_evidence: None,
            }),
        }
    }

    #[test]
    fn one_turn_projects_assistant_tool_and_terminal_state() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(4), Some(SubmissionId(8)));
        reader.observe(1, &ServerEvent::Ui(UiEvent::Text("hello".into())));
        reader.observe(
            2,
            &ServerEvent::Ui(UiEvent::ToolStart {
                id: "provider-id".into(),
                name: "shell".into(),
                args: serde_json::Value::Null,
            }),
        );
        reader.observe(
            3,
            &ServerEvent::Ui(UiEvent::ToolEnd {
                id: "provider-id".into(),
                ok: true,
                exit_code: Some(0),
                output: String::new(),
                diff: None,
            }),
        );
        let snapshot = reader.snapshot().unwrap();
        let turn = snapshot.turn.unwrap();
        assert_eq!(turn.turn_id, ProductTurnId(4));
        assert_eq!(turn.items.len(), 2);
        assert_eq!(turn.items[0].item_id, "item-1");
        assert_eq!(turn.items[1].item_id, "item-2");
        assert_eq!(turn.items[1].state, ItemStateV1::Completed);
        assert_eq!(snapshot.source_event_seq, 3);
    }

    #[test]
    fn submission_receipt_updates_by_id_without_claiming_early_application() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.observe(
            1,
            &ServerEvent::Submission {
                id: SubmissionId(7),
                state: iteron_protocol::SubmissionLifecycleState::Received,
                reason_code: None,
            },
        );
        let received = reader.snapshot().unwrap();
        assert_eq!(received.submissions.len(), 1);
        assert_eq!(
            received.submissions[0].state,
            iteron_protocol::SubmissionLifecycleState::Received
        );
        reader.observe(
            2,
            &ServerEvent::Submission {
                id: SubmissionId(7),
                state: iteron_protocol::SubmissionLifecycleState::Applied,
                reason_code: None,
            },
        );
        let applied = reader.snapshot().unwrap();
        assert_eq!(applied.submissions.len(), 1);
        assert_eq!(
            applied.submissions[0].state,
            iteron_protocol::SubmissionLifecycleState::Applied
        );
    }

    #[test]
    fn provider_failure_has_one_visible_terminal_and_cannot_be_rewritten() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), Some(SubmissionId(2)));
        reader.observe(1, &ServerEvent::Ui(UiEvent::Text("partial".into())));
        reader.observe(
            2,
            &ServerEvent::Ui(UiEvent::Done("provider disconnected".into())),
        );
        reader.observe(
            3,
            &terminal_event(Outcome::HarnessError, Some("provider disconnected")),
        );
        reader.observe(4, &terminal_event(Outcome::Done, None));
        let turn = reader.snapshot().unwrap().turn.unwrap();
        assert_eq!(turn.state, TurnStateV1::Failed);
        assert_eq!(
            turn.terminal_error.as_deref(),
            Some("provider disconnected")
        );
        assert_eq!(turn.items[0].state, ItemStateV1::Failed);
        assert_eq!(
            reader
                .terminal_diagnostics(ProductTurnId(1))
                .unwrap()
                .evidence,
            TerminalEvidenceV1::unavailable(),
            "a legacy terminal cannot be upgraded from its error text"
        );
    }

    #[test]
    fn typed_provider_terminal_evidence_survives_reconnect_and_event_gap() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        reader.observe(1, &ServerEvent::Ui(UiEvent::Text("partial answer ".into())));
        let mut failed = terminal_event(Outcome::HarnessError, Some("provider disconnected"));
        let ServerEvent::RunEnded { summary, .. } = &mut failed else {
            unreachable!()
        };
        summary.terminal_evidence = Some(TerminalEvidenceV1 {
            failure_code: Some(iteron_protocol::PolicyHarnessErrorCode::ProviderError),
            effect_state: iteron_protocol::product_contract::TerminalEffectStateV1::Unknown,
        });
        reader.observe(2, &failed);
        let reconnect = reader.clone();
        let diagnostics = reconnect.terminal_diagnostics(ProductTurnId(1)).unwrap();
        assert_eq!(
            diagnostics.terminal_event_seq,
            reader
                .events_read(0)
                .unwrap()
                .unwrap()
                .latest_terminal
                .unwrap()
                .event_seq
        );
        assert_eq!(
            diagnostics.evidence.effect_state,
            iteron_protocol::product_contract::TerminalEffectStateV1::Unknown
        );
        assert_eq!(
            reader.snapshot().unwrap().turn.unwrap().items[0].state,
            ItemStateV1::Failed
        );
        reader.with_mut(|projection| {
            for _ in 0..=MAX_PRODUCT_EVENTS {
                projection.emit(
                    Some(3),
                    Some(ProductTurnId(1)),
                    None,
                    ProductEventKindV1::SourceGap { dropped: 1 },
                );
            }
        });
        let page = reconnect.events_read(0).unwrap().unwrap();
        assert!(page.gap.is_some());
        assert_eq!(page.latest_terminal.unwrap().state, TurnStateV1::Failed);
        assert_eq!(
            reconnect.terminal_diagnostics(ProductTurnId(1)),
            Some(diagnostics)
        );
        assert!(reconnect.terminal_diagnostics(ProductTurnId(2)).is_none());
    }

    #[test]
    fn same_thread_run_rebind_drops_old_terminal_diagnostics() {
        let reader = ContractReader::default();
        let thread_id = SessionId("same-thread".into());
        let first_run = RunId("first-run".into());
        let second_run = RunId("second-run".into());
        reader.bind_identity(thread_id, first_run.clone());
        reader.begin_turn(first_run.clone(), ProductTurnId(1), None);
        let mut failed = terminal_event(Outcome::HarnessError, Some("old provider error"));
        let ServerEvent::RunEnded { summary, .. } = &mut failed else {
            unreachable!()
        };
        summary.run_id = first_run.0.clone();
        summary.terminal_evidence = Some(TerminalEvidenceV1 {
            failure_code: Some(iteron_protocol::PolicyHarnessErrorCode::ProviderError),
            effect_state: iteron_protocol::product_contract::TerminalEffectStateV1::Unknown,
        });
        reader.observe(1, &failed);
        assert_eq!(
            reader
                .terminal_diagnostics(ProductTurnId(1))
                .unwrap()
                .run_id,
            first_run
        );

        assert!(reader.rebind_run(second_run.clone()));
        assert_eq!(reader.snapshot().unwrap().run_id, second_run);
        assert!(reader.terminal_diagnostics(ProductTurnId(1)).is_none());
        let page = reader.events_read(0).unwrap().unwrap();
        assert!(page.latest_terminal.is_none());
        assert!(page.events.iter().any(|event| event.run_id == first_run));

        reader.begin_turn(second_run.clone(), ProductTurnId(2), None);
        let mut done = terminal_event(Outcome::Done, None);
        let ServerEvent::RunEnded { summary, .. } = &mut done else {
            unreachable!()
        };
        summary.run_id = second_run.0.clone();
        summary.terminal_evidence = Some(TerminalEvidenceV1 {
            failure_code: None,
            effect_state: iteron_protocol::product_contract::TerminalEffectStateV1::NotDispatched,
        });
        reader.observe(2, &done);
        assert!(reader.terminal_diagnostics(ProductTurnId(1)).is_none());
        assert_eq!(
            reader
                .terminal_diagnostics(ProductTurnId(2))
                .unwrap()
                .run_id,
            second_run
        );
    }

    #[test]
    fn successful_terminal_completes_streamed_answer_exactly_once() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), Some(SubmissionId(2)));
        reader.observe(1, &ServerEvent::Ui(UiEvent::Text("answer".into())));
        reader.observe(2, &terminal_event(Outcome::Done, None));
        reader.observe(
            3,
            &terminal_event(Outcome::HarnessError, Some("late failure")),
        );
        let turn = reader.snapshot().unwrap().turn.unwrap();
        assert_eq!(turn.state, TurnStateV1::Completed);
        assert_eq!(turn.items[0].state, ItemStateV1::Completed);
        assert!(turn.terminal_error.is_none());
    }

    #[test]
    fn non_successful_turns_keep_partial_items_non_complete() {
        for (outcome, state) in [
            (Outcome::Interrupted, TurnStateV1::Interrupted),
            (Outcome::Drained, TurnStateV1::Drained),
            (
                Outcome::BudgetExhausted("max_turns"),
                TurnStateV1::BudgetExhausted,
            ),
            (Outcome::Stuck, TurnStateV1::Stuck),
        ] {
            let reader = ContractReader::default();
            reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
            reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
            reader.observe(1, &ServerEvent::Ui(UiEvent::Text("partial".into())));
            reader.observe(2, &terminal_event(outcome, None));
            let turn = reader.snapshot().unwrap().turn.unwrap();
            assert_eq!(turn.state, state);
            assert_eq!(turn.items[0].state, ItemStateV1::Failed);
        }
    }

    #[test]
    fn product_cursor_is_contiguous_even_when_eq_has_ignored_sequence_numbers() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), Some(SubmissionId(3)));
        reader.observe(10, &ServerEvent::Notice("not projected".into()));
        reader.observe(27, &ServerEvent::Ui(UiEvent::Text("Hello 世界 ".into())));
        let page = reader.events_read(0).unwrap().unwrap();
        assert!(page.gap.is_none());
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.event_seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(page.events[0].source_event_seq, None);
        assert_eq!(page.events[1].source_event_seq, Some(27));
        assert_eq!(page.events[2].source_event_seq, Some(27));
        assert_eq!(page.events[2].turn_id, Some(ProductTurnId(1)));
        assert_eq!(page.events[2].item_id.as_deref(), Some("item-1"));
        assert!(
            matches!(&page.events[2].event, ProductEventKindV1::ItemContent {
            channel: ItemContentChannelV1::Assistant, content
        } if content == "Hello 世界 ")
        );
    }

    #[test]
    fn bounded_content_gap_retains_latest_failed_terminal_for_reconnect() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        for seq in 1..=(MAX_PRODUCT_EVENTS as u64 + 2) {
            reader.observe(seq, &ServerEvent::Ui(UiEvent::Text("x ".into())));
        }
        reader.observe(
            900,
            &terminal_event(Outcome::HarnessError, Some("provider disconnected")),
        );
        let page = reader.events_read(0).unwrap().unwrap();
        assert!(page.gap.is_some());
        assert!(page.oldest_available > 1);
        assert_eq!(
            page.events.first().unwrap().event_seq,
            page.oldest_available
        );
        let terminal = page.latest_terminal.unwrap();
        assert_eq!(terminal.state, TurnStateV1::Failed);
        assert_eq!(terminal.error.as_deref(), Some("provider disconnected"));
        assert_eq!(terminal.turn_id, ProductTurnId(1));
        let tail = reader.events_read(page.latest_cursor - 2).unwrap().unwrap();
        assert!(tail.gap.is_none());
        assert_eq!(tail.events.last().unwrap().event_seq, terminal.event_seq);
        assert!(matches!(&tail.events.last().unwrap().event,
            ProductEventKindV1::TurnEnded { state: TurnStateV1::Failed, error: Some(error), .. }
            if error == "provider disconnected"));
    }

    #[test]
    fn adoption_rebind_rejects_live_turn_without_changing_identity() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        assert!(!reader.can_rebind_run());
        assert!(!reader.rebind_run(RunId("other".into())));
        assert_eq!(reader.snapshot().unwrap().run_id.0, "r");
        reader.observe(1, &terminal_event(Outcome::Done, None));
        assert!(reader.can_rebind_run());
        assert!(reader.rebind_run(RunId("other".into())));
        assert_eq!(reader.snapshot().unwrap().run_id.0, "other");
        assert!(
            reader
                .events_read(0)
                .unwrap()
                .unwrap()
                .latest_terminal
                .is_none()
        );
    }

    #[test]
    fn product_ring_scrubs_assistant_tool_arguments_and_output_before_storage() {
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        reader.observe(
            1,
            &ServerEvent::Ui(UiEvent::Text(format!("{} {secret} safe", "x".repeat(8190)))),
        );
        reader.observe(
            2,
            &ServerEvent::Ui(UiEvent::ToolStart {
                id: "provider-id".into(),
                name: format!("tool {secret}"),
                args: serde_json::json!({"nested": [{"token": secret}]}),
            }),
        );
        reader.observe(
            3,
            &ServerEvent::Ui(UiEvent::ToolEnd {
                id: "provider-id".into(),
                ok: false,
                exit_code: Some(1),
                output: format!("error {secret}"),
                diff: None,
            }),
        );
        let stored =
            reader.with_mut(|projection| serde_json::to_string(&projection.events).unwrap());
        assert!(
            !stored.contains(secret),
            "raw canary reached the product event ring"
        );
        assert!(stored.contains("[REDACTED"));
        let public = serde_json::to_string(&reader.events_read(0).unwrap()).unwrap();
        assert!(!public.contains(secret));
        assert!(public.contains("tool_input_json"));
        assert!(public.contains("tool_output"));
    }

    #[test]
    fn approval_arguments_scrub_secret_keys_and_refuse_upstream_truncation() {
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        let mut nested = serde_json::Map::new();
        nested.insert(secret.into(), serde_json::json!("ordinary value"));
        reader.observe(
            1,
            &ServerEvent::Ui(UiEvent::ApprovalRequest {
                id: SubmissionId(7),
                tool: "shell".into(),
                capability: iteron_protocol::Capability::CodeExecuting,
                reason: "run command".into(),
                arguments: serde_json::json!({"nested": nested}),
                workspace: "/fixture".into(),
            }),
        );
        assert!(reader.approval_prompt_complete(SubmissionId(7)));
        let reconnect = reader.clone();
        let stored =
            reader.with_mut(|projection| serde_json::to_string(&projection.events).unwrap());
        let public = serde_json::to_string(&reconnect.events_read(0).unwrap()).unwrap();
        assert!(!stored.contains(secret));
        assert!(!public.contains(secret));
        reader.observe(
            2,
            &ServerEvent::Ui(UiEvent::ApprovalRequest {
                id: SubmissionId(8),
                tool: "shell".into(),
                capability: iteron_protocol::Capability::CodeExecuting,
                reason: "run command".into(),
                arguments: serde_json::json!({"command": "redacted upstream", "_truncated_for_ui": true}),
                workspace: "/fixture".into(),
            }),
        );
        assert!(!reader.approval_prompt_complete(SubmissionId(8)));
        assert!(
            reader
                .events_read(0)
                .unwrap()
                .unwrap()
                .events
                .iter()
                .any(|event| {
                    matches!(
                        &event.event,
                        ProductEventKindV1::ApprovalRequested {
                            approval_id: SubmissionId(8),
                            prompt_complete: false,
                            ..
                        }
                    )
                })
        );
    }

    #[test]
    fn oversized_redacted_source_reports_omitted_content() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        reader.observe(
            1,
            &ServerEvent::Ui(UiEvent::ToolStart {
                id: "tool".into(),
                name: "shell".into(),
                args: serde_json::Value::Null,
            }),
        );
        reader.observe(
            2,
            &ServerEvent::Ui(UiEvent::ToolEnd {
                id: "tool".into(),
                ok: false,
                exit_code: Some(1),
                output: "x".repeat(MAX_PRODUCT_SOURCE_CONTENT_BYTES + 100),
                diff: None,
            }),
        );
        let mut cursor = 0;
        let mut captured = 0;
        let mut omitted = false;
        loop {
            let page = reader.events_read(cursor).unwrap().unwrap();
            for event in &page.events {
                match &event.event {
                    ProductEventKindV1::ItemContent {
                        channel: ItemContentChannelV1::ToolOutput,
                        content,
                    } => captured += content.len(),
                    ProductEventKindV1::ContentOmitted {
                        omitted_redacted_bytes: 100,
                        ..
                    } => omitted = true,
                    _ => {}
                }
            }
            assert!(page.next_cursor > cursor);
            cursor = page.next_cursor;
            if cursor == page.latest_cursor {
                break;
            }
        }
        assert!(captured <= MAX_PRODUCT_SOURCE_CONTENT_BYTES);
        assert!(omitted);
    }

    #[test]
    fn split_secret_is_scrubbed_across_deltas_and_reconnect_cursor() {
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        reader.observe(1, &ServerEvent::Ui(UiEvent::Text("safe sk-an".into())));
        let before = reader.events_read(0).unwrap().unwrap();
        assert_eq!(
            before.events.last().unwrap().item_id.as_deref(),
            Some("item-1")
        );
        let cursor = before.next_cursor;
        assert!(!serde_json::to_string(&before).unwrap().contains("sk-an"));
        reader.observe(
            2,
            &ServerEvent::Ui(UiEvent::Text(
                "t-api03-AbCdEfGhIjKlMnOpQrStUvWx tail ".into(),
            )),
        );
        reader.observe(3, &ServerEvent::Ui(UiEvent::Thinking("sk-an".into())));
        reader.observe(
            4,
            &ServerEvent::Ui(UiEvent::Thinking(
                "t-api03-AbCdEfGhIjKlMnOpQrStUvWx ".into(),
            )),
        );
        let reconnected = reader.clone();
        let after = reconnected.events_read(cursor).unwrap().unwrap();
        assert!(after.gap.is_none());
        let public = serde_json::to_string(&after).unwrap();
        assert!(!public.contains(secret));
        assert!(!public.contains("sk-an"));
        assert!(public.contains("[REDACTED"));
        assert!(
            after
                .events
                .iter()
                .any(|event| event.item_id.as_deref() == Some("item-1"))
        );
        assert!(
            after
                .events
                .iter()
                .any(|event| event.item_id.as_deref() == Some("item-2"))
        );
        let stored =
            reader.with_mut(|projection| serde_json::to_string(&projection.events).unwrap());
        assert!(!stored.contains(secret));
    }

    #[test]
    fn split_url_userinfo_is_scrubbed_in_ring_and_after_reconnect() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        reader.observe(1, &ServerEvent::Ui(UiEvent::Text("link https:".into())));
        let cursor = reader.events_read(0).unwrap().unwrap().next_cursor;
        reader.observe(
            2,
            &ServerEvent::Ui(UiEvent::Text(
                "//user:plainpassword@host.example done ".into(),
            )),
        );
        let stored =
            reader.with_mut(|projection| serde_json::to_string(&projection.events).unwrap());
        let reconnected = reader.clone();
        let public = serde_json::to_string(&reconnected.events_read(cursor).unwrap()).unwrap();
        assert!(!stored.contains("plainpassword"));
        assert!(!public.contains("plainpassword"));
        assert!(public.contains("REDACTED"));
    }

    #[test]
    fn split_pem_body_is_suppressed_in_ring_and_after_reconnect() {
        let body = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        reader.observe(1, &ServerEvent::Ui(UiEvent::Text("safe -----BE".into())));
        let cursor = reader.events_read(0).unwrap().unwrap().next_cursor;
        reader.observe(
            2,
            &ServerEvent::Ui(UiEvent::Text("GIN PRIVATE KEY-----\n".into())),
        );
        reader.observe(3, &ServerEvent::Ui(UiEvent::Text(format!("{body}\n"))));
        reader.observe(
            4,
            &ServerEvent::Ui(UiEvent::Text(
                "-----END PRIVATE KEY-----\nordinary tail ".into(),
            )),
        );
        let stored =
            reader.with_mut(|projection| serde_json::to_string(&projection.events).unwrap());
        let public = serde_json::to_string(&reader.clone().events_read(cursor).unwrap()).unwrap();
        assert!(!stored.contains(body));
        assert!(!public.contains(body));
        assert!(public.contains("REDACTED PRIVATE KEY"));
        assert!(public.contains("ordinary tail"));
    }

    #[test]
    fn empty_failed_terminal_replaces_partial_text_explicitly_after_reconnect() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        reader.observe(1, &ServerEvent::Ui(UiEvent::Text("partial".into())));
        let cursor = reader.events_read(0).unwrap().unwrap().next_cursor;
        reader.observe(
            2,
            &terminal_event(Outcome::HarnessError, Some("provider disconnected")),
        );
        let page = reader.clone().events_read(cursor).unwrap().unwrap();
        assert!(page.events.iter().any(|event| matches!(&event.event,
            ProductEventKindV1::ItemContent { channel: ItemContentChannelV1::FinalAnswer, content }
            if content.is_empty())));
        let terminal = page.latest_terminal.unwrap();
        assert_eq!(terminal.state, TurnStateV1::Failed);
        assert!(terminal.terminal_text_exact);
        assert_eq!(terminal.error.as_deref(), Some("provider disconnected"));
        assert_eq!(
            page.events
                .iter()
                .filter(|event| matches!(&event.event, ProductEventKindV1::TurnEnded { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn terminal_reconciles_final_answer_after_source_gap_without_claiming_a_spill_exact() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        reader.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        reader.observe(1, &ServerEvent::Lagged { dropped: 2 });
        let mut terminal = terminal_event(Outcome::Done, None);
        if let ServerEvent::RunEnded { summary, .. } = &mut terminal {
            summary.assistant_text = "canonical final answer".into();
        }
        reader.observe(2, &terminal);
        let page = reader.events_read(0).unwrap().unwrap();
        assert!(page.events.iter().any(|event| matches!(&event.event,
            ProductEventKindV1::ItemContent { channel: ItemContentChannelV1::FinalAnswer, content }
            if content == "canonical final answer")));
        assert!(page.latest_terminal.unwrap().terminal_text_exact);

        let spilled = ContractReader::default();
        spilled.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        spilled.begin_turn(RunId("r".into()), ProductTurnId(1), None);
        spilled.observe_with_spill(1, &terminal, Some(1024 * 1024));
        let page = spilled.events_read(0).unwrap().unwrap();
        assert!(!page.latest_terminal.unwrap().terminal_text_exact);
        assert!(page.events.iter().any(|event| matches!(&event.event,
            ProductEventKindV1::TerminalTextUnavailable { reason_code }
            if reason_code == "eq_terminal_spill")));
    }

    #[test]
    fn future_product_cursor_is_typed_error() {
        let reader = ContractReader::default();
        reader.bind_identity(SessionId("session-r".into()), RunId("r".into()));
        let error = reader.events_read(1).unwrap().unwrap_err();
        assert_eq!(
            error,
            ProductEventsReadErrorV1::CursorAhead {
                requested_after: 1,
                latest_cursor: 0,
            }
        );
    }
}
