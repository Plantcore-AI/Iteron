//! Private Product V1 presentation state. A content terminal never releases a runtime submission.
use iteron_protocol::{
    RunId,
    product_contract::{PRODUCT_CONTRACT_VERSION, ProductTurnId, ThreadSnapshotV1},
};

const MAX_TERMINAL_TEXT_BYTES: usize = 256 * 1024;
#[derive(Default)]
pub(super) struct ProductPresentation {
    run: Option<RunId>,
    active: bool,
    turn: Option<TurnSummary>,
    final_text: String,
    final_seen: bool,
    final_complete: bool,
    terminal_seen: bool,
    terminal: Option<String>,
    generation: u64,
}
struct TurnSummary {
    id: ProductTurnId,
    items: usize,
    omitted: u32,
}
/// Once-owned display text derived from this owner's complete Product content observation.
pub(super) struct ProductAnswer {
    run: RunId,
    generation: u64,
    text: String,
}
impl ProductAnswer {
    pub(super) fn text(&self) -> &str {
        &self.text
    }
}

impl ProductPresentation {
    pub(super) fn observe_snapshot(&mut self, snapshot: &ThreadSnapshotV1) {
        if snapshot.contract_version != PRODUCT_CONTRACT_VERSION {
            self.unavailable();
            return;
        }
        self.select_run(&snapshot.run_id);
        self.active = true;
        self.turn = snapshot.turn.as_ref().map(|turn| TurnSummary {
            id: turn.turn_id,
            items: turn.items.len(),
            omitted: turn.omitted_items,
        });
    }
    pub(super) fn select_run(&mut self, run: &RunId) {
        if self.run.as_ref() == Some(run) {
            return;
        }
        self.clear_selected_run();
        self.run = Some(run.clone());
        self.final_complete = true;
    }
    pub(super) fn clear_selected_run(&mut self) {
        let next = self.generation.wrapping_add(1);
        *self = Self::default();
        self.generation = next;
    }
    pub(super) fn unavailable(&mut self) {
        self.active = false;
        self.turn = None;
    }
    pub(super) fn stream_active(&self) -> bool {
        self.active
    }
    pub(super) fn turn_status(&self) -> Option<String> {
        self.turn.as_ref().map(|turn| {
            format!(
                "turn {} · {} item{}{}",
                turn.id.0,
                turn.items,
                if turn.items == 1 { "" } else { "s" },
                if turn.omitted > 0 {
                    format!(" · {} omitted", turn.omitted)
                } else {
                    String::new()
                }
            )
        })
    }
    pub(super) fn begin_turn(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.final_text.clear();
        self.final_seen = false;
        self.final_complete = true;
        self.terminal_seen = false;
        self.terminal = None;
    }
    pub(super) fn append_final(&mut self, text: &str) {
        if self.terminal_seen {
            return;
        }
        self.final_seen = true;
        let limit = iteron_tunables::param_integer(
            "cli.tui.product_projection.max_terminal_text_bytes",
            MAX_TERMINAL_TEXT_BYTES,
        )
        .min(MAX_TERMINAL_TEXT_BYTES);
        if self.final_text.len().saturating_add(text.len()) > limit || !self.final_complete {
            self.mark_incomplete();
            return;
        }
        self.final_text.reserve_exact(text.len());
        self.final_text.push_str(text);
    }
    pub(super) fn mark_incomplete(&mut self) {
        self.final_complete = false;
    }
    pub(super) fn finish_terminal(&mut self, exact: bool) -> Option<ProductAnswer> {
        if self.terminal_seen {
            return None;
        }
        self.terminal_seen = true;
        if !exact || !self.final_seen || !self.final_complete {
            return None;
        }
        let run = self.run.clone()?;
        self.final_seen = false;
        Some(ProductAnswer {
            run,
            generation: self.generation,
            text: std::mem::take(&mut self.final_text),
        })
    }
    pub(super) fn retain_terminal(&mut self, answer: ProductAnswer) -> bool {
        if self.run.as_ref() != Some(&answer.run) || self.generation != answer.generation {
            return false;
        }
        self.terminal = Some(answer.text);
        true
    }
    pub(super) fn take_terminal(&mut self) -> Option<String> {
        self.terminal.take()
    }
    #[cfg(test)]
    pub(super) fn terminal_answer(&self) -> Option<&str> {
        self.terminal.as_deref()
    }
}

#[cfg(test)]
mod tests;
