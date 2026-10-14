use super::{App, WorkflowUiEvent};

impl App {
    pub(super) fn workflow_event(&mut self, event: WorkflowUiEvent) {
        if matches!(&event, WorkflowUiEvent::RunStarted { .. }) {
            self.flush_text();
        }
        if self.history.observe_workflow(event) {
            self.autoscroll();
        }
    }
}
