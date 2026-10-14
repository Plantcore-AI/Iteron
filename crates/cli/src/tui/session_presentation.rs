//! Human-readable session identity; asynchronous reads never overwrite newer user intent.

#[derive(Default)]
pub(super) struct TitleLookup {
    pending: Option<tokio::task::JoinHandle<Option<(String, String)>>>,
    scope: Option<super::history_client::HistoryClient>,
}

impl TitleLookup {
    pub(super) fn start(
        &mut self,
        history: super::history_client::HistoryClient,
        expected: String,
    ) {
        self.cancel();
        self.scope = Some(history.clone());
        self.pending = Some(tokio::spawn(async move {
            let title = history.title().await;
            history.is_current().then_some((expected, title))
        }));
    }

    pub(super) fn busy(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) async fn poll(&mut self, current: &mut String) -> bool {
        if !self.pending.as_ref().is_some_and(|job| job.is_finished()) {
            return false;
        }
        let Some(job) = self.pending.take() else {
            return false;
        };
        let result = job.await;
        let current_scope = self.scope.take().is_some_and(|scope| scope.is_current());
        if current_scope && let Ok(Some((expected, title))) = result {
            let previous = current.clone();
            apply_startup_title(current, &expected, &title);
            return *current != previous;
        }
        false
    }

    pub(super) fn cancel(&mut self) {
        if let Some(job) = self.pending.take() {
            job.abort();
        }
        self.scope = None;
    }
}

impl Drop for TitleLookup {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(super) fn apply_startup_title(current: &mut String, initial: &str, hydrated: &str) {
    if current != initial {
        return;
    }
    if let Some(title) = meaningful_title(hydrated) {
        *current = super::ui_safe_text(title);
    } else if current == "Loading session…" {
        *current = "Untitled conversation".into();
    }
}

pub(super) fn apply_prompt_title(current: &mut String, prompt_title: &str) {
    if meaningful_title(current).is_none() && !prompt_title.trim().is_empty() {
        *current = super::ui_safe_text(prompt_title);
    }
}

fn meaningful_title(title: &str) -> Option<&str> {
    let title = title.trim();
    (!title.is_empty()
        && !matches!(
            title,
            "(untitled)" | "New session" | "Untitled conversation"
        ))
    .then_some(title)
}

pub(super) fn title(title: &str, run: &str) -> String {
    meaningful_title(title)
        .filter(|title| *title != run)
        .map(super::ui_safe_text)
        .unwrap_or_else(|| "Untitled conversation".into())
}

pub(super) fn workspace_label(workspace: &str) -> String {
    std::path::Path::new(workspace)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|label| !label.is_empty())
        .map(super::ui_safe_text)
        .unwrap_or_else(|| super::ui_safe_text(workspace))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_title_hydration_preserves_prompt_and_rename() {
        for current in ["hi", "Investigate cache", "我的会话"] {
            let mut actual = current.to_owned();
            apply_prompt_title(&mut actual, "A later prompt with attachments");
            apply_startup_title(&mut actual, "New session", "(untitled)");
            apply_startup_title(&mut actual, "New session", "Older title");
            assert_eq!(actual, current);
        }
        let mut initial = "Loading session…".to_owned();
        apply_prompt_title(&mut initial, "Prompt before saved title arrives");
        assert_eq!(initial, "Loading session…");
        apply_startup_title(&mut initial, "Loading session…", "Saved conversation");
        assert_eq!(initial, "Saved conversation");
        apply_prompt_title(&mut initial, "A follow-up in this resumed conversation");
        assert_eq!(initial, "Saved conversation");
        let mut fresh = "New session".to_owned();
        apply_prompt_title(&mut fresh, "First prompt");
        apply_prompt_title(&mut fresh, "Second prompt");
        assert_eq!(fresh, "First prompt");
        assert_eq!(title("(untitled)", "run-opaque"), "Untitled conversation");
        assert_eq!(title("run-opaque", "run-opaque"), "Untitled conversation");
    }
}
