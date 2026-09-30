//! Private completion menu, debounce and one physical path-worker owner.
//! Only immutable menu views leave this domain. The terminal driver polls ready work and the
//! composer supplies its exact current draft; neither receives a mutable worker/generation bag.

use super::driver_support::{byte_index, complete_path};
use crate::commands;
use crate::editor::Editor;
use crossterm::event::KeyCode;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

pub(super) struct Completion {
    pub(super) items: Vec<(String, String)>,
    pub(super) sel: usize,
    pub(super) token_start: usize,
    pub(super) lead: char,
}

#[derive(Default)]
pub(super) struct CompletionOwner {
    menu: Option<Completion>,
    due: Option<Instant>,
    generation: u64,
    job: Option<JoinHandle<(u64, String, Option<Completion>)>>,
}
impl CompletionOwner {
    pub(super) fn view(&self) -> Option<&Completion> {
        self.menu.as_ref()
    }
    pub(super) fn is_open(&self) -> bool {
        self.menu.is_some()
    }
    pub(super) fn due(&self) -> Option<Instant> {
        self.due
    }
    pub(super) fn has_worker(&self) -> bool {
        self.job.is_some()
    }
    pub(super) fn dismiss(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.menu = None;
        self.due = None;
        // Retain the physical blocking worker slot until its actual work ends. Repeated Esc or
        // replacement never creates unbounded parallel directory walks.
    }
    pub(super) fn schedule(&mut self, editor: &Editor, now: Instant) {
        self.generation = self.generation.wrapping_add(1);
        let source = editor.text();
        if commands::slash_prefix(&source).is_some() {
            self.due = None;
            self.menu = build_completion(&source, editor.cursor(), Path::new("."));
        } else {
            self.due = Some(
                now + iteron_tunables::param_duration(
                    "cli.tui.completion_debounce",
                    Duration::from_millis(75),
                ),
            );
            self.menu = None;
        }
    }
    pub(super) fn start_due(&mut self, editor: &Editor, repo: &Path, now: Instant) {
        if self.job.is_some() || !self.due.is_some_and(|due| due <= now) {
            return;
        }
        self.due = None;
        let source = editor.text();
        let cursor = editor.cursor();
        let generation = self.generation;
        let repo = repo.to_path_buf();
        self.job = Some(tokio::task::spawn_blocking(move || {
            let completion = build_completion(&source, cursor, &repo);
            (generation, source, completion)
        }));
    }
    pub(super) async fn poll_ready(&mut self, editor: &Editor) -> bool {
        if !self.job.as_ref().is_some_and(|job| job.is_finished()) {
            return false;
        }
        let Some(job) = self.job.take() else {
            return false;
        };
        if let Ok((generation, source, menu)) = job.await
            && generation == self.generation
            && source == editor.text()
        {
            self.menu = menu;
            return true;
        }
        false
    }
    pub(super) fn navigate(&mut self, code: KeyCode) {
        let Some(menu) = self.menu.as_mut() else {
            return;
        };
        let len = menu.items.len();
        if len == 0 {
            return;
        }
        menu.sel = match code {
            KeyCode::Down => (menu.sel + 1) % len,
            KeyCode::Up => (menu.sel + len - 1) % len,
            KeyCode::PageDown => menu.sel.saturating_add(8).min(len - 1),
            KeyCode::PageUp => menu.sel.saturating_sub(8),
            KeyCode::Home => 0,
            KeyCode::End => len - 1,
            _ => return,
        };
    }
    pub(super) fn enter_submits(&self) -> bool {
        self.menu.as_ref().is_some_and(|menu| {
            if menu.lead != '/' {
                return false;
            }
            let Some((name, _)) = menu.items.get(menu.sel) else {
                return false;
            };
            commands::COMMANDS.iter().any(|command| {
                command.name == name && (command.args.is_empty() || command.args.starts_with('['))
            })
        })
    }
    #[cfg(test)]
    pub(super) fn refresh(&mut self, editor: &Editor, repo: &Path) {
        self.menu = build_completion(&editor.text(), editor.cursor(), repo);
    }
    #[cfg(test)]
    pub(super) fn install_fixture(&mut self, menu: Completion) {
        self.menu = Some(menu);
    }
    pub(super) fn accept(&mut self, editor: &mut Editor) {
        let Some(comp) = self.menu.take() else {
            return;
        };
        let Some((item, _)) = comp.items.get(comp.sel).cloned() else {
            return;
        };
        let text = editor.text();
        if comp.token_start > text.len() || !text.is_char_boundary(comp.token_start) {
            return;
        }
        let token_end = text[comp.token_start.min(text.len())..]
            .find(char::is_whitespace)
            .map(|i| comp.token_start + i)
            .unwrap_or(text.len());
        // A directory item (ends with '/') gets NO trailing space, so the mention token stays open
        // and the menu re-populates for drill-down (review: accepting a dir closed the menu).
        let sep = if item.ends_with('/') { "" } else { " " };
        let trailing_spaces =
            text[token_end..].len() - text[token_end..].trim_start_matches(' ').len();
        let replacement = format!("{item}{sep}");
        let _ = editor.replace_completion_span(
            comp.token_start,
            token_end + trailing_spaces,
            &replacement,
        );
    }
}
impl Drop for CompletionOwner {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            job.abort();
        }
    }
}

pub(super) fn build_completion(
    text: &str,
    cursor_chars: usize,
    repo: &std::path::Path,
) -> Option<Completion> {
    if text.contains('\n') {
        return None; // no menu in multi-line mode
    }
    // slash-command menu
    if let Some(prefix) = commands::slash_prefix(text) {
        let items: Vec<(String, String)> = commands::complete_slash(prefix)
            .into_iter()
            .map(|c| (c.name.to_string(), format!("{}  {}", c.args, c.help)))
            .collect();
        if !items.is_empty() {
            return Some(Completion {
                items,
                sel: 0,
                token_start: 1,
                lead: '/',
            });
        }
        return None;
    }
    // @file menu (path completion at the cursor)
    let cursor_bytes = byte_index(text, cursor_chars);
    if let Some((at, partial)) = commands::at_mention_at(text, cursor_bytes) {
        let matches = complete_path(repo, partial);
        if !matches.is_empty() {
            let items = matches.into_iter().map(|p| (p, String::new())).collect();
            return Some(Completion {
                items,
                sel: 0,
                token_start: at + 1,
                lead: '@',
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{CompletionOwner, Duration, Editor, Instant};

    #[tokio::test]
    async fn dismiss_keeps_one_physical_worker_and_rejects_its_stale_menu() {
        let root =
            std::env::temp_dir().join(format!("iteron-completion-stale-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("actual.txt"), "physical candidate").unwrap();
        let mut editor = Editor::new();
        editor.insert_str("@act");
        let mut owner = CompletionOwner::default();
        let now = Instant::now();
        owner.schedule(&editor, now);
        owner.start_due(&editor, &root, now + Duration::from_secs(1));
        assert!(owner.has_worker());
        owner.dismiss();
        assert!(
            owner.has_worker(),
            "dismissal retains physical admission until work ends"
        );
        owner.start_due(&editor, &root, now + Duration::from_secs(2));
        tokio::time::timeout(Duration::from_secs(5), async {
            while owner.has_worker() {
                assert!(!owner.poll_ready(&editor).await);
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            !owner.is_open(),
            "a dismissed generation cannot reopen its menu"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
