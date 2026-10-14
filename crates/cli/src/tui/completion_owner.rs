//! Private completion menu, debounce and one physical path-worker owner.
//! Only immutable menu views leave this domain. The terminal driver polls ready work and the
//! composer supplies its exact current draft; neither receives a mutable worker/generation bag.

use super::driver_support::byte_index;
#[cfg(test)]
use super::driver_support::complete_path;
use crate::app_server::PathCompletionPort;
use crate::commands;
use crate::editor::Editor;
use crossterm::event::KeyCode;
#[cfg(test)]
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
        // Keep one pending observation. The host retains its physical read slot through native
        // completion even if this observer is canceled or replaced.
    }
    pub(super) fn schedule(&mut self, editor: &Editor, now: Instant) {
        self.generation = self.generation.wrapping_add(1);
        let source = editor.text();
        if commands::slash_prefix(&source).is_some() {
            self.due = None;
            self.menu = slash_completion(&source);
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
    pub(super) fn start_due(
        &mut self,
        editor: &Editor,
        port: Option<PathCompletionPort>,
        now: Instant,
    ) {
        if self.job.is_some() || self.due.is_none_or(|due| due > now) {
            return;
        }
        self.due = None;
        let source = editor.text();
        if source.len() > 1024 * 1024 {
            return;
        }
        let Some((at, partial)) = path_query(&source, editor.cursor()) else {
            return;
        };
        let Some(port) = port else {
            return;
        };
        let partial = partial.to_owned();
        let generation = self.generation;
        self.job = Some(tokio::spawn(async move {
            let menu = port
                .complete(partial)
                .await
                .ok()
                .and_then(|rows| path_menu(at, rows.items, rows.incomplete));
            (generation, source, menu)
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

fn slash_completion(text: &str) -> Option<Completion> {
    if text.contains('\n') {
        return None;
    }
    let prefix = commands::slash_prefix(text)?;
    let items = commands::complete_slash(prefix)
        .into_iter()
        .map(|command| {
            (
                command.name.to_string(),
                format!("{}  {}", command.args, command.help),
            )
        })
        .collect::<Vec<_>>();
    (!items.is_empty()).then_some(Completion {
        items,
        sel: 0,
        token_start: 1,
        lead: '/',
    })
}
fn path_query(text: &str, cursor_chars: usize) -> Option<(usize, &str)> {
    if text.contains('\n') {
        return None;
    }
    commands::at_mention_at(text, byte_index(text, cursor_chars))
}
fn path_menu(at: usize, paths: Vec<String>, incomplete: bool) -> Option<Completion> {
    if paths.is_empty() {
        return None;
    }
    let items = paths
        .into_iter()
        .enumerate()
        .map(|(index, path)| {
            (
                path,
                if index == 0 && incomplete {
                    "partial directory scan".into()
                } else {
                    String::new()
                },
            )
        })
        .collect();
    Some(Completion {
        items,
        sel: 0,
        token_start: at + 1,
        lead: '@',
    })
}
#[cfg(test)]
pub(super) fn build_completion(text: &str, cursor_chars: usize, repo: &Path) -> Option<Completion> {
    slash_completion(text).or_else(|| {
        let (at, partial) = path_query(text, cursor_chars)?;
        path_menu(at, complete_path(repo, partial), false)
    })
}

#[cfg(test)]
mod tests {
    use super::{CompletionOwner, Duration, Editor, Instant};

    #[test]
    fn partial_directory_observation_has_visible_menu_truth_and_preserves_inserted_filename() {
        let mut app = crate::tui::App::new();
        app.editor.insert_str("@act");
        let menu = super::path_menu(0, vec!["actual.txt".into()], true).unwrap();
        assert_eq!(menu.items[0].1, "partial directory scan");
        app.completions.install_fixture(menu);
        let screen = crate::tui::tests::render_text(&mut app, 100, 18);
        assert!(screen.contains("partial directory scan"), "{screen}");
        app.accept_completion();
        assert_eq!(app.editor.text(), "@actual.txt ");
    }

    #[tokio::test]
    async fn dismiss_keeps_one_physical_worker_and_rejects_its_stale_menu() {
        let root =
            std::env::temp_dir().join(format!("iteron-completion-stale-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("actual.txt"), "physical candidate").unwrap();
        let root = root.canonicalize().unwrap();
        let fixture = crate::app_server::completion_fixture(&root);
        let port = || fixture.port();
        let mut editor = Editor::new();
        editor.insert_str("@act");
        let mut owner = CompletionOwner::default();
        let now = Instant::now();
        owner.schedule(&editor, now);
        owner.start_due(&editor, Some(port()), now + Duration::from_secs(1));
        assert!(owner.has_worker());
        owner.dismiss();
        assert!(
            owner.has_worker(),
            "dismissal retains physical admission until work ends"
        );
        owner.start_due(&editor, Some(port()), now + Duration::from_secs(2));
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
        assert!(fixture.shutdown().await);
        drop(fixture);
        std::fs::remove_dir_all(root).unwrap();
    }
}
