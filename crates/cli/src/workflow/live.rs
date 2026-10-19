//! Terminal adapter for live workflow runs.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use iteron_host::workflow::projection::ui_safe_progress;
use iteron_workflow::events::{ProgressEvent, ProgressSink};
use iteron_workflow::{AgentSpawner, RunHandle, RunReport, RunSpec, WorkflowEngine};
use std::sync::Arc;

/// A [`ProgressSink`] that folds every engine event into a shared live [`crate::block::WorkflowRunCard`]
/// — the TTY counterpart of [`StdoutProgressSink`]. Reading the card each frame + this upsert IS the
/// design §3.2 store step; the live loop below drives the render.
pub struct CardProgressSink {
    card: Arc<std::sync::Mutex<crate::block::WorkflowRunCard>>,
}

impl CardProgressSink {
    pub fn new(card: Arc<std::sync::Mutex<crate::block::WorkflowRunCard>>) -> Self {
        CardProgressSink { card }
    }
}

impl ProgressSink for CardProgressSink {
    fn emit(&self, event: ProgressEvent) {
        if let Ok(mut card) = self.card.lock() {
            card.ingest(ui_safe_progress(event));
        }
    }
}

/// Restores the terminal (leaves raw mode + the alternate screen, shows the cursor) on drop, so an
/// early `?` or a Ctrl-C never leaves the terminal wedged — the #1 TUI failure mode.
struct LiveTermGuard {
    /// `true` only if this guard actually switched the console into raw mode. When the guard is
    /// nested inside an outer TUI that already owns raw mode, enabling again would overwrite
    /// crossterm's cached original console mode and leave cooked-input flags cleared on teardown.
    entered_raw_mode: bool,
}

impl LiveTermGuard {
    fn enter() -> anyhow::Result<Self> {
        let already_raw = crossterm::terminal::is_raw_mode_enabled().unwrap_or(false);
        if !already_raw {
            crossterm::terminal::enable_raw_mode()?;
        }
        crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::cursor::Hide
        )?;
        Ok(LiveTermGuard {
            entered_raw_mode: !already_raw,
        })
    }
}

impl Drop for LiveTermGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::cursor::Show,
            crossterm::terminal::LeaveAlternateScreen
        );
        if self.entered_raw_mode {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Flatten rendered lines to plain text (styling dropped) so the settled tree can be echoed into the
/// normal terminal scrollback after the alternate screen is left.
pub(super) fn plain_lines(lines: &[ratatui::text::Line<'static>]) -> String {
    lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Spinner cadence, and therefore also the worst-case latency between a Ctrl-C press and the run
/// being told to stop: the loop drains buffered key events once per frame.
const LIVE_TICK: std::time::Duration = std::time::Duration::from_millis(80);

/// What one key press means to the live workflow surface.
///
/// [`LiveTermGuard::enter`] turns raw mode ON, which clears `ISIG`: the terminal stops translating
/// Ctrl-C into `SIGINT`, so no signal handler — and in particular not `tokio::signal::ctrl_c` — can
/// ever fire while this tree is on screen. Ctrl-C arrives as an ordinary key event, and this is the
/// only place that decides what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LiveAction {
    /// Not a control key for this surface — keep rendering.
    Ignore,
    /// First Ctrl-C: cancel the run, then keep rendering until it actually settles.
    Cancel,
    /// Ctrl-C again while the run is still settling: stop waiting on it.
    ForceExit,
}

/// The key → action decision, kept pure so the interrupt contract is testable with no terminal.
pub(super) fn live_key_action(key: KeyEvent, cancel_requested: bool) -> LiveAction {
    // Windows (and any terminal with keyboard enhancement pushed) also reports releases; only a
    // press or an auto-repeat is an operator intent.
    if matches!(key.kind, KeyEventKind::Release) {
        return LiveAction::Ignore;
    }
    let ctrl_c = key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'));
    if !ctrl_c {
        return LiveAction::Ignore;
    }
    if cancel_requested {
        LiveAction::ForceExit
    } else {
        LiveAction::Cancel
    }
}

/// How the live loop ended.
pub(super) enum LiveOutcome {
    /// The run settled — on its own, or as `stopped` after a cancel. `cancelled` records whether
    /// Ctrl-C was taken, because the operator deserves to be told why the tree stopped moving;
    /// `spin` is the spinner phase the last live frame used, so the settled frame continues it.
    Settled {
        report: RunReport,
        cancelled: bool,
        spin: usize,
    },
    /// A second Ctrl-C arrived while the run was still settling: stop waiting on it.
    Forced,
}

/// The live loop's control flow, with the terminal factored out behind `draw`/`next_key`/`cancel` so
/// the interrupt path can be driven headlessly in tests. Draws a frame, drains whatever keys are
/// already buffered, then waits for either the run to settle or the next spinner tick.
pub(super) async fn live_loop<F, D, K, C>(
    future: F,
    mut draw: D,
    mut next_key: K,
    cancel: C,
    tick: std::time::Duration,
) -> anyhow::Result<LiveOutcome>
where
    F: std::future::Future<Output = anyhow::Result<RunReport>>,
    D: FnMut(bool, usize) -> anyhow::Result<()>,
    K: FnMut() -> Option<KeyEvent>,
    C: Fn(),
{
    let mut spin: usize = 0;
    let mut cancelled = false;

    tokio::pin!(future);
    let mut ticker = tokio::time::interval(tick);

    loop {
        // Keys are drained BEFORE the frame is drawn, so the frame the operator is looking at
        // already reflects the Ctrl-C they just pressed instead of acknowledging it a tick later —
        // or never, if the run settles immediately after being cancelled.
        while let Some(key) = next_key() {
            match live_key_action(key, cancelled) {
                LiveAction::Ignore => {}
                LiveAction::Cancel => {
                    cancelled = true;
                    // Idempotent and immediate: it trips the run's token, it does not block.
                    cancel();
                }
                LiveAction::ForceExit => return Ok(LiveOutcome::Forced),
            }
        }
        draw(cancelled, spin)?;
        tokio::select! {
            result = &mut future => {
                return Ok(LiveOutcome::Settled { report: result?, cancelled, spin });
            }
            _ = ticker.tick() => spin = spin.wrapping_add(1),
        }
    }
}

/// The banner the cancel path adds to the frame. A cancelled run whose tree simply stopped moving is
/// indistinguishable from a hung one, so the frame has to SAY it.
fn cancel_banner(settled: bool) -> &'static str {
    if settled {
        "run cancelled (Ctrl-C)"
    } else {
        "cancelling (Ctrl-C) \u{b7} press Ctrl-C again to stop waiting"
    }
}

/// One frame body: the run tree, plus the cancellation banner once Ctrl-C has been taken.
pub(super) fn live_lines(
    card: &crate::block::WorkflowRunCard,
    width: u16,
    theme: &crate::theme::Theme,
    spin: usize,
    cancelled: bool,
) -> Vec<ratatui::text::Line<'static>> {
    let mut lines = crate::block::render_workflow_run(card, width, theme, spin);
    if cancelled {
        lines.push(ratatui::text::Line::default());
        lines.push(ratatui::text::Line::from(ratatui::text::Span::styled(
            cancel_banner(card.finished).to_string(),
            ratatui::style::Style::default().fg(theme.error),
        )));
    }
    lines
}

/// The real key source: drain what crossterm has already buffered, never blocking the frame loop.
/// An unreadable stdin yields `None` rather than an error — losing input must not abandon a run that
/// is still executing on its own thread.
fn next_terminal_key() -> Option<KeyEvent> {
    while crossterm::event::poll(std::time::Duration::ZERO).unwrap_or(false) {
        match crossterm::event::read() {
            Ok(crossterm::event::Event::Key(key)) => return Some(key),
            // Resize/mouse/paste: consumed, not actionable here. Keep draining.
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Render the QuickJS-workflow phase→agent tree LIVE (design §3.3) while the run behind `handle`
/// drives `card` through [`CardProgressSink`], advancing the braille spinner every 80ms, then leave
/// the alternate screen and echo the settled tree into scrollback.
///
/// The handle — not a bare future — is what makes the surface interruptible: Ctrl-C calls
/// [`RunHandle::cancel`], which aborts in-flight children and interrupts a sync JS loop, and the loop
/// keeps rendering until the run actually settles as `stopped`.
async fn render_live(
    card: Arc<std::sync::Mutex<crate::block::WorkflowRunCard>>,
    handle: RunHandle,
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    use ratatui::Terminal;
    use ratatui::backend::CrosstermBackend;
    use ratatui::widgets::Paragraph;

    // `join` takes `&self`, so the joining future and the Ctrl-C handler share one handle.
    let handle = Arc::new(handle);
    let joiner = handle.clone();
    let future = async move { joiner.join().await };

    let mut guard = Some(LiveTermGuard::enter()?);
    let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    let outcome = {
        let card = card.clone();
        let draw = |cancelled: bool, spin: usize| -> anyhow::Result<()> {
            term.draw(|frame| {
                let area = frame.area();
                let snapshot = card.lock().unwrap();
                let lines = live_lines(&snapshot, area.width, theme, spin, cancelled);
                drop(snapshot);
                frame.render_widget(Paragraph::new(lines), area);
            })?;
            Ok(())
        };
        live_loop(
            future,
            draw,
            next_terminal_key,
            || handle.cancel(),
            iteron_tunables::param_duration("cli.workflow.live.live_tick", LIVE_TICK),
        )
        .await?
    };

    let (report, cancelled, spin) = match outcome {
        LiveOutcome::Settled {
            report,
            cancelled,
            spin,
        } => (report, cancelled, spin),
        LiveOutcome::Forced => {
            // `process::exit` runs no destructors, so the guard would never restore the terminal.
            // Restore it explicitly FIRST, then leave; the run was already told to cancel.
            drop(guard.take());
            eprintln!("workflow run interrupted; cancellation requested and not awaited");
            std::process::exit(i32::from(crate::output::EXIT_INTERRUPTED));
        }
    };

    // The engine reports `stopped` for exactly the token this loop trips, so either signal is proof.
    let cancelled = cancelled || report.stopped;
    if let Ok(mut card) = card.lock() {
        card.finished = true;
    }
    let mut final_plain = String::new();
    term.draw(|frame| {
        let area = frame.area();
        let snapshot = card.lock().unwrap();
        let lines = live_lines(&snapshot, area.width, theme, spin, cancelled);
        final_plain = plain_lines(&lines);
        frame.render_widget(Paragraph::new(lines), area);
    })?;
    drop(guard.take());

    // Terminal restored — echo the settled tree into normal scrollback so it survives the run.
    if !final_plain.trim().is_empty() {
        println!("{final_plain}");
    }
    Ok(report)
}

/// Launch a run in the BACKGROUND (via [`WorkflowEngine::launch`] → [`RunHandle`], review B3) and
/// attach the live tree to it: the run drives its own OS thread + runtime while this foreground loop
/// renders the shared card, reads keys, and `join`s the handle.
async fn launch_live(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    name: &str,
    phases: &[String],
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    let card = Arc::new(std::sync::Mutex::new(new_run_card(
        spec.run_id.as_str(),
        name,
        phases,
    )));
    let sink: Arc<dyn ProgressSink> = Arc::new(CardProgressSink::new(card.clone()));
    let handle = WorkflowEngine::launch(spec, spawner, sink);
    render_live(card, handle, theme).await
}

/// Run one fully-specified [`RunSpec`], rendering the live tree (design §3.3). `iteron workflow run`
/// (TTY) and `iteron workflow resume` (TTY) both call it. Non-TTY uses [`StdoutProgressSink`].
///
/// This used to await `WorkflowEngine::execute` directly — a bare future with no cancellation
/// handle — which is why Ctrl-C could not stop a run: raw mode had already suppressed `SIGINT`, and
/// nothing on this path could act on the key event that replaced it. It now goes through
/// [`WorkflowEngine::launch`] for the same reason [`watch_live`] always did: a [`RunHandle`] can be
/// cancelled.
pub async fn run_live(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    name: &str,
    phases: &[String],
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    launch_live(spec, spawner, name, phases, theme).await
}

/// One live card seeded with the script's DECLARED `meta.phases`, so every phase box is laid out on
/// the first frame instead of appearing only once execution reaches it.
pub(super) fn new_run_card(
    run_id: &str,
    name: &str,
    phases: &[String],
) -> crate::block::WorkflowRunCard {
    let mut card = crate::block::WorkflowRunCard::new(run_id, name);
    card.declare_phases(phases.iter().cloned());
    card
}

/// The `RunHandle` counterpart of [`run_live`] for `iteron workflow watch <runId>`, which re-launches a
/// prior run. Same loop, same interrupt contract. Non-TTY uses [`StdoutProgressSink`].
pub async fn watch_live(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    name: &str,
    phases: &[String],
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    launch_live(spec, spawner, name, phases, theme).await
}

#[cfg(all(test, feature = "script-workflows"))]
mod tests {
    use super::*;
    use iteron_workflow::RunId;
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn ctrl_c() -> KeyEvent {
        key(KeyCode::Char('c'), KeyModifiers::CONTROL)
    }

    fn settled_report() -> RunReport {
        RunReport {
            run_id: RunId::new("wf_interrupt"),
            value: serde_json::Value::Null,
            stopped: true,
            cache_hits: 0,
            cache_misses: 0,
            errors: 0,
            tokens: 0,
            tool_calls: 0,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn ctrl_c_is_the_key_that_cancels_and_nothing_else_is() {
        assert_eq!(live_key_action(ctrl_c(), false), LiveAction::Cancel);
        assert_eq!(
            live_key_action(key(KeyCode::Char('C'), KeyModifiers::CONTROL), false),
            LiveAction::Cancel,
            "a shifted Ctrl-C is still Ctrl-C"
        );
        for benign in [
            key(KeyCode::Char('c'), KeyModifiers::NONE),
            key(KeyCode::Char('c'), KeyModifiers::ALT),
            key(KeyCode::Char('d'), KeyModifiers::CONTROL),
            key(KeyCode::Esc, KeyModifiers::NONE),
            key(KeyCode::Enter, KeyModifiers::NONE),
        ] {
            assert_eq!(
                live_key_action(benign, false),
                LiveAction::Ignore,
                "{benign:?} must not stop a running workflow"
            );
        }
    }

    #[test]
    fn a_key_release_never_cancels() {
        // Windows reports a Release for every press; acting on both would cancel twice from one
        // physical Ctrl-C, i.e. force-exit before the run ever got a chance to settle.
        let mut release = ctrl_c();
        release.kind = KeyEventKind::Release;
        assert_eq!(live_key_action(release, false), LiveAction::Ignore);
        assert_eq!(live_key_action(release, true), LiveAction::Ignore);
    }

    #[test]
    fn a_second_ctrl_c_while_settling_forces_the_exit() {
        assert_eq!(live_key_action(ctrl_c(), true), LiveAction::ForceExit);
    }

    #[test]
    fn the_cancelled_frame_says_so_instead_of_just_freezing() {
        let theme = crate::theme::Theme::dark();
        let mut card = new_run_card("wf_interrupt", "triage", &["plan".to_string()]);

        let live = plain_lines(&live_lines(&card, 80, &theme, 0, true));
        assert!(live.contains("cancelling"), "{live}");
        assert!(live.contains("Ctrl-C again"), "{live}");

        card.finished = true;
        let settled = plain_lines(&live_lines(&card, 80, &theme, 0, true));
        assert!(settled.contains("run cancelled"), "{settled}");

        let untouched = plain_lines(&live_lines(&card, 80, &theme, 0, false));
        assert!(
            !untouched.contains("cancel"),
            "a run nobody interrupted must not claim it was cancelled: {untouched}"
        );
    }

    #[tokio::test]
    async fn ctrl_c_invokes_cancel_and_the_loop_keeps_rendering_until_the_run_settles() {
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::new(Mutex::new(Vec::<bool>::new()));

        // The stand-in for the engine: it only resolves once cancellation was actually requested,
        // so a loop that drew a "cancelled" banner without calling `cancel()` would hang here.
        let settles_on_cancel = {
            let cancelled = cancelled.clone();
            async move {
                loop {
                    if cancelled.load(Ordering::SeqCst) {
                        return Ok(settled_report());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        };

        let mut keys = vec![ctrl_c()].into_iter();
        let draw_log = observed.clone();
        let cancel_flag = cancelled.clone();

        let outcome = live_loop(
            settles_on_cancel,
            move |cancelled, _spin| {
                draw_log.lock().unwrap().push(cancelled);
                Ok(())
            },
            move || keys.next(),
            move || cancel_flag.store(true, Ordering::SeqCst),
            std::time::Duration::from_millis(1),
        )
        .await
        .expect("the live loop settles");

        assert!(
            cancelled.load(Ordering::SeqCst),
            "Ctrl-C must actually invoke cancel() on the run handle"
        );
        match outcome {
            LiveOutcome::Settled {
                report, cancelled, ..
            } => {
                assert!(cancelled, "the loop must report that it was interrupted");
                assert!(report.stopped, "an interrupted run settles as stopped");
            }
            LiveOutcome::Forced => panic!("one Ctrl-C must wait for the run, not force-exit"),
        }
        let frames = observed.lock().unwrap();
        assert!(
            frames.iter().any(|drawn| *drawn),
            "the operator must see at least one frame acknowledging the interrupt: {frames:?}"
        );
    }

    #[tokio::test]
    async fn a_second_ctrl_c_stops_waiting_on_a_run_that_will_not_settle() {
        let cancels = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = cancels.clone();
        // A run that ignores cancellation entirely — exactly the case a single Ctrl-C cannot fix.
        let never_settles = async {
            std::future::pending::<()>().await;
            unreachable!()
        };
        let mut keys = vec![ctrl_c(), ctrl_c()].into_iter();

        let outcome = live_loop(
            never_settles,
            |_cancelled, _spin| Ok(()),
            move || keys.next(),
            move || {
                counted.fetch_add(1, Ordering::SeqCst);
            },
            std::time::Duration::from_millis(1),
        )
        .await
        .expect("the live loop returns instead of hanging");

        assert!(
            matches!(outcome, LiveOutcome::Forced),
            "a second Ctrl-C must stop waiting rather than hang forever"
        );
        assert_eq!(
            cancels.load(Ordering::SeqCst),
            1,
            "the run is asked to cancel once; the second press is the operator giving up"
        );
    }
}
