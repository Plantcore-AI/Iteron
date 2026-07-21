//! Terminal input demultiplexing for bounded OSC 11 background detection.
//!
//! Crossterm turns an unknown OSC response into ordinary key events. This adapter recognizes only
//! the exact, bounded OSC 11 grammar, queues every unrelated event for normal TUI dispatch, and stays
//! armed after a timeout so a late response cannot become synthetic operator input.

use crate::theme::capabilities::{BackgroundTone, Environment, tone_from_osc11_body};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const OSC11_QUERY: &[u8] = b"\x1b]11;?\x1b\\";
const OSC11_TIMEOUT: Duration = Duration::from_millis(80);
const MAX_OSC11_BODY_CHARS: usize = 48;
const MAX_STARTUP_REPLAY_EVENTS: usize = 256;
const CANDIDATE_TIMEOUT: Duration = Duration::from_millis(40);

#[derive(Debug, Default)]
pub(crate) struct TerminalInput {
    queued: VecDeque<Event>,
    osc11: Osc11Demux,
}

impl TerminalInput {
    /// Query only when automatic background selection is active. The write and reply wait share one
    /// deadline; normal events observed during the probe are replayed in exact event order.
    pub(crate) fn query_background(&mut self, environment: &Environment) -> Option<BackgroundTone> {
        if !environment.wants_background_query() || !terminal_pair_is_supported() {
            return None;
        }

        let deadline = self.begin_query(write_query_until)?;

        loop {
            if self.queued.len() >= MAX_STARTUP_REPLAY_EVENTS {
                return None;
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            if !event::poll(remaining).ok()? {
                return None;
            }
            let incoming = event::read().ok()?;
            if let Some(tone) = self.route(incoming) {
                return Some(tone);
            }
        }
    }

    /// Read the next operator event while suppressing a matching late OSC 11 response. A partial
    /// candidate is held for at most 40 ms; if it is not the terminal response, it is replayed.
    pub(crate) fn read(&mut self, timeout: Duration) -> std::io::Result<Option<Event>> {
        if let Some(event) = self.queued.pop_front() {
            return Ok(Some(event));
        }

        let deadline = Instant::now() + timeout;
        loop {
            self.osc11.expire(Instant::now(), &mut self.queued);
            if let Some(event) = self.queued.pop_front() {
                return Ok(Some(event));
            }

            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            let wait = self.osc11.cap_wait(remaining, Instant::now());
            if !event::poll(wait)? {
                self.osc11.expire(Instant::now(), &mut self.queued);
                return Ok(self.queued.pop_front());
            }
            let incoming = event::read()?;
            let _late_tone = self.route(incoming);
            if let Some(event) = self.queued.pop_front() {
                return Ok(Some(event));
            }
            if Instant::now() >= deadline && !self.osc11.has_candidate() {
                return Ok(None);
            }
        }
    }

    fn route(&mut self, event: Event) -> Option<BackgroundTone> {
        self.osc11.route(event, &mut self.queued)
    }

    fn begin_query(
        &mut self,
        write: impl FnOnce(Instant) -> std::io::Result<()>,
    ) -> Option<Instant> {
        self.osc11.arm();
        let deadline = Instant::now() + OSC11_TIMEOUT;
        // Even a failed write may have emitted a query prefix. Stay armed so a terminal response to
        // that partial write can never become synthetic operator input.
        write(deadline).ok().map(|()| deadline)
    }
}

#[derive(Debug, Default)]
struct Osc11Demux {
    armed: bool,
    candidate: Option<Candidate>,
}

#[derive(Debug)]
struct Candidate {
    started: Instant,
    events: Vec<Event>,
    text: String,
}

impl Osc11Demux {
    fn arm(&mut self) {
        self.armed = true;
        self.candidate = None;
    }

    fn has_candidate(&self) -> bool {
        self.candidate.is_some()
    }

    fn cap_wait(&self, requested: Duration, now: Instant) -> Duration {
        self.candidate
            .as_ref()
            .and_then(|candidate| {
                (candidate.started + CANDIDATE_TIMEOUT).checked_duration_since(now)
            })
            .map_or(requested, |candidate_wait| requested.min(candidate_wait))
    }

    fn expire(&mut self, now: Instant, queued: &mut VecDeque<Event>) {
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| now.duration_since(candidate.started) >= CANDIDATE_TIMEOUT)
        {
            self.replay_candidate(queued);
        }
    }

    fn route(&mut self, event: Event, queued: &mut VecDeque<Event>) -> Option<BackgroundTone> {
        if !self.armed {
            queued.push_back(event);
            return None;
        }

        if self.candidate.is_none() {
            if is_alt_char(&event, ']') {
                self.candidate = Some(Candidate {
                    started: Instant::now(),
                    events: vec![event],
                    text: String::new(),
                });
            } else {
                queued.push_back(event);
            }
            return None;
        }

        if is_alt_char(&event, ']') {
            self.replay_candidate(queued);
            self.candidate = Some(Candidate {
                started: Instant::now(),
                events: vec![event],
                text: String::new(),
            });
            return None;
        }

        if is_osc_terminator(&event) {
            let mut candidate = self.candidate.take().expect("candidate checked above");
            candidate.events.push(event);
            if let Some(body) = candidate.text.strip_prefix("11;")
                && let Some(tone) = tone_from_osc11_body(body)
            {
                self.armed = false;
                return Some(tone);
            }
            queued.extend(candidate.events);
            return None;
        }

        let Some(character) = plain_char(&event) else {
            self.replay_candidate(queued);
            queued.push_back(event);
            return None;
        };
        let candidate = self.candidate.as_mut().expect("candidate checked above");
        let prefix = ['1', '1', ';'];
        let valid = if candidate.text.len() < prefix.len() {
            character == prefix[candidate.text.len()]
        } else {
            character.is_ascii_hexdigit()
                || matches!(character, '#' | ':' | '/')
                || character == 'r'
                || character == 'g'
                || character == 'b'
        };
        if !valid || candidate.text.len() >= 3 + MAX_OSC11_BODY_CHARS {
            self.replay_candidate(queued);
            queued.push_back(event);
            return None;
        }
        candidate.text.push(character);
        candidate.events.push(event);
        None
    }

    fn replay_candidate(&mut self, queued: &mut VecDeque<Event>) {
        if let Some(candidate) = self.candidate.take() {
            queued.extend(candidate.events);
        }
    }
}

fn response_key(event: &Event) -> Option<&KeyEvent> {
    let Event::Key(key) = event else {
        return None;
    };
    matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat).then_some(key)
}

fn is_alt_char(event: &Event, expected: char) -> bool {
    response_key(event).is_some_and(|key| {
        key.code == KeyCode::Char(expected) && key.modifiers == KeyModifiers::ALT
    })
}

fn is_osc_terminator(event: &Event) -> bool {
    is_alt_char(event, '\\')
        || response_key(event).is_some_and(|key| {
            key.code == KeyCode::Char('g') && key.modifiers == KeyModifiers::CONTROL
        })
}

fn plain_char(event: &Event) -> Option<char> {
    let key = response_key(event)?;
    (key.modifiers == KeyModifiers::NONE)
        .then_some(key.code)
        .and_then(|code| match code {
            KeyCode::Char(character) if character.is_ascii() => Some(character),
            _ => None,
        })
}

#[cfg(unix)]
fn terminal_pair_is_supported() -> bool {
    // SAFETY: isatty only inspects these process-owned descriptors.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

#[cfg(not(unix))]
fn terminal_pair_is_supported() -> bool {
    false
}

#[cfg(unix)]
fn write_query_until(deadline: Instant) -> std::io::Result<()> {
    let descriptor = libc::STDOUT_FILENO;
    // SAFETY: fcntl reads flags from the valid process-owned stdout descriptor.
    let original_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if original_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    struct RestoreFlags(i32);
    impl Drop for RestoreFlags {
        fn drop(&mut self) {
            // SAFETY: restoring flags on stdout is best-effort during scope exit.
            let _ = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, self.0) };
        }
    }
    let _restore = RestoreFlags(original_flags);
    // SAFETY: setting O_NONBLOCK changes only stdout's file status flags for this bounded scope.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut written = 0;
    while written < OSC11_QUERY.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "OSC 11 write timed out")
            })?;
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: descriptor,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized descriptor for this call.
        let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 || pollfd.revents & libc::POLLOUT == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "OSC 11 write timed out",
            ));
        }
        // SAFETY: the remaining query slice is live and its exact byte length bounds the write.
        let count = unsafe {
            libc::write(
                descriptor,
                OSC11_QUERY[written..].as_ptr().cast(),
                OSC11_QUERY.len() - written,
            )
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        written += count as usize;
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_query_until(_deadline: Instant) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "OSC 11 query transport is not enabled on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(character: char, modifiers: KeyModifiers) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(character), modifiers))
    }

    fn response(body: &str) -> Vec<Event> {
        let mut events = vec![key(']', KeyModifiers::ALT)];
        events.extend(
            "11;"
                .chars()
                .chain(body.chars())
                .map(|c| key(c, KeyModifiers::NONE)),
        );
        events.push(key('\\', KeyModifiers::ALT));
        events
    }

    #[test]
    fn response_is_demultiplexed_while_unrelated_input_is_replayed() {
        let mut input = TerminalInput::default();
        input.osc11.arm();
        let typed = key('x', KeyModifiers::NONE);
        assert_eq!(input.route(typed.clone()), None);
        let mut tone = None;
        for event in response("rgb:ffff/ffff/ffff") {
            tone = input.route(event).or(tone);
        }
        assert_eq!(tone, Some(BackgroundTone::Light));
        assert_eq!(input.queued.pop_front(), Some(typed));
        assert!(input.queued.is_empty());
    }

    #[test]
    fn late_response_is_swallowed_and_a_false_prefix_is_replayed_exactly() {
        let mut input = TerminalInput::default();
        input.osc11.arm();
        let false_prefix = [key(']', KeyModifiers::ALT), key('x', KeyModifiers::NONE)];
        for event in false_prefix.clone() {
            assert_eq!(input.route(event), None);
        }
        assert_eq!(input.queued.pop_front(), Some(false_prefix[0].clone()));
        assert_eq!(input.queued.pop_front(), Some(false_prefix[1].clone()));

        for event in response("#000000") {
            let _ = input.route(event);
        }
        assert!(
            input.queued.is_empty(),
            "late OSC bytes must not reach the operator input queue"
        );
        let typed = key('z', KeyModifiers::NONE);
        let _ = input.route(typed.clone());
        assert_eq!(input.queued.pop_front(), Some(typed));
    }

    #[test]
    fn partial_write_failure_stays_armed_and_swallows_a_possible_late_response() {
        let mut input = TerminalInput::default();
        let mut partial_write = Vec::new();
        assert!(
            input
                .begin_query(|_| {
                    partial_write.extend_from_slice(&OSC11_QUERY[..4]);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "injected partial write timeout",
                    ))
                })
                .is_none()
        );
        assert_eq!(partial_write, &OSC11_QUERY[..4]);
        assert!(input.osc11.armed);

        for event in response("#ffffff") {
            let _ = input.route(event);
        }
        assert!(input.queued.is_empty());
        assert!(!input.osc11.armed);
    }
}
