//! Terminal input demultiplexing for bounded startup capability detection.
//!
//! Crossterm turns unknown terminal responses into ordinary key events. This adapter recognizes only
//! the exact, bounded OSC 11 and Windows keyboard-enhancement grammars, queues every unrelated event
//! for normal TUI dispatch, and stays armed after a timeout so a late response cannot become
//! synthetic operator input.

use crate::theme::capabilities::{BackgroundTone, Environment, tone_from_osc11_body};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::time::{Duration, Instant};

#[cfg(windows)]
mod windows_query;

const OSC11_QUERY: &[u8] = b"\x1b]11;?\x1b\\";
const OSC11_TIMEOUT: Duration = Duration::from_millis(80);
const MAX_OSC11_BODY_CHARS: usize = 48;
const MAX_STARTUP_REPLAY_EVENTS: usize = 256;
const CANDIDATE_TIMEOUT: Duration = Duration::from_millis(40);
#[cfg(any(windows, test))]
const KEYBOARD_ENHANCEMENT_QUERY: &[u8] = b"\x1b[?u\x1b[c";
#[cfg(any(windows, test))]
const KEYBOARD_QUERY_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_KEYBOARD_RESPONSE_CHARS: usize = 24;
const MAX_KEYBOARD_RESPONSE_EVENTS: usize = 64;
/// Operator escape hatch for the blocking progressive-keyboard probe. Any value other than empty
/// or `0` skips the query outright and keeps the portable Ctrl-J path.
pub(crate) const NO_KEYBOARD_ENHANCEMENT_ENV: &str = "CORE_NO_KBD_ENHANCEMENT";

#[derive(Debug, Default)]
pub(crate) struct TerminalInput {
    queued: VecDeque<Event>,
    keyboard: KeyboardResponseDemux,
    osc11: Osc11Demux,
}

impl TerminalInput {
    /// Probe progressive keyboard enhancement through the currently supported terminal backend.
    ///
    /// The probe writes a query and then BLOCKS waiting for a reply, so it is only worth paying for
    /// on a terminal the environment already says can answer an interactive query. It shares the
    /// OSC 11 gate (`interactive_query_supported` excludes `TERM=dumb`, tmux and screen, which
    /// multiplex the reply away) plus the console/isatty pair check, and an operator can disable it
    /// outright with `CORE_NO_KBD_ENHANCEMENT`.
    ///
    /// Crossterm answers the Windows case with a hard-coded `false`, so Windows runs the query
    /// natively instead: the query bytes and the primary device-attributes sentinel share one
    /// bounded wait, unrelated startup events are replayed in exact order, and a late terminal
    /// response stays armed for suppression instead of becoming input.
    pub(crate) fn supports_keyboard_enhancement(&mut self, environment: &Environment) -> bool {
        if !keyboard_enhancement_probe_allowed(
            environment.interactive_query_supported,
            terminal_pair_is_supported(),
            std::env::var_os(NO_KEYBOARD_ENHANCEMENT_ENV).as_deref(),
        ) {
            return false;
        }
        #[cfg(windows)]
        {
            let Some(deadline) = self.begin_keyboard_query(windows_query::write_keyboard_query)
            else {
                return false;
            };

            let mut supported = false;
            for _ in 0..MAX_STARTUP_REPLAY_EVENTS {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return supported;
                };
                let Ok(true) = event::poll(remaining) else {
                    return supported;
                };
                let Ok(incoming) = event::read() else {
                    return supported;
                };
                match self.route_all(incoming).keyboard {
                    Some(KeyboardResponse::Enhancement) => supported = true,
                    Some(KeyboardResponse::DeviceAttributes) => return supported,
                    None => {}
                }
            }
            supported
        }
        #[cfg(unix)]
        {
            crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false)
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }

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
            self.expire_keyboard_candidate(Instant::now());
            self.osc11.expire(Instant::now(), &mut self.queued);
            if let Some(event) = self.queued.pop_front() {
                return Ok(Some(event));
            }

            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            let wait = self.osc11.cap_wait(remaining, Instant::now());
            let wait = self.keyboard.cap_wait(wait, Instant::now());
            if !event::poll(wait)? {
                self.expire_keyboard_candidate(Instant::now());
                self.osc11.expire(Instant::now(), &mut self.queued);
                return Ok(self.queued.pop_front());
            }
            let incoming = event::read()?;
            let _late_tone = self.route(incoming);
            if let Some(event) = self.queued.pop_front() {
                return Ok(Some(event));
            }
            if Instant::now() >= deadline
                && !self.keyboard.has_candidate()
                && !self.osc11.has_candidate()
            {
                return Ok(None);
            }
        }
    }

    fn route(&mut self, event: Event) -> Option<BackgroundTone> {
        self.route_all(event).background
    }

    fn route_all(&mut self, event: Event) -> RoutedResponses {
        let mut forwarded = VecDeque::new();
        self.keyboard.expire(Instant::now(), &mut forwarded);
        let keyboard = self.keyboard.route(event, &mut forwarded);
        let mut background = None;
        while let Some(event) = forwarded.pop_front() {
            background = self.osc11.route(event, &mut self.queued).or(background);
        }
        RoutedResponses {
            keyboard,
            background,
        }
    }

    fn expire_keyboard_candidate(&mut self, now: Instant) {
        let mut forwarded = VecDeque::new();
        self.keyboard.expire(now, &mut forwarded);
        while let Some(event) = forwarded.pop_front() {
            let _ = self.osc11.route(event, &mut self.queued);
        }
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

    #[cfg(any(windows, test))]
    fn begin_keyboard_query(
        &mut self,
        write: impl FnOnce(Instant) -> std::io::Result<()>,
    ) -> Option<Instant> {
        self.keyboard.arm();
        let deadline = Instant::now() + KEYBOARD_QUERY_TIMEOUT;
        // A timeout or short write can still have emitted a query prefix. Keep the demux armed so
        // every corresponding late response stays out of the operator input stream.
        write(deadline).ok().map(|()| deadline)
    }
}

#[derive(Debug, Default)]
struct RoutedResponses {
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    keyboard: Option<KeyboardResponse>,
    background: Option<BackgroundTone>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyboardResponse {
    Enhancement,
    DeviceAttributes,
}

#[derive(Debug, Default)]
struct KeyboardResponseDemux {
    armed: bool,
    candidate: Option<KeyboardCandidate>,
}

#[derive(Debug)]
struct KeyboardCandidate {
    started: Instant,
    events: Vec<Event>,
    text: String,
}

impl KeyboardResponseDemux {
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn arm(&mut self) {
        self.armed = true;
        self.candidate = None;
    }

    fn expire(&mut self, now: Instant, forwarded: &mut VecDeque<Event>) {
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| now.duration_since(candidate.started) >= CANDIDATE_TIMEOUT)
        {
            self.replay_candidate(forwarded);
        }
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

    fn route(&mut self, event: Event, forwarded: &mut VecDeque<Event>) -> Option<KeyboardResponse> {
        if !self.armed {
            forwarded.push_back(event);
            return None;
        }

        let token = keyboard_response_token(&event);
        if matches!(
            token,
            Some(KeyboardToken::Escape | KeyboardToken::EscapeBracket)
        ) {
            self.replay_candidate(forwarded);
            self.candidate = Some(KeyboardCandidate {
                started: Instant::now(),
                events: vec![event],
                text: match token {
                    Some(KeyboardToken::Escape) => "\x1b".into(),
                    Some(KeyboardToken::EscapeBracket) => "\x1b[".into(),
                    _ => unreachable!("token matched above"),
                },
            });
            return None;
        }

        let Some(candidate) = self.candidate.as_mut() else {
            forwarded.push_back(event);
            return None;
        };
        if is_key_release(&event) {
            if candidate.events.len() >= MAX_KEYBOARD_RESPONSE_EVENTS {
                self.replay_candidate(forwarded);
                forwarded.push_back(event);
            } else {
                candidate.events.push(event);
            }
            return None;
        }
        let Some(KeyboardToken::Character(character)) = token else {
            self.replay_candidate(forwarded);
            forwarded.push_back(event);
            return None;
        };
        candidate.events.push(event);
        candidate.text.push(character);

        const PREFIX: &str = "\x1b[?";
        if candidate.events.len() > MAX_KEYBOARD_RESPONSE_EVENTS
            || candidate.text.len() > PREFIX.len() + MAX_KEYBOARD_RESPONSE_CHARS
            || (candidate.text.len() <= PREFIX.len() && !PREFIX.starts_with(&candidate.text))
        {
            self.replay_candidate(forwarded);
            return None;
        }
        let body = candidate.text.strip_prefix(PREFIX)?;
        let terminator = body.chars().last()?;
        if matches!(terminator, 'u' | 'c') {
            let parameters = &body[..body.len() - terminator.len_utf8()];
            if valid_csi_parameters(parameters) {
                self.candidate = None;
                let response = if terminator == 'u' {
                    KeyboardResponse::Enhancement
                } else {
                    self.armed = false;
                    KeyboardResponse::DeviceAttributes
                };
                return Some(response);
            }
            self.replay_candidate(forwarded);
            return None;
        }
        if !matches!(terminator, '0'..='9' | ';') {
            self.replay_candidate(forwarded);
        }
        None
    }

    fn replay_candidate(&mut self, forwarded: &mut VecDeque<Event>) {
        if let Some(candidate) = self.candidate.take() {
            forwarded.extend(candidate.events);
        }
    }
}

fn valid_csi_parameters(parameters: &str) -> bool {
    !parameters.is_empty()
        && parameters.len() <= MAX_KEYBOARD_RESPONSE_CHARS
        && parameters.split(';').all(|parameter| {
            !parameter.is_empty() && parameter.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyboardToken {
    Escape,
    EscapeBracket,
    Character(char),
}

fn keyboard_response_token(event: &Event) -> Option<KeyboardToken> {
    let key = response_key(event)?;
    match key.code {
        KeyCode::Esc if key.modifiers.is_empty() => Some(KeyboardToken::Escape),
        KeyCode::Char('[') if key.modifiers == KeyModifiers::ALT => {
            Some(KeyboardToken::EscapeBracket)
        }
        KeyCode::Char(character)
            if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
        {
            Some(KeyboardToken::Character(character))
        }
        _ => None,
    }
}

fn is_key_release(event: &Event) -> bool {
    matches!(event, Event::Key(key) if key.kind == KeyEventKind::Release)
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

#[cfg(windows)]
fn terminal_pair_is_supported() -> bool {
    windows_query::terminal_pair_is_supported()
}

#[cfg(not(any(unix, windows)))]
fn terminal_pair_is_supported() -> bool {
    false
}

/// Decide whether the blocking progressive-keyboard query may run at all. Kept free of I/O so the
/// exact gate — not an approximation of it — is what the tests pin.
fn keyboard_enhancement_probe_allowed(
    interactive_query_supported: bool,
    terminal_pair_supported: bool,
    escape_hatch: Option<&OsStr>,
) -> bool {
    interactive_query_supported && terminal_pair_supported && !escape_hatch_enabled(escape_hatch)
}

/// Absent, empty, whitespace, and `0` all mean "leave the probe on"; anything else disables it.
fn escape_hatch_enabled(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| {
        let value = value.to_string_lossy();
        let value = value.trim();
        !value.is_empty() && value != "0"
    })
}

#[cfg(any(windows, test))]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyboardQueryState {
    Fresh,
    Running,
    Complete,
    Poisoned,
}

#[cfg(any(windows, test))]
struct KeyboardQueryGate(std::sync::atomic::AtomicU8);

#[cfg(any(windows, test))]
impl KeyboardQueryGate {
    const fn new() -> Self {
        Self(std::sync::atomic::AtomicU8::new(
            KeyboardQueryState::Fresh as u8,
        ))
    }

    fn try_start(&self) -> bool {
        self.0
            .compare_exchange(
                KeyboardQueryState::Fresh as u8,
                KeyboardQueryState::Running as u8,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    fn complete(&self) {
        self.finish(KeyboardQueryState::Complete);
    }

    fn poison(&self) {
        self.finish(KeyboardQueryState::Poisoned);
    }

    fn finish(&self, state: KeyboardQueryState) {
        let _ = self.0.compare_exchange(
            KeyboardQueryState::Running as u8,
            state as u8,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
    }

    #[cfg(test)]
    fn state(&self) -> KeyboardQueryState {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            value if value == KeyboardQueryState::Fresh as u8 => KeyboardQueryState::Fresh,
            value if value == KeyboardQueryState::Running as u8 => KeyboardQueryState::Running,
            value if value == KeyboardQueryState::Complete as u8 => KeyboardQueryState::Complete,
            value if value == KeyboardQueryState::Poisoned as u8 => KeyboardQueryState::Poisoned,
            _ => unreachable!("keyboard query gate stores only declared states"),
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Clone)]
struct KeyboardQueryRequest {
    deadline: Instant,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(any(windows, test))]
impl KeyboardQueryRequest {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn should_abort(&self, now: Instant) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire) || now >= self.deadline
    }
}

#[cfg(any(windows, test))]
fn exact_keyboard_query_write(written: usize) -> std::io::Result<()> {
    if written == KEYBOARD_ENHANCEMENT_QUERY.len() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            format!(
                "keyboard capability query wrote {written} of {} bytes",
                KEYBOARD_ENHANCEMENT_QUERY.len()
            ),
        ))
    }
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

    fn key_release(character: char) -> Event {
        Event::Key(KeyEvent::new_with_kind(
            KeyCode::Char(character),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ))
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

    fn csi_response(parameters: &str, terminator: char) -> Vec<Event> {
        let mut events = vec![
            Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            key('[', KeyModifiers::NONE),
        ];
        events.extend(
            std::iter::once('?')
                .chain(parameters.chars())
                .chain(std::iter::once(terminator))
                .map(|character| key(character, KeyModifiers::NONE)),
        );
        events
    }

    fn folded_csi_response(parameters: &str, terminator: char) -> Vec<Event> {
        let mut events = vec![key('[', KeyModifiers::ALT)];
        events.extend(
            std::iter::once('?')
                .chain(parameters.chars())
                .chain(std::iter::once(terminator))
                .map(|character| key(character, KeyModifiers::NONE)),
        );
        events
    }

    #[test]
    fn keyboard_probe_is_refused_without_interactive_query_evidence_or_by_the_escape_hatch() {
        // The probe blocks for up to 2000 ms with no reply, so every negative gate must hold
        // BEFORE the query is written; a terminal that cannot answer must cost nothing.
        assert!(keyboard_enhancement_probe_allowed(true, true, None));
        assert!(keyboard_enhancement_probe_allowed(
            true,
            true,
            Some(OsStr::new("0"))
        ));
        assert!(keyboard_enhancement_probe_allowed(
            true,
            true,
            Some(OsStr::new("  "))
        ));
        assert!(!keyboard_enhancement_probe_allowed(false, true, None));
        assert!(!keyboard_enhancement_probe_allowed(true, false, None));
        assert!(!keyboard_enhancement_probe_allowed(
            true,
            true,
            Some(OsStr::new("1"))
        ));
        assert!(!keyboard_enhancement_probe_allowed(
            true,
            true,
            Some(OsStr::new("yes"))
        ));
    }

    #[test]
    fn keyboard_probe_demuxes_positive_response_and_device_sentinel() {
        let mut input = TerminalInput::default();
        input.keyboard.arm();
        let typed = key('x', KeyModifiers::NONE);
        assert_eq!(input.route_all(typed.clone()).keyboard, None);

        let mut responses = Vec::new();
        for event in csi_response("1", 'u')
            .into_iter()
            .chain(folded_csi_response("1;2", 'c'))
        {
            if let Some(response) = input.route_all(event).keyboard {
                responses.push(response);
            }
        }

        assert_eq!(
            responses,
            [
                KeyboardResponse::Enhancement,
                KeyboardResponse::DeviceAttributes
            ]
        );
        assert_eq!(input.queued.pop_front(), Some(typed));
        assert!(input.queued.is_empty());
        assert!(!input.keyboard.armed);
    }

    #[test]
    fn keyboard_probe_unsupported_and_false_prefix_paths_are_exact() {
        let mut input = TerminalInput::default();
        input.keyboard.arm();
        let false_prefix = [
            Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            key('[', KeyModifiers::NONE),
            key('A', KeyModifiers::NONE),
        ];
        for event in false_prefix.clone() {
            assert_eq!(input.route_all(event).keyboard, None);
        }
        for expected in false_prefix {
            assert_eq!(input.queued.pop_front(), Some(expected));
        }

        let mut response = None;
        for event in csi_response("1;2", 'c') {
            response = input.route_all(event).keyboard.or(response);
        }
        assert_eq!(response, Some(KeyboardResponse::DeviceAttributes));
        assert!(input.queued.is_empty());
        assert!(!input.keyboard.armed);
    }

    #[test]
    fn keyboard_probe_partial_candidate_expires_and_replays_exactly() {
        let mut input = TerminalInput::default();
        input.keyboard.arm();
        let partial = [
            Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            key('[', KeyModifiers::NONE),
            key('?', KeyModifiers::SHIFT),
        ];
        for event in partial.clone() {
            assert_eq!(input.route_all(event).keyboard, None);
        }
        input.expire_keyboard_candidate(Instant::now() + CANDIDATE_TIMEOUT);
        for expected in partial {
            assert_eq!(input.queued.pop_front(), Some(expected));
        }
        assert!(input.queued.is_empty());
        assert!(input.keyboard.armed);
    }

    #[test]
    fn keyboard_probe_release_overflow_replays_candidate_and_current_event() {
        let mut input = TerminalInput::default();
        input.keyboard.arm();
        let escape = Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(input.route_all(escape.clone()).keyboard, None);

        let retained_release = key_release('r');
        for _ in 1..MAX_KEYBOARD_RESPONSE_EVENTS {
            assert_eq!(input.route_all(retained_release.clone()).keyboard, None);
        }
        assert_eq!(
            input
                .keyboard
                .candidate
                .as_ref()
                .map(|candidate| candidate.events.len()),
            Some(MAX_KEYBOARD_RESPONSE_EVENTS)
        );

        let overflow_release = key_release('z');
        assert_eq!(input.route_all(overflow_release.clone()).keyboard, None);
        assert!(input.keyboard.candidate.is_none());
        assert_eq!(input.queued.len(), MAX_KEYBOARD_RESPONSE_EVENTS + 1);
        assert_eq!(input.queued.pop_front(), Some(escape));
        for _ in 1..MAX_KEYBOARD_RESPONSE_EVENTS {
            assert_eq!(input.queued.pop_front(), Some(retained_release.clone()));
        }
        assert_eq!(input.queued.pop_front(), Some(overflow_release));
        assert!(input.queued.is_empty());
    }

    #[test]
    fn keyboard_query_gate_is_one_shot_after_completion() {
        let gate = KeyboardQueryGate::new();
        assert_eq!(gate.state(), KeyboardQueryState::Fresh);
        assert!(gate.try_start());
        assert_eq!(gate.state(), KeyboardQueryState::Running);
        assert!(!gate.try_start());
        gate.complete();
        assert_eq!(gate.state(), KeyboardQueryState::Complete);
        assert!(!gate.try_start());
        gate.poison();
        assert_eq!(gate.state(), KeyboardQueryState::Complete);
    }

    #[test]
    fn keyboard_query_gate_poison_is_permanent() {
        let gate = KeyboardQueryGate::new();
        assert!(gate.try_start());
        gate.poison();
        assert_eq!(gate.state(), KeyboardQueryState::Poisoned);
        assert!(!gate.try_start());
        gate.complete();
        assert_eq!(gate.state(), KeyboardQueryState::Poisoned);
    }

    #[test]
    fn keyboard_query_request_stops_before_a_late_worker_can_start() {
        let caller = KeyboardQueryRequest::new(Instant::now() + Duration::from_secs(1));
        let delayed_worker = caller.clone();
        assert!(!delayed_worker.should_abort(Instant::now()));
        caller.cancel();
        assert!(delayed_worker.should_abort(Instant::now()));

        let expired = KeyboardQueryRequest::new(Instant::now());
        assert!(expired.should_abort(Instant::now()));
    }

    #[test]
    fn keyboard_query_write_requires_the_exact_frame() {
        assert!(exact_keyboard_query_write(KEYBOARD_ENHANCEMENT_QUERY.len()).is_ok());
        assert_eq!(
            exact_keyboard_query_write(KEYBOARD_ENHANCEMENT_QUERY.len() - 1)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WriteZero
        );
    }

    #[test]
    fn failed_keyboard_query_write_stays_armed_for_a_late_response() {
        let mut input = TerminalInput::default();
        let mut partial_write = Vec::new();
        assert!(
            input
                .begin_keyboard_query(|deadline| {
                    assert!(deadline > Instant::now());
                    partial_write.extend_from_slice(&KEYBOARD_ENHANCEMENT_QUERY[..3]);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "injected partial keyboard-query write",
                    ))
                })
                .is_none()
        );
        assert_eq!(partial_write, &KEYBOARD_ENHANCEMENT_QUERY[..3]);
        assert!(input.keyboard.armed);

        for event in csi_response("1;2", 'c') {
            let _ = input.route_all(event);
        }
        assert!(input.queued.is_empty());
        assert!(!input.keyboard.armed);
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
