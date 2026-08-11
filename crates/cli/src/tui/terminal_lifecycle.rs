//! Ownership and restoration of terminal process state.

use super::{keyboard_enhancement, mouse_capture, terminal_input};
use crate::theme;
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::{cursor, execute, terminal};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

/// One interactive frontend owns the process terminal title stack frame.
static TITLE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Best-effort terminal restore shared by Drop, panic, signal and explicit shutdown paths.
pub(super) fn restore_terminal(keyboard: &keyboard_enhancement::Restorer) {
    let mut stdout = std::io::stdout();
    let _ = keyboard.restore(&mut stdout);
    restore_terminal_modes(&mut stdout);
}

fn restore_terminal_modes(stdout: &mut impl Write) {
    restore_terminal_title_to(stdout, &TITLE_ACTIVE);
    let _ = terminal::disable_raw_mode();
    let _ = execute!(stdout, DisableBracketedPaste);
    let _ = mouse_capture::release(stdout);
    let _ = execute!(stdout, cursor::Show);
    let _ = execute!(
        stdout,
        crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
    );
    let _ = execute!(stdout, crossterm::style::ResetColor);
    let _ = execute!(stdout, terminal::LeaveAlternateScreen);
}

pub(super) fn set_terminal_title_to(
    writer: &mut impl Write,
    capabilities: iteron_statusline::Capabilities,
    title: &str,
    active: &AtomicBool,
) -> std::io::Result<bool> {
    if !capabilities.title_stack_restores() {
        return Ok(false);
    }
    let title = match iteron_statusline::set_title(title) {
        Ok(title) => title,
        Err(_) => return Ok(false),
    };
    writer.write_all(iteron_statusline::title_stack_push().as_bytes())?;
    if let Err(error) = writer.write_all(title.as_bytes()) {
        let _ = writer.write_all(iteron_statusline::restore_title().as_bytes());
        let _ = writer.flush();
        return Err(error);
    }
    writer.flush()?;
    active.store(true, Ordering::Release);
    Ok(true)
}

pub(super) fn replace_terminal_title_to(
    writer: &mut impl Write,
    capabilities: iteron_statusline::Capabilities,
    title: &str,
    active: &AtomicBool,
) -> std::io::Result<bool> {
    if !active.load(Ordering::Acquire) || !capabilities.title_stack_restores() {
        return Ok(false);
    }
    let title = match iteron_statusline::set_title(title) {
        Ok(title) => title,
        Err(_) => return Ok(false),
    };
    writer.write_all(title.as_bytes())?;
    writer.flush()?;
    Ok(true)
}

pub(super) fn restore_terminal_title_to(writer: &mut impl Write, active: &AtomicBool) {
    if active.swap(false, Ordering::AcqRel) {
        let _ = writer.write_all(iteron_statusline::restore_title().as_bytes());
        let _ = writer.flush();
    }
}

fn restore_terminal_after_panic(keyboard: &keyboard_enhancement::Restorer) {
    let mut stdout = std::io::stdout();
    let _ = restore_terminal_after_panic_to(keyboard, &mut stdout);
}

pub(super) fn restore_terminal_after_panic_to(
    keyboard: &keyboard_enhancement::Restorer,
    stdout: &mut impl Write,
) -> bool {
    if matches!(
        keyboard.restore_after_panic(stdout),
        Ok(keyboard_enhancement::PanicRestoreOutcome::Deferred)
    ) {
        return false;
    }
    restore_terminal_modes(stdout);
    true
}

/// Owns terminal modes and restores them on every catchable exit.
pub(super) struct TermGuard {
    keyboard: keyboard_enhancement::Controller,
    mouse_capture: mouse_capture::Controller<std::io::Stdout>,
}

impl TermGuard {
    pub(super) fn new() -> std::io::Result<Self> {
        let keyboard = keyboard_enhancement::Controller::default();
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(
            std::io::stdout(),
            terminal::EnterAlternateScreen,
            EnableBracketedPaste
        ) {
            restore_terminal(&keyboard.restorer());
            return Err(error);
        }
        let mouse_capture = match mouse_capture::Controller::capture_to_terminal(std::io::stdout())
        {
            Ok(mouse_capture) => mouse_capture,
            Err(error) => {
                restore_terminal(&keyboard.restorer());
                return Err(error);
            }
        };
        let default = std::panic::take_hook();
        let panic_keyboard = keyboard.restorer();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal_after_panic(&panic_keyboard);
            default(info);
        }));
        Ok(Self {
            keyboard,
            mouse_capture,
        })
    }

    pub(super) fn keyboard_restorer(&self) -> keyboard_enhancement::Restorer {
        self.keyboard.restorer()
    }

    pub(super) fn set_title(
        &self,
        capabilities: iteron_statusline::Capabilities,
        title: &str,
    ) -> std::io::Result<bool> {
        set_terminal_title_to(&mut std::io::stdout(), capabilities, title, &TITLE_ACTIVE)
    }

    pub(super) fn replace_title(
        &self,
        capabilities: iteron_statusline::Capabilities,
        title: &str,
    ) -> std::io::Result<bool> {
        replace_terminal_title_to(&mut std::io::stdout(), capabilities, title, &TITLE_ACTIVE)
    }

    pub(super) fn negotiate_keyboard(
        &self,
        terminal_input: &mut terminal_input::TerminalInput,
        environment: &theme::capabilities::Environment,
    ) -> std::io::Result<bool> {
        self.keyboard
            .negotiate(terminal_input.supports_keyboard_enhancement(environment))
    }

    pub(super) fn toggle_mouse_capture(&mut self) -> std::io::Result<mouse_capture::State> {
        self.mouse_capture.toggle()
    }

    /// Temporarily hand the physical terminal to an operator-owned external editor.
    pub(super) fn suspend_for_external_editor(&mut self) -> std::io::Result<mouse_capture::State> {
        let desired_mouse = self.mouse_capture.state();
        self.mouse_capture.release()?;
        let mut stdout = std::io::stdout();
        let suspended = (|| {
            let _ = self.keyboard.restorer().restore(&mut stdout)?;
            terminal::disable_raw_mode()?;
            execute!(stdout, DisableBracketedPaste)?;
            execute!(stdout, cursor::Show)?;
            execute!(
                stdout,
                crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
            )?;
            execute!(stdout, crossterm::style::ResetColor)?;
            execute!(stdout, terminal::LeaveAlternateScreen)?;
            Ok(())
        })();
        if suspended.is_err() {
            restore_terminal_modes(&mut stdout);
        }
        suspended.map(|()| desired_mouse)
    }

    pub(super) fn resume_after_external_editor(
        &mut self,
        desired_mouse: mouse_capture::State,
    ) -> std::io::Result<()> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(
            std::io::stdout(),
            terminal::EnterAlternateScreen,
            EnableBracketedPaste
        ) {
            restore_terminal(&self.keyboard.restorer());
            return Err(error);
        }
        self.mouse_capture.set(desired_mouse)?;
        Ok(())
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = self.mouse_capture.release();
        restore_terminal(&self.keyboard.restorer());
    }
}
