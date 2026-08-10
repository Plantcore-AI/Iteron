//! Window title: set it, and be able to give it back.
//!
//! Setting a terminal title is a side effect on a surface the agent borrowed and does not own. An
//! agent that sets the title and exits leaves the operator's tab permanently named after a session
//! that ended, in every other shell they open in it. So the title is pushed onto the terminal's own
//! title stack before it is changed, and popped on the way out -- rather than "restored" by writing
//! back a title we guessed, which is wrong whenever the operator had set one themselves.
//!
//! The stack is XTerm's `CSI 22 ; 2 t` / `CSI 23 ; 2 t`, which every terminal this ships to either
//! implements or ignores. Ignoring it is safe: the fallback is the pre-existing behaviour of a
//! title that stays set, never a corrupted screen.

use crate::safe_text::{Unsafe, check};

/// `ESC ] 2 ; <text> BEL` -- set the window title.
///
/// BEL rather than `ESC \` as the terminator: both are legal, and BEL is accepted by strictly more
/// terminal emulators in the wild.
pub fn set_title(text: &str) -> Result<String, Unsafe> {
    // Refuses rather than sanitising. A title is not a display path that must show something; if
    // the value is hostile the correct action is to not set a title at all.
    check(text)?;
    Ok(format!("\u{1b}]2;{text}\u{7}"))
}

/// `CSI 22 ; 2 t` -- push the current title onto the terminal's stack.
pub fn title_stack_push() -> &'static str {
    "\u{1b}[22;2t"
}

/// `CSI 23 ; 2 t` -- pop it back.
pub fn title_stack_pop() -> &'static str {
    "\u{1b}[23;2t"
}

/// The full restore sequence to emit on shutdown.
pub fn restore_title() -> &'static str {
    title_stack_pop()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safe_text::MAX_FIELD_BYTES;

    #[test]
    fn a_title_is_wrapped_in_osc_2_and_bel() {
        assert_eq!(
            set_title("iteron — main").unwrap(),
            "\u{1b}]2;iteron — main\u{7}"
        );
    }

    #[test]
    fn a_hostile_title_is_refused_rather_than_repaired() {
        // Repairing here would let a caller believe it set the title it asked for. Refusing means
        // no title is set, which is the safe outcome for a borrowed surface.
        assert!(matches!(
            set_title("a\u{7}\u{1b}]0;evil\u{7}"),
            Err(Unsafe::ControlByte { .. })
        ));
    }

    #[test]
    fn the_terminator_cannot_be_closed_early_by_the_payload() {
        // Both OSC terminators must be impossible inside the payload: BEL is a C0 control and
        // `ESC \` starts with ESC, so `check` already excludes them. This pins that.
        for payload in ["x\u{7}y", "x\u{1b}\\y", "x\u{9c}y"] {
            assert!(set_title(payload).is_err(), "{payload:?} must be refused");
        }
    }

    #[test]
    fn an_overlong_title_is_refused() {
        assert!(set_title(&"a".repeat(MAX_FIELD_BYTES + 1)).is_err());
    }

    #[test]
    fn push_and_pop_are_the_documented_xterm_stack_sequences() {
        assert_eq!(title_stack_push(), "\u{1b}[22;2t");
        assert_eq!(title_stack_pop(), "\u{1b}[23;2t");
        assert_eq!(restore_title(), title_stack_pop());
    }

    #[test]
    fn a_full_session_is_push_then_set_then_pop() {
        // The ordering that leaves the operator's tab as it was found.
        let session = format!(
            "{}{}{}",
            title_stack_push(),
            set_title("iteron").unwrap(),
            restore_title()
        );
        assert!(session.starts_with("\u{1b}[22;2t"));
        assert!(session.ends_with("\u{1b}[23;2t"));
    }

    #[test]
    fn non_ascii_titles_are_allowed() {
        assert!(set_title("主线 · iteron 🚀").is_ok());
    }
}
