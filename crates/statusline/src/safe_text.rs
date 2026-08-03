//! Make untrusted text safe to place inside a terminal control sequence.
//!
//! A status line and a window title are built from values the agent does not control: a branch
//! name, a file path, a model identifier returned by a provider. Those reach the terminal *inside*
//! an escape sequence, which makes them an injection surface rather than a display concern. A
//! branch literally named `x\x1b]0;pwned\x07` sets the operator's window title when it is rendered;
//! a value containing `\x1b[2J` clears their screen.
//!
//! The rule here is deliberately not "strip the escapes". Stripping is a silent repair, and a
//! caller cannot tell the difference between a branch named `main` and one named `ma\x1bin` after
//! the fact. Instead this module refuses, so a hostile value produces a typed error, and offers an
//! explicit lossy renderer for the display paths that must show *something*.

/// Why a value cannot be placed in a control sequence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unsafe {
    #[error("value contains control byte {byte:#04x} at index {index}")]
    ControlByte { byte: u8, index: usize },
    #[error("value is {len} bytes, over the {limit}-byte field limit")]
    TooLong { len: usize, limit: usize },
}

/// Longest single interpolated value. A title is a single line in a chrome the operator did not
/// size; an unbounded branch name would push everything else out of it.
pub const MAX_FIELD_BYTES: usize = 256;

/// True for scalar values that must never reach the terminal inside a control sequence.
///
/// C0 (`U+0000..=U+001F`) covers ESC and BEL, the two that begin and end an OSC. DEL and the C1
/// range (`U+0080..=U+009F`) are included because several terminals still decode C1 directly, which
/// makes `U+009C` a String Terminator and `U+009B` a CSI introducer -- an injection that survives
/// any filter written only against ESC.
fn is_forbidden(ch: char) -> bool {
    let c = ch as u32;
    c <= 0x1F || c == 0x7F || (0x80..=0x9F).contains(&c)
}

/// Accept a value for use inside a control sequence, or say exactly why not.
///
/// This scans `char`s, not bytes, and the distinction is load-bearing. UTF-8 encodes every
/// multi-byte character using continuation bytes in `0x80..=0xBF`, which *overlaps the C1 range
/// exactly*. A byte-oriented scan therefore cannot tell `U+009C` (String Terminator) from the
/// second byte of `中`, and rejects all non-ASCII text as hostile. Because `&str` is guaranteed
/// valid UTF-8, iterating scalar values makes the two unambiguous.
pub fn check(value: &str) -> Result<(), Unsafe> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(Unsafe::TooLong {
            len: value.len(),
            limit: MAX_FIELD_BYTES,
        });
    }
    for (index, ch) in value.char_indices() {
        if is_forbidden(ch) {
            // Reported as a byte so the operator can locate it in the raw value; every forbidden
            // scalar here is single-byte in UTF-8 except the C1 range, whose lead byte is `0xC2`.
            return Err(Unsafe::ControlByte {
                byte: ch as u32 as u8,
                index,
            });
        }
    }
    Ok(())
}

/// Render a value for display, replacing every forbidden byte with `U+FFFD`.
///
/// This is the explicit lossy path. It exists so a status line can still show a weird-but-harmless
/// filename, and it is deliberately separate from [`check`] so no caller performs a silent repair
/// while believing it validated.
pub fn lossy(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        out.push(if is_forbidden(ch) { '\u{FFFD}' } else { ch });
    }
    if out.len() > MAX_FIELD_BYTES {
        // Truncate on a char boundary, then mark it: a silently shortened path reads as a
        // different path, which is worse than an obviously elided one.
        let mut end = MAX_FIELD_BYTES.saturating_sub(1);
        while end > 0 && !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_osc_injection_in_a_branch_name_is_refused() {
        // The real attack: a branch whose name closes the current sequence and opens a title one.
        let hostile = "feature\u{1b}]0;pwned\u{7}";
        assert_eq!(
            check(hostile),
            Err(Unsafe::ControlByte {
                byte: 0x1b,
                index: 7
            })
        );
    }

    #[test]
    fn a_csi_screen_clear_is_refused() {
        assert!(matches!(
            check("x\u{1b}[2J"),
            Err(Unsafe::ControlByte { byte: 0x1b, .. })
        ));
    }

    #[test]
    fn c1_controls_are_refused_not_only_esc() {
        // 0x9B is a one-byte CSI and 0x9C a one-byte String Terminator in terminals that decode
        // C1. A filter written only against 0x1B lets both through.
        for ch in ['\u{9b}', '\u{9c}', '\u{90}'] {
            let value = format!("a{ch}b");
            assert!(
                matches!(check(&value), Err(Unsafe::ControlByte { .. })),
                "U+{:04X} must be refused",
                ch as u32
            );
        }
    }

    #[test]
    fn bel_and_del_and_newline_are_refused() {
        for byte in ['\u{7}', '\u{7f}', '\n', '\r', '\t'] {
            assert!(
                matches!(check(&format!("a{byte}")), Err(Unsafe::ControlByte { .. })),
                "{byte:?} must be refused"
            );
        }
    }

    #[test]
    fn ordinary_and_non_ascii_text_is_accepted() {
        // CJK and emoji must pass: their UTF-8 bytes are all >= 0x80 but none fall in C1, so a
        // byte scan accepts them while a naive "any byte >= 0x7F" filter would not.
        for value in ["main", "feat/br-9", "分支/主线", "release 🚀", "a-b_c.d"] {
            assert_eq!(check(value), Ok(()), "{value} must be accepted");
        }
    }

    #[test]
    fn a_c1_control_and_a_utf8_continuation_byte_are_not_confused() {
        // The trap this pins, which a byte-oriented scan cannot escape: UTF-8 continuation bytes
        // occupy 0x80..=0xBF, which *contains* the whole C1 range 0x80..=0x9F. `一` encodes as
        // E4 B8 80, and that final 0x80 is byte-identical to the C1 control PAD.
        assert_eq!("一".as_bytes(), &[0xE4, 0xB8, 0x80]);
        assert!("一".bytes().any(|b| (0x80..=0x9F).contains(&b)));
        assert_eq!("分".as_bytes(), &[0xE5, 0x88, 0x86]);

        // As scalar values the two are unambiguous, so ordinary text is accepted and the real
        // control is refused. A byte scan cannot make this distinction and rejects both.
        assert_eq!(check("一分"), Ok(()));
        assert!(matches!(check("\u{9c}"), Err(Unsafe::ControlByte { .. })));
    }

    #[test]
    fn an_overlong_value_is_refused_with_its_length() {
        let long = "a".repeat(MAX_FIELD_BYTES + 1);
        assert_eq!(
            check(&long),
            Err(Unsafe::TooLong {
                len: MAX_FIELD_BYTES + 1,
                limit: MAX_FIELD_BYTES
            })
        );
    }

    #[test]
    fn lossy_replaces_rather_than_deletes_so_the_value_still_looks_wrong() {
        // Deleting would turn `ma<ESC>in` into `main`, which is indistinguishable from the real
        // branch. Replacement keeps it visibly different.
        assert_eq!(lossy("ma\u{1b}in"), "ma\u{fffd}in");
        assert_ne!(lossy("ma\u{1b}in"), "main");
    }

    #[test]
    fn lossy_output_is_always_safe_to_embed() {
        let hostile = "x\u{1b}]0;t\u{7}\u{9c}\n";
        let cleaned = lossy(hostile);
        assert_eq!(check(&cleaned), Ok(()), "lossy output must satisfy check");
    }

    #[test]
    fn lossy_truncation_marks_itself_and_respects_char_boundaries() {
        let long = "中".repeat(MAX_FIELD_BYTES); // 3 bytes each, far over the limit
        let cleaned = lossy(&long);
        assert!(cleaned.ends_with('…'), "elision must be visible");
        assert!(cleaned.len() <= MAX_FIELD_BYTES + 3);
        // Round-trips as valid UTF-8 with no split character.
        assert!(cleaned.chars().all(|c| c == '…' || c == '中'));
    }
}
