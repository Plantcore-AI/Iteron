//! Tests for the platform-independent half of the pseudoterminal seam.
//!
//! Everything here runs on every host, including the macOS machine this module was written on.
//! The ConPTY calls themselves cannot be executed here and are not simulated: a fake that
//! "passes" without touching `CreatePseudoConsole` would only prove the fake works. What is
//! covered instead is the logic that is genuinely portable and that historically carries the
//! bugs — dimension validation, the columns/rows-to-`COORD` mapping, argv quoting, and the
//! teardown ordering constant that `ConPty::close` iterates.

use super::*;

// -- PtySize validation ----------------------------------------------------

#[test]
fn a_size_inside_the_shared_bounds_is_accepted_and_reports_what_it_was_given() {
    let size = PtySize::new(120, 40).expect("120x40 is ordinary");
    assert_eq!(size.cols(), 120);
    assert_eq!(size.rows(), 40);
}

#[test]
fn zero_is_rejected_on_each_axis_because_conpty_refuses_it() {
    assert_eq!(
        PtySize::new(0, 40),
        Err(PtyError::InvalidSize {
            field: "cols",
            value: 0,
            min: PTY_MIN_DIMENSION,
            max: PTY_MAX_DIMENSION,
        })
    );
    assert_eq!(
        PtySize::new(120, 0),
        Err(PtyError::InvalidSize {
            field: "rows",
            value: 0,
            min: PTY_MIN_DIMENSION,
            max: PTY_MAX_DIMENSION,
        })
    );
}

#[test]
fn the_ceiling_is_the_signed_16_bit_maximum_not_the_unsigned_one() {
    // A `winsize` would take 32768; a `COORD` would read it back as -32768. The shared type
    // takes the intersection so this can never reach a platform call.
    assert_eq!(PTY_MAX_DIMENSION, 32_767);
    assert!(PtySize::new(32_767, 32_767).is_ok());

    assert_eq!(
        PtySize::new(32_768, 40),
        Err(PtyError::InvalidSize {
            field: "cols",
            value: 32_768,
            min: 1,
            max: 32_767,
        })
    );
    assert_eq!(
        PtySize::new(120, 32_768),
        Err(PtyError::InvalidSize {
            field: "rows",
            value: 32_768,
            min: 1,
            max: 32_767,
        })
    );
    assert!(PtySize::new(u16::MAX, 40).is_err());
}

#[test]
fn cols_are_checked_before_rows_so_the_first_bad_axis_is_the_one_reported() {
    let error = PtySize::new(0, 0).unwrap_err();
    assert!(
        matches!(error, PtyError::InvalidSize { field: "cols", .. }),
        "expected the cols failure, got {error:?}"
    );
}

// -- The transposition guard ------------------------------------------------

#[test]
fn cols_map_to_coord_x_and_rows_map_to_coord_y() {
    // The regression test for the classic pseudoterminal bug. `struct winsize` lists ws_row
    // first and `COORD` lists X first, so a mechanical translation between the two transposes
    // the pair. Distinct values are used so a swap cannot pass.
    let size = PtySize::new(200, 50).unwrap();
    let (x, y) = size.to_coord_parts();
    assert_eq!(x, 200, "COORD.X must carry columns");
    assert_eq!(y, 50, "COORD.Y must carry rows");
}

#[test]
fn the_largest_legal_size_converts_without_wrapping_negative() {
    let (x, y) = PtySize::new(PTY_MAX_DIMENSION, PTY_MAX_DIMENSION)
        .unwrap()
        .to_coord_parts();
    assert_eq!((x, y), (i16::MAX, i16::MAX));
    assert!(
        x > 0 && y > 0,
        "a legal size must never present as negative"
    );
}

#[test]
fn size_displays_with_its_axis_order_spelled_out() {
    assert_eq!(
        PtySize::new(80, 24).unwrap().to_string(),
        "80x24 (cols x rows)"
    );
}

// -- Error taxonomy ---------------------------------------------------------

#[test]
fn hresult_and_win32_errors_stay_distinguishable_in_their_own_numbering() {
    // CreatePseudoConsole reports an HRESULT and does not set the last-error value; CreatePipe
    // does the opposite. Rendering both as one integer would give the reader a number they
    // cannot look up, so the two must not collapse into the same text.
    let hr = PtyError::Hresult {
        call: "CreatePseudoConsole",
        hr: -2147024809, // E_INVALIDARG
    };
    assert_eq!(
        hr.to_string(),
        "CreatePseudoConsole failed: HRESULT 0x80070057"
    );

    let os = PtyError::Os {
        call: "CreatePipe",
        code: 8, // ERROR_NOT_ENOUGH_MEMORY
    };
    assert_eq!(os.to_string(), "CreatePipe failed: Windows error 8");
    assert_ne!(hr, os);
}

#[test]
fn the_unsupported_message_names_the_backend_and_its_floor() {
    let text = PtyError::Unsupported.to_string();
    assert!(text.contains("ConPTY"), "{text}");
    assert!(text.contains("CreatePseudoConsole"), "{text}");
    assert!(text.contains("1809"), "{text}");
}

#[test]
fn an_invalid_size_says_which_axis_and_what_the_bounds_were() {
    let text = PtySize::new(0, 24).unwrap_err().to_string();
    assert_eq!(text, "pseudoterminal cols must be within 1..=32767; got 0");
}

// -- Command line quoting ---------------------------------------------------

#[test]
fn plain_arguments_are_passed_through_untouched() {
    assert_eq!(
        command_line_from_argv(&["cmd.exe", "/c", "ver"]).unwrap(),
        "cmd.exe /c ver"
    );
}

#[test]
fn arguments_containing_whitespace_are_quoted() {
    assert_eq!(
        command_line_from_argv(&["a.exe", "C:\\Program Files\\x"]).unwrap(),
        "a.exe \"C:\\Program Files\\x\""
    );
    // Tab, newline and vertical tab are separators for CommandLineToArgvW too.
    assert_eq!(
        command_line_from_argv(&["a.exe", "x\ty"]).unwrap(),
        "a.exe \"x\ty\""
    );
    assert_eq!(
        command_line_from_argv(&["a.exe", "x\u{b}y"]).unwrap(),
        "a.exe \"x\u{b}y\""
    );
}

#[test]
fn an_empty_argument_survives_as_an_empty_quoted_pair() {
    // Without the quotes this argument would simply vanish from the child's argv.
    assert_eq!(
        command_line_from_argv(&["a.exe", ""]).unwrap(),
        "a.exe \"\""
    );
}

#[test]
fn embedded_quotes_are_escaped_with_a_backslash() {
    assert_eq!(
        command_line_from_argv(&["a.exe", "say \"hi\""]).unwrap(),
        "a.exe \"say \\\"hi\\\"\""
    );
}

#[test]
fn backslashes_are_only_doubled_when_a_quote_follows_them() {
    // Interior backslashes not before a quote stay single.
    assert_eq!(
        command_line_from_argv(&["a.exe", "a\\b c"]).unwrap(),
        "a.exe \"a\\b c\""
    );
    // A run of backslashes immediately before an embedded quote is doubled, then the quote is
    // escaped: two backslashes + a quote becomes four backslashes + an escaped quote.
    assert_eq!(
        command_line_from_argv(&["a.exe", "a\\\\\"b"]).unwrap(),
        "a.exe \"a\\\\\\\\\\\"b\""
    );
}

#[test]
fn a_trailing_backslash_is_doubled_so_it_cannot_escape_the_closing_quote() {
    // `"C:\dir\"` would leave the argument unterminated; it must become `"C:\dir\\"`.
    assert_eq!(
        command_line_from_argv(&["a.exe", "C:\\dir with space\\"]).unwrap(),
        "a.exe \"C:\\dir with space\\\\\""
    );
    // Two trailing backslashes become four.
    assert_eq!(
        command_line_from_argv(&["a.exe", "x y\\\\"]).unwrap(),
        "a.exe \"x y\\\\\\\\\""
    );
}

#[test]
fn a_trailing_backslash_in_an_otherwise_plain_argument_is_left_alone() {
    // No quoting was needed, so no escaping is needed either; doubling here would corrupt a
    // perfectly ordinary path.
    assert_eq!(
        command_line_from_argv(&["a.exe", "C:\\dir\\"]).unwrap(),
        "a.exe C:\\dir\\"
    );
}

#[test]
fn an_empty_argv_is_refused_rather_than_producing_an_empty_command_line() {
    let empty: [&str; 0] = [];
    assert!(matches!(
        command_line_from_argv(&empty),
        Err(PtyError::Argv(_))
    ));
}

#[test]
fn an_interior_nul_is_refused_because_it_would_truncate_the_command_line() {
    let error = command_line_from_argv(&["a.exe", "we\0ird"]).unwrap_err();
    match error {
        PtyError::Argv(message) => {
            assert!(message.contains("NUL"), "{message}");
            assert!(
                message.contains('1'),
                "should name the argument index: {message}"
            );
        }
        other => panic!("expected an Argv error, got {other:?}"),
    }
}

/// A reverse implementation of `CommandLineToArgvW`'s parsing rules, used only to check that
/// what the quoter emits parses back to what went in. Round-tripping catches escaping mistakes
/// that hand-written expectations miss, because it does not depend on my having predicted the
/// right output string.
fn parse_command_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut started = false;
    let mut backslashes = 0usize;
    let flush_backslashes = |current: &mut String, backslashes: &mut usize, halve: bool| {
        let count = if halve {
            *backslashes / 2
        } else {
            *backslashes
        };
        for _ in 0..count {
            current.push('\\');
        }
        *backslashes = 0;
    };
    for character in line.chars() {
        match character {
            '\\' => {
                backslashes += 1;
                started = true;
            }
            '"' => {
                let escaped = backslashes % 2 == 1;
                flush_backslashes(&mut current, &mut backslashes, true);
                if escaped {
                    current.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                flush_backslashes(&mut current, &mut backslashes, false);
                if started {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                flush_backslashes(&mut current, &mut backslashes, false);
                current.push(c);
                started = true;
            }
        }
    }
    flush_backslashes(&mut current, &mut backslashes, false);
    if started {
        out.push(current);
    }
    out
}

#[test]
fn the_quoter_round_trips_through_the_documented_parsing_rules() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["cmd.exe", "/c", "ver"],
        vec!["a.exe", ""],
        vec!["a.exe", "C:\\Program Files\\app.exe"],
        vec!["a.exe", "C:\\dir with space\\"],
        vec!["a.exe", "say \"hi\""],
        vec!["a.exe", "a\\\\\"b"],
        vec!["a.exe", "x y\\\\"],
        vec!["a.exe", "trailing\\"],
        vec!["a.exe", "\\\\server\\share\\path with space"],
        vec!["a.exe", "--flag=value with space", "plain", "\"quoted\""],
        vec!["a.exe", "tab\there", "nl\nhere"],
        vec!["a.exe", "\u{4f60}\u{597d} \u{4e16}\u{754c}"],
    ];
    for case in cases {
        let line = command_line_from_argv(&case).unwrap();
        let parsed = parse_command_line(&line);
        assert_eq!(
            parsed, case,
            "round trip failed for {case:?} which rendered as {line}"
        );
    }
}

// -- Teardown ordering ------------------------------------------------------

#[test]
fn the_teardown_order_is_exactly_the_sequence_close_executes() {
    assert_eq!(
        TEARDOWN_ORDER,
        [
            TeardownStep::StartOutputDrain,
            TeardownStep::CloseInputWrite,
            TeardownStep::WaitForChild,
            TeardownStep::ClosePseudoConsole,
            TeardownStep::JoinOutputDrain,
            TeardownStep::CloseOutputRead,
        ]
    );
}

fn position(step: TeardownStep) -> usize {
    TEARDOWN_ORDER
        .iter()
        .position(|candidate| *candidate == step)
        .expect("every step appears in TEARDOWN_ORDER")
}

#[test]
fn the_drain_starts_before_the_pseudoconsole_is_closed() {
    // The deadlock rule. ClosePseudoConsole blocks until the pseudoconsole has flushed its
    // output, and a full anonymous pipe with no reader never drains, so closing first parks the
    // calling thread forever. This is the Windows counterpart of the Unix drain-before-reap
    // rule, escalated from lost output to a hang.
    assert!(
        position(TeardownStep::StartOutputDrain) < position(TeardownStep::ClosePseudoConsole),
        "ClosePseudoConsole would deadlock without a reader already running"
    );
}

#[test]
fn stdin_reaches_eof_before_the_child_is_waited_on() {
    // A child blocked reading stdin cannot exit until the write end is gone, so waiting first
    // would burn the whole timeout every run.
    assert!(position(TeardownStep::CloseInputWrite) < position(TeardownStep::WaitForChild));
}

#[test]
fn the_drain_is_joined_only_after_the_pseudoconsole_is_gone() {
    // EOF on the output pipe is produced by the pseudoconsole being closed; joining earlier
    // would wait on a thread that has no reason to finish yet.
    assert!(position(TeardownStep::ClosePseudoConsole) < position(TeardownStep::JoinOutputDrain));
}

#[test]
fn the_output_handle_is_released_last() {
    assert_eq!(
        position(TeardownStep::CloseOutputRead),
        TEARDOWN_ORDER.len() - 1
    );
}

#[test]
fn every_teardown_step_appears_exactly_once() {
    let mut seen = TEARDOWN_ORDER.to_vec();
    let before = seen.len();
    seen.sort_by_key(|step| format!("{step:?}"));
    seen.dedup();
    assert_eq!(seen.len(), before, "TEARDOWN_ORDER must not repeat a step");
}
