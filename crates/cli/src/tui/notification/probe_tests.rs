use super::*;

#[test]
fn terminal_probes_share_the_frame_writer_and_follow_the_shell_in_order() {
    let (mut output, mut transport) = LiveTerminalWriter::with_desktop_sequences(Vec::new(), true);
    output.write_all(b"input-ready-shell").unwrap();
    transport
        .admit_probe(super::super::terminal_input::KEYBOARD_ENHANCEMENT_PROTOCOL_QUERY)
        .unwrap();
    transport
        .admit_probe(super::super::terminal_input::OSC11_QUERY)
        .unwrap();
    assert_eq!(
        transport
            .admit_probe(b"\x1b]unowned\x07")
            .expect_err("only the two closed probe frames are admitted")
            .kind(),
        io::ErrorKind::InvalidInput
    );
    output.flush().unwrap();
    assert_eq!(
        output.into_inner(),
        [
            b"input-ready-shell".as_slice(),
            super::super::terminal_input::KEYBOARD_ENHANCEMENT_PROTOCOL_QUERY,
            super::super::terminal_input::OSC11_QUERY,
        ]
        .concat(),
        "the retained frame is written first, then complete probe frames on the same owner"
    );
}
