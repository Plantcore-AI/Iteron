//! Shared physical server launch and bounded control observation for native host journeys.
use super::{
    BufReader, CoreProcess, Instant, Path, Scratch, SocketAddr, TcpStream, Value,
    core_command_with_launch, fresh_bearer_token, receive, spawn_core_command_with_token_input,
    timeout, wait_for_listening,
};

pub(super) fn launch(
    scratch: &Scratch,
    workspace: &Path,
    turns: u32,
    arguments: &[&str],
) -> (CoreProcess, String, SocketAddr) {
    let token = fresh_bearer_token();
    let mut process = spawn_core_command_with_token_input(
        core_command_with_launch(scratch, workspace, turns, arguments),
        token.as_bytes(),
    );
    let address = wait_for_listening(&mut process);
    (process, token, address)
}
pub(super) fn matching_control(reader: &mut BufReader<TcpStream>, request_id: u64) -> Value {
    let deadline = Instant::now() + timeout();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "native host control {request_id} timed out"
        );
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(reader);
        if frame["type"] == "control_reply" && frame["request_id"] == request_id {
            return frame["reply"].clone();
        }
    }
}

/// The transport rejects an observer before dispatch, so this is an error frame rather than a
/// correlated App Server control reply. Each caller has exactly one outstanding observer request.
pub(super) fn observer_authority_denied(reader: &mut BufReader<TcpStream>) {
    let deadline = Instant::now() + timeout();
    for _ in 0..256 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "observer authority denial timed out");
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(reader);
        if frame["type"] == "error" {
            assert_eq!(frame["code"], "observer_authority");
            return;
        }
        assert_ne!(
            frame["type"], "control_reply",
            "observer mutation reached dispatch"
        );
    }
    panic!("bounded observer replay did not reach the authority denial");
}
