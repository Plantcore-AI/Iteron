//! Real Unix terminal clients exit and reattach without owning the independent service process.
use super::{
    PROTOCOL_VERSION, PausedProvider, RetainedCore, Scratch, connect, control, hello, only_rollout,
    read_service, receive, reply, send, spawn_core, take_stderr, timeout,
};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};
use serde_json::json;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

struct Ui {
    master: Option<Box<dyn MasterPty + Send>>,
    slave: Option<Box<dyn SlavePty + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    writer: Option<Box<dyn Write + Send>>,
    chunks: Option<Receiver<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
    baseline: Vec<u64>,
    capture: Vec<u8>,
    parser: vt100::Parser,
    cursor_queries: usize,
}
fn field(value: impl Into<u64>) -> u64 {
    value.into()
}
fn flags(master: &(dyn MasterPty + Send)) -> Vec<u64> {
    let state = master.get_termios().expect("actual terminal state");
    vec![
        field(state.input_flags.bits()),
        field(state.output_flags.bits()),
        field(state.control_flags.bits()),
        field(state.local_flags.bits()),
        u64::from(state.control_chars[libc::VMIN]),
        u64::from(state.control_chars[libc::VTIME]),
    ]
}
impl Ui {
    fn start(scratch: &Scratch, endpoint: SocketAddr, service_id: &str, token_file: &Path) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 140,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let baseline = flags(pair.master.as_ref());
        let mut command = CommandBuilder::new("/bin/sh");
        command.env_clear();
        command.env("HOME", scratch.home());
        command.env("PATH", "/usr/bin:/bin");
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        command.env("LANG", "C.UTF-8");
        command.cwd(scratch.repo());
        // Only the create-only fixture file path appears in argv. Token bytes are ordinary stdin
        // data, never terminal-echoed keystrokes, environment, arguments or a printed diagnostic.
        command.args([
            "-c",
            "exec \"$1\" attach \"$2\" --service-id \"$3\" <\"$4\"",
            "iteron-attach-fixture",
            env!("CARGO_BIN_EXE_iteron"),
        ]);
        command.arg(endpoint.to_string());
        command.arg(service_id);
        command.arg(token_file);
        let child = pair.slave.spawn_command(command).unwrap();
        let writer = pair.master.take_writer().unwrap();
        let mut source = pair.master.try_clone_reader().unwrap();
        let (send, receive) = mpsc::sync_channel(32);
        let reader = std::thread::spawn(move || {
            let mut buffer = [0u8; 8192];
            loop {
                match source.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        if send.send(buffer[..count].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            master: Some(pair.master),
            slave: Some(pair.slave),
            child: Some(child),
            writer: Some(writer),
            chunks: Some(receive),
            reader: Some(reader),
            baseline,
            capture: Vec::new(),
            parser: vt100::Parser::new(24, 140, 4096),
            cursor_queries: 0,
        }
    }
    fn write(&mut self, bytes: &[u8]) {
        let writer = self.writer.as_mut().unwrap();
        writer.write_all(bytes).unwrap();
        writer.flush().unwrap();
    }
    fn ingest(&mut self, bytes: &[u8]) {
        assert!(
            self.capture.len().saturating_add(bytes.len()) <= 2 * 1024 * 1024,
            "bounded actual terminal capture"
        );
        self.capture.extend_from_slice(bytes);
        self.parser.process(bytes);
        let queries = self
            .capture
            .windows(4)
            .filter(|bytes| *bytes == b"\x1b[6n")
            .count();
        while self.cursor_queries < queries {
            self.cursor_queries += 1;
            let (row, column) = self.parser.screen().cursor_position();
            self.write(format!("\x1b[{};{}R", row + 1, column + 1).as_bytes());
        }
    }
    fn visible(&mut self, text: &str) {
        let deadline = Instant::now() + timeout();
        while Instant::now() < deadline {
            let next = self
                .chunks
                .as_ref()
                .unwrap()
                .recv_timeout(Duration::from_millis(20));
            if let Ok(bytes) = next {
                self.ingest(&bytes);
            }
            if self.parser.screen().contents().contains(text) {
                return;
            }
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "attached client exited before the actual frame"
            );
        }
        panic!("expected attached-client terminal frame was not observed");
    }
    fn detach(mut self, token: &str) {
        self.write(b"/detach\r");
        let deadline = Instant::now() + timeout();
        loop {
            while let Ok(bytes) = self.chunks.as_ref().unwrap().try_recv() {
                self.ingest(&bytes);
            }
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                assert!(status.success());
                self.child = None;
                break;
            }
            assert!(
                Instant::now() < deadline,
                "actual attached-client exit was not observed"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            flags(self.master.as_ref().unwrap().as_ref()),
            self.baseline,
            "native raw-mode flags must be restored"
        );
        assert!(
            !self
                .capture
                .windows(token.len())
                .any(|bytes| bytes == token.as_bytes())
        );
        assert!(
            self.capture.windows(8).any(|bytes| bytes == b"\x1b[?1049l")
                || !self.capture.windows(8).any(|bytes| bytes == b"\x1b[?1049h"),
            "an entered alternate screen must be restored"
        );
    }
}
impl Drop for Ui {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.writer = None;
        self.slave = None;
        self.master = None;
        self.chunks = None;
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
#[test]
fn actual_tui_exit_retains_backend_turn_and_reopened_tui_observes_same_run_terminal() {
    let provider = PausedProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    let (process, token, endpoint) = spawn_core(&scratch);
    let mut core = RetainedCore(Some(process));
    let mut socket = connect(endpoint);
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let mut greeting = hello(&token, PROTOCOL_VERSION, 0);
    greeting["product_contract_version"] = json!(1);
    greeting["live_only"] = json!(true);
    send(&mut socket, greeting);
    assert_eq!(receive(&mut reader)["type"], "hello");
    let service = read_service(&mut socket, &mut reader, 1);
    let scope = service["service"]["scope"].clone();
    let run = service["service"]["current_run_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token_file = scratch.root.join("attach-token-input");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token_file)
            .unwrap();
        writeln!(file, "{token}").unwrap();
    }
    let mut first = Ui::start(
        &scratch,
        endpoint,
        scope["service_id"].as_str().unwrap(),
        &token_file,
    );
    first.visible("Attached");
    first.write(b"keep the actual backend turn running\r");
    provider.request_seen.recv_timeout(timeout()).unwrap();
    first.detach(&token);
    assert!(core.0.as_mut().unwrap().child.try_wait().unwrap().is_none());
    let current = read_service(&mut socket, &mut reader, 2);
    assert_eq!(current["service"]["scope"], scope);
    assert_eq!(current["service"]["current_run_id"], run);
    assert_eq!(current["service"]["stopping"], false);
    let mut second = Ui::start(
        &scratch,
        endpoint,
        scope["service_id"].as_str().unwrap(),
        &token_file,
    );
    second.visible("Attached");
    provider.release.send(()).unwrap();
    second.visible("parity reply");
    second.visible("completed");
    second.detach(&token);
    assert!(core.0.as_mut().unwrap().child.try_wait().unwrap().is_none());
    let current = read_service(&mut socket, &mut reader, 3);
    assert_eq!(current["service"]["current_run_id"], run);
    assert_eq!(current["service"]["stopping"], false);
    send(
        &mut socket,
        control(
            4,
            PROTOCOL_VERSION,
            json!({"type":"resident_service_v1","command":{"action":"stop","scope":scope}}),
        ),
    );
    assert_eq!(reply(&mut reader, 4)["status"], "requested");
    drop(reader);
    drop(socket);
    let deadline = Instant::now() + timeout();
    loop {
        if let Some(status) = core.0.as_mut().unwrap().child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let logs = take_stderr(core.0.as_mut().unwrap());
    core.0 = None;
    assert!(
        !logs
            .windows(token.len())
            .any(|bytes| bytes == token.as_bytes())
    );
    provider.finish();
    let path = only_rollout(&scratch.runs());
    assert_eq!(
        path.file_stem().and_then(|name| name.to_str()),
        Some(run.as_str())
    );
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                &event.kind,
                iteron_protocol::EventKind::EffectIntent {
                    provider_route_attempt: Some(_),
                    ..
                }
            ))
            .count(),
        1
    );
    let answer=events.iter().find(|event|matches!(&event.kind,iteron_protocol::EventKind::Message{message} if message.role==iteron_protocol::Role::Assistant && message.content.iter().any(|block|matches!(block,iteron_protocol::Block::Text{text}if text=="parity reply")))).unwrap();
    assert!(events.iter().any(|event| event.seq > answer.seq
        && event.turn == answer.turn
        && matches!(&event.kind,iteron_protocol::EventKind::Done{outcome}if outcome=="Done")));
    std::fs::remove_file(token_file).unwrap();
}
