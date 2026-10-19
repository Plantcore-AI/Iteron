use iteron_protocol::PROTOCOL_VERSION;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(20);

struct OwnedServer {
    child: Child,
    root: PathBuf,
}

impl Drop for OwnedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_iteron-app-server"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

#[test]
fn identity_and_contract_do_not_require_a_provider_or_terminal() {
    let version = command().arg("-V").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        format!("iteron-app-server {}", env!("CARGO_PKG_VERSION"))
    );
    let help = command().arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--listen"));
    assert!(!help.contains("--tui"));
    let contract = command().arg("--machine-contract").output().unwrap();
    assert!(contract.status.success());
    let contract: Value = serde_json::from_slice(&contract.stdout).unwrap();
    assert_eq!(contract["application"], "iteron-app-server");
    assert_eq!(contract["terminal_frontend"], false);
    assert_eq!(contract["protocol_version"], PROTOCOL_VERSION);
}

fn receive(reader: &mut BufReader<TcpStream>) -> Value {
    let mut line = String::new();
    reader.take(1024 * 1024).read_line(&mut line).unwrap();
    serde_json::from_str(&line).expect("bounded transport frame")
}

fn send(connection: &mut TcpStream, value: Value) {
    let mut frame = serde_json::to_vec(&value).unwrap();
    frame.push(b'\n');
    connection.write_all(&frame).unwrap();
}

fn control(connection: &mut TcpStream, request: u64, value: Value) {
    send(
        connection,
        json!({
            "type":"control", "protocol_version":PROTOCOL_VERSION,
            "request_id":request, "control":value,
        }),
    );
}

fn reply(reader: &mut BufReader<TcpStream>, request: u64) -> Value {
    let deadline = Instant::now() + TIMEOUT;
    for _ in 0..1024 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "server response deadline");
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(reader);
        assert_ne!(frame["type"], "error");
        if frame["type"] == "control_reply" && frame["request_id"] == request {
            return frame["reply"].clone();
        }
    }
    panic!("server response exceeded bounded frame count")
}

#[test]
fn independent_server_authenticates_reconnects_and_stops_through_shared_contract() {
    let provider = TcpListener::bind("127.0.0.1:0").unwrap();
    provider.set_nonblocking(true).unwrap();
    let root =
        std::env::temp_dir().join(format!("iteron-independent-server-{}", std::process::id()));
    fs::create_dir_all(root.join("home/.iteron")).unwrap();
    fs::create_dir_all(root.join("repo")).unwrap();
    let root = root.canonicalize().unwrap();
    let config = json!({
        "provider":"standalone-fixture", "model":"fixture-model", "effort":"low",
        "providers":[{
            "id":"standalone-fixture", "adapter":"openai_chat", "error_profile":"custom",
            "api_root":format!("http://{}/v1",provider.local_addr().unwrap()),
            "key_env":"ITERON_STANDALONE_TEST_KEY", "enabled":true, "catalog":false,
            "models":["fixture-model"],
            "model_capabilities":{"fixture-model":{"context_window_tokens":1000000}}
        }]
    });
    fs::write(
        root.join("home/.iteron/config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let child = command()
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("ITERON_STANDALONE_TEST_KEY", "synthetic-loopback-fixture")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .arg("--repo")
        .arg(root.join("repo"))
        .arg("--runs-dir")
        .arg(root.join("runs"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut server = OwnedServer { child, root };
    // Per-process synthetic bearer: it is passed only on the inherited pipe and authenticated socket.
    let token = format!("{:064x}", std::process::id());
    server
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(token.as_bytes())
        .unwrap();
    let stderr = server.child.stderr.take().unwrap();
    let (ready, received) = std::sync::mpsc::sync_channel(1);
    let logs = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr.take(2 * 1024 * 1024));
        let mut captured = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if let Ok(value) = serde_json::from_str::<Value>(&line)
                && value["event"] == "listening"
            {
                let endpoint = value["listen"]
                    .as_str()
                    .unwrap()
                    .parse::<SocketAddr>()
                    .unwrap();
                let _ = ready.try_send(endpoint);
            }
            captured.push_str(&line);
        }
        captured
    });
    let endpoint = received
        .recv_timeout(TIMEOUT)
        .expect("independent server listening");
    let mut scope = Value::Null;
    for generation in 1..=2 {
        let mut stream = TcpStream::connect_timeout(&endpoint, TIMEOUT).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        send(
            &mut stream,
            json!({
                "type":"hello", "bearer_token":token, "protocol_version":PROTOCOL_VERSION,
                "product_contract_version":iteron_protocol::product_contract::PRODUCT_CONTRACT_VERSION,
                "live_only":true,
            }),
        );
        assert_eq!(receive(&mut reader)["type"], "hello");
        control(
            &mut stream,
            1,
            json!({"type":"resident_service_v1","command":{"action":"read"}}),
        );
        let current = reply(&mut reader, 1);
        if generation == 1 {
            scope = current["service"]["scope"].clone();
            assert!(scope.is_object());
        } else {
            assert_eq!(current["service"]["scope"], scope);
            control(
                &mut stream,
                2,
                json!({"type":"resident_service_v1","command":{"action":"stop","scope":scope}}),
            );
            assert_eq!(reply(&mut reader, 2)["status"], "requested");
        }
    }
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "shared server teardown deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!logs.join().unwrap().contains(&token));
    assert_eq!(
        provider.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
