use super::*;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn huge_single_line_is_fully_drained_but_memory_retention_is_bounded() {
    let limit = 4 * 1024;
    let (mut writer, mut reader) = tokio::io::duplex(1024);
    let producer = tokio::spawn(async move {
        let flood = vec![b'x'; 1024 * 1024];
        writer.write_all(&flood).await.unwrap();
    });
    let mut capture = BoundedCapture::with_limit(limit);
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        drain_bounded(&mut reader, &mut capture, limit, None, OutputStream::Stdout),
    )
    .await
    .expect("reader must continue draining after the retention ceiling")
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), producer)
        .await
        .expect("bounded producer must finish after its pipe is drained")
        .unwrap();

    let (text, truncated) = capture.finish("stdout", limit);
    assert!(truncated);
    assert_eq!(text.matches('x').count(), limit);
    assert!(text.ends_with("remaining output was drained]\n"));
    assert!(
        text.len() <= limit + 96,
        "only the bounded payload plus a fixed marker is retained"
    );
}

#[tokio::test]
async fn utf8_scalar_split_at_the_byte_ceiling_is_safe() {
    let bytes = b"abc\xF0\x9F\x98\x80tail"; // `abc`, then a four-byte emoji.
    let mut reader = &bytes[..];
    let mut capture = BoundedCapture::with_limit(5); // retain only the first two emoji bytes
    drain_bounded(&mut reader, &mut capture, 5, None, OutputStream::Stdout)
        .await
        .unwrap();
    let (text, truncated) = capture.finish("stdout", 5);

    assert!(truncated);
    assert!(text.starts_with("abc\n[stdout truncated"));
    assert!(
        !text.contains('\u{FFFD}'),
        "an incomplete boundary scalar is dropped, not corrupted"
    );
}

#[tokio::test]
async fn observer_is_bounded_and_terminal_bypasses_a_full_chunk_queue() {
    let (observer, mut receiver) = OutputObserver::bounded("cargo test", 7, 4);
    for value in 0_u8..100 {
        let _ = observer.inner.chunk_tx.try_send(OutputChunk {
            command_identity: Arc::from("cargo test"),
            attempt: 7,
            stream: OutputStream::Stdout,
            bytes: Arc::from([value]),
            retained_limit_bytes: 1024,
            dropped_chunks: 0,
        });
    }
    observer.finish(
        &RunOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: true,
            stderr_truncated: false,
            timed_out: false,
        },
        false,
    );

    let mut delivered_chunks = 0;
    let terminal = loop {
        match receiver.recv().await {
            Some(OutputObservation::Chunk(_)) => delivered_chunks += 1,
            Some(OutputObservation::Terminal(terminal)) => break terminal,
            None => panic!("terminal state must survive a full lossy chunk queue"),
        }
    };
    assert_eq!(delivered_chunks, 4, "only the bounded queue may drain");
    assert_eq!(terminal.command_identity.as_ref(), "cargo test");
    assert_eq!(terminal.attempt, 7);
    assert!(terminal.stdout_truncated);
}

struct AlwaysFailReader;

impl tokio::io::AsyncRead for AlwaysFailReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("injected read failure")))
    }
}

#[tokio::test]
async fn read_error_publishes_exactly_one_io_terminal_past_full_chunk_queue() {
    let (observer, mut receiver) = OutputObserver::bounded("failing verifier", 3, 4);
    for value in 0_u8..4 {
        observer
            .inner
            .chunk_tx
            .try_send(OutputChunk {
                command_identity: Arc::from("failing verifier"),
                attempt: 3,
                stream: OutputStream::Stdout,
                bytes: Arc::from([value]),
                retained_limit_bytes: 64,
                dropped_chunks: 0,
            })
            .unwrap();
    }
    let mut reader = AlwaysFailReader;
    let mut capture = BoundedCapture::with_limit(64);
    assert!(
        drain_bounded(
            &mut reader,
            &mut capture,
            64,
            Some(&observer),
            OutputStream::Stdout,
        )
        .await
        .is_err()
    );
    // A later collector settlement cannot overwrite the first authoritative error terminal.
    observer.finish(
        &RunOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
        },
        false,
    );

    let terminal = loop {
        match receiver.recv().await {
            Some(OutputObservation::Chunk(_)) => {}
            Some(OutputObservation::Terminal(terminal)) => break terminal,
            None => panic!("I/O-failure terminal was lost behind chunk pressure"),
        }
    };
    assert_eq!(terminal.reason, OutputTerminalReason::IoFailure);
    assert_eq!(terminal.exit_code, SIGNALLED_EXIT_CODE);
    assert!(
        receiver.recv().await.is_none(),
        "terminal must be delivered once"
    );
}

#[tokio::test]
async fn observer_cancellation_is_race_free() {
    let (observer, _receiver) = OutputObserver::bounded("verifier", 1, 4);
    observer.cancel();
    tokio::time::timeout(std::time::Duration::from_millis(50), observer.cancelled())
        .await
        .expect("a cancellation sent before waiter creation must still be observed");
}

#[cfg(unix)]
fn piped_grouped_bash(script: &str) -> tokio::process::Child {
    let mut command = tokio::process::Command::new("bash");
    command
        .arg("-lc")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_process_group(&mut command);
    command.spawn().unwrap()
}

#[cfg(unix)]
fn termination_fixture(label: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "core-termination-{label}-{}-{nonce:x}",
        std::process::id()
    ))
}

#[cfg(unix)]
#[tokio::test]
async fn cooperative_termination_runs_cleanup_before_the_grace_expires() {
    let root = termination_fixture("cooperative");
    std::fs::create_dir_all(&root).unwrap();
    let marker = root.join("term-cleanup");
    let mut child = piped_grouped_bash(&format!(
        "trap 'printf cleaned > {} ; exit 0' TERM; echo ready; while :; do sleep 0.02; done",
        marker.display()
    ));
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("ready"));

    let started = std::time::Instant::now();
    terminate_process_group_and_reap(&mut child).await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "cooperative child did not exit within the bounded grace"
    );
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "cleaned");
    assert!(child.try_wait().unwrap().is_some(), "child was not reaped");
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn ignored_sigterm_is_force_killed_after_one_bounded_grace_and_reaped() {
    let mut child = piped_grouped_bash("trap '' TERM; echo ready; while :; do sleep 1; done");
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("ready"));

    let started = std::time::Instant::now();
    terminate_process_group_and_reap(&mut child).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(TERMINATION_GRACE_MS.saturating_sub(25)),
        "force kill happened before the SIGTERM grace: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "force-kill/reap exceeded its total bound: {elapsed:?}"
    );
    assert!(child.try_wait().unwrap().is_some(), "child was not reaped");
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_the_collector_kills_the_shells_entire_process_group() {
    let root = termination_fixture("collector-drop");
    std::fs::create_dir_all(&root).unwrap();
    let ready = root.join("ready");
    let escaped = root.join("escaped-descendant");
    let mut child = piped_grouped_bash(&format!(
        "printf ready > {}; (sleep 1; printf leaked > {}) & wait",
        ready.display(),
        escaped.display()
    ));
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut conf = Confinement::egress_off(&root);
    conf.timeout_secs = 30;
    let mut collecting = Box::pin(collect_child_output(child, stdout, stderr, &conf));

    tokio::select! {
        result = &mut collecting => panic!("collector finished before cancellation: {result:?}"),
        () = async {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while !ready.exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("shell reached its long-running section");
        } => {}
    }

    // This is the cancellation shape used by the runtime: dropping the admitted tool future
    // drops the sandbox collector rather than waiting for its one-hour command timeout.
    drop(collecting);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert!(
        !escaped.exists(),
        "a background descendant must not survive collector cancellation"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[tokio::test]
async fn simultaneous_stdout_and_stderr_floods_are_bounded_without_deadlock() {
    let mut child =
        piped_grouped_bash("(yes O | head -c 1048576) & (yes E | head -c 1048576 >&2) & wait");
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut conf = Confinement::egress_off(std::env::temp_dir());
    conf.timeout_secs = 5;
    conf.max_output_bytes = 8 * 1024;

    let output = collect_child_output(child, stdout, stderr, &conf)
        .await
        .unwrap();

    assert!(
        !output.timed_out,
        "finite dual-stream flood must drain to completion"
    );
    assert!(output.stdout_truncated);
    assert!(output.stderr_truncated);
    assert!(output.stdout.contains("[stdout truncated after 8192 bytes"));
    assert!(output.stderr.contains("[stderr truncated after 8192 bytes"));
    assert!(output.stdout.len() <= conf.max_output_bytes + 96);
    assert!(output.stderr.len() <= conf.max_output_bytes + 96);
}

#[cfg(unix)]
#[tokio::test]
async fn timeout_kills_descendants_waits_and_preserves_partial_output() {
    let pid = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("core-output-timeout-{pid}-{nonce:x}"));
    std::fs::create_dir_all(&root).unwrap();
    let marker = root.join("escaped-descendant");

    let mut command = tokio::process::Command::new("bash");
    command
        .arg("-c")
        .arg("(sleep 2; printf leaked > \"$1\") & echo child-started; wait")
        .arg("sandbox-timeout-test")
        .arg(&marker)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_process_group(&mut command);
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut conf = Confinement::egress_off(&root);
    conf.timeout_secs = 1;
    conf.max_output_bytes = 1024;

    let output = collect_child_output(child, stdout, stderr, &conf)
        .await
        .unwrap();
    assert!(output.timed_out);
    assert!(
        output.stdout.contains("child-started"),
        "bytes read before timeout must be retained"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(
        !marker.exists(),
        "the background descendant must die with the timed-out group"
    );
    let _ = std::fs::remove_dir_all(root);
}
