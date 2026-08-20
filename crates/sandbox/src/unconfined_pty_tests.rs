//! An unconfined persistent PTY must run with the operator's own authority.
//!
//! `spawn_confined_pty_process` branched only on `target_os`, so `Confinement::unconfined` still
//! reached bubblewrap on Linux and `/usr/bin/sandbox-exec` on macOS. Every other backend already
//! had this branch -- `bubblewrap.rs`, `seatbelt.rs`, and the one-shot path in `lib.rs` all
//! delegate to `run_direct` on the bit -- so the gap was in the PTY path alone.
//!
//! These tests need no provider, no model and no credential: they spawn `/bin/sh -c`, wait for it,
//! and look at the filesystem.

use super::*;

/// Two sibling directories: the child's workspace, and a path outside it that a sandbox would
/// deny. `Fixture` removes the tree on drop, including when a test panics.
struct Fixture {
    root: std::path::PathBuf,
    workspace: std::path::PathBuf,
    outside: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture(label: &str) -> Fixture {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "iteron-unconfined-pty-{label}-{}-{nonce:x}",
        std::process::id()
    ));
    let workspace = root.join("workspace");
    let outside = root.join("outside");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(&outside).expect("outside");
    Fixture {
        root,
        workspace,
        outside,
    }
}

/// `sh -c` that writes a probe file into the sibling directory, addressed relatively so the
/// command text itself carries no absolute path a sandbox profile could have been widened for.
const WRITE_SIBLING: &str = "printf ok > ../outside/probe";

/// A window a real terminal could have. `WindowSize` refuses a zero dimension by design.
fn window() -> pty::WindowSize {
    pty::WindowSize::new(24, 80).expect("24x80 is a valid window")
}

#[tokio::test]
async fn an_unconfined_pty_reaches_outside_the_workspace_and_says_it_was_direct() {
    let fx = fixture("allows");
    let (workspace, outside) = (&fx.workspace, &fx.outside);
    let conf = Confinement::unconfined(workspace);

    let mut process = spawn_confined_pty_process(WRITE_SIBLING, &conf, window())
        .await
        .expect("an unconfined PTY must start without any sandbox being available");

    assert_eq!(
        process.backend(),
        PersistentBackend::DirectPty,
        "the receipt must name direct execution, not the sandbox that did not run"
    );

    let status = process.wait().await.expect("reap the child");
    assert!(status.success(), "the child exited {status:?}");

    let probe = outside.join("probe");
    assert!(
        probe.is_file(),
        "an unconfined child must be able to write outside its workspace: {} missing",
        probe.display()
    );
    assert_eq!(std::fs::read_to_string(&probe).expect("read probe"), "ok");
}

/// The control. Confinement must keep working exactly as before, and must keep failing closed.
#[tokio::test]
async fn a_confined_pty_is_still_denied_the_same_write() {
    let fx = fixture("denies");
    let (workspace, outside) = (&fx.workspace, &fx.outside);
    let conf = Confinement::egress_off(workspace);

    let spawned = spawn_confined_pty_process(WRITE_SIBLING, &conf, window()).await;

    let probe = outside.join("probe");
    match spawned {
        // The sandbox is present and ran: the write must have been denied.
        Ok(mut process) => {
            assert_ne!(
                process.backend(),
                PersistentBackend::DirectPty,
                "a confined confinement must never be served by the direct path"
            );
            let _ = process.wait().await;
            assert!(
                !probe.is_file(),
                "a confined child wrote outside its workspace: {} exists",
                probe.display()
            );
        }
        // No sandbox on this host: refusing is the fail-closed answer, and nothing may have run.
        Err(SandboxError::Unsupported) => {
            assert!(
                !probe.is_file(),
                "a refused confinement still ran the command: {} exists",
                probe.display()
            );
        }
        Err(other) => panic!("unexpected confined-spawn error: {other:?}"),
    }
}

/// The scratch redirection is a confinement mechanism, so an unconfined child must keep the
/// operator's own temp directory. Acceptance criterion three of the report.
#[tokio::test]
async fn an_unconfined_pty_keeps_the_operator_tmpdir() {
    let fx = fixture("tmpdir");
    let (workspace, outside) = (&fx.workspace, &fx.outside);
    let conf = Confinement::unconfined(workspace);

    let mut process = spawn_confined_pty_process(
        "printf '%s' \"${TMPDIR:-unset}\" > ../outside/tmpdir",
        &conf,
        window(),
    )
    .await
    .expect("spawn");
    let _ = process.wait().await;

    let observed = std::fs::read_to_string(outside.join("tmpdir")).expect("read tmpdir probe");
    assert!(
        !observed.starts_with(&conf.scratch.to_string_lossy().to_string()),
        "an unconfined child was redirected to the confined scratch dir: {observed}"
    );
}
