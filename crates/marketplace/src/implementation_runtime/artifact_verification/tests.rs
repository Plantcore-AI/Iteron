use super::*;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-artifact-verification-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("program")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn complete_sha256_known_answer_and_changed_native_bytes_are_observed() {
    let fixture = Fixture::new();
    std::fs::write(fixture.path(), b"abc").unwrap();
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    verify_program(
        &fixture.path(),
        expected,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    std::fs::write(fixture.path(), b"abd").unwrap();
    assert!(matches!(
        verify_program(
            &fixture.path(),
            expected,
            Instant::now() + Duration::from_secs(1)
        ),
        Err(ImplementationRuntimeError::ContentMismatch { .. }),
    ));
}

#[test]
fn sparse_oversize_is_refused_before_hashing_and_expired_scope_before_open() {
    let fixture = Fixture::new();
    File::create(fixture.path())
        .unwrap()
        .set_len(MAX_EXECUTABLE_BYTES + 1)
        .unwrap();
    let expected = "0".repeat(64);
    assert!(matches!(
        verify_program(
            &fixture.path(),
            &expected,
            Instant::now() + Duration::from_secs(1)
        ),
        Err(ImplementationRuntimeError::InvalidPlan(
            "executable exceeds its byte bound"
        )),
    ));
    assert!(matches!(
        verify_program(&fixture.0.join("absent"), &expected, Instant::now()),
        Err(ImplementationRuntimeError::Deadline { .. }),
    ));
}

#[cfg(unix)]
#[test]
fn actual_fifo_and_symlink_are_refused_with_no_wait_for_a_writer() {
    use std::os::unix::{ffi::OsStrExt as _, fs::symlink};
    let fixture = Fixture::new();
    let fifo = std::ffi::CString::new(fixture.path().as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let started = Instant::now();
    assert!(
        verify_program(
            &fixture.path(),
            &"0".repeat(64),
            started + Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    std::fs::remove_file(fixture.path()).unwrap();
    let target = fixture.0.join("target");
    std::fs::write(&target, b"abc").unwrap();
    symlink(target, fixture.path()).unwrap();
    assert!(
        verify_program(
            &fixture.path(),
            &"0".repeat(64),
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
}
