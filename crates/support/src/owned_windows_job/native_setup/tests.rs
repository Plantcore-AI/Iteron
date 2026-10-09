//! Actual no-process reservation/ACL cleanup, without substituting a caller cleanup boolean.
use super::*;
use crate::windows_process_isolation::WindowsIsolationPolicy;

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-native-setup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("workspace")).unwrap();
        std::fs::create_dir(root.join("scratch")).unwrap();
        Self(root)
    }
    fn setup(&self) -> IsolationSetup {
        let executable = std::env::current_exe().unwrap();
        let directory = self.0.join("workspace");
        let isolation = WindowsProcessIsolation::prepare(WindowsIsolationPolicy {
            workspace: &directory,
            scratch: &self.0.join("scratch"),
            executable: &executable,
            environment: &[],
            write_roots: &[],
            read_only_roots: &[],
            allow_egress: false,
        })
        .unwrap();
        IsolationSetup {
            isolation,
            executable,
            directory,
            environment: Vec::new(),
        }
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn native_setup_binding_refusal_retires_its_reserved_lease_without_creation() {
    let workspace = Workspace::new();
    let mut setup = workspace.setup();
    let isolation = setup.isolation.clone();
    setup
        .environment
        .push(("NOT_IN_FROZEN_SNAPSHOT".into(), "synthetic".into()));
    let error = match Prepared::admit(Some(setup)).await {
        Ok(_) => panic!("a different environment cannot enter native creation"),
        Err(error) => error,
    };
    assert_eq!(error.stage, "native isolation setup");
    assert!(error.not_dispatched() && error.cleanup_known());
    assert!(isolation.validate_scope_still_bound().is_err());
    assert!(isolation.reserve_launch().is_err());
    assert_eq!(
        std::fs::read_dir(workspace.0.join("workspace"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn native_setup_drop_keeps_installed_reservation_until_physical_cleanup() {
    let workspace = Workspace::new();
    let setup = workspace.setup();
    let isolation = setup.isolation.clone();
    let prepared = Prepared::admit(Some(setup))
        .await
        .unwrap_or_else(|error| panic!("native setup must install actual permissions: {error}"));
    let job = prepared.job.clone();
    let observation = prepared.retirement.as_ref().unwrap().observation();
    assert_eq!(job.active_processes().unwrap(), 0);
    assert!(isolation.validate_scope_still_bound().is_ok());
    assert!(isolation.reserve_launch().is_err());
    drop(prepared);
    assert!(observation.observe(Duration::from_secs(5)).await);
    assert_eq!(job.active_processes().unwrap(), 0);
    assert!(isolation.validate_scope_still_bound().is_err());
    assert!(isolation.reserve_launch().is_err());
}
