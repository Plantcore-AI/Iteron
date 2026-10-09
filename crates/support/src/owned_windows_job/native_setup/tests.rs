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
    async fn sandbox(
        &self,
        scratch: &Path,
        workspace: Option<&File>,
    ) -> Result<WindowsSandboxLaunch, WindowsJobLaunchError> {
        let executable = std::env::current_exe().unwrap();
        WindowsSandboxLaunch::prepare(
            WindowsIsolationPolicy {
                workspace: &self.0.join("workspace"),
                scratch,
                executable: &executable,
                environment: &[],
                write_roots: &[],
                read_only_roots: &[],
                allow_egress: false,
            },
            workspace,
        )
        .await
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
    assert!(
        workspace.0.join("scratch").is_dir(),
        "a raw caller-owned scratch is not deleted"
    );
}

#[tokio::test]
async fn native_sandbox_scratch_is_create_only_and_never_deletes_an_existing_directory() {
    let workspace = Workspace::new();
    let scratch = workspace.0.join("scratch");
    let original = scratch.join("caller-owned.txt");
    std::fs::write(&original, b"caller-owned source").unwrap();
    let error = match workspace.sandbox(&scratch, None).await {
        Ok(_) => panic!("a caller-owned directory cannot become a create-only scratch"),
        Err(error) => error,
    };
    assert!(error.not_dispatched() && error.cleanup_known());
    assert_eq!(std::fs::read(&original).unwrap(), b"caller-owned source");
    assert_eq!(
        std::fs::read_dir(workspace.0.join("workspace"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn native_sandbox_drop_retires_the_same_created_scratch_and_cannot_steal_a_live_owner() {
    let workspace = Workspace::new();
    let scratch = workspace.0.join("created-scratch");
    let launch = workspace
        .sandbox(&scratch, None)
        .await
        .unwrap_or_else(|error| panic!("native factory must install its exact scope: {error}"));
    let prepared = launch.prepared.as_ref().unwrap();
    let job = prepared.job.clone();
    let observation = prepared.retirement.as_ref().unwrap().observation();
    let isolation = prepared.retirement.as_ref().unwrap().isolation().unwrap();
    assert!(isolation.validate_scope_still_bound().is_ok());
    std::fs::create_dir(scratch.join("nested")).unwrap();
    std::fs::write(
        scratch.join("nested").join("output.txt"),
        b"retained native bytes",
    )
    .unwrap();
    let error = match workspace.sandbox(&scratch, None).await {
        Ok(_) => panic!("a concurrent preparation cannot take the original scratch"),
        Err(error) => error,
    };
    assert!(error.not_dispatched() && error.cleanup_known());
    assert_eq!(
        std::fs::read(scratch.join("nested").join("output.txt")).unwrap(),
        b"retained native bytes"
    );
    assert!(
        launch
            .prepared
            .as_ref()
            .unwrap()
            .retirement
            .as_ref()
            .unwrap()
            .isolation()
            .unwrap()
            .validate_scope_still_bound()
            .is_ok()
    );
    assert_eq!(job.active_processes().unwrap(), 0);
    drop(launch);
    assert!(observation.observe(Duration::from_secs(5)).await);
    assert_eq!(job.active_processes().unwrap(), 0);
    assert!(
        !scratch.try_exists().unwrap(),
        "observed terminal cleanup includes the same native namespace"
    );
    assert!(workspace.0.join("workspace").is_dir());
}

#[tokio::test]
async fn native_sandbox_workspace_capability_mismatch_retires_only_its_created_scratch() {
    let workspace = Workspace::new();
    let scratch = workspace.0.join("refused-scratch");
    let different_object = File::open(std::env::current_exe().unwrap()).unwrap();
    let error = match workspace.sandbox(&scratch, Some(&different_object)).await {
        Ok(_) => panic!("a file cannot substitute for the held workspace directory"),
        Err(error) => error,
    };
    assert!(error.not_dispatched() && error.cleanup_known());
    assert!(!scratch.try_exists().unwrap());
    assert!(workspace.0.join("workspace").is_dir());
    assert!(workspace.0.join("scratch").is_dir());
}
