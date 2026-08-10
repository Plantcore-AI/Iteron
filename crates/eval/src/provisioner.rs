//! Prebuilt-image and no-daemon provisioning for corpus test commands.
//!
//! Image acquisition is an operator-side preparation step and may require registry egress. Test
//! execution never does: Docker receives `--network none`, while the no-daemon path runs through
//! the repository's existing [`iteron_sandbox::Confinement::egress_off`] backend. A Docker daemon is
//! an explicit host trust boundary, so this module does not punch its control socket through the
//! filesystem sandbox and pretend that the resulting process is workspace-confined.
//!
//! The daemonless backend does not claim to reconstruct a benchmark environment from
//! `environment_setup_commit`: a commit id without a setup repository and build recipe cannot
//! specify a build. Image-less fixtures may use the pinned host toolchain. If a task declares an
//! image and that image is unavailable, the host command is retained only as an egress-off
//! diagnostic and the receipt is forced to `InfrastructureFailed`, preventing host-unbuilt results
//! from entering the benchmark denominator.

use crate::corpus::CorpusTask;
use crate::process::{ProcessSpec, run_process};
use crate::types::OracleStatus;
use iteron_sandbox::Confinement;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROVISION_OUTPUT_LIMIT: usize = 128 * 1024;
const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestSet {
    FailToPass,
    PassToPass,
    #[serde(other)]
    Unknown,
}

impl TestSet {
    fn label(self) -> &'static str {
        match self {
            Self::FailToPass => "fail_to_pass",
            Self::PassToPass => "pass_to_pass",
            Self::Unknown => "unknown",
        }
    }

    fn tests(self, task: &CorpusTask) -> &[String] {
        match self {
            Self::FailToPass => &task.fail_to_pass,
            Self::PassToPass => &task.pass_to_pass,
            Self::Unknown => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningBackend {
    Docker,
    LocalNoDaemon,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCommandReceipt {
    pub language: String,
    pub test_set: TestSet,
    pub test_ids: Vec<String>,
    pub backend: ProvisioningBackend,
    pub image: Option<String>,
    pub platform: Option<String>,
    pub status: OracleStatus,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub egress_disabled: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSetReceipt {
    pub test_set: TestSet,
    pub status: OracleStatus,
    pub commands: Vec<TestCommandReceipt>,
}

#[derive(Debug, Clone)]
pub struct Provisioner {
    docker_bin: PathBuf,
    /// Optional platform pin for heterogeneous hosts such as arm64 DGX Spark machines evaluating
    /// official amd64-only benchmark images.
    docker_platform: Option<String>,
}

#[derive(Debug, Clone)]
struct PreparedImage {
    workdir: String,
}

impl Default for Provisioner {
    fn default() -> Self {
        let docker_platform = std::env::var("ITERON_EVAL_DOCKER_PLATFORM")
            .ok()
            .filter(|platform| !platform.trim().is_empty())
            .or_else(|| {
                matches!(std::env::consts::ARCH, "aarch64" | "arm")
                    .then(|| "linux/amd64".to_owned())
            });
        Self {
            docker_bin: PathBuf::from("docker"),
            docker_platform,
        }
    }
}

impl Provisioner {
    pub fn with_docker_platform(mut self, platform: impl Into<String>) -> Self {
        self.docker_platform = Some(platform.into());
        self
    }

    pub async fn run_test_set(
        &self,
        task: &CorpusTask,
        workspace: &Path,
        test_set: TestSet,
        timeout: Duration,
    ) -> TestSetReceipt {
        if test_set == TestSet::Unknown {
            return TestSetReceipt {
                test_set,
                status: OracleStatus::InfrastructureFailed,
                commands: Vec::new(),
            };
        }
        let tests = test_set.tests(task);
        if tests.is_empty() {
            return TestSetReceipt {
                test_set,
                status: OracleStatus::Passed,
                commands: Vec::new(),
            };
        }

        let image = task.dockerhub_tag.as_deref();
        let prepared_image = match image {
            Some(image) => self.ensure_image(image).await,
            None => None,
        };
        let backend = if prepared_image.is_some() {
            ProvisioningBackend::Docker
        } else {
            ProvisioningBackend::LocalNoDaemon
        };

        let mut commands = Vec::with_capacity(task.test_cmd.len());
        for (language, command) in &task.test_cmd {
            let mut receipt = match backend {
                ProvisioningBackend::Docker => {
                    self.run_docker(
                        image.expect("Docker backend requires an image"),
                        &prepared_image
                            .as_ref()
                            .expect("Docker backend requires a prepared image")
                            .workdir,
                        workspace,
                        language,
                        command,
                        test_set,
                        tests,
                        timeout,
                    )
                    .await
                }
                ProvisioningBackend::LocalNoDaemon => {
                    self.run_local(workspace, language, command, test_set, tests, timeout)
                        .await
                }
                ProvisioningBackend::Unknown => TestCommandReceipt {
                    language: language.to_owned(),
                    test_set,
                    test_ids: tests.to_vec(),
                    backend,
                    image: image.map(str::to_owned),
                    platform: None,
                    status: OracleStatus::InfrastructureFailed,
                    exit_code: None,
                    timed_out: false,
                    egress_disabled: false,
                    detail: "unknown provisioning backend".into(),
                },
            };
            if image.is_some() && backend == ProvisioningBackend::LocalNoDaemon {
                receipt.status = OracleStatus::InfrastructureFailed;
                receipt.detail = format!(
                    "required prebuilt image was unavailable; host-unbuilt diagnostic only: {}",
                    receipt.detail
                );
            }
            commands.push(receipt);
        }
        let status = aggregate_status(commands.iter().map(|receipt| receipt.status));
        TestSetReceipt {
            test_set,
            status,
            commands,
        }
    }

    async fn ensure_image(&self, image: &str) -> Option<PreparedImage> {
        if let Some(prepared) = self.inspect_image(image).await {
            return Some(prepared);
        }

        let pull = run_process(&ProcessSpec {
            program: self.docker_bin.clone(),
            args: {
                let mut args = vec!["pull".into()];
                if let Some(platform) = &self.docker_platform {
                    args.push("--platform".into());
                    args.push(platform.into());
                }
                args.push(image.into());
                args
            },
            cwd: None,
            clear_env: false,
            inherit_env: Vec::new(),
            env: Vec::new(),
            timeout: IMAGE_PULL_TIMEOUT,
            max_output_bytes: PROVISION_OUTPUT_LIMIT,
        })
        .await;
        if !pull.as_ref().is_ok_and(|output| output.success()) {
            return None;
        }
        self.inspect_image(image).await
    }

    async fn inspect_image(&self, image: &str) -> Option<PreparedImage> {
        let inspect = run_process(&ProcessSpec {
            program: self.docker_bin.clone(),
            args: vec![
                "image".into(),
                "inspect".into(),
                "--format".into(),
                "{{.Config.WorkingDir}}".into(),
                image.into(),
            ],
            cwd: None,
            clear_env: false,
            inherit_env: Vec::new(),
            env: Vec::new(),
            timeout: Duration::from_secs(15),
            max_output_bytes: 4 * 1024,
        })
        .await
        .ok()?;
        if !inspect.success() || inspect.stdout_truncated {
            return None;
        }
        let configured = String::from_utf8(inspect.stdout).ok()?;
        let configured = configured.trim();
        let workdir = if configured.is_empty() {
            "/workspace"
        } else {
            configured
        };
        if !workdir.starts_with('/')
            || workdir == "/"
            || workdir.contains([',', '\r', '\n', '\0'])
            || workdir.len() > 4_096
        {
            return None;
        }
        Some(PreparedImage {
            workdir: workdir.to_owned(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_docker(
        &self,
        image: &str,
        container_workdir: &str,
        workspace: &Path,
        language: &str,
        command: &str,
        test_set: TestSet,
        tests: &[String],
        timeout: Duration,
    ) -> TestCommandReceipt {
        let mut args: Vec<OsString> = vec![
            "run".into(),
            "--rm".into(),
            "--network".into(),
            "none".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges".into(),
            "--pids-limit".into(),
            "512".into(),
            "--tmpfs".into(),
            "/tmp:rw,nosuid,nodev,size=1073741824".into(),
            "--mount".into(),
            format!("type=bind,src={},dst=/workspace", workspace.display()).into(),
        ];
        if container_workdir != "/workspace" {
            args.push("--mount".into());
            args.push(
                format!(
                    "type=bind,src={},dst={container_workdir}",
                    workspace.display()
                )
                .into(),
            );
        }
        args.extend([
            "--workdir".into(),
            container_workdir.into(),
            "--entrypoint".into(),
            "/bin/bash".into(),
        ]);
        if let Some(platform) = &self.docker_platform {
            args.push("--platform".into());
            args.push(platform.into());
        }
        args.extend([
            "--env".into(),
            format!("ITERON_EVAL_TEST_SET={}", test_set.label()).into(),
            "--env".into(),
            format!(
                "ITERON_EVAL_TEST_IDS_JSON={}",
                serde_json::to_string(tests).unwrap_or_else(|_| "[]".into())
            )
            .into(),
            image.into(),
            "-lc".into(),
            command.into(),
        ]);
        let output = run_process(&ProcessSpec {
            program: self.docker_bin.clone(),
            args,
            cwd: None,
            clear_env: false,
            inherit_env: Vec::new(),
            env: Vec::new(),
            timeout,
            max_output_bytes: PROVISION_OUTPUT_LIMIT,
        })
        .await;
        process_receipt(
            language,
            test_set,
            tests,
            ProvisioningBackend::Docker,
            Some(image),
            self.docker_platform.as_deref(),
            output,
        )
    }

    async fn run_local(
        &self,
        workspace: &Path,
        language: &str,
        command: &str,
        test_set: TestSet,
        tests: &[String],
        timeout: Duration,
    ) -> TestCommandReceipt {
        let ids = serde_json::to_string(tests).unwrap_or_else(|_| "[]".into());
        let wrapped = format!(
            "export ITERON_EVAL_TEST_SET={}; export ITERON_EVAL_TEST_IDS_JSON={}; {}",
            shell_quote(test_set.label()),
            shell_quote(&ids),
            command
        );
        let mut confinement = Confinement::egress_off(workspace);
        confinement.timeout_secs = timeout.as_secs().max(1);
        confinement.max_output_bytes = PROVISION_OUTPUT_LIMIT;
        let output = iteron_sandbox::platform_sandbox()
            .run(&wrapped, &confinement)
            .await;
        let (status, exit_code, timed_out, detail) = match output {
            Ok(output) if output.timed_out => (
                OracleStatus::TimedOut,
                Some(output.exit_code),
                true,
                "timed out inside the egress-off sandbox".to_owned(),
            ),
            Ok(output) => (
                if output.exit_code == 0 {
                    OracleStatus::Passed
                } else {
                    OracleStatus::TestFailed
                },
                Some(output.exit_code),
                false,
                bounded_detail(&output.stdout, &output.stderr),
            ),
            Err(error) => (
                OracleStatus::InfrastructureFailed,
                None,
                false,
                format!("sandbox refused or failed: {error}"),
            ),
        };
        TestCommandReceipt {
            language: language.to_owned(),
            test_set,
            test_ids: tests.to_vec(),
            backend: ProvisioningBackend::LocalNoDaemon,
            image: None,
            platform: None,
            status,
            exit_code,
            timed_out,
            egress_disabled: true,
            detail,
        }
    }
}

fn process_receipt(
    language: &str,
    test_set: TestSet,
    tests: &[String],
    backend: ProvisioningBackend,
    image: Option<&str>,
    platform: Option<&str>,
    output: Result<crate::process::ProcessOutput, crate::process::ProcessError>,
) -> TestCommandReceipt {
    let (status, exit_code, timed_out, detail) = match output {
        Ok(output) if output.timed_out => (
            OracleStatus::TimedOut,
            Some(output.exit_code),
            true,
            "container command exceeded its wall-clock limit".to_owned(),
        ),
        Ok(output) => (
            if output.exit_code == 0 {
                OracleStatus::Passed
            } else {
                OracleStatus::TestFailed
            },
            Some(output.exit_code),
            false,
            bounded_detail(
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr),
            ),
        ),
        Err(error) => (
            OracleStatus::InfrastructureFailed,
            None,
            false,
            error.to_string(),
        ),
    };
    TestCommandReceipt {
        language: language.to_owned(),
        test_set,
        test_ids: tests.to_vec(),
        backend,
        image: image.map(str::to_owned),
        platform: platform.map(str::to_owned),
        status,
        exit_code,
        timed_out,
        egress_disabled: true,
        detail,
    }
}

fn aggregate_status(statuses: impl Iterator<Item = OracleStatus>) -> OracleStatus {
    statuses.fold(OracleStatus::Passed, |aggregate, status| {
        use OracleStatus::{InfrastructureFailed, NotRun, Passed, TestFailed, TimedOut};
        match (aggregate, status) {
            (InfrastructureFailed, _) | (_, InfrastructureFailed) => InfrastructureFailed,
            (TimedOut, _) | (_, TimedOut) => TimedOut,
            (TestFailed, _) | (_, TestFailed) => TestFailed,
            (NotRun, _) | (_, NotRun) => NotRun,
            (Passed, Passed) => Passed,
        }
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn bounded_detail(stdout: &str, stderr: &str) -> String {
    let stdout = normalize_pytest_elapsed(stdout);
    let stderr = normalize_pytest_elapsed(stderr);
    let mut detail = format!("{stdout}\n{stderr}");
    if detail.len() > 4_096 {
        let start = detail
            .char_indices()
            .rev()
            .nth(4_095)
            .map_or(0, |(index, _)| index);
        detail = format!("…{}", &detail[start..]);
    }
    detail
}

fn normalize_pytest_elapsed(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    for chunk in text.split_inclusive('\n') {
        let (line, newline) = chunk
            .strip_suffix('\n')
            .map_or((chunk, ""), |line| (line, "\n"));
        let Some(marker) = line.rfind(" in ") else {
            normalized.push_str(line);
            normalized.push_str(newline);
            continue;
        };
        let tail = &line[marker + 4..];
        let Some(seconds) = tail.find("s ") else {
            normalized.push_str(line);
            normalized.push_str(newline);
            continue;
        };
        let elapsed = &tail[..seconds];
        let is_pytest_summary = line.starts_with('=')
            && line.ends_with('=')
            && !elapsed.is_empty()
            && elapsed.bytes().any(|byte| byte.is_ascii_digit())
            && elapsed
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.');
        if is_pytest_summary {
            normalized.push_str(&line[..marker + 4]);
            normalized.push_str("<elapsed>");
            normalized.push_str(&tail[seconds..]);
        } else {
            normalized.push_str(line);
        }
        normalized.push_str(newline);
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{Provenance, digest_tasks};
    use crate::types::Partition;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn workspace(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "iteron-eval-provisioner-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn task(command: &str) -> CorpusTask {
        CorpusTask {
            id: "provisioner-fixture".into(),
            repo_url: "https://example.invalid/repo.git".into(),
            commit: "0".repeat(40),
            prompt: "fixture".into(),
            verify_command: command.into(),
            ground_truth_command: command.into(),
            dockerhub_tag: None,
            fail_to_pass: vec!["fixture::f2p".into()],
            pass_to_pass: vec!["fixture::p2p".into()],
            test_cmd: BTreeMap::from([("sh".into(), command.into())]),
            partition: Partition::HeldOut,
            provenance: Provenance {
                source: "fixture".into(),
                task_id: "fixture".into(),
                license: Some("MIT".into()),
            },
            benchmark: None,
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn no_daemon_fallback_denies_egress_and_keeps_workspace_writable() {
        let workspace = workspace("local");
        std::fs::create_dir_all(&workspace).unwrap();
        let task = task(
            "printf writable > receipt.txt; \
             if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 https://example.com; \
             then exit 9; else exit 0; fi",
        );
        let receipt = Provisioner::default()
            .run_test_set(
                &task,
                &workspace,
                TestSet::FailToPass,
                Duration::from_secs(10),
            )
            .await;
        assert_eq!(receipt.status, OracleStatus::Passed);
        assert_eq!(
            std::fs::read_to_string(workspace.join("receipt.txt")).unwrap(),
            "writable"
        );
        assert!(receipt.commands.iter().all(|item| item.egress_disabled));
        assert_eq!(digest_tasks(&[task]).unwrap().len(), 71);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn missing_declared_image_never_becomes_a_comparable_host_result() {
        let workspace = workspace("missing-image");
        std::fs::create_dir_all(&workspace).unwrap();
        let mut task = task("printf diagnostic > host-unbuilt.txt; exit 0");
        task.dockerhub_tag = Some("example.invalid/benchmark:pinned".into());
        let provisioner = Provisioner {
            docker_bin: PathBuf::from("definitely-not-a-real-docker-binary"),
            docker_platform: None,
        };
        let receipt = provisioner
            .run_test_set(
                &task,
                &workspace,
                TestSet::FailToPass,
                Duration::from_secs(10),
            )
            .await;
        assert_eq!(receipt.status, OracleStatus::InfrastructureFailed);
        assert_eq!(
            receipt.commands[0].backend,
            ProvisioningBackend::LocalNoDaemon
        );
        assert_eq!(
            receipt.commands[0].status,
            OracleStatus::InfrastructureFailed
        );
        assert!(
            receipt.commands[0]
                .detail
                .contains("host-unbuilt diagnostic only")
        );
        assert_eq!(
            std::fs::read_to_string(workspace.join("host-unbuilt.txt")).unwrap(),
            "diagnostic"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn non_python_test_command_runs_through_the_same_provisioner_boundary() {
        let workspace = workspace("go-command");
        std::fs::create_dir_all(&workspace).unwrap();
        let mut task = task("unused");
        task.test_cmd = BTreeMap::from([(
            "go".into(),
            "test \"$ITERON_EVAL_TEST_SET\" = fail_to_pass; \
             test \"$ITERON_EVAL_TEST_IDS_JSON\" = '[\"fixture::f2p\"]'; \
             printf go-command-ran > go-command.txt"
                .into(),
        )]);
        let receipt = Provisioner::default()
            .run_test_set(
                &task,
                &workspace,
                TestSet::FailToPass,
                Duration::from_secs(10),
            )
            .await;
        assert_eq!(receipt.status, OracleStatus::Passed, "{receipt:#?}");
        assert_eq!(receipt.commands[0].language, "go");
        assert_eq!(
            std::fs::read_to_string(workspace.join("go-command.txt")).unwrap(),
            "go-command-ran"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn future_receipt_enums_degrade_to_unknown() {
        assert_eq!(
            serde_json::from_str::<TestSet>("\"future_set\"").unwrap(),
            TestSet::Unknown
        );
        assert_eq!(
            serde_json::from_str::<ProvisioningBackend>("\"future_backend\"").unwrap(),
            ProvisioningBackend::Unknown
        );
    }

    #[test]
    fn pytest_wall_time_is_normalized_without_rewriting_ordinary_output() {
        let left =
            "====================== 1 passed in 0.47s ======================\nfinished in 3.2s\n";
        let right =
            "====================== 1 passed in 1.06s ======================\nfinished in 3.2s\n";
        assert_eq!(
            normalize_pytest_elapsed(left),
            "====================== 1 passed in <elapsed>s ======================\nfinished in 3.2s\n"
        );
        assert_eq!(
            normalize_pytest_elapsed(left),
            normalize_pytest_elapsed(right)
        );
    }

    /// Gated acceptance witness for #32. Run on DGX Spark with:
    /// `cargo test -p iteron-eval real_pro_image_denies_network_and_writes_workspace -- --ignored`
    #[tokio::test]
    #[ignore = "requires Docker plus the official SWE-bench Pro image"]
    async fn real_pro_image_denies_network_and_writes_workspace() {
        let workspace = workspace("docker");
        std::fs::create_dir_all(&workspace).unwrap();
        let mut task = task(
            "python3 -c \"import pathlib,socket,sys; \
             pathlib.Path('/workspace/docker-receipt.txt').write_text('writable'); \
             socket.getaddrinfo('example.com', 443); sys.exit(9)\"; \
             test \"$?\" -ne 9",
        );
        task.dockerhub_tag = Some(
            "jefzda/sweap-images:ansible.ansible-ansible__ansible-be59caa59bf47ca78a4760eb7ff38568372a8260-v1055803c3a812189a1133297f7f5468579283f86"
                .into(),
        );
        let receipt = Provisioner::default()
            .with_docker_platform("linux/amd64")
            .run_test_set(
                &task,
                &workspace,
                TestSet::FailToPass,
                Duration::from_secs(120),
            )
            .await;
        assert_eq!(receipt.status, OracleStatus::Passed, "{receipt:#?}");
        assert_eq!(
            receipt.commands[0].backend,
            ProvisioningBackend::Docker,
            "falling back locally is not the real-image witness"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.join("docker-receipt.txt")).unwrap(),
            "writable"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }
}
