//! Fixed project scaffolding. Only the actual host captures workspace and permission authority.
use crate::runtime::Agent;
use iteron_protocol::{RunId, ToolUse};
use std::path::PathBuf;

const INSTRUCTIONS: &[u8] = b"# Project instructions for coding agents\n\n- (describe build/test commands, conventions, and gotchas here)\n";
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InitStatus {
    Created,
    Existing,
    NotPublished,
    PublicationUnknown,
}
#[derive(Debug, serde::Serialize)]
pub(crate) struct InitEntry {
    pub(crate) name: &'static str,
    pub(crate) status: InitStatus,
}
#[derive(Debug, serde::Serialize)]
pub(crate) struct ProjectInitReceipt {
    pub(crate) source_run: RunId,
    pub(crate) entries: Vec<InitEntry>,
    pub(crate) refusal: Option<&'static str>,
}
impl ProjectInitReceipt {
    pub(crate) fn unknown(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.status == InitStatus::PublicationUnknown)
    }
}
pub(crate) struct NativeProjectInit {
    workspace: PathBuf,
    run: RunId,
    config: String,
    admitted: bool,
}
impl NativeProjectInit {
    pub(crate) fn capture(agent: &Agent) -> Self {
        let config = crate::config::starter_project_config();
        let admitted = [
            (".iteron/config.json", config.as_str()),
            (
                "AGENTS.md",
                std::str::from_utf8(INSTRUCTIONS).expect("static UTF8"),
            ),
        ]
        .into_iter()
        .all(|(path, content)| {
            agent.admit_operator_tool_call(&ToolUse {
                id: "host-project-initializer".into(),
                name: "write_file".into(),
                input: serde_json::json!({"path":path,"content":content}),
            })
        });
        Self {
            workspace: agent.workspace.clone(),
            run: agent.rollout.run_id().clone(),
            config,
            admitted,
        }
    }
    pub(crate) fn execute(self) -> ProjectInitReceipt {
        let mut receipt = ProjectInitReceipt {
            source_run: self.run,
            entries: Vec::with_capacity(3),
            refusal: None,
        };
        if !self.admitted {
            receipt.refusal = Some("actual host permission policy refuses project initialization");
            return receipt;
        }
        native(&self.workspace, self.config.as_bytes(), &mut receipt);
        receipt
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn native(workspace: &std::path::Path, config: &[u8], receipt: &mut ProjectInitReceipt) {
    use super::capability_fs::{RootBinding, same_file, traverse};
    use super::export::{ExclusivePublication, publish_at};
    use std::os::fd::AsRawFd as _;
    let root = match RootBinding::open(workspace) {
        Ok(root) => root,
        Err(_) => {
            receipt.refusal = Some("workspace is unavailable or contains a symbolic link");
            return;
        }
    };
    if !root.still_bound() {
        receipt.refusal = Some("workspace namespace changed before initialization");
        return;
    }
    let created =
        unsafe { libc::mkdirat(root.root().as_raw_fd(), c".iteron".as_ptr(), 0o700) } == 0;
    if !created && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        receipt.entries.push(InitEntry {
            name: ".iteron",
            status: InitStatus::NotPublished,
        });
        return;
    }
    let components = vec![".iteron".to_owned()];
    let directory = match traverse(root.root(), &components) {
        Ok(directory) => directory,
        Err(_) => {
            receipt.entries.push(InitEntry {
                name: ".iteron",
                status: if created {
                    InitStatus::PublicationUnknown
                } else {
                    InitStatus::NotPublished
                },
            });
            return;
        }
    };
    if created && (directory.sync_all().is_err() || root.root().sync_all().is_err()) {
        receipt.entries.push(InitEntry {
            name: ".iteron",
            status: InitStatus::PublicationUnknown,
        });
        return;
    }
    let bound = || {
        root.still_bound()
            && traverse(root.root(), &components)
                .and_then(|current| same_file(&directory, &current))
                .unwrap_or(false)
    };
    if !bound() {
        receipt.entries.push(InitEntry {
            name: ".iteron",
            status: if created {
                InitStatus::PublicationUnknown
            } else {
                InitStatus::NotPublished
            },
        });
        return;
    }
    receipt.entries.push(InitEntry {
        name: ".iteron",
        status: if created {
            InitStatus::Created
        } else {
            InitStatus::Existing
        },
    });
    for (name, leaf, parent, bytes) in [
        (".iteron/config.json", "config.json", &directory, config),
        ("AGENTS.md", "AGENTS.md", root.root(), INSTRUCTIONS),
    ] {
        if !bound() {
            receipt.refusal = Some("workspace namespace changed before file publication");
            return;
        }
        let mut status = match publish_at(parent, leaf, bytes) {
            ExclusivePublication::Created => InitStatus::Created,
            ExclusivePublication::Exists => InitStatus::Existing,
            ExclusivePublication::NotPublished => InitStatus::NotPublished,
            ExclusivePublication::OutcomeUnknown => InitStatus::PublicationUnknown,
        };
        if status == InitStatus::Created && !bound() {
            status = InitStatus::PublicationUnknown;
        }
        receipt.entries.push(InitEntry { name, status });
        if status == InitStatus::PublicationUnknown {
            return;
        }
    }
}
#[cfg(windows)]
fn native(workspace: &std::path::Path, config: &[u8], receipt: &mut ProjectInitReceipt) {
    use iteron_support::durable_windows_state::{
        WindowsStateError, WindowsWorkspacePublisher, WorkspacePublishError,
    };
    let root = match WindowsWorkspacePublisher::open(workspace) {
        Ok(root) => root,
        Err(_) => {
            receipt.refusal =
                Some("workspace requires an accessible ordinary local NTFS directory");
            return;
        }
    };
    let (directory, created) = match root.open_or_create_child(".iteron") {
        Ok(child) => child,
        Err(error) => {
            receipt.entries.push(InitEntry {
                name: ".iteron",
                status: if matches!(error, WindowsStateError::OutcomeUnknown) {
                    InitStatus::PublicationUnknown
                } else {
                    InitStatus::NotPublished
                },
            });
            return;
        }
    };
    receipt.entries.push(InitEntry {
        name: ".iteron",
        status: if created {
            InitStatus::Created
        } else {
            InitStatus::Existing
        },
    });
    for (name, leaf, parent, bytes) in [
        (".iteron/config.json", "config.json", &directory, config),
        ("AGENTS.md", "AGENTS.md", &root, INSTRUCTIONS),
    ] {
        let mut nonce = [0; 16];
        if getrandom::fill(&mut nonce).is_err() {
            receipt.refusal = Some("native private staging nonce unavailable");
            return;
        }
        let status = match parent.publish(leaf, bytes, nonce) {
            Ok(()) => InitStatus::Created,
            Err(WorkspacePublishError::Exists) => InitStatus::Existing,
            Err(WorkspacePublishError::NotPublished) => InitStatus::NotPublished,
            Err(WorkspacePublishError::OutcomeUnknown) => InitStatus::PublicationUnknown,
        };
        receipt.entries.push(InitEntry { name, status });
        if status == InitStatus::PublicationUnknown {
            return;
        }
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn native(_: &std::path::Path, _: &[u8], receipt: &mut ProjectInitReceipt) {
    receipt.refusal = Some("native project initialization unsupported on this platform");
}
#[cfg(test)]
mod tests;
