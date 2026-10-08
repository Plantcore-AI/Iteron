//! Existing offline lab intents. No runtime activation, signing or provider execution is exposed.
mod comparison;
mod model;
use super::workspace_storage::{NativeDirectory, Publication, StorageError};
use crate::runtime::Agent;
use iteron_protocol::ToolUse;
pub(crate) use model::{ComparisonViewV1, LabActionV1, LabFactsV1, RequestStatusV1, RequestViewV1};
use model::{ExperimentRequest, prepare_request, project_request};
use std::path::PathBuf;
const MAX_SCAN: usize = 4096;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
fn max_request_bytes() -> usize {
    // Preserve the existing lowering-only request-read control at its original address.
    iteron_tunables::param_integer(
        "cli.tui.experiment_lab.max_request_bytes",
        MAX_REQUEST_BYTES,
    )
    .min(MAX_REQUEST_BYTES)
}
pub(crate) struct NativeExperimentLab {
    workspace: PathBuf,
    action: PreparedAction,
    #[cfg(test)]
    pause: Option<(
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
    #[cfg(test)]
    panic_after_publish: bool,
}
enum PreparedAction {
    List,
    Request {
        request: Box<ExperimentRequest>,
        bytes: Vec<u8>,
    },
    Compare {
        bundle: String,
        key: String,
    },
}
pub(crate) struct LabCompletion {
    pub(crate) facts: Result<LabFactsV1, &'static str>,
    pub(crate) publication_unknown: bool,
}
impl NativeExperimentLab {
    pub(crate) fn capture(agent: &Agent, action: LabActionV1) -> Result<Self, &'static str> {
        action.validate()?;
        let (action, call) = match action {
            LabActionV1::List => (
                PreparedAction::List,
                ToolUse {
                    id: "operator-lab-list".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path":".iteron/experiments"}),
                },
            ),
            LabActionV1::Request { family, value } => {
                let (request, bytes) = prepare_request(&family, &value)?;
                let path = format!(".iteron/experiments/requests/{}.json", request.request_id);
                let call = ToolUse {
                    id: "operator-lab-request".into(),
                    name: "write_file".into(),
                    input: serde_json::json!({"path":path,"content":std::str::from_utf8(&bytes).map_err(|_|"request encoding unavailable")?}),
                };
                (
                    PreparedAction::Request {
                        request: Box::new(request),
                        bytes,
                    },
                    call,
                )
            }
            LabActionV1::Compare {
                bundle_id,
                trusted_public_key,
            } => {
                let call = ToolUse {
                    id: "operator-lab-compare".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path":format!(".iteron/experiments/evidence/{bundle_id}")}),
                };
                (
                    PreparedAction::Compare {
                        bundle: bundle_id,
                        key: trusted_public_key,
                    },
                    call,
                )
            }
        };
        if !agent.admit_operator_tool_call(&call) {
            return Err("lab filesystem access is denied by current policy or authority ceiling");
        }
        Ok(Self {
            workspace: agent.workspace.clone(),
            action,
            #[cfg(test)]
            pause: None,
            #[cfg(test)]
            panic_after_publish: false,
        })
    }
    pub(crate) fn mutating(&self) -> bool {
        matches!(self.action, PreparedAction::Request { .. })
    }
    pub(crate) fn execute(self) -> LabCompletion {
        #[cfg(test)]
        if let Some((started, release)) = self.pause {
            started.send(()).unwrap();
            release
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
        let mut unknown = false;
        let result = (|| {
            let root =
                NativeDirectory::open(&self.workspace).map_err(|_| "workspace is unavailable")?;
            match self.action {
                PreparedAction::List => list(&root),
                PreparedAction::Compare { bundle, key } => {
                    comparison::compare(&root, &bundle, &key)
                }
                PreparedAction::Request { request, bytes } => {
                    let directory = chain(&root, &[".iteron", "experiments", "requests"], true)
                        .map_err(|error| {
                            unknown = error == StorageError::PublicationUnknown;
                            "experiment request directory publication is unavailable or unconfirmed"
                        })?
                        .ok_or("experiment request directory unavailable")?;
                    let leaf = format!("{}.json", request.request_id);
                    let status = match directory.publish(&leaf, &bytes) {
                        Publication::Created => RequestStatusV1::Created,
                        Publication::Existing => {
                            let actual = directory
                                .read(&leaf, max_request_bytes())
                                .map_err(|_| "existing request cannot be safely verified")?;
                            if actual != bytes {
                                return Err("request identity collision; existing bytes retained");
                            }
                            RequestStatusV1::Existing
                        }
                        Publication::NotPublished => RequestStatusV1::NotPublished,
                        Publication::Unknown => {
                            unknown = true;
                            RequestStatusV1::PublicationUnknown
                        }
                    };
                    #[cfg(test)]
                    if self.panic_after_publish && status == RequestStatusV1::Created {
                        panic!("actual published request lost its host receipt");
                    }
                    Ok(LabFactsV1::Request {
                        receipt: project_request(&request, status),
                    })
                }
            }
        })();
        LabCompletion {
            facts: result,
            publication_unknown: unknown,
        }
    }
}
#[cfg(test)]
impl NativeExperimentLab {
    pub(crate) fn pause(
        mut self,
        start: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Self {
        self.pause = Some((start, release));
        self
    }
    pub(crate) fn panic_after_publish(mut self) -> Self {
        self.panic_after_publish = true;
        self
    }
}
#[cfg(test)]
pub(crate) mod tests;
fn chain(
    root: &NativeDirectory,
    names: &[&str],
    create: bool,
) -> Result<Option<NativeDirectory>, StorageError> {
    let mut current = None;
    for name in names {
        let parent = current.as_ref().unwrap_or(root);
        let Some(next) = parent.child(name, create)? else {
            return Ok(None);
        };
        current = Some(next);
    }
    Ok(current)
}
fn list(root: &NativeDirectory) -> Result<LabFactsV1, &'static str> {
    let Some(root) = chain(root, &[".iteron", "experiments"], false)
        .map_err(|_| "experiment namespace is unsafe")?
    else {
        return Ok(LabFactsV1::Inventory {
            requests: Vec::new(),
            bundles: Vec::new(),
            incomplete: false,
        });
    };
    let mut requests = Vec::new();
    let mut bundles = Vec::new();
    let mut incomplete = false;
    let mut read_remaining = 8 * 1024 * 1024usize;
    if let Some(directory) = root
        .child("requests", false)
        .map_err(|_| "request namespace is unsafe")?
    {
        let (mut entries, more) = directory
            .list(MAX_SCAN)
            .map_err(|_| "request enumeration unavailable")?;
        incomplete |= more;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, is_dir) in entries {
            if is_dir || !name.ends_with(".json") {
                continue;
            }
            if read_remaining == 0 {
                incomplete = true;
                break;
            }
            let bytes = match directory.read(&name, max_request_bytes().min(read_remaining)) {
                Ok(bytes) => bytes,
                Err(_) => {
                    incomplete = true;
                    continue;
                }
            };
            read_remaining -= bytes.len();
            let request: ExperimentRequest = match serde_json::from_slice(&bytes) {
                Ok(request) => request,
                Err(_) => {
                    incomplete = true;
                    continue;
                }
            };
            if request.validate().is_err() || name != format!("{}.json", request.request_id) {
                incomplete = true;
                continue;
            }
            if requests.len() == 80 {
                incomplete = true;
                break;
            }
            requests.push(project_request(&request, RequestStatusV1::Existing));
        }
    }
    if let Some(directory) = root
        .child("evidence", false)
        .map_err(|_| "evidence namespace is unsafe")?
    {
        let (mut entries, more) = directory
            .list(MAX_SCAN)
            .map_err(|_| "evidence enumeration unavailable")?;
        incomplete |= more;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, is_dir) in entries {
            if !is_dir {
                continue;
            }
            let Some(bundle) = directory
                .child(&name, false)
                .map_err(|_| "evidence child unavailable")?
            else {
                incomplete = true;
                continue;
            };
            let (names, more) = bundle
                .list(17)
                .map_err(|_| "evidence index enumeration unavailable")?;
            if more {
                incomplete = true;
            }
            if !names
                .iter()
                .any(|(name, is_dir)| name == "bundle.index.json" && !is_dir)
            {
                incomplete = true;
                continue;
            }
            if bundles.len() == 40 {
                incomplete = true;
                break;
            }
            bundles.push(model::display(&name));
        }
    }
    Ok(LabFactsV1::Inventory {
        requests,
        bundles,
        incomplete,
    })
}
