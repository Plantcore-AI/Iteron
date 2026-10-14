//! One physical attachment preparation slot. Cancellation invalidates presentation while the
//! actual bounded reader/decoder keeps its admission until it completes. No App/editor borrow
//! crosses the worker boundary; only fully prepared values return for composer admission.
use super::{clipboard_image::clipboard_image_bytes, context_chips};
use crate::{file_input, image_input};
use std::path::PathBuf;
use tokio::{sync::mpsc, task::JoinHandle};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum AttachmentEffectState {
    #[default]
    Idle,
    Queued,
    Reading,
    Decoding,
    Ready,
    Failed,
    Cancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AttachmentFollowup {
    None,
    SubmitComposer,
    QueueRunningDraft,
}

#[derive(Debug)]
pub(super) enum AttachmentOrigin {
    Clipboard,
    Dropped {
        original: String,
    },
    DroppedFile {
        original: String,
    },
    ContextFile,
    #[cfg(not(test))]
    Bare {
        original: String,
        start: usize,
        end: usize,
        draft_revision: u64,
        dropped_shape: bool,
        followup: AttachmentFollowup,
    },
    ComposerSubmission {
        raw: String,
        draft_revision: u64,
        image_mentions: Vec<image_input::ImageMention>,
        file_mentions: Vec<file_input::FileMention>,
    },
}

#[derive(Debug)]
pub(super) enum AttachmentWorkerOutput {
    Prepared(image_input::PreparedImage),
    PreparedFile(file_input::PreparedFile),
    PreparedSubmission {
        images: Vec<image_input::PreparedImage>,
        files: Vec<file_input::PreparedFile>,
    },
    PreparedContextDiff {
        label: String,
        document: String,
    },
    EmptyClipboard,
}

#[derive(Debug)]
pub(super) struct AttachmentEffectResult {
    generation: u64,
    pub(super) origin: AttachmentOrigin,
    pub(super) result: Result<AttachmentWorkerOutput, String>,
}

pub(super) struct SubmissionPreparation {
    pub(super) image_preparer: image_input::ImagePreparer,
    pub(super) file_preparer: file_input::FilePreparer,
    pub(super) workspace: PathBuf,
    pub(super) raw: String,
    pub(super) draft_revision: u64,
    pub(super) image_mentions: Vec<image_input::ImageMention>,
    pub(super) file_mentions: Vec<file_input::FileMention>,
}

struct PhysicalAttachmentResult {
    generation: u64,
    result: Result<AttachmentWorkerOutput, String>,
}

pub(super) enum AttachmentUpdate {
    Prepared(AttachmentEffectResult),
    Failed {
        error: String,
        origin: Option<AttachmentOrigin>,
    },
    Cancelled,
}

#[derive(Default)]
pub(super) struct AttachmentOwner {
    job: Option<JoinHandle<PhysicalAttachmentResult>>,
    origin: Option<AttachmentOrigin>,
    generation: u64,
    progress: Option<mpsc::Receiver<AttachmentEffectState>>,
    state: AttachmentEffectState,
    cancelled: bool,
}
impl AttachmentOwner {
    pub(super) fn is_busy(&self) -> bool {
        self.job.is_some()
    }
    #[cfg(test)]
    pub(super) fn state(&self) -> AttachmentEffectState {
        self.state
    }
    pub(super) fn is_current(&self, effect: &AttachmentEffectResult) -> bool {
        !self.cancelled && effect.generation == self.generation
    }
    pub(super) fn accepted(&mut self) {
        self.state = AttachmentEffectState::Ready;
    }
    pub(super) fn refused(&mut self) {
        self.state = AttachmentEffectState::Failed;
    }
    pub(super) fn draft_changed(&mut self) {
        self.state = AttachmentEffectState::Cancelled;
    }
    /// The slot stays occupied until the actual worker finishes. Aborting a blocking join handle
    /// cannot cancel its filesystem/decode work and must not admit another physical task.
    pub(super) fn invalidate(&mut self) -> Option<AttachmentOrigin> {
        self.generation = self.generation.wrapping_add(1);
        self.cancelled = true;
        self.progress = None;
        self.state = AttachmentEffectState::Cancelled;
        self.origin.take()
    }
    fn begin(&mut self) -> Option<u64> {
        if self.is_busy() {
            return None;
        }
        self.generation = self.generation.wrapping_add(1);
        self.cancelled = false;
        self.progress = None;
        self.state = AttachmentEffectState::Queued;
        Some(self.generation)
    }
    pub(super) fn queue_context_diff(&mut self, workspace: PathBuf, scope: String) -> bool {
        let Some(generation) = self.begin() else {
            return false;
        };
        self.origin = Some(AttachmentOrigin::ContextFile);
        self.job =
            Some(tokio::spawn(async move {
                let result = context_chips::diff_document(&workspace, &scope).await.map(
                    |(label, document)| AttachmentWorkerOutput::PreparedContextDiff {
                        label,
                        document,
                    },
                );
                PhysicalAttachmentResult { generation, result }
            }));
        true
    }
    pub(super) fn queue_image(
        &mut self,
        preparer: image_input::ImagePreparer,
        path: PathBuf,
        origin: AttachmentOrigin,
        preflight: Result<(), String>,
    ) -> Result<(), AttachmentOrigin> {
        let Some(generation) = self.begin() else {
            return Err(origin);
        };
        self.origin = Some(origin);
        self.job = Some(tokio::task::spawn_blocking(move || {
            let result = preflight
                .and_then(|()| preparer.prepare_path(&path).map_err(|e| e.to_string()))
                .map(AttachmentWorkerOutput::Prepared);
            PhysicalAttachmentResult { generation, result }
        }));
        Ok(())
    }
    pub(super) fn queue_file(
        &mut self,
        preparer: file_input::FilePreparer,
        kind: file_input::ContextKind,
        workspace: PathBuf,
        path: PathBuf,
        origin: AttachmentOrigin,
    ) -> Result<(), AttachmentOrigin> {
        let Some(generation) = self.begin() else {
            return Err(origin);
        };
        self.origin = Some(origin);
        self.job = Some(tokio::task::spawn_blocking(move || {
            let result = preparer
                .prepare_typed_path(kind, &workspace, &path)
                .map(AttachmentWorkerOutput::PreparedFile)
                .map_err(|e| e.to_string());
            PhysicalAttachmentResult { generation, result }
        }));
        Ok(())
    }
    pub(super) fn queue_clipboard(
        &mut self,
        preparer: image_input::ImagePreparer,
        preflight: Result<(), String>,
    ) -> bool {
        let Some(generation) = self.begin() else {
            return false;
        };
        let (progress_tx, progress_rx) = mpsc::channel(2);
        self.progress = Some(progress_rx);
        self.origin = Some(AttachmentOrigin::Clipboard);
        self.job = Some(tokio::spawn(async move {
            if let Err(error) = preflight {
                return PhysicalAttachmentResult {
                    generation,
                    result: Err(error),
                };
            }
            let _ = progress_tx.try_send(AttachmentEffectState::Reading);
            let result = match clipboard_image_bytes().await {
                Ok(Some(bytes)) => {
                    let _ = progress_tx.try_send(AttachmentEffectState::Decoding);
                    tokio::task::spawn_blocking(move || {
                        preparer
                            .prepare_bytes("clipboard.png", &bytes)
                            .map(AttachmentWorkerOutput::Prepared)
                            .map_err(|e| e.to_string())
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("clipboard decoder worker failed: {e}")))
                }
                Ok(None) => Ok(AttachmentWorkerOutput::EmptyClipboard),
                Err(error) => Err(error.to_owned()),
            };
            PhysicalAttachmentResult { generation, result }
        }));
        true
    }
    pub(super) fn queue_submission(&mut self, request: SubmissionPreparation) -> bool {
        let SubmissionPreparation {
            image_preparer,
            file_preparer,
            workspace,
            raw,
            draft_revision,
            image_mentions,
            file_mentions,
        } = request;
        let Some(generation) = self.begin() else {
            return false;
        };
        let image_paths = resolved_image_paths(&workspace, &image_mentions);
        let file_paths = file_mentions
            .iter()
            .map(|m| m.path().to_path_buf())
            .collect();
        self.origin = Some(AttachmentOrigin::ComposerSubmission {
            raw,
            draft_revision,
            image_mentions,
            file_mentions,
        });
        self.job = Some(tokio::task::spawn_blocking(move || {
            let result = prepare_submission_attachments(
                image_preparer,
                file_preparer,
                workspace,
                image_paths,
                file_paths,
            )
            .map(|(images, files)| AttachmentWorkerOutput::PreparedSubmission { images, files });
            PhysicalAttachmentResult { generation, result }
        }));
        true
    }
    pub(super) fn poll_progress(&mut self) -> bool {
        if self.cancelled {
            return false;
        }
        let before = self.state;
        if self.is_busy() && self.state == AttachmentEffectState::Queued {
            self.state = AttachmentEffectState::Reading;
        }
        if let Some(progress) = self.progress.as_mut() {
            for _ in 0..2 {
                let Ok(state) = progress.try_recv() else {
                    break;
                };
                self.state = state;
            }
        }
        before != self.state
    }
    pub(super) async fn poll_ready(&mut self) -> Option<AttachmentUpdate> {
        if !self.job.as_ref().is_some_and(|job| job.is_finished()) {
            return None;
        }
        let result = self.job.take().expect("finished job was present").await;
        Some(self.completed(result))
    }
    fn completed(
        &mut self,
        result: Result<PhysicalAttachmentResult, tokio::task::JoinError>,
    ) -> AttachmentUpdate {
        self.progress = None;
        if self.cancelled {
            return AttachmentUpdate::Cancelled;
        }
        let origin = self.origin.take();
        match result {
            Ok(physical) if physical.generation == self.generation => match origin {
                Some(origin) => AttachmentUpdate::Prepared(AttachmentEffectResult {
                    generation: physical.generation,
                    origin,
                    result: physical.result,
                }),
                None => {
                    self.draft_changed();
                    AttachmentUpdate::Cancelled
                }
            },
            Ok(_) => {
                self.draft_changed();
                AttachmentUpdate::Cancelled
            }
            Err(error) => {
                self.refused();
                AttachmentUpdate::Failed {
                    error: format!("attachment worker failed: {error}"),
                    origin,
                }
            }
        }
    }
    #[cfg(test)]
    pub(super) async fn wait_ready(&mut self) -> AttachmentUpdate {
        let result = self
            .job
            .take()
            .expect("test attachment worker was present")
            .await;
        self.completed(result)
    }
}
pub(super) fn resolved_image_paths(
    workspace: &std::path::Path,
    mentions: &[image_input::ImageMention],
) -> Vec<std::path::PathBuf> {
    mentions
        .iter()
        .map(|mention| {
            let path = mention.reference().path();
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                workspace.join(path)
            }
        })
        .collect()
}

pub(super) fn prepare_submission_attachments(
    image_preparer: image_input::ImagePreparer,
    file_preparer: file_input::FilePreparer,
    workspace: std::path::PathBuf,
    image_paths: Vec<std::path::PathBuf>,
    file_paths: Vec<std::path::PathBuf>,
) -> Result<
    (
        Vec<image_input::PreparedImage>,
        Vec<file_input::PreparedFile>,
    ),
    String,
> {
    let mut images = Vec::with_capacity(image_paths.len());
    for path in image_paths {
        images.push(
            image_preparer
                .prepare_path(&path)
                .map_err(|error| format!("image attachment refused: {error}"))?,
        );
    }
    let mut files = Vec::with_capacity(file_paths.len());
    for path in file_paths {
        files.push(
            file_preparer
                .prepare_path(&workspace, &path)
                .map_err(|error| format!("file attachment refused: {error}"))?,
        );
    }
    Ok((images, files))
}

#[cfg(test)]
mod tests {
    use super::{
        AttachmentEffectState, AttachmentOrigin, AttachmentOwner, AttachmentUpdate,
        AttachmentWorkerOutput, PhysicalAttachmentResult,
    };
    use crate::file_input::{ContextKind, FileAttachments};
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn cancellation_returns_owned_path_and_keeps_real_file_preparation_slot_until_completion()
    {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "iteron-attachment-slot-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("evidence.txt");
        std::fs::write(&path, "exact retained evidence\n").unwrap();
        let preparer = FileAttachments::default().preparer();
        let mut owner = AttachmentOwner::default();
        let generation = owner.begin().unwrap();
        let original = path.to_string_lossy().into_owned();
        owner.origin = Some(AttachmentOrigin::DroppedFile {
            original: original.clone(),
        });
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let workspace = root.clone();
        let requested = path.clone();
        owner.job = Some(tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let result = preparer
                .prepare_path(&workspace, &requested)
                .map(AttachmentWorkerOutput::PreparedFile)
                .map_err(|error| error.to_string());
            PhysicalAttachmentResult { generation, result }
        }));
        tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        let Some(AttachmentOrigin::DroppedFile { original: restored }) = owner.invalidate() else {
            panic!("cancel must return the exact owned path")
        };
        assert_eq!(restored, original);
        assert!(owner.is_busy());
        assert_eq!(owner.state(), AttachmentEffectState::Cancelled);
        assert!(owner.poll_ready().await.is_none());
        let refused = owner.queue_file(
            preparer,
            ContextKind::File,
            root.clone(),
            path.clone(),
            AttachmentOrigin::DroppedFile {
                original: "second request".into(),
            },
        );
        assert!(
            matches!(refused, Err(AttachmentOrigin::DroppedFile {original}) if original == "second request")
        );
        release_tx.send(()).unwrap();
        assert!(matches!(
            owner.wait_ready().await,
            AttachmentUpdate::Cancelled
        ));
        assert!(!owner.is_busy());
        owner
            .queue_file(
                preparer,
                ContextKind::File,
                root.clone(),
                path,
                AttachmentOrigin::ContextFile,
            )
            .unwrap();
        let AttachmentUpdate::Prepared(effect) = owner.wait_ready().await else {
            panic!("new physical task must complete")
        };
        assert!(owner.is_current(&effect));
        let Ok(AttachmentWorkerOutput::PreparedFile(prepared)) = effect.result else {
            panic!("must be a real prepared file")
        };
        assert_eq!(prepared.text_bytes(), "exact retained evidence\n".len());
        std::fs::remove_dir_all(root).unwrap();
    }
}
