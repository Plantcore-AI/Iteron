//! Single frontend owner of after-turn input and exact identified steer previews.
//! Queue values own their attachment stores; immutable views cannot dequeue or acknowledge them.
//! This is frontend pending intent, never runtime admission or durable completion authority.

use crate::{file_input, image_input};
use iteron_protocol::SubmissionId;
use std::collections::VecDeque;

/// Bound the two pending lanes together.
pub(super) const MAX_PENDING_SUBMISSIONS: usize = 32;
/// Oversize interactive follow-ups stay in the draft.
pub(super) const MAX_SUBMISSION_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubmissionAdmission {
    Accept,
    IgnoreEmpty,
    Reject,
}

#[derive(Clone)]
pub(super) struct PendingInput {
    pub(super) seq: u64,
    pub(super) text: String,
    /// Set only while an identified steer awaits an exact runtime admission signal.
    pub(super) submission_id: Option<SubmissionId>,
    /// The chips this submission was composed with, moved out of the composer when it was queued.
    ///
    /// They travel WITH the text because `Editor::take_submit` clears the attachment stores: an
    /// image dropped during a run and queued behind it would otherwise be discarded on the way to
    /// the queue, or — worse — still be sitting in the composer when the operator writes an
    /// unrelated message next, and would be sent with that one instead. Neither is a thing anyone
    /// asked for. A steer cannot carry them at all (`Op::Steer` is text, and the protocol is
    /// frozen), which is why a draft with chips is always routed to this queue.
    pub(super) images: image_input::ImageAttachments,
    pub(super) files: file_input::FileAttachments,
    pub(super) draft: Option<crate::editor::QueuedDraftMetadata>,
}

/// Identity of a queued submission is what it will send: its order, its words, and how many chips
/// ride with it. The attachment stores hold decoded bytes and are deliberately not compared —
/// equality is used by the queue-ordering assertions, not to decide whether two images are alike.
impl PartialEq for PendingInput {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
            && self.text == other.text
            && self.submission_id == other.submission_id
            && self.images.len() == other.images.len()
            && self.files.len() == other.files.len()
    }
}

impl Eq for PendingInput {}

impl std::fmt::Debug for PendingInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInput")
            .field("seq", &self.seq)
            .field("text", &self.text)
            .field("submission_id", &self.submission_id)
            .field("images", &self.images.len())
            .field("files", &self.files.len())
            .finish()
    }
}

impl PendingInput {
    pub(super) fn has_attachments(&self) -> bool {
        !self.images.is_empty() || !self.files.is_empty()
    }
}

#[derive(Default)]
pub(super) struct InputLanes {
    queued: VecDeque<PendingInput>,
    steer_previews: VecDeque<PendingInput>,
    next_submission_seq: u64,
}
impl InputLanes {
    pub(super) fn queued(&self) -> &VecDeque<PendingInput> {
        &self.queued
    }
    pub(super) fn steers(&self) -> &VecDeque<PendingInput> {
        &self.steer_previews
    }
    pub(super) fn pending_count(&self) -> usize {
        self.queued.len().saturating_add(self.steer_previews.len())
    }
    pub(super) fn pop_next(&mut self) -> Option<PendingInput> {
        self.queued.pop_front()
    }
    pub(super) fn reclaim_latest(&mut self, editor: &mut crate::editor::Editor) -> bool {
        if !editor.can_restore_owned_draft() {
            return false;
        }
        let Some(input) = self.queued.pop_back() else {
            return false;
        };
        let seq = input.seq;
        let submission_id = input.submission_id;
        let draft = crate::editor::OwnedComposerDraft {
            text: input.text,
            images: input.images,
            files: input.files,
            metadata: input.draft,
        };
        match editor.restore_owned_draft(draft) {
            Ok(()) => true,
            Err(draft) => {
                let crate::editor::OwnedComposerDraft {
                    text,
                    images,
                    files,
                    metadata,
                } = *draft;
                self.queued.push_back(PendingInput {
                    seq,
                    submission_id,
                    text,
                    images,
                    files,
                    draft: metadata,
                });
                false
            }
        }
    }

    /// Restore the very value whose submission or local command was refused. Its chips and order
    /// were never cloned into another live queue.
    pub(super) fn restore_next(&mut self, input: PendingInput) {
        self.queued.push_front(input);
    }
    pub(super) fn admission(
        text: &str,
        pending: usize,
    ) -> Result<SubmissionAdmission, LaneRefusal> {
        if text.trim().is_empty() {
            return Ok(SubmissionAdmission::IgnoreEmpty);
        }
        if text.len() > submission_bytes() {
            return Err(LaneRefusal::TooLarge);
        }
        if pending >= pending_limit() {
            return Err(LaneRefusal::Full);
        }
        Ok(SubmissionAdmission::Accept)
    }

    pub(super) fn queue(
        &mut self,
        text: String,
        images: image_input::ImageAttachments,
        files: file_input::FileAttachments,
        draft: Option<crate::editor::QueuedDraftMetadata>,
    ) -> Result<(), Box<QueueRefusal>> {
        let has_attachments = !images.is_empty() || !files.is_empty();
        let admission = Self::admission(&text, self.pending_count());
        let refusal = match admission {
            Err(reason) => Some(reason),
            Ok(SubmissionAdmission::IgnoreEmpty) if !has_attachments => return Ok(()),
            Ok(SubmissionAdmission::IgnoreEmpty) if self.pending_count() >= pending_limit() => {
                Some(LaneRefusal::Full)
            }
            Ok(_) => None,
        };
        if let Some(reason) = refusal {
            return Err(Box::new(QueueRefusal {
                text,
                images,
                files,
                draft,
                reason,
            }));
        }
        let mut input = self.mint(text);
        input.images = images;
        input.files = files;
        input.draft = draft;
        self.queued.push_back(input);
        Ok(())
    }

    pub(super) fn track_steer(&mut self, text: String, id: SubmissionId) {
        debug_assert!(!text.trim().is_empty());
        debug_assert!(
            text.len()
                <= iteron_tunables::param_integer(
                    "cli.tui.driver_support.max_submission_bytes",
                    MAX_SUBMISSION_BYTES
                )
        );
        debug_assert!(
            self.pending_count()
                < iteron_tunables::param_integer(
                    "cli.tui.driver_support.max_pending_submissions",
                    MAX_PENDING_SUBMISSIONS
                )
        );
        let mut input = self.mint(text);
        input.submission_id = Some(id);
        self.steer_previews.push_back(input);
    }

    pub(super) fn settle_steer_submission(&mut self, id: SubmissionId) {
        if let Some(index) = self
            .steer_previews
            .iter()
            .position(|preview| preview.submission_id == Some(id))
        {
            self.steer_previews.remove(index);
        }
    }

    fn mint(&mut self, text: String) -> PendingInput {
        let seq = self.next_submission_seq;
        self.next_submission_seq = self.next_submission_seq.wrapping_add(1);
        PendingInput {
            seq,
            text,
            submission_id: None,
            images: image_input::ImageAttachments::default(),
            files: file_input::FileAttachments::default(),
            draft: None,
        }
    }

    pub(super) fn requeue_unadmitted(
        &mut self,
        unadmitted: Vec<String>,
        submission_ids: &[Option<SubmissionId>],
    ) -> RequeueReport {
        let mut report = RequeueReport::default();
        for (index, text) in unadmitted.into_iter().enumerate() {
            let id = submission_ids.get(index).copied().flatten();
            let preview = id
                .and_then(|id| {
                    self.steer_previews
                        .iter()
                        .position(|preview| preview.submission_id == Some(id))
                })
                .and_then(|index| self.steer_previews.remove(index));
            if let Some(mut preview) = preview {
                // Exact frontend identity selects its original owned operator words and chips.
                // A run-wide snapshot cannot replace them with another client's returned text.
                preview.submission_id = None;
                self.queued.push_back(preview);
                report.queued += 1;
            } else if id.is_some() {
                // The run can contain steering from another authenticated client. Observing its
                // non-admission does not grant this frontend authority to resubmit its request.
                report.foreign += 1;
            } else if matches!(
                Self::admission(&text, self.pending_count()),
                Ok(SubmissionAdmission::Accept)
            ) {
                let input = self.mint(text);
                self.queued.push_back(input);
                report.queued += 1;
            } else {
                // Old no-ID snapshots have no exact owner correlation. Reserve capacity for
                // every tracked local preview first, and report incompatible overflow explicitly.
                report.legacy_unrestored += 1;
            }
        }
        report.unmatched = self.steer_previews.len();
        self.queued
            .extend(self.steer_previews.drain(..).map(|mut preview| {
                preview.submission_id = None;
                preview
            }));
        self.queued.make_contiguous().sort_by_key(|input| input.seq);
        debug_assert!(self.queued.len() <= pending_limit());
        report
    }
}

#[derive(Clone, Copy)]
pub(super) enum LaneRefusal {
    TooLarge,
    Full,
}
pub(super) struct QueueRefusal {
    pub(super) text: String,
    pub(super) reason: LaneRefusal,
    pub(super) images: image_input::ImageAttachments,
    pub(super) files: file_input::FileAttachments,
    pub(super) draft: Option<crate::editor::QueuedDraftMetadata>,
}
impl QueueRefusal {
    pub(super) fn into_owned_draft(self) -> crate::editor::OwnedComposerDraft {
        crate::editor::OwnedComposerDraft {
            text: self.text,
            images: self.images,
            files: self.files,
            metadata: self.draft,
        }
    }
}

#[derive(Default)]
pub(super) struct RequeueReport {
    pub(super) queued: usize,
    pub(super) unmatched: usize,
    pub(super) foreign: usize,
    pub(super) legacy_unrestored: usize,
}
fn pending_limit() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.driver_support.max_pending_submissions",
        MAX_PENDING_SUBMISSIONS,
    )
}
fn submission_bytes() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.driver_support.max_submission_bytes",
        MAX_SUBMISSION_BYTES,
    )
}
