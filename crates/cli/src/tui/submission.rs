use super::*;

pub(super) fn submit_composer(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
) {
    // A drop that arrived as keystrokes rather than as a bracketed paste is still a drop. Convert
    // it before anything reads the draft, so the rest of this function sees the chips and anchors
    // the paste lane would have produced.
    attach_bare_image_paths(app, session.workspace());
    let raw = app.editor.text();
    let mentions = match image_input::parse_image_mentions(&raw) {
        Ok(mentions) => mentions,
        Err(error) => {
            app.note(
                block::NoticeLevel::Warn,
                format!("image attachment refused: {error}"),
            );
            return;
        }
    };
    let mut staged: ImageAttachments = app.editor.attachments().clone();
    for mention in &mentions {
        let reference = mention.reference().path();
        let path = if reference.is_absolute() {
            reference.to_path_buf()
        } else {
            session.workspace().join(reference)
        };
        if let Err(error) = staged.attach_path(&path) {
            app.note(
                block::NoticeLevel::Warn,
                format!("image attachment refused: {error}"),
            );
            return;
        }
    }
    // File mentions resolve on the same terms, into the same kind of staged clone, and are
    // contained by `file_input::FileAttachments` — which routes every path through the workspace
    // containment `read_file` uses. A refusal here leaves the draft and its chips untouched.
    let file_mentions = match file_input::parse_file_mentions(&raw) {
        Ok(mentions) => mentions,
        Err(error) => {
            app.note(
                block::NoticeLevel::Warn,
                format!("file attachment refused: {error}"),
            );
            return;
        }
    };
    let mut staged_files: file_input::FileAttachments = app.editor.files().clone();
    for mention in &file_mentions {
        if let Err(error) = staged_files.attach_path(session.workspace(), mention.path()) {
            app.note(
                block::NoticeLevel::Warn,
                format!("file attachment refused: {error}"),
            );
            return;
        }
    }

    let mut text = raw;
    // Both mention kinds are cut out of the prompt by byte range, so the ranges must be removed
    // from the end backwards across the *union* of them, not once per kind: two independent
    // reverse passes shift the offsets the second pass is still holding.
    let mut cuts: Vec<std::ops::Range<usize>> = mentions
        .iter()
        .map(|mention| mention.byte_range.clone())
        .chain(
            file_mentions
                .iter()
                .map(|mention| mention.byte_range.clone()),
        )
        .collect();
    cuts.sort_by_key(|range| range.start);
    for range in cuts.iter().rev() {
        text.replace_range(range.clone(), "");
    }
    // Pasted blocks come back LAST, after the mentions have been parsed and cut. That order is the
    // guarantee that pasted bytes are inert: text the operator did not write cannot name an
    // `@file(...)` mention and make the composer read it, because by the time those bytes exist in
    // the string there is nothing left that looks for mentions.
    // Image anchors are resolved in the same pass, against the EDITOR's attachments rather than the
    // staged clone. Only a chip the operator can see may answer an anchor: `staged` also holds the
    // images just admitted from `@image(...)` mentions, which have no chip and no visible id, and
    // resolving against it would let a hand-typed `[Image #1]` point at one of them by coincidence
    // of numbering. An anchor the composer cannot show is an anchor nobody wrote on purpose.
    let text = paste_input::expand(
        &text,
        app.editor.pastes(),
        app.editor.attachments(),
        app.editor.files(),
    );
    if text.len() > iteron_protocol::task::MAX_TASK_TEXT_BYTES {
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "submission refused: {} bytes exceeds the {}-byte task limit — the draft and its \
                 pasted blocks are untouched",
                text.len(),
                iteron_protocol::task::MAX_TASK_TEXT_BYTES
            ),
        );
        return;
    }
    let text = text.trim().to_owned();
    if text.is_empty() && staged.is_empty() && staged_files.is_empty() {
        return;
    }
    // The frozen segment list cannot interleave text and images, so an anchor's position is
    // honoured the only way the wire allows: the anchored images lead, in the order the sentence
    // names them, and everything the sentence does not name follows in attach order — which is
    // byte-for-byte what an unanchored draft has always sent.
    // Same store, same reason: a mention's image is never named by an anchor, so it keeps its place
    // behind the ones that are. `staged` opens as a clone of these attachments, ids and all, so the
    // ids read from the editor address the very same images inside it.
    let anchor_order = paste_input::anchored_image_ids(&text, app.editor.attachments());
    submit_staged_input(
        app,
        session,
        notifier,
        text,
        staged,
        staged_files,
        anchor_order,
        true,
    );
}

/// Send one composed submission: text plus the images and files it was staged with.
///
/// Shared by the composer and by the after-turn queue, so a submission that waited behind a run is
/// assembled by the same code that assembles an immediate one. `clear_composer` is the only
/// difference between them: the composer path consumes the draft it just read, and the queued path
/// has no draft to consume — its chips were moved out of the composer when it was queued.
#[allow(clippy::too_many_arguments)]
pub(super) fn submit_staged_input(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
    text: String,
    mut staged: image_input::ImageAttachments,
    staged_files: file_input::FileAttachments,
    anchor_order: Vec<u32>,
    clear_composer: bool,
) -> bool {
    staged.order_by_anchors(&anchor_order);
    let op = if !staged_files.is_empty() {
        // Files present: the one operation that can carry them, images included. Admission is
        // re-run by the kernel, so a refusal here buys the operator a message in the composer
        // rather than being the only thing standing between a bad payload and a turn.
        let images = staged
            .as_slice()
            .iter()
            .map(|attachment| attachment.content().clone())
            .collect::<Vec<_>>();
        let files = staged_files.to_file_contents();
        if let Err(reason) = iteron_protocol::input::validate_file_submission(&text, &images, &files)
        {
            app.note(
                block::NoticeLevel::Warn,
                format!("file attachment refused: {reason}"),
            );
            return false;
        }
        Op::UserInputV3 {
            text: text.clone(),
            images,
            files,
        }
    } else if staged.is_empty() {
        Op::UserInput { text: text.clone() }
    } else {
        let segments = match staged.to_content_segments(text.clone()) {
            Ok(segments) => segments,
            Err(error) => {
                app.note(
                    block::NoticeLevel::Warn,
                    format!("image attachment refused: {error}"),
                );
                return false;
            }
        };
        Op::UserInputV2 { segments }
    };
    let editor_revision = app.editor.persistence_revision();
    if let Some(submission_id) = submit_operation(app, session, notifier, op) {
        // Only the plain-text turn is offered back: re-sending staged attachments would re-read
        // files that may have changed since, which is a different request, not a retry (I-39).
        app.retryable_task = (staged.is_empty() && staged_files.is_empty()).then(|| text.clone());
        let image_count = staged.len();
        let file_count = staged_files.len();
        let display_text = if text.is_empty() {
            let mut summary = String::from("[");
            if image_count > 0 {
                summary.push_str(&format!(
                    "{image_count} image attachment{}",
                    if image_count == 1 { "" } else { "s" }
                ));
            }
            if file_count > 0 {
                if image_count > 0 {
                    summary.push_str(", ");
                }
                summary.push_str(&format!(
                    "{file_count} file attachment{}",
                    if file_count == 1 { "" } else { "s" }
                ));
            }
            summary.push(']');
            summary
        } else {
            text
        };
        app.pending_turn_receipt = Some(PendingTurnReceipt {
            id: submission_id,
            editor_revision,
            clear_composer,
            display_text,
        });
        return true;
    }
    false
}
