use super::*;

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

pub(super) fn queue_context_diff_effect(app: &mut App, workspace: PathBuf, scope: String) {
    if let Some(previous) = app.attachment_job.take() {
        previous.abort();
        app.attachment_effect_state = AttachmentEffectState::Cancelled;
    }
    app.attachment_generation = app.attachment_generation.wrapping_add(1);
    let generation = app.attachment_generation;
    app.attachment_effect_state = AttachmentEffectState::Queued;
    app.attachment_job = Some(tokio::spawn(async move {
        let result =
            context_chips::diff_document(&workspace, &scope)
                .await
                .map(
                    |(label, document)| AttachmentWorkerOutput::PreparedContextDiff {
                        label,
                        document,
                    },
                );
        AttachmentEffectResult {
            generation,
            origin: AttachmentOrigin::ContextFile,
            result,
        }
    }));
}

#[derive(Debug)]
pub(super) struct AttachmentEffectResult {
    pub(super) generation: u64,
    pub(super) origin: AttachmentOrigin,
    pub(super) result: Result<AttachmentWorkerOutput, String>,
}

/// Replace the one bounded attachment job. Cancellation is explicit state; its detached blocking
/// read remains contained by `image_input`'s process-wide single-flight gate.
pub(super) fn queue_image_path_effect(app: &mut App, path: PathBuf, origin: AttachmentOrigin) {
    if let Some(previous) = app.attachment_job.take() {
        previous.abort();
        app.attachment_effect_state = AttachmentEffectState::Cancelled;
    }
    app.attachment_generation = app.attachment_generation.wrapping_add(1);
    let generation = app.attachment_generation;
    let preflight = app.editor.attachments().preflight_path(&path);
    let preparer = app.editor.attachments().preparer();
    app.attachment_effect_state = AttachmentEffectState::Queued;
    app.attachment_job = Some(tokio::task::spawn_blocking(move || {
        let result = preflight
            .and_then(|()| preparer.prepare_path(&path))
            .map(AttachmentWorkerOutput::Prepared)
            .map_err(|error| error.to_string());
        AttachmentEffectResult {
            generation,
            origin,
            result,
        }
    }));
}

pub(super) fn queue_clipboard_image_effect(app: &mut App) {
    if let Some(previous) = app.attachment_job.take() {
        previous.abort();
        app.attachment_effect_state = AttachmentEffectState::Cancelled;
    }
    app.attachment_generation = app.attachment_generation.wrapping_add(1);
    let generation = app.attachment_generation;
    let preflight = app.editor.attachments().preflight_label("clipboard.png");
    let preparer = app.editor.attachments().preparer();
    let (progress_tx, progress_rx) = tokio::sync::mpsc::channel(2);
    app.attachment_progress = Some(progress_rx);
    app.attachment_effect_state = AttachmentEffectState::Queued;
    app.attachment_job = Some(tokio::spawn(async move {
        if let Err(error) = preflight {
            return AttachmentEffectResult {
                generation,
                origin: AttachmentOrigin::Clipboard,
                result: Err(error.to_string()),
            };
        }
        let _ = progress_tx.send(AttachmentEffectState::Reading).await;
        let result = match clipboard_image_bytes().await {
            Ok(Some(bytes)) => {
                let _ = progress_tx.send(AttachmentEffectState::Decoding).await;
                tokio::task::spawn_blocking(move || {
                    preparer
                        .prepare_bytes("clipboard.png", &bytes)
                        .map(AttachmentWorkerOutput::Prepared)
                        .map_err(|error| error.to_string())
                })
                .await
                .unwrap_or_else(|error| Err(format!("clipboard decoder worker failed: {error}")))
            }
            Ok(None) => Ok(AttachmentWorkerOutput::EmptyClipboard),
            Err(error) => Err(error.to_owned()),
        };
        AttachmentEffectResult {
            generation,
            origin: AttachmentOrigin::Clipboard,
            result,
        }
    }));
}

pub(super) fn queue_file_path_effect(
    app: &mut App,
    kind: file_input::ContextKind,
    workspace: PathBuf,
    path: PathBuf,
    origin: AttachmentOrigin,
) {
    if let Some(previous) = app.attachment_job.take() {
        previous.abort();
        app.attachment_effect_state = AttachmentEffectState::Cancelled;
    }
    app.attachment_generation = app.attachment_generation.wrapping_add(1);
    let generation = app.attachment_generation;
    let preparer = app.editor.files().preparer();
    app.attachment_effect_state = AttachmentEffectState::Queued;
    app.attachment_job = Some(tokio::task::spawn_blocking(move || {
        let result = preparer
            .prepare_typed_path(kind, &workspace, &path)
            .map(AttachmentWorkerOutput::PreparedFile)
            .map_err(|error| error.to_string());
        AttachmentEffectResult {
            generation,
            origin,
            result,
        }
    }));
}

/// Apply only the actor's prepared value on the TUI thread. No path read, decoder, HEIC helper, or
/// base64 encoder is reachable from this function.
pub(super) fn finish_attachment_effect(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
    effect: AttachmentEffectResult,
) {
    if effect.generation != app.attachment_generation {
        app.attachment_effect_state = AttachmentEffectState::Cancelled;
        return;
    }
    let AttachmentEffectResult { origin, result, .. } = effect;
    match result {
        Ok(AttachmentWorkerOutput::PreparedContextDiff { label, document }) => {
            match app
                .editor
                .attach_context(file_input::ContextKind::Diff, &label, document)
            {
                Ok(chip) => {
                    let summary = (
                        chip.display_name().to_owned(),
                        chip.id(),
                        chip.text_bytes(),
                        chip.digest().get(..12).unwrap_or(chip.digest()).to_owned(),
                    );
                    app.attachment_effect_state = AttachmentEffectState::Ready;
                    app.note(
                        block::NoticeLevel::Ok,
                        format!(
                            "attached {} context as [File #{}] · {} bytes · sha256:{}",
                            summary.0, summary.1, summary.2, summary.3
                        ),
                    );
                }
                Err(error) => {
                    app.attachment_effect_state = AttachmentEffectState::Failed;
                    app.note(
                        block::NoticeLevel::Warn,
                        format!("diff context refused: {error}"),
                    );
                }
            }
        }
        Ok(AttachmentWorkerOutput::PreparedFile(prepared)) => {
            let name = prepared.display_name().to_owned();
            let text_bytes = prepared.text_bytes();
            match app.editor.admit_prepared_file(prepared) {
                Ok(attachment) => {
                    let attachment_id = attachment.id();
                    app.attachment_effect_state = AttachmentEffectState::Ready;
                    app.note(
                        block::NoticeLevel::Ok,
                        format!(
                            "attached {name} ({text_bytes} bytes) as [File #{}] — deleting the tag removes its chip",
                            attachment_id
                        ),
                    );
                }
                Err(error) => {
                    app.attachment_effect_state = AttachmentEffectState::Failed;
                    app.note(
                        block::NoticeLevel::Warn,
                        format!("file attachment refused: {error}"),
                    );
                }
            }
        }
        Ok(AttachmentWorkerOutput::PreparedSubmission { images, files }) => {
            let AttachmentOrigin::ComposerSubmission {
                raw,
                draft_revision,
                image_mentions,
                file_mentions,
            } = origin
            else {
                app.attachment_effect_state = AttachmentEffectState::Failed;
                app.note(
                    block::NoticeLevel::Warn,
                    "attachment worker returned a mismatched submission result",
                );
                return;
            };
            if app.editor.persistence_revision() != draft_revision || app.editor.text() != raw {
                app.attachment_effect_state = AttachmentEffectState::Cancelled;
                app.note(
                    block::NoticeLevel::Info,
                    "attachments finished after the draft changed; submission kept for review",
                );
                return;
            }
            app.attachment_effect_state = AttachmentEffectState::Ready;
            submit_prepared_composer(
                app,
                session,
                notifier,
                raw,
                image_mentions,
                file_mentions,
                images,
                files,
            );
        }
        Ok(AttachmentWorkerOutput::Prepared(prepared)) => {
            let prepared_summary = (
                prepared.display_name().to_owned(),
                prepared.media_type(),
                prepared.file_bytes(),
            );
            let followup = match &origin {
                #[cfg(not(test))]
                AttachmentOrigin::Bare {
                    start,
                    end,
                    original,
                    draft_revision,
                    followup,
                    ..
                } => {
                    if app.editor.persistence_revision() != *draft_revision
                        || app.editor.span(*start, *end) != *original
                    {
                        app.attachment_effect_state = AttachmentEffectState::Cancelled;
                        app.note(
                            block::NoticeLevel::Info,
                            "image finished after the draft changed; path kept as text",
                        );
                        return;
                    }
                    app.editor.delete_span(*start, *end);
                    app.editor.set_cursor(*start);
                    *followup
                }
                _ => AttachmentFollowup::None,
            };
            match app.editor.admit_prepared_image(prepared) {
                Ok(attachment) => {
                    let attachment_id = attachment.id();
                    app.attachment_effect_state = AttachmentEffectState::Ready;
                    let (name, media_type, file_bytes) = prepared_summary;
                    app.note(
                        block::NoticeLevel::Ok,
                        format!(
                            "attached {name} ({}, {file_bytes} bytes) as [Image #{}] at the cursor",
                            media_type.as_str(),
                            attachment_id
                        ),
                    );
                    match followup {
                        AttachmentFollowup::None => {}
                        AttachmentFollowup::SubmitComposer => {
                            submit_composer(app, session, notifier);
                        }
                        AttachmentFollowup::QueueRunningDraft => {
                            queue_draft_with_chips(app);
                        }
                    }
                }
                Err(error) => {
                    app.attachment_effect_state = AttachmentEffectState::Failed;
                    #[cfg(not(test))]
                    if let AttachmentOrigin::Bare {
                        start, original, ..
                    } = origin
                    {
                        app.editor.set_cursor(start);
                        app.editor.insert_str(&original);
                    }
                    app.note(
                        block::NoticeLevel::Warn,
                        format!("image attachment refused: {error}"),
                    );
                }
            }
        }
        Ok(AttachmentWorkerOutput::EmptyClipboard) => {
            app.attachment_effect_state = AttachmentEffectState::Failed;
            app.note(
                block::NoticeLevel::Info,
                "no supported clipboard image adapter found; paste or drag an image path instead",
            );
        }
        Err(error) => {
            app.attachment_effect_state = AttachmentEffectState::Failed;
            match origin {
                AttachmentOrigin::Dropped { original, .. } => {
                    app.editor.insert_str(&original);
                    app.note(
                        block::NoticeLevel::Warn,
                        format!("image attachment refused: {error} — the path is still in the composer as text"),
                    );
                }
                AttachmentOrigin::DroppedFile { original } => {
                    app.editor.insert_str(&original);
                    app.note(
                        block::NoticeLevel::Warn,
                        format!("file attachment refused: {error} — the path is still in the composer as text"),
                    );
                }
                #[cfg(not(test))]
                AttachmentOrigin::Bare {
                    dropped_shape,
                    ..
                } if dropped_shape => app.note(
                    block::NoticeLevel::Warn,
                    format!("image attachment refused: {error} — the path is still in the composer as text"),
                ),
                _ => app.note(block::NoticeLevel::Warn, error),
            }
        }
    }
}

/// Resolve explicit `@path.png` mentions into the same bounded attachment collection used by
/// drag/drop, then submit one legacy or multimodal SQ operation. Work is staged against a clone:
/// an invalid file or a saturated SQ leaves the operator's draft and chips intact.
/// Image paths sitting in the draft as bare text, as `(char_start, char_end, path)` spans.
///
/// A terminal drop is supposed to arrive as a bracketed paste, and when it does the paste lane turns
/// it into a chip. Not every terminal sends one: some replay a drop as ordinary keystrokes, and then
/// the path is just text the operator watched appear — no chip, no anchor, and the picture is not
/// sent. This scan is the backstop that does not depend on which lane the bytes came in through.
///
/// Tokens are split on ASCII whitespace that is NOT backslash-escaped, because that is exactly how
/// a terminal writes a dropped path: `/tmp/Screenshot\ 2026-08-06\ at\ 3.57.44\ PM.png` is ONE
/// token. A token counts only if it parses as an image reference — an absolute-looking path with a
/// recognised image extension — and the caller drops it again if the bytes do not sniff as that
/// image, so prose that merely mentions a path is never converted.
///
/// ASCII, not `char::is_whitespace`: see [`dropped_image_reference`] for the file names that
/// distinction decides.
pub(super) fn bare_image_path_spans(text: &str) -> Vec<(usize, usize, PathBuf)> {
    let mut spans = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if chars[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        let mut token = String::new();
        while index < chars.len() {
            let character = chars[index];
            if character == '\\' && index + 1 < chars.len() {
                token.push(character);
                token.push(chars[index + 1]);
                index += 2;
                continue;
            }
            if character.is_ascii_whitespace() {
                break;
            }
            token.push(character);
            index += 1;
        }
        if let Ok(Some(path)) = dropped_image_reference(&token) {
            spans.push((start, index, path));
        }
    }
    spans
}

/// One bracketed paste landing on the composer.
///
/// A function rather than an arm of the event-loop `match` so the drop lane can be driven by a test
/// the way the terminal drives it. The bug this pulls out of the loop was invisible to every test
/// that existed: the parser was asked the right question in isolation and answered correctly, while
/// the lane that actually receives a drop fell through to "ordinary pasted text" and said nothing.
///
/// A drop is a drop whether or not a run is in flight. This used to be gated on `!app.running`,
/// which meant dragging a screenshot onto a working agent silently produced a line of path text —
/// the operator's evidence that the feature exists at all is the chip, and there was none. The
/// draft that carries the chip is queued rather than steered (`Op::Steer` cannot hold an image), so
/// nothing about the running turn changes.
pub(super) fn handle_composer_paste(app: &mut App, workspace: &Path, pasted: &str) {
    match dropped_image_reference(pasted) {
        Ok(Some(path)) => {
            let image_path = if path.is_absolute() {
                path
            } else {
                workspace.join(path)
            };
            #[cfg(test)]
            {
                let attached = app.editor.attach_image_path(&image_path).map(|attachment| {
                    (
                        attachment.id(),
                        attachment.display_name().to_owned(),
                        attachment.media_type(),
                        attachment.file_bytes(),
                    )
                });
                match attached {
                    Ok((id, name, media_type, file_bytes)) => app.note(
                        block::NoticeLevel::Ok,
                        format!(
                            "attached {name} ({}, {file_bytes} bytes) as [Image #{id}] at the cursor",
                            media_type.as_str()
                        ),
                    ),
                    Err(error) => {
                        app.editor.insert_str(pasted);
                        note_image_refusal(app, &image_path, &error);
                    }
                }
                app.completion = None;
            }
            #[cfg(not(test))]
            queue_image_path_effect(
                app,
                image_path.clone(),
                AttachmentOrigin::Dropped {
                    original: pasted.to_owned(),
                },
            );
            #[cfg(not(test))]
            app.note(
                block::NoticeLevel::Info,
                "image queued · reading and decoding in background · you can keep typing",
            );
            #[cfg(not(test))]
            {
                app.completion = None;
            }
        }
        Ok(None) => {
            // Not an image. A whole-input paste that is an absolute path already
            // inside the workspace is a dragged-in file, and becomes a file chip
            // on the same terms; anything else is ordinary pasted text.
            // A dropped FILE is admitted on the same terms as a dropped image,
            // during a run as well: the chip lands on the draft and the draft is
            // queued behind the turn. The `app.running` half of this match used to
            // send it to the composer as raw path text instead.
            match file_input::parse_dropped_file_path(workspace, pasted) {
                Some(dropped) => {
                    queue_file_path_effect(
                        app,
                        file_input::ContextKind::File,
                        workspace.to_path_buf(),
                        dropped,
                        AttachmentOrigin::DroppedFile {
                            original: pasted.to_owned(),
                        },
                    );
                    app.note(
                        block::NoticeLevel::Info,
                        "file queued · reading in background · you can keep typing",
                    );
                    app.completion = None;
                }
                // A paste too big to read is held aside as one tag rather than
                // dumped line by line into the composer: the operator keeps a
                // legible draft, and `take_submit` puts the original bytes back
                // where the tag stood. Small pastes stay inline — a tag they
                // cannot read would be worse than the three lines they can.
                _ if paste_input::should_capture(pasted) => {
                    match app.editor.capture_paste(pasted) {
                        Ok(capture) => app.note(
                            block::NoticeLevel::Ok,
                            format!(
                                "held paste #{} aside ({} line{}, {} bytes) — deleting the tag removes its chip",
                                capture.id,
                                capture.lines + 1,
                                if capture.lines == 0 { "" } else { "s" },
                                capture.bytes
                            ),
                        ),
                        Err(error) => app.note(
                            block::NoticeLevel::Warn,
                            format!("paste refused: {error}"),
                        ),
                    }
                    app.schedule_completion();
                }
                _ => {
                    app.editor.insert_str(pasted);
                    // The same conversion the typing lane runs, on the lane that does NOT end in a
                    // keystroke. A drop that arrives inside a longer paste, or split across more
                    // than one paste event, only becomes a whole path once it is in the buffer —
                    // and nothing else was ever going to look at it, because the keystroke hook
                    // fires on `KeyCode::Char` and a paste is not one.
                    attach_bare_image_paths(app, workspace);
                    app.schedule_completion();
                }
            }
        }
        Err(error) => app.note(
            block::NoticeLevel::Warn,
            format!("image attachment refused: {error}"),
        ),
    }
}

/// The image path one dropped token names, or `None` if the token is not one.
///
/// [`image_input::parse_explicit_image_path`] remains the only authority on what counts as an image
/// reference — the extension whitelist, the `-` / `~/` / `://` / control-character refusals, the
/// length bound. All this function adds is the terminal's half of the contract.
///
/// A terminal escapes a dropped path for a SHELL, so it escapes exactly what a shell splits on —
/// ASCII space and tab — and writes every other character of the file name through untouched.
/// `char::is_whitespace` is the Unicode predicate and answers `true` for a great deal more than
/// that, so any path containing a non-ASCII space was read as two tokens and the drop was refused
/// as "not a path".
///
/// That is not a corner case, it is every macOS screenshot. Since the system time format changed,
/// screenshots are named `Screenshot <date> at <time>\u{202f}PM.png` with U+202F NARROW NO-BREAK
/// SPACE before AM/PM. The terminal escapes the three ASCII spaces as `\ ` and leaves the U+202F
/// raw, so the dropped token is `…/Screenshot\ 2026-08-06\ at\ 5.26.07<U+202F>PM.png`. Confirmed
/// against a recorded session: the parser stopped at the U+202F, the paste lane fell through to
/// "ordinary pasted text", and the escaped path went to the model as prose — no chip, no image, and
/// nothing said about any of it.
pub(super) fn dropped_image_reference(
    raw: &str,
) -> Result<Option<PathBuf>, image_input::ImageInputError> {
    match image_input::parse_explicit_image_path(raw) {
        Ok(Some(reference)) => return Ok(Some(reference.path().to_path_buf())),
        Err(error) => return Err(error),
        Ok(None) => {}
    }
    // Retry ONLY the non-ASCII-space case. Everything else the parser turned down, it turned down
    // on its own terms, and this must not second-guess it.
    let token = raw.trim();
    if !token
        .chars()
        .any(|character| character.is_whitespace() && !character.is_ascii_whitespace())
    {
        return Ok(None);
    }
    let Some(decoded) = decode_dropped_escapes(token) else {
        return Ok(None);
    };
    // A trailing backslash would be an escape with nothing after it once quoted, and an empty
    // candidate is not a path. Both are rejected here so the quoted retry below can never mean
    // something different from the token the terminal wrote.
    if decoded.is_empty() || decoded.ends_with('\\') {
        return Ok(None);
    }
    // The double-quoted form is the parser's OWN way of being told "these characters are one path";
    // inside it whitespace is not a separator, and every other check it makes still runs. Asking it
    // again this way is how the terminal's escaping is undone without re-deciding what an image is.
    Ok(
        image_input::parse_explicit_image_path(&format!("\"{decoded}\""))?
            .map(|reference| reference.path().to_path_buf()),
    )
}

/// Undo the escaping a terminal applies when it writes a dropped path.
///
/// Conservative on purpose, and the same rule the shared parser uses: a backslash may only
/// introduce a character a terminal would actually have escaped. An unrecognised escape means this
/// is not a dropped path, and the token is left alone rather than guessed at.
///
/// Unescaped ASCII whitespace ends a shell token, so seeing it means this is more than one token
/// and therefore not one path. Non-ASCII whitespace is deliberately NOT a separator here: a
/// terminal does not escape it, which is the entire reason this decoder exists.
///
/// On Windows a backslash is a path separator and nothing is escaped, so the token already is the
/// path — mirroring `image_input::parse`, which makes the same platform split.
pub(super) fn decode_dropped_escapes(token: &str) -> Option<String> {
    if cfg!(windows) {
        return (!token
            .chars()
            .any(|character| character.is_ascii_whitespace()))
        .then(|| token.to_owned());
    }
    let mut decoded = String::with_capacity(token.len());
    let mut escaped = false;
    for character in token.chars() {
        if escaped {
            if !matches!(character, '\\' | '"' | '\'' | ' ') {
                return None;
            }
            decoded.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character.is_ascii_whitespace() || matches!(character, '"' | '\'') {
            // An unescaped quote means the terminal wrote a quoted token, which the parser already
            // handles verbatim on the fast path above; reaching here with one means the token is
            // something else entirely.
            return None;
        } else {
            decoded.push(character);
        }
    }
    (!escaped).then_some(decoded)
}

/// Turn every bare image path in the draft into the chip and anchor it should have been.
///
/// Right to left, so the span of a path earlier in the sentence is still valid after a later one is
/// replaced. A path whose bytes cannot be read or do not sniff as an image is LEFT AS TEXT — the
/// operator may simply have been talking about a file — but it is NOT left in silence: the token
/// already passed the image-reference parser, so something that looks exactly like a dropped
/// picture did not become one, and the operator has to be able to find out why. Silence here is how
/// a screenshot whose ephemeral temp file had already been deleted looked identical to a feature
/// that does not exist.
pub(super) fn attach_bare_image_paths(app: &mut App, workspace: &Path) -> bool {
    queue_bare_image_path(app, workspace, AttachmentFollowup::None)
}

pub(super) fn queue_bare_image_path(
    app: &mut App,
    workspace: &Path,
    followup: AttachmentFollowup,
) -> bool {
    let spans = bare_image_path_spans(&app.editor.text());
    #[cfg(test)]
    {
        let _ = followup;
        let mut attached_any = false;
        for (start, end, path) in spans.into_iter().rev() {
            let dropped_shape = path.is_absolute();
            let absolute = if path.is_absolute() {
                path
            } else {
                workspace.join(path)
            };
            let original = app.editor.span(start, end);
            let before = app.editor.chip_count();
            app.editor.delete_span(start, end);
            app.editor.set_cursor(start);
            match app.editor.attach_image_path(&absolute) {
                Ok(_) => attached_any = true,
                Err(error) => {
                    debug_assert_eq!(app.editor.chip_count(), before);
                    app.editor.insert_str(&original);
                    if dropped_shape {
                        note_image_refusal(app, &absolute, &error);
                    }
                }
            }
        }
        attached_any
    }
    #[cfg(not(test))]
    if let Some((start, end, path)) = spans.into_iter().next_back() {
        // A terminal always writes an ABSOLUTE path when a file is dropped, so an absolute token
        // that fails to attach is a drop that went wrong and is worth saying so. A relative one is
        // far more likely to be prose — `see report.png` — and warning about every file name in a
        // pasted changelog would turn the transcript into noise nobody reads.
        let dropped_shape = path.is_absolute();
        let absolute = if path.is_absolute() {
            path
        } else {
            workspace.join(path)
        };
        let original = app.editor.span(start, end);
        let draft_revision = app.editor.persistence_revision();
        queue_image_path_effect(
            app,
            absolute.clone(),
            AttachmentOrigin::Bare {
                original,
                start,
                end,
                draft_revision,
                dropped_shape,
                followup,
            },
        );
        app.note(
            block::NoticeLevel::Info,
            "image queued · reading and decoding in background",
        );
        return true;
    }
    #[cfg(not(test))]
    false
}

/// Say — once per distinct path — that something shaped like a dropped image did not attach.
///
/// Deduplicated because [`attach_bare_image_paths`] rescans the whole draft on every keystroke: one
/// unreadable path left in the composer would otherwise push a notice per character typed. Only the
/// notice is suppressed, never the attempt, so a file that appears later still becomes a chip.
#[cfg(test)]
pub(super) fn note_image_refusal(app: &mut App, path: &Path, error: &image_input::ImageInputError) {
    if !app.refused_image_paths.insert(path.to_path_buf()) {
        return;
    }
    if app.refused_image_paths.len()
        > iteron_tunables::param_integer("cli.tui.max_refused_image_paths", MAX_REFUSED_IMAGE_PATHS)
    {
        app.refused_image_paths.clear();
    }
    app.note(
        block::NoticeLevel::Warn,
        format!("image attachment refused: {error} — the path is still in the composer as text"),
    );
}

/// Queue a mid-run draft that carries chips, moving the chips out of the composer with the text.
///
/// Returns whether it was queued. Admission is checked against the text the submission would
/// actually carry — [`crate::editor::Editor::submission_text`], not the raw buffer — and it is
/// checked BEFORE the draft is consumed, because the alternative is a refusal that has already
/// cleared the composer and dropped the images on the floor.
pub(super) fn queue_draft_with_chips(app: &mut App) -> bool {
    let preview = app.editor.submission_text();
    // A slash command or a `!bash` line is a frontend action, not a message: neither can carry an
    // attachment. Queuing one with chips would either send the command to the model as prose or
    // drop the chips on the way, and both are silent. Say so and keep everything where it is.
    if slash_command_body(preview.trim()).is_some() || preview.trim_start().starts_with('!') {
        app.note(
            block::NoticeLevel::Warn,
            "a slash command cannot carry attachments — send the chips as a message first, or \
             remove them with alt+backspace"
                .to_string(),
        );
        return false;
    }
    let pending = app.queued.len().saturating_add(app.steer_previews.len());
    if matches!(
        app.submission_admission(&preview, pending, "pending input"),
        SubmissionAdmission::Reject
    ) {
        return false;
    }
    let images = app.editor.attachments().clone();
    let files = app.editor.files().clone();
    let text = app.editor.take_submit();
    if let Err(text) = app.queue_after_turn_with(text, images, files) {
        // Unreachable in practice: the same admission just accepted this text. Preserve the words
        // rather than assume it.
        app.editor.insert_str(&text);
        return false;
    }
    true
}
